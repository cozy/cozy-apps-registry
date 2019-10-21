package registry

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/cozy/cozy-apps-registry/asset"
	"github.com/cozy/cozy-apps-registry/config"
	"github.com/ncw/swift"
	"io"
	"io/ioutil"
	"path"
	"strings"

	"github.com/go-kivik/kivik"
)

const rootPrefix = "registry"
const couchPrefix = "couchdb"
const swiftPrefix = "swift"
const documentSuffix = ".json"
const contentTypeAttr = "COZY.content-type"
const contentEncodingAttr = "COZY.content-encoding"

func writeFile(writer *tar.Writer, path string, content []byte, attrs map[string]string) error {
	header := &tar.Header{
		Typeflag:   tar.TypeReg,
		Name:       path,
		Mode:       0600,
		Size:       int64(len(content)),
		PAXRecords: attrs,
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return nil
}

func writeReaderFile(writer *tar.Writer, path string, reader io.Reader, attrs map[string]string) error {
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return err
	}
	return writeFile(writer, path, content, attrs)
}

func exportCouchAttachment(writer *tar.Writer, prefix string, db *kivik.DB, id string, filename string) error {
	file := path.Join(prefix, filename)
	fmt.Printf("      Exporting %s.%s.%s attachment\n", db.Name(), id, filename)
	att, err := db.GetAttachment(ctx, id, filename)
	if err != nil {
		return err
	}
	defer att.Content.Close()

	content, err := ioutil.ReadAll(att.Content)
	if err != nil {
		return err
	}
	metadata := map[string]string{
		contentTypeAttr:     att.ContentType,
		contentEncodingAttr: att.ContentEncoding,
	}
	if err = writeFile(writer, file, content, metadata); err != nil {
		return err
	}

	return nil
}

func exportCouchAttachments(writer *tar.Writer, prefix string, db *kivik.DB, id string, attachments map[string]interface{}) error {
	if attachments == nil {
		return nil
	}

	prefix = path.Join(prefix, id)
	fmt.Printf("    Exporting %s attachments\n", id)
	for name := range attachments {
		if err := exportCouchAttachment(writer, prefix, db, id, name); err != nil {
			return err
		}
	}

	return nil
}

func exportCouchDocument(writer *tar.Writer, prefix string, db *kivik.DB, rows *kivik.Rows) error {
	id := rows.ID()
	if strings.HasPrefix(id, "_design") {
		return nil
	}

	file := path.Join(prefix, fmt.Sprintf("%s%s", id, documentSuffix))
	fmt.Printf("    Exporting %s\n", id)

	var value map[string]interface{}
	if err := rows.ScanDoc(&value); err != nil {
		return err
	}

	delete(value, "_rev")
	attachments, _ := value["_attachments"].(map[string]interface{})
	delete(value, "_attachments")

	var data []byte
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err = writeFile(writer, file, data, nil); err != nil {
		return err
	}

	// Only export after document, else import will fail
	if err := exportCouchAttachments(writer, prefix, db, id, attachments); err != nil {
		return err
	}

	return nil
}

func exportCouchDb(writer *tar.Writer, prefix string, db *kivik.DB) error {
	name := db.Name()
	prefix = path.Join(prefix, name)
	fmt.Printf("  Exporting %s\n", name)

	skip := 0
	for {
		rows, err := db.AllDocs(ctx, map[string]interface{}{
			"include_docs": true,
			"limit":        1000,
			"skip":         skip,
		})
		if err != nil {
			return err
		}
		noContent := true
		for rows.Next() {
			noContent = false
			skip += 1
			if err := exportCouchDocument(writer, prefix, db, rows); err != nil {
				return err
			}
		}
		if noContent {
			break
		}
	}

	return nil
}

func couchDatabases() []*kivik.DB {
	dbs := []*kivik.DB{asset.AssetStore.DB}
	for _, c := range spaces {
		dbs = append(dbs, c.DBs()...)
	}
	return dbs
}

func exportCouch(writer *tar.Writer, prefix string) error {
	fmt.Printf("  Exporting CouchDB\n")
	prefix = path.Join(prefix, couchPrefix)

	dbs := couchDatabases()
	for _, db := range dbs {
		if err := exportCouchDb(writer, prefix, db); err != nil {
			return err
		}
	}

	return nil
}

func exportSwiftContainer(writer *tar.Writer, prefix string, connection *swift.Connection, container string) error {
	fmt.Printf("    Exporting %s\n", container)
	prefix = path.Join(prefix, container)

	return connection.ObjectsWalk(container, nil, func(opts *swift.ObjectsOpts) (interface{}, error) {
		objects, err := connection.Objects(container, opts)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			name := object.Name
			fmt.Printf("      Exporting %s\n", name)

			buffer := new(bytes.Buffer)
			if _, err := connection.ObjectGet(container, name, buffer, false, nil); err != nil {
				return nil, err
			}

			file := path.Join(prefix, name)
			metadata := map[string]string{
				contentTypeAttr: object.ContentType,
			}
			if err := writeReaderFile(writer, file, buffer, metadata); err != nil {
				return nil, err
			}
		}
		return objects, nil
	})
}

func swiftContainers() []string {
	containers := []string{asset.AssetContainerName}
	for _, space := range spaces {
		container := GetPrefixOrDefault(space)
		containers = append(containers, container)
	}
	return containers
}

func exportSwift(writer *tar.Writer, prefix string) error {
	fmt.Printf("  Exporting Swift\n")
	prefix = path.Join(prefix, swiftPrefix)

	containers := swiftContainers()

	connection := config.GetConfig().SwiftConnection
	for _, container := range containers {
		if err := exportSwiftContainer(writer, prefix, connection, container); err != nil {
			return err
		}
	}

	return nil
}

func Export(writer io.Writer) (err error) {
	buf := bufio.NewWriter(writer)
	defer func() {
		if e := buf.Flush(); e != nil && err == nil {
			err = e
		}
	}()
	zw := gzip.NewWriter(writer)
	defer func() {
		if e := zw.Close(); e != nil && err == nil {
			err = e
		}
	}()
	tw := tar.NewWriter(zw)
	defer func() {
		if e := tw.Close(); e != nil && err == nil {
			err = e
		}
	}()

	if err := exportCouch(tw, rootPrefix); err != nil {
		return err
	}
	if err := exportSwift(tw, rootPrefix); err != nil {
		return err
	}

	return nil
}
