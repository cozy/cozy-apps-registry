package registry

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/cozy/cozy-apps-registry/asset"
	"io"
	"io/ioutil"
	"path"
	"strings"

	"github.com/go-kivik/kivik"
)

func writeFile(writer *tar.Writer, path string, content []byte) error {
	header := &tar.Header{
		Name: path,
		Mode: 0600,
		Size: int64(len(content)),
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return nil
}

func exportCouchAttachment(writer *tar.Writer, prefix string, db *kivik.DB, id string, filename string) error {
	file := path.Join(prefix, filename)
	fmt.Printf("      Exporting %s.%s.%s attachment…\n", db.Name(), id, filename)
	att, err := db.GetAttachment(ctx, id, filename)
	if err != nil {
		return err
	}
	defer att.Content.Close()

	content, err := ioutil.ReadAll(att.Content)
	if err != nil {
		return err
	}
	if err = writeFile(writer, file, content); err != nil {
		return err
	}

	return nil
}

func exportCouchAttachments(writer *tar.Writer, prefix string, db *kivik.DB, id string, value map[string]interface{}) error {
	if attachments, ok := value["_attachments"].(map[string]interface{}); ok {
		prefix = path.Join(prefix, id)
		fmt.Printf("    Exporting %s attachments…\n", id)
		for name := range attachments {
			if err := exportCouchAttachment(writer, prefix, db, id, name); err != nil {
				return err
			}
		}
		delete(value, "_attachments")
	}
	return nil
}

func exportCouchDoc(writer *tar.Writer, prefix string, db *kivik.DB, rows *kivik.Rows) error {
	id := rows.ID()
	if strings.HasPrefix(id, "_design") {
		return nil
	}

	file := path.Join(prefix, fmt.Sprintf("%s.json", id))
	fmt.Printf("    Exporting %s…\n", id)

	var value map[string]interface{}
	if err := rows.ScanDoc(&value); err != nil {
		return err
	}

	delete(value, "_rev")
	if err := exportCouchAttachments(writer, prefix, db, id, value); err != nil {
		return err
	}

	var data []byte
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if err = writeFile(writer, file, data); err != nil {
		return err
	}

	return nil
}

func exportCouchDb(writer *tar.Writer, prefix string, db *kivik.DB) error {
	name := db.Name()
	prefix = path.Join(prefix, name)
	fmt.Printf("  Exporting %s…\n", name)

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
			if err := exportCouchDoc(writer, prefix, db, rows); err != nil {
				return err
			}
		}
		if noContent {
			break
		}
	}

	return nil
}

func exportCouch(writer *tar.Writer, prefix string) error {
	fmt.Printf("  Exporting CouchDB…\n")

	prefix = path.Join(prefix, "couchdb")

	dbs := []*kivik.DB{asset.AssetStore.DB}
	for _, c := range spaces {
		dbs = append(dbs, c.DBs()...)
	}

	for _, db := range dbs {
		if err := exportCouchDb(writer, prefix, db); err != nil {
			return err
		}
	}

	return nil
}

func exportSwift(writer *tar.Writer, prefix string) error {
	return nil
}

func Export(writer io.Writer) error {
	buf := bufio.NewWriter(writer)
	defer buf.Flush()
	zw := gzip.NewWriter(writer)
	defer zw.Close()
	tw := tar.NewWriter(zw)
	defer tw.Close()

	prefix := "registry"

	if err := exportCouch(tw, prefix); err != nil {
		return err
	}
	if err := exportSwift(tw, prefix); err != nil {
		return err
	}

	return nil
}

func Import(reader io.Reader) error {
	return nil
}
