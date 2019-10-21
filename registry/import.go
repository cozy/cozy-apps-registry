package registry

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/cozy/cozy-apps-registry/asset"
	"github.com/cozy/cozy-apps-registry/config"
	"github.com/go-kivik/kivik"
	"io"
	"io/ioutil"
	"path"
	"strings"
)

func cleanCouch() error {
	fmt.Printf("Clean CouchDB\n")
	for _, db := range couchDatabases() {
		name := db.Name()
		fmt.Printf("  Clean CouchDB %s\n", name)
		if err := client.DestroyDB(ctx, name); err != nil {
			return err
		}
		if err := client.CreateDB(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func importCouchDocument(reader io.Reader, db string, id string) (string, error) {
	fmt.Printf("Import CouchDB document %s.%s\n", db, id)

	var doc json.RawMessage
	if err := json.NewDecoder(reader).Decode(&doc); err != nil {
		return "", err
	}

	c := client.DB(ctx, db)
	return c.Put(ctx, id, doc)
}

func importCouchAttachment(reader io.Reader, header *tar.Header, db string, id string, rev string, path string) (string, error) {
	fmt.Printf("Import CouchDB attachment %s.%s.%s\n", db, id, path)

	att := &kivik.Attachment{
		Content:         ioutil.NopCloser(reader),
		Size:            header.Size,
		Filename:        path,
		ContentType:     header.PAXRecords[contentTypeAttr],
		ContentEncoding: header.PAXRecords[contentEncodingAttr],
	}

	c := client.DB(ctx, db)
	return c.PutAttachment(ctx, id, rev, att)
}

func importCouch(reader io.Reader, header *tar.Header, parts []string, rev string) (string, error) {
	switch len(parts) {
	case 2:
		// We import a document
		db, id := parts[0], parts[1]
		id = strings.TrimSuffix(id, documentSuffix)
		return importCouchDocument(reader, db, id)
	default:
		// We import an attachment
		db, id, parts := parts[0], parts[1], parts[2:]
		path := path.Join(parts...)
		return importCouchAttachment(reader, header, db, id, rev, path)
	}
}

func cleanSwift() error {
	connection := config.GetConfig().SwiftConnection
	for _, container := range swiftContainers() {
		if err := asset.DeleteContainer(connection, container); err != nil {
			return err
		}
		if err := connection.ContainerCreate(container, nil); err != nil {
			return err
		}
	}

	return nil
}

func importSwift(reader io.Reader, header *tar.Header, parts []string) error {
	container, parts := parts[0], parts[1:]
	path := path.Join(parts...)
	fmt.Printf("Import Swift document %s.%s\n", container, path)

	contentType := header.PAXRecords[contentTypeAttr]

	connection := config.GetConfig().SwiftConnection
	_, err := connection.ObjectPut(container, path, reader, false, "", contentType, nil)
	return err
}

func Import(reader io.Reader, drop bool) error {
	zw, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer zw.Close()
	tw := tar.NewReader(zw)

	if drop {
		if err := cleanCouch(); err != nil {
			return err
		}
		if err := cleanSwift(); err != nil {
			return err
		}
	}

	rev := ""
	for {
		header, err := tw.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		name := header.Name
		parts := strings.Split(name, "/")
		prefix, parts := parts[0], parts[1:]
		if prefix != rootPrefix {
			continue
		}

		prefix, parts = parts[0], parts[1:]
		switch prefix {
		case couchPrefix:
			if rev, err = importCouch(tw, header, parts, rev); err != nil {
				return err
			}
		case swiftPrefix:
			if err = importSwift(tw, header, parts); err != nil {
				return err
			}
		}

	}

	return nil
}
