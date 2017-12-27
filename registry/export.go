package registry

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/go-kivik/kivik"
)

func Export(out io.Writer) (err error) {
	buf := bufio.NewWriter(out)
	defer func() {
		if err == nil {
			err = buf.Flush()
		}
	}()

	zw := gzip.NewWriter(buf)
	defer func() {
		if err == nil {
			err = zw.Close()
		}
	}()

	tw := tar.NewWriter(zw)
	defer func() {
		if err == nil {
			err = tw.Close()
		}
	}()

	for _, c := range contexts {
		if err = writeDocs(c.AppsDB(), tw); err != nil {
			return
		}
		if err = writeDocs(c.VersDB(), tw); err != nil {
			return
		}
	}

	err = writeDocs(globalEditorsDB, tw)
	return
}

func writeDocs(db *kivik.DB, tw *tar.Writer) error {
	rows, err := db.AllDocs(ctx, map[string]interface{}{
		"include_docs": true,
		"limit":        2000,
	})
	if err != nil {
		return err
	}

	type attachment struct {
		docID string
		name  string
	}

	dbName := db.Name()

	var atts []*attachment
	for rows.Next() {
		if strings.HasPrefix(rows.ID(), "_design") {
			continue
		}

		var v map[string]interface{}
		if err = rows.ScanDoc(&v); err != nil {
			return err
		}

		if attachments, ok := v["_attachments"].(map[string]interface{}); ok {
			for name := range attachments {
				atts = append(atts, &attachment{docID: rows.ID(), name: name})
			}
			delete(v, "_attachments")
		}

		delete(v, "_rev")

		var data []byte
		data, err = json.Marshal(v)
		if err != nil {
			return err
		}

		hdr := &tar.Header{
			Name:     path.Join(dbName, rows.ID()),
			Size:     int64(len(data)),
			Mode:     0640,
			Typeflag: tar.TypeReg,
		}
		if err = tw.WriteHeader(hdr); err != nil {
			return err
		}

		_, err = io.Copy(tw, bytes.NewReader(data))
		if err != nil {
			return err
		}
	}

	for _, att := range atts {
		if err = writeAttachment(db, tw, dbName, att.docID, att.name); err != nil {
			return err
		}
	}

	return nil
}

func writeAttachment(db *kivik.DB, tw *tar.Writer, dbName, docID, filename string) error {
	u := fmt.Sprintf("%s/%s/%s/%s",
		clientURL.String(),
		url.PathEscape(db.Name()),
		url.PathEscape(docID),
		url.PathEscape(filename),
	)

	res, err := http.Get(u)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Could not fetch attachment %q: %s",
			fmt.Sprintf("%s/%s/%s", dbName, docID, filename), res.Status)
	}

	size, err := strconv.ParseInt(res.Header.Get("content-length"), 10, 64)
	if err != nil {
		return err
	}

	hdr := &tar.Header{
		Name:     path.Join(dbName, docID, filename),
		Size:     size,
		Mode:     0640,
		Typeflag: tar.TypeReg,
		Xattrs: map[string]string{
			"type": res.Header.Get("Content-Type"),
		},
	}
	if err = tw.WriteHeader(hdr); err != nil {
		return err
	}

	_, err = io.Copy(tw, res.Body)
	return err
}

func Import(in io.Reader) (err error) {
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			err = zr.Close()
		}
	}()

	docs := make(map[string]string) // id -> rev of created documents

	tr := tar.NewReader(zr)
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}

		parts := strings.SplitN(hdr.Name, "/", 3)
		if len(parts) < 2 {
			continue
		}

		dbName := parts[0]
		docID := parts[1]

		var ok bool
		ok, err = client.DBExists(ctx, dbName)
		if err != nil {
			return
		}
		if !ok {
			if err = client.CreateDB(ctx, dbName); err != nil {
				return
			}
		}

		var db *kivik.DB
		db, err = client.DB(ctx, dbName)
		if err != nil {
			return
		}

		if len(parts) == 3 {
			attName := parts[2]
			attLong := fmt.Sprintf("%s/%s/%s", dbName, docID, attName)
			rev, ok := docs[docID]
			if !ok {
				return fmt.Errorf("Could not create attachment %q: document was not created",
					attLong)
			}

			fmt.Printf("Creating attachment %q...", attLong)
			a := kivik.NewAttachment(attName, hdr.Xattrs["type"], ioutil.NopCloser(tr))
			rev, err = db.PutAttachment(ctx, docID, rev, a)
			if err != nil {
				return fmt.Errorf("Could not create attachment %q: %s",
					attLong, err)
			}
			fmt.Println("ok.")

			docs[docID] = rev
			continue
		}

		var v json.RawMessage
		if err = json.NewDecoder(tr).Decode(&v); err != nil {
			return err
		}
		fmt.Printf("Creating document %q...", fmt.Sprintf("%s/%s", dbName, docID))
		id, rev, err := db.CreateDoc(ctx, v)
		if err != nil {
			return err
		}
		fmt.Println("ok.")

		docs[id] = rev
	}

	return nil
}