package asset

import (
	"bytes"
	"context"
	"io"

	"github.com/go-kivik/kivik"

	"github.com/cozy/cozy-apps-registry/config"
	"github.com/cozy/swift"
)

const assetContainerName string = "__assets__"

func AddAsset(asset *GlobalAsset, content io.Reader, source string) error {

	// Add to swift
	conf, err := config.GetConfig()
	sc := conf.SwiftConnection

	// Creating object to swift
	f, err := sc.ObjectCreate(assetContainerName, asset.MD5, true, asset.MD5, asset.ContentType, nil)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, content)
	if err != nil {
		return err
	}

	// CouchDB
	var doc *GlobalAsset
	row := globalAssetStoreDB.Get(context.Background(), asset.MD5, nil)
	err = row.ScanDoc(&doc)
	if err != nil && kivik.StatusCode(err) != kivik.StatusNotFound {
		return err
	}

	var docRev string
	// If asset does not exist, create it
	if kivik.StatusCode(err) == kivik.StatusNotFound {
		doc = asset
		doc.ID = asset.MD5
		_, docRev, err = globalAssetStoreDB.CreateDoc(context.Background(), doc)
		if err != nil {
			return err
		}
		doc.Rev = docRev
	}

	// Update it
	found := false
	for _, usedBy := range doc.UsedBy {
		if usedBy == source {
			found = true
			break
		}
	}
	if !found {
		doc.UsedBy = append(doc.UsedBy, source)
	}
	_, err = globalAssetStoreDB.Put(context.Background(), doc.ID, doc, nil)
	if err != nil {
		return err
	}

	return nil

}

func GetAsset(md5 string) (*bytes.Buffer, swift.Headers, error) {
	conf, err := config.GetConfig()
	if err != nil {
		return nil, nil, err
	}
	buf := new(bytes.Buffer)
	sc := conf.SwiftConnection
	headers, err := sc.ObjectGet(assetContainerName, md5, buf, false, nil)
	if err != nil {
		return nil, nil, err
	}
	return buf, headers, nil
}
