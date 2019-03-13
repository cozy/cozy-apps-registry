package asset

import (
	"bytes"
	"io"

	"github.com/go-kivik/kivik"

	"github.com/cozy/cozy-apps-registry/config"
	"github.com/cozy/swift"
)

func AddAsset(asset *GlobalAsset, content io.Reader, source string) error {

	// Add to swift
	conf, err := config.GetConfig()
	sc := conf.SwiftConnection

	// Creating object to swift
	f, err := sc.ObjectCreate(AssetContainerName, asset.MD5, true, asset.MD5, asset.ContentType, nil)
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
	row := globalAssetStoreDB.Get(ctx, asset.MD5, nil)
	err = row.ScanDoc(&doc)
	if err != nil && kivik.StatusCode(err) != kivik.StatusNotFound {
		return err
	}

	var docRev string
	// If asset does not exist in CouchDB global asset database, create it
	if kivik.StatusCode(err) == kivik.StatusNotFound {
		doc = asset
		doc.ID = asset.MD5
		_, docRev, err = globalAssetStoreDB.CreateDoc(ctx, doc)
		if err != nil {
			return err
		}
		doc.Rev = docRev
	}

	// Updating the UsedBy field to add the new app version
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
	_, err = globalAssetStoreDB.Put(ctx, doc.ID, doc, nil)
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
	headers, err := sc.ObjectGet(AssetContainerName, md5, buf, false, nil)
	if err != nil {
		return nil, nil, err
	}
	return buf, headers, nil
}

// Remove asset cleans a UsedByEntry and deletes the asset is there are no more app using the asset
func RemoveAsset(md5, versionFilepath string) error {
	row := globalAssetStoreDB.Get(ctx, md5)

	var assetDoc *GlobalAsset
	err := row.ScanDoc(&assetDoc)
	if err != nil && kivik.StatusCode(err) != kivik.StatusNotFound {
		return err
	}

	var updatedVersions []string
	for _, versionfp := range assetDoc.UsedBy {
		if versionfp == versionFilepath {
			continue
		}
		updatedVersions = append(updatedVersions, versionfp)
	}

	if len(updatedVersions) > 0 {
		assetDoc.UsedBy = updatedVersions
		_, err := globalAssetStoreDB.Put(ctx, md5, assetDoc)
		if err != nil {
			return err
		}
	} else {
		// No more app is using the asset, we are going to clean it from couch
		// and swift
		conf, err := config.GetConfig()
		if err != nil {
			return err
		}
		sc := conf.SwiftConnection

		// Deleting the object from swift. If the object is not found, we should
		// not crash
		err = sc.ObjectDelete(AssetContainerName, md5)
		if err != nil && err != swift.ObjectNotFound {
			return err
		}

		_, err = globalAssetStoreDB.Delete(ctx, md5, assetDoc.Rev)
		return err
	}

	return nil
}
