package asset

import (
	"bytes"
	"io"

	"github.com/cozy/swift"
)

type SwiftFS struct {
	Connection *swift.Connection
}

func (s *SwiftFS) AddAsset(asset *GlobalAsset, content io.Reader) error {
	// Creating object to swift
	sc := s.Connection
	f, err := sc.ObjectCreate(AssetContainerName, asset.MD5, true, asset.MD5, asset.ContentType, nil)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, content)
	return err

}

func (s *SwiftFS) GetAsset(md5 string) (*bytes.Buffer, map[string]string, error) {
	sc := s.Connection
	buf := new(bytes.Buffer)
	headers, err := sc.ObjectGet(AssetContainerName, md5, buf, false, nil)
	if err != nil {
		return nil, nil, err
	}
	return buf, headers, nil
}

// Remove asset cleans a UsedByEntry and deletes the asset is there are no more app using the asset
func (s *SwiftFS) RemoveAsset(md5 string) error {
	// No more app is using the asset, we are going to clean it from couch
	// and swift
	sc := s.Connection

	// Deleting the object from swift. If the object is not found, we should
	// not crash
	err := sc.ObjectDelete(AssetContainerName, md5)
	if err != nil && err != swift.ObjectNotFound {
		return err
	}

	return nil
}
