package asset

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"io/ioutil"

	"github.com/cozy/swift"
)

type SwiftFS struct {
	Connection *swift.Connection
}

func (s *SwiftFS) AddAsset(asset *GlobalAsset, content io.Reader) error {
	// Creating object in swift
	sc := s.Connection

	buf, err := ioutil.ReadAll(content)
	if err != nil {
		return err
	}

	// Calculating md5sum for swift insertion
	md5sum := md5.New()
	_, err = md5sum.Write(buf)
	if err != nil {
		return err
	}
	sum := md5sum.Sum(nil)

	f, err := sc.ObjectCreate(AssetContainerName, asset.Shasum, true, hex.EncodeToString(sum), asset.ContentType, nil)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(buf)
	return err

}

func (s *SwiftFS) GetAsset(shasum string) (*bytes.Buffer, map[string]string, error) {
	sc := s.Connection
	buf := new(bytes.Buffer)
	headers, err := sc.ObjectGet(AssetContainerName, shasum, buf, false, nil)
	if err != nil {
		return nil, nil, err
	}
	return buf, headers, nil
}

// Remove asset cleans a UsedByEntry and deletes the asset is there are no more app using the asset
func (s *SwiftFS) RemoveAsset(shasum string) error {
	sc := s.Connection

	// Deleting the object from swift. If the object is not found, we should
	// not crash
	err := sc.ObjectDelete(AssetContainerName, shasum)
	if err != nil && err != swift.ObjectNotFound {
		return err
	}

	return nil
}
