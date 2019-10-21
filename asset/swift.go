package asset

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/ncw/swift"
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

	f, err := sc.ObjectCreate(AssetContainerName, asset.Shasum, true, "", asset.ContentType, nil)
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

func (s *SwiftFS) EmptyThenDeleteContainer(name string) error {
	sc := s.Connection

	// First emptying the container
	objs, err := sc.ObjectNames(name, nil)
	if err != nil {
		return err
	}

	_, err = sc.BulkDelete(name, objs)
	if err != nil {
		for _, obj := range objs {
			err = sc.ObjectDelete(name, obj)
			if err != nil {
				return err
			}
		}
	}

	return sc.ContainerDelete(name)
}
