package storage

import (
	"bytes"
	"io"

	"github.com/ncw/swift"
)

type swiftFS struct {
	conn *swift.Connection
}

func (s *swiftFS) Ensure(prefix Prefix) error {
	return s.conn.ContainerCreate(string(prefix), nil)
}

func (s *swiftFS) Create(prefix Prefix, name, contentType string, content io.Reader) error {
	f, err := s.conn.ObjectCreate(string(prefix), name, true, "", contentType, nil)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, content)
	if e := f.Close(); e != nil && err == nil {
		err = e
	}
	return err
}

func (s *swiftFS) Get(prefix Prefix, name string) (*bytes.Buffer, map[string]string, error) {
	buf := new(bytes.Buffer)
	headers, err := s.conn.ObjectGet(string(prefix), name, buf, false, nil)
	if err != nil {
		return nil, nil, err
	}
	return buf, headers, nil
}

// Remove asset cleans a UsedByEntry and deletes the asset is there are no more app using the asset
func (s *swiftFS) Remove(prefix Prefix, name string) error {
	// Deleting the object from swift. If the object is not found, it's OK.
	err := s.conn.ObjectDelete(string(prefix), name)
	if err != nil && err != swift.ObjectNotFound {
		return err
	}

	return nil
}
