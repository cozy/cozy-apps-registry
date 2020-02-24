// Package storage can be used to persist files in a storage. It is Open-Stack
// Swift in production, but having a Swift server in local for development can
// be difficult, so this package can also used a local file system for the
// storage.
package storage

import (
	"bytes"
	"io"

	"github.com/cozy/cozy-apps-registry/config"
)

// Prefix is a way to regroup files. It can be related to a space, but there is
// also a prefix for the global assets. It is mapped to a Swift container (or a
// directory for the local file-system).
type Prefix string

// Operator is an interface with the operations that can be done on the storage.
type Operator interface {
	// Ensure make sure that the Swift container or local directory exists.
	Ensure(prefix Prefix) error
	// Create adds a file to the given container/directory.
	Create(prefix Prefix, name, contentType string, content io.Reader) error
	// Get fetches a file from the given container/directory.
	Get(prefix Prefix, name string) (*bytes.Buffer, map[string]string, error)
	// Remove deletes a file from the given container/directory.
	Remove(prefix Prefix, name string) error
}

// New returns a storage operator.
func New() Operator {
	conf := config.GetConfig()
	return &swiftFS{conn: conf.SwiftConnection}
}
