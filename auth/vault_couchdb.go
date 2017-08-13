package auth

import (
	"context"
	"encoding/json"

	"github.com/flimzy/kivik"
)

type couchdbVault struct {
	db  *kivik.DB
	ctx context.Context
}

type editorWithPrivateKey struct {
	Name                     string `json:"name"`
	PrivateKeyBytes          []byte `json:"private_key,omitempty"`
	PrivateKeyBytesEncrypted []byte `json:"private_key_encrypted,omitempty"`
	PublicKeyBytes           []byte `json:"public_key"`
}

func NewCouchdbVault(client *kivik.Client, dbName string) (EditorVault, error) {
	ctx := context.Background()
	db, err := client.DB(ctx, dbName)
	if err != nil {
		return nil, err
	}
	return &couchdbVault{db, ctx}, nil
}

func (r *couchdbVault) LoadEditors() ([]*Editor, error) {
	// XXX: db.AllDocs does not seem to work properly ?
	rows, err := r.db.Find(r.ctx, json.RawMessage(`{"selector":{}}`))
	if err != nil {
		return nil, err
	}
	var editors []*Editor
	for rows.Next() {
		var e editorWithPrivateKey
		if err := rows.ScanDoc(&e); err != nil {
			return nil, err
		}
		editor := &Editor{
			name:                     e.Name,
			privateKeyBytes:          e.PrivateKeyBytes,
			privateKeyBytesEncrypted: e.PrivateKeyBytesEncrypted,
			publicKeyBytes:           e.PublicKeyBytes,
		}
		editors = append(editors, editor)
	}
	return editors, nil
}

func (r *couchdbVault) AddEditor(editor *Editor) error {
	doc := editorWithPrivateKey{
		Name:                     editor.name,
		PrivateKeyBytes:          editor.privateKeyBytes,
		PrivateKeyBytesEncrypted: editor.privateKeyBytesEncrypted,
		PublicKeyBytes:           editor.publicKeyBytes,
	}
	_, _, err := r.db.CreateDoc(r.ctx, doc)
	return err
}
