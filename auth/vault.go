package auth

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/flimzy/kivik"
)

type couchdbVault struct {
	db  *kivik.DB
	ctx context.Context
}

type editorForCouchdb struct {
	ID             string `json:"_id,omitempty"`
	Rev            string `json:"_rev,omitempty"`
	Name           string `json:"name"`
	SessionSalt    []byte `json:"session_secret_salt"`
	PublicKeyBytes []byte `json:"public_key"`
}

func NewCouchdbVault(client *kivik.Client, dbName string) (Vault, error) {
	ctx := context.Background()
	db, err := client.DB(ctx, dbName)
	if err != nil {
		return nil, err
	}
	return &couchdbVault{db, ctx}, nil
}

func (r *couchdbVault) GetEditor(editorName string) (*Editor, error) {
	e, err := r.getEditor(editorName)
	if err != nil {
		return nil, err
	}
	return &Editor{
		name:           e.Name,
		sessionSalt:    e.SessionSalt,
		publicKeyBytes: e.PublicKeyBytes,
	}, nil
}

func (r *couchdbVault) CreateEditor(editor *Editor) error {
	_, err := r.getEditor(editor.name)
	if err == nil {
		return ErrEditorExists
	}
	if err != ErrEditorNotFound {
		return err
	}
	_, _, err = r.db.CreateDoc(r.ctx, &editorForCouchdb{
		ID:             strings.ToLower(editor.name),
		Name:           editor.name,
		SessionSalt:    editor.sessionSalt,
		PublicKeyBytes: editor.publicKeyBytes,
	})
	return err
}

func (r *couchdbVault) UpdateEditor(editor *Editor) error {
	e, err := r.getEditor(editor.name)
	if err != nil {
		return err
	}
	_, err = r.db.Put(r.ctx, e.ID, &editorForCouchdb{
		ID:             e.ID,
		Rev:            e.Rev,
		Name:           editor.name,
		SessionSalt:    editor.sessionSalt,
		PublicKeyBytes: editor.publicKeyBytes,
	})
	return err
}

func (r *couchdbVault) DeleteEditor(editor *Editor) error {
	e, err := r.getEditor(editor.name)
	if err != nil {
		return err
	}
	_, err = r.db.Delete(r.ctx, e.ID, e.Rev)
	return err
}

func (r *couchdbVault) AllEditors() ([]*Editor, error) {
	rows, err := r.db.Find(r.ctx, json.RawMessage(`{"selector":{},"limit":2000}`))
	if err != nil {
		return nil, err
	}
	var editors []*Editor
	for rows.Next() {
		var e editorForCouchdb
		if strings.HasPrefix(rows.ID(), "_design") {
			continue
		}
		if err = rows.ScanDoc(&e); err != nil {
			return nil, err
		}
		editors = append(editors, &Editor{
			name:           e.Name,
			sessionSalt:    e.SessionSalt,
			publicKeyBytes: e.PublicKeyBytes,
		})
	}
	return editors, nil
}

func (r *couchdbVault) getEditor(editorName string) (*editorForCouchdb, error) {
	editorID := strings.ToLower(editorName)
	row, err := r.db.Get(r.ctx, editorID)
	if kivik.StatusCode(err) == kivik.StatusNotFound {
		return nil, ErrEditorNotFound
	}
	if err != nil {
		return nil, err
	}
	var doc editorForCouchdb
	if err = row.ScanDoc(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
