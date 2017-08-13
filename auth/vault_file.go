package auth

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

type fileVault struct {
	filename string
}

func NewFileVault(filename string) (EditorVault, error) {
	return &fileVault{filename}, nil
}

func (r *fileVault) LoadEditors() ([]*Editor, error) {
	f, err := os.OpenFile(r.filename, os.O_RDONLY|os.O_CREATE, 0660)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var editors []*Editor
	var editor *Editor
	errBadFileFormat := fmt.Errorf("Bad file format %s", r.filename)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		isEmpty := len(fields) == 0 || line[0] == '#'
		if isEmpty && editor != nil {
			editors = append(editors, editor)
			editor = nil
		}
		if isEmpty {
			continue
		}

		if len(fields) < 2 {
			return nil, errBadFileFormat
		}

		key, val := fields[0], fields[1]
		editorCmd := key == "editor"
		if editor == nil && !editorCmd {
			return nil, errBadFileFormat
		}
		if editor != nil && editorCmd {
			return nil, errBadFileFormat
		}
		if editorCmd {
			editor = &Editor{name: val}
			continue
		}

		switch key {
		case "public_key":
			editor.publicKeyBytes, err = base64.StdEncoding.DecodeString(val)
		case "encrypted_private_key":
			editor.privateKeyBytesEncrypted, err = base64.StdEncoding.DecodeString(val)
		case "private_key":
			editor.privateKeyBytes, err = base64.StdEncoding.DecodeString(val)
		default:
			return nil, errBadFileFormat
		}
		if err != nil {
			return nil, errBadFileFormat
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return editors, nil
}

func (r *fileVault) AddEditor(editor *Editor) error {
	f, err := os.OpenFile(r.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		return err
	}
	defer f.Close()
	b := new(bytes.Buffer)
	fmt.Fprintf(f, "#\n")
	fmt.Fprintf(f, "# -------------------------------------------------\n")
	fmt.Fprintf(f, "#\n")
	fmt.Fprintf(f, "\n")
	fmt.Fprintf(f, "editor                  %s\n", editor.name)
	fmt.Fprintf(f, "public_key              %s\n", base64.StdEncoding.EncodeToString(editor.publicKeyBytes))
	if editor.HasPrivateKey() {
		if editor.HasEncryptedPrivateKey() {
			fmt.Fprintf(b, "encrypted_private_key   %s\n", base64.StdEncoding.EncodeToString(editor.privateKeyBytesEncrypted))
		} else {
			fmt.Fprintf(b, "private_key             %s\n", base64.StdEncoding.EncodeToString(editor.privateKeyBytes))
		}
	}
	fmt.Fprintf(b, "\n\n")
	_, err = io.Copy(f, b)
	return err
}
