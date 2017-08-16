package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"regexp"

	"github.com/cozy/cozy-registry-v3/errshttp"
)

const (
	sessionSecretLen = 16

	saltLen  = 16
	nonceLen = 12 // GCM standard nonce size

	rsaKeyBitSize = 2048
)

var (
	errEditorNotFound = errshttp.NewError(http.StatusNotFound, "Editor not found")
	errEditorExists   = errshttp.NewError(http.StatusConflict, "Editor already exists")
	errBadEditorName  = errshttp.NewError(http.StatusBadRequest, "Editor name should only contain alphanumeric characters")
)

var editorReg = regexp.MustCompile("^[A-Za-z][A-Za-z0-9]*$")

const (
	privKeyBlocType = "PRIVATE KEY"
	pubKeyBlocType  = "PUBLIC KEY"
)

type (
	EditorRegistry struct {
		Vault
	}

	Vault interface {
		GetEditor(editorName string) (*Editor, error)
		CreateEditor(editor *Editor) error
		UpdateEditor(editor *Editor) error
		DeleteEditor(editor *Editor) error
	}

	Editor struct {
		name                     string
		sessionSecret            []byte
		privateKeyBytes          []byte
		privateKeyBytesEncrypted []byte
		publicKeyBytes           []byte
		publicKey                *rsa.PublicKey
	}
)

func NewEditorRegistry(vault Vault) (*EditorRegistry, error) {
	return &EditorRegistry{vault}, nil
}

func CkeckEditorName(editorName string) error {
	if !editorReg.MatchString(editorName) {
		return errBadEditorName
	}
	return nil
}

func (r *EditorRegistry) CreateEditorWithPublicKey(editorName string, publicKeyBytes []byte) (*Editor, error) {
	if err := CkeckEditorName(editorName); err != nil {
		return nil, err
	}

	publicKey, err := unmarshalPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	editor := &Editor{
		name:           editorName,
		sessionSecret:  readRand(sessionSecretLen),
		publicKeyBytes: publicKeyBytes,
		publicKey:      publicKey,
	}
	if err = r.CreateEditor(editor); err != nil {
		return nil, err
	}
	return editor, nil
}

func (r *EditorRegistry) CreateEditorAndPrivateKey(editorName string, passphrase []byte) (*Editor, error) {
	if err := CkeckEditorName(editorName); err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBitSize)
	if err != nil {
		return nil, err
	}

	var privateKeyBytesEncrypted, privateKeyBytes []byte
	if len(passphrase) == 0 {
		privateKeyBytes, err = marshalPrivateKey(privateKey)
	} else {
		privateKeyBytesEncrypted, err = marshalAndEncryptPrivateKey(privateKey, editorName, passphrase)
	}
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := marshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	editor := &Editor{
		name:                     editorName,
		sessionSecret:            readRand(sessionSecretLen),
		privateKeyBytes:          privateKeyBytes,
		privateKeyBytesEncrypted: privateKeyBytesEncrypted,
		publicKeyBytes:           publicKeyBytes,
		publicKey:                publicKey,
	}
	if err = r.CreateEditor(editor); err != nil {
		return nil, err
	}
	return editor, nil
}

func (r *EditorRegistry) RevokeSessionTokens(editor *Editor) error {
	editor.sessionSecret = readRand(sessionSecretLen)
	return r.UpdateEditor(editor)
}
