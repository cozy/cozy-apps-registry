package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cozy/cozy-registry-v3/errshttp"
)

const (
	saltLen  = 16
	nonceLen = 12 // GCM standard nonce size

	rsaKeyBitSize = 4096
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

type EditorVault interface {
	LoadEditors() ([]*Editor, error)
	AddEditor(editor *Editor) error
}

type Editor struct {
	name                     string
	privateKeyBytes          []byte
	privateKeyBytesEncrypted []byte
	publicKeyBytes           []byte
	publicKey                *rsa.PublicKey
}

func (e *Editor) MarshalJSON() ([]byte, error) {
	j := struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}{
		Name:      e.name,
		PublicKey: e.MarshalPublickKeyPEM(),
	}
	return json.Marshal(j)
}

func (e *Editor) MarshalPublickKeyPEM() string {
	block := &pem.Block{
		Type:  pubKeyBlocType,
		Bytes: e.publicKeyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

func (e *Editor) MarshalPrivateKeyPEM(password []byte) (string, error) {
	privateKey, err := e.privateKey(password)
	if err != nil {
		return "", err
	}
	privateKeyBytes, err := marshalPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  privKeyBlocType,
		Bytes: privateKeyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (e *Editor) Name() string {
	return e.name
}

func (e *Editor) IsComplete() bool {
	return len(e.name) > 0 && len(e.publicKeyBytes) > 0
}

type EditorRegistry struct {
	vault   EditorVault
	editors map[string]*Editor
}

func NewEditorRegistry(vault EditorVault) (*EditorRegistry, error) {
	editors, err := vault.LoadEditors()
	if err != nil {
		return nil, err
	}
	editorsMap := make(map[string]*Editor)
	for _, editor := range editors {
		if !editor.IsComplete() {
			return nil, fmt.Errorf("Editor %s is missing some values", editor.name)
		}
		if _, ok := editorsMap[strings.ToLower(editor.name)]; ok {
			return nil, fmt.Errorf("Editor %s has multiple entries", editor.name)
		}
		editorsMap[strings.ToLower(editor.name)] = editor
	}
	return &EditorRegistry{
		editors: editorsMap,
		vault:   vault,
	}, nil
}

func (e *EditorRegistry) GetEditor(editorName string) (*Editor, error) {
	editor, ok := e.editors[strings.ToLower(editorName)]
	if !ok {
		return nil, errEditorNotFound
	}
	return editor, nil
}

func (e *EditorRegistry) AddEditor(editor *Editor) error {
	if _, err := e.GetEditor(editor.name); err == nil {
		return errEditorExists
	}
	return e.vault.AddEditor(editor)
}

func MatchEditorName(editorName string) error {
	if !editorReg.MatchString(editorName) {
		return errBadEditorName
	}
	return nil
}

func CreateEditorWithPublicKey(editorName string, publicKeyBytes []byte) (*Editor, error) {
	if !editorReg.MatchString(editorName) {
		return nil, errBadEditorName
	}

	publicKey, err := unmarshalPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	return &Editor{
		name:           editorName,
		publicKeyBytes: publicKeyBytes,
		publicKey:      publicKey,
	}, nil
}

func CreateEditorAndPrivateKey(editorName string, password []byte) (*Editor, error) {
	if !editorReg.MatchString(editorName) {
		return nil, errors.New("Editor name should only contain alphanumeric characters")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBitSize)
	if err != nil {
		return nil, err
	}

	var privateKeyBytesEncrypted, privateKeyBytes []byte
	if len(password) == 0 {
		privateKeyBytes, err = marshalPrivateKey(privateKey)
	} else {
		privateKeyBytesEncrypted, err = marshalAndEncryptPrivateKey(privateKey, editorName, password)
	}
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := marshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &Editor{
		name:                     editorName,
		privateKeyBytes:          privateKeyBytes,
		privateKeyBytesEncrypted: privateKeyBytesEncrypted,
		publicKeyBytes:           publicKeyBytes,
		publicKey:                publicKey,
	}, nil
}

func (e *Editor) GenerateSignature(hashed, password []byte) ([]byte, error) {
	if len(hashed) != crypto.SHA256.Size() {
		panic("hash has not valid length")
	}

	privateKey, err := e.privateKey(password)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
}

func (e *Editor) VerifySignature(hashed, signature []byte) (bool, error) {
	if len(hashed) != crypto.SHA256.Size() {
		panic("hash has not valid length")
	}

	publicKey, err := e.PublicKey()
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil, nil
}

func (e *Editor) GenerateToken(password []byte) ([]byte, error) {

	cap := len(e.name) + 8 /* unix timestamp */ + 72 /* ~signature length */
	buf := bytes.NewBuffer(make([]byte, 0, cap))

	buf.Write([]byte(e.name))
	binary.Write(buf, binary.BigEndian, time.Now().Unix())

	hash := sha256.New()
	hash.Write(buf.Bytes())
	hashed := hash.Sum(nil)

	sig, err := e.GenerateSignature(hashed, password)
	if err != nil {
		return nil, err
	}

	buf.Write(sig)
	buf.Next(len(e.name))

	return buf.Bytes(), nil
}

func (e *Editor) VerifyToken(token []byte) (bool, error) {
	if len(token) < 8 /* unix timestamp */ {
		return false, errors.New("Bad token")
	}

	// now := int64(binary.BigEndian.Uint64(token[:8]))
	val := append([]byte(e.name), token[:8]...)
	sig := token[8:]

	hash := sha256.New()
	hash.Write(val)
	hashed := hash.Sum(nil)

	return e.VerifySignature(hashed, sig)
}

func (e *Editor) privateKey(password []byte) (*rsa.PrivateKey, error) {
	if !e.HasPrivateKey() {
		return nil, fmt.Errorf("No private key stored for this editor")
	}

	var privateKey *rsa.PrivateKey
	var err error
	if len(e.privateKeyBytesEncrypted) > 0 {
		privateKey, err = decryptPrivateKey(e.privateKeyBytesEncrypted, e.name, password)
	} else {
		privateKey, err = unmarshalPrivateKey(e.privateKeyBytes)
	}
	if err != nil {
		return nil, err
	}

	return privateKey, err
}

func (e *Editor) PublicKey() (*rsa.PublicKey, error) {
	if e.publicKey == nil {
		var err error
		e.publicKey, err = unmarshalPublicKey(e.publicKeyBytes)
		if err != nil {
			return nil, err
		}
	}
	return e.publicKey, nil
}

func (e *Editor) HasPrivateKey() bool {
	return len(e.privateKeyBytesEncrypted) > 0 || len(e.privateKeyBytes) > 0
}

func (e *Editor) HasEncryptedPrivateKey() bool {
	return len(e.privateKeyBytesEncrypted) > 0
}
