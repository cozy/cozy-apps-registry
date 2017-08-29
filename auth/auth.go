package auth

import (
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"net/http"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/cozy/cozy-registry-v3/errshttp"
)

const (
	masterSecretLen  = 32
	sessionSecretLen = 32

	sessionSaltLen = 16
)

var (
	ErrEditorNotFound = errshttp.NewError(http.StatusNotFound, "Editor not found")
	ErrEditorExists   = errshttp.NewError(http.StatusConflict, "Editor already exists")
	ErrBadEditorName  = errshttp.NewError(http.StatusBadRequest, "Editor name should only contain alphanumeric characters")
	ErrUnauthorized   = errshttp.NewError(http.StatusUnauthorized, "Unauthorized")

	ErrMissingPassphrase = errors.New("Missing passphrase")
)

var editorReg = regexp.MustCompile("^[A-Za-z][A-Za-z0-9]*$")

const (
	pubKeyBlocType = "PUBLIC KEY"
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
		AllEditors() ([]*Editor, error)
	}

	Editor struct {
		name           string
		sessionSalt    []byte
		publicKeyBytes []byte
		publicKey      *rsa.PublicKey
	}
)

func NewEditorRegistry(vault Vault) (*EditorRegistry, error) {
	return &EditorRegistry{vault}, nil
}

func CkeckEditorName(editorName string) error {
	if !editorReg.MatchString(editorName) {
		return ErrBadEditorName
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
		sessionSalt:    readRand(sessionSaltLen),
		publicKeyBytes: publicKeyBytes,
		publicKey:      publicKey,
	}

	if err = r.CreateEditor(editor); err != nil {
		return nil, err
	}
	return editor, nil
}

func (r *EditorRegistry) CreateEditorWithoutPublicKey(editorName string) (*Editor, error) {
	if err := CkeckEditorName(editorName); err != nil {
		return nil, err
	}

	editor := &Editor{
		name:        editorName,
		sessionSalt: readRand(sessionSaltLen),
	}

	if err := r.CreateEditor(editor); err != nil {
		return nil, err
	}
	return editor, nil
}

func (r *EditorRegistry) RevokeSessionTokens(editor *Editor, masterSecret, token []byte) error {
	if !editor.VerifySessionToken(masterSecret, token) {
		return ErrUnauthorized
	}
	editor.sessionSalt = readRand(sessionSaltLen)
	return r.UpdateEditor(editor)
}

func DecryptMasterSecret(content, passphrase []byte) ([]byte, error) {
	var encryptedSecret struct {
		Salt   []byte
		Nonce  []byte
		Secret []byte
	}

	if len(passphrase) == 0 {
		return nil, ErrMissingPassphrase
	}

	if _, err := asn1.Unmarshal(content, &encryptedSecret); err != nil {
		return nil, err
	}
	if len(encryptedSecret.Salt) != 16 || len(encryptedSecret.Nonce) != 12 {
		return nil, errors.New("Bad secret file")
	}

	N := 16384
	r := 8
	p := 1
	derivedKey, err := scrypt.Key(passphrase, encryptedSecret.Salt, N, r, p, 32)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return nil, err
	}

	secret, err := aead.Open(nil, encryptedSecret.Nonce, encryptedSecret.Secret, nil)
	if err != nil {
		return nil, err
	}

	if len(secret) != masterSecretLen {
		return nil, errors.New("Bad secret file: bad length of secret")
	}

	return secret, nil
}

func IsSecretClear(secret []byte) bool {
	return len(secret) == masterSecretLen
}

func EncryptMasterSecret(secret, passphrase []byte) ([]byte, error) {
	var encryptedSecret struct {
		Salt   []byte
		Nonce  []byte
		Secret []byte
	}

	if len(secret) != masterSecretLen {
		panic("Bad len for master secret")
	}
	if len(passphrase) == 0 {
		return nil, ErrMissingPassphrase
	}

	salt := readRand(16)
	nonce := readRand(12)

	N := 16384
	r := 8
	p := 1
	derivedKey, err := scrypt.Key(passphrase, salt, N, r, p, 32)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return nil, err
	}

	encrypted := aead.Seal(nil, nonce, secret, nil)
	encryptedSecret.Nonce = nonce
	encryptedSecret.Salt = salt
	encryptedSecret.Secret = encrypted

	return asn1.Marshal(encryptedSecret)
}

func GenerateMasterSecret() []byte {
	return readRand(masterSecretLen)
}
