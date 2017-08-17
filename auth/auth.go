package auth

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/cozy/cozy-registry-v3/errshttp"
)

const (
	masterSecretLen = 32

	sessionSaltLen   = 16
	sessionSecretLen = 16
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

func GetMasterSecret(filename string, passphrase []byte) ([]byte, error) {
	var encryptedSecret struct {
		Salt   []byte
		Nonce  []byte
		Secret []byte
	}

	plainMagic := []byte("session-secret=")
	cipherMagic := []byte("ciphered-session-secret=")

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	r := io.LimitReader(f, 2048)

	var fileContent []byte
	{
		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, r)
		if err != nil {
			return nil, err
		}
		fileContent = buf.Bytes()
	}

	if bytes.HasPrefix(fileContent, cipherMagic) {
		if len(passphrase) == 0 {
			return nil, ErrMissingPassphrase
		}

		fileContent = fileContent[len(cipherMagic):]
		if _, err := asn1.Unmarshal(fileContent, &encryptedSecret); err != nil {
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

		fileContent, err = aead.Open(nil, encryptedSecret.Nonce, encryptedSecret.Secret, cipherMagic)
		if err != nil {
			return nil, err
		}
	}

	if !bytes.HasPrefix(fileContent, plainMagic) {
		return nil, errors.New("Bad secret file")
	}

	secret := fileContent[len(plainMagic):]
	if len(secret) != masterSecretLen {
		return nil, errors.New("Bad secret file: secret has not the correct length")
	}
	return secret, nil
}

func GenerateMasterSecret(filename string, passphrase []byte) error {
	var encryptedSecret struct {
		Salt   []byte
		Nonce  []byte
		Secret []byte
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0660)
	if err != nil {
		return err
	}

	plainMagic := []byte("session-secret=")
	cipherMagic := []byte("ciphered-session-secret=")
	masterSecret := readRand(masterSecretLen)

	fileContent := append(plainMagic, masterSecret...)

	if len(passphrase) > 0 {
		salt := readRand(16)
		nonce := readRand(12)

		N := 16384
		r := 8
		p := 1
		derivedKey, err := scrypt.Key(passphrase, salt, N, r, p, 32)
		if err != nil {
			return err
		}

		aead, err := chacha20poly1305.New(derivedKey)
		if err != nil {
			return err
		}

		encrypted := aead.Seal(nil, nonce, fileContent, cipherMagic)
		encryptedSecret.Nonce = nonce
		encryptedSecret.Salt = salt
		encryptedSecret.Secret = encrypted

		fileContent, err = asn1.Marshal(encryptedSecret)
		if err != nil {
			return err
		}

		fileContent = append(cipherMagic, fileContent...)
	}

	_, err = f.Write(fileContent)
	return err
}
