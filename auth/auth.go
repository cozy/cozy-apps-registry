package auth

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/cozy/cozy-registry-v3/errshttp"
)

const (
	saltLen  = 16
	nonceLen = 12 // GCM standard nonce size
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
	publicKey                interface{}
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

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

type ecdsaSignature struct {
	R, S *big.Int
}

func (e *Editor) GenerateSignature(hashed, password []byte) ([]byte, error) {
	if len(hashed) != crypto.SHA256.Size() {
		panic("hash has not valid length")
	}

	privateKey, err := e.privateKey(password)
	if err != nil {
		return nil, err
	}

	pub, err := e.PublicKey()
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok ||
		publicKey.X.Cmp(privateKey.X) != 0 ||
		publicKey.Y.Cmp(privateKey.Y) != 0 {
		return nil, errors.New("Private key does not match public key")
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{r, s})
}

func (e *Editor) VerifySignature(hashed, signature []byte) (bool, error) {
	if len(hashed) != crypto.SHA256.Size() {
		panic("hash has not valid length")
	}

	publicKey, err := e.PublicKey()
	if err != nil {
		return false, err
	}

	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if _, err = asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return false, err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return false, errors.New("ECDSA signature contained zero or negative values")
		}
		return ecdsa.Verify(pub, hashed[:], ecdsaSig.R, ecdsaSig.S), nil
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
		return err == nil, nil
	default:
		return false,
			errors.New("Not supported public key type: only ECDSA and RSA are supported")
	}
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

func (e *Editor) privateKey(password []byte) (*ecdsa.PrivateKey, error) {
	if !e.HasPrivateKey() {
		return nil, fmt.Errorf("No private key stored for this editor")
	}

	var privateKey *ecdsa.PrivateKey
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

func (e *Editor) PublicKey() (interface{}, error) {
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

func marshalAndEncryptPrivateKey(privateKey *ecdsa.PrivateKey, editorName string, pass []byte) ([]byte, error) {
	if len(pass) == 0 {
		panic("password is empty")
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	salt := generateRandomBytes(saltLen)
	aead, err := createAEADCipherFromPassWithKeyDerivation(pass, salt)
	if err != nil {
		return nil, err
	}

	nonce := generateRandomBytes(nonceLen)
	additionalData := []byte(editorName)

	privateKeyBytesEncrypted, err := aead.Seal(nil, nonce, privateKeyBytes, additionalData), nil
	if err != nil {
		return nil, err
	}

	keyData := struct {
		Key   []byte
		Nonce []byte
		Salt  []byte
	}{
		Key:   privateKeyBytesEncrypted,
		Nonce: nonce,
		Salt:  salt,
	}

	return asn1.Marshal(keyData)
}

func decryptPrivateKey(privateKeyBytesEncrypted []byte, editorName string, pass []byte) (*ecdsa.PrivateKey, error) {
	var keyData struct {
		Key   []byte
		Nonce []byte
		Salt  []byte
	}

	_, err := asn1.Unmarshal(privateKeyBytesEncrypted, &keyData)
	if err != nil {
		return nil, err
	}

	aead, err := createAEADCipherFromPassWithKeyDerivation(pass, keyData.Salt)
	if err != nil {
		return nil, err
	}

	additionalData := []byte(editorName)
	privateKeyBytes, err := aead.Open(nil, keyData.Nonce, keyData.Key, additionalData)
	if err != nil {
		return nil, err
	}

	return unmarshalPrivateKey(privateKeyBytes)
}

func createAEADCipherFromPassWithKeyDerivation(pass, salt []byte) (cipher.AEAD, error) {
	if len(salt) != saltLen {
		return nil, fmt.Errorf("bad salt length %d != %d", len(salt), saltLen)
	}

	derivedKeyLen := 32
	N := 16384
	r := 8
	p := 1

	derivedKey, err := scrypt.Key(pass, salt, N, r, p, derivedKeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm, nil
}

func unmarshalPrivateKey(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(privateKeyBytes)
}

func marshalPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(privateKey)
}

func marshalPublicKey(publicKey interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

func unmarshalPublicKey(publicKeyBytes []byte) (interface{}, error) {
	if bytes.HasPrefix(publicKeyBytes, []byte("-----BEGIN")) {
		block, _ := pem.Decode(publicKeyBytes)
		if block == nil {
			return nil, fmt.Errorf("Failed to parse PEM block containing the public key")
		}
		if block.Type != pubKeyBlocType {
			return nil, fmt.Errorf(`Bad PEM block type, got "%s" expecting "%s"`,
				block.Type, pubKeyBlocType)
		}
		publicKeyBytes = block.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
	default:
		return nil, errors.New("Not supported public key type: only ecdsa and rsa are supported")
	}
	return pub, nil
}

func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}
