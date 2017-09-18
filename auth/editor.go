package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

func (e *Editor) MarshalJSON() ([]byte, error) {
	v := struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key,omitempty"`
	}{
		Name:      e.name,
		PublicKey: e.MarshalPublicKeyPEM(),
	}
	return json.Marshal(v)
}

func (e *Editor) MarshalPublicKeyPEM() string {
	if len(e.publicKeyBytes) == 0 {
		return ""
	}
	block := &pem.Block{
		Type:  pubKeyBlocType,
		Bytes: e.publicKeyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

func (e *Editor) Name() string {
	return e.name
}

func (e *Editor) IsComplete() bool {
	return len(e.name) > 0 &&
		len(e.sessionSalt) == sessionSaltLen
}

func (e *Editor) VerifySignature(message, signature []byte) bool {
	publicKey, err := e.PublicKey()
	if err != nil {
		return false
	}

	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
	return err == nil
}

func (e *Editor) GenerateSessionToken(masterSecret []byte, maxAge time.Duration) ([]byte, error) {
	sessionSecret, err := e.sessionSecret(masterSecret)
	if err != nil {
		return nil, err
	}
	token, err := GenerateToken(sessionSecret, nil, []byte(e.name), maxAge)
	if err != nil {
		return nil, err
	}
	return GenerateToken(masterSecret, token, nil, 0)
}

func (e *Editor) VerifySessionToken(masterSecret, token []byte) bool {
	value, ok := VerifyToken(masterSecret, token, nil)
	if !ok {
		return false
	}
	sessionSecret, err := e.sessionSecret(masterSecret)
	if err != nil {
		return false
	}
	_, ok = VerifyToken(sessionSecret, value, []byte(e.name))
	return ok
}

func (e *Editor) sessionSecret(masterSecret []byte) ([]byte, error) {
	if len(masterSecret) != secretLen {
		panic("master secret has no correct length")
	}

	kdf := hkdf.New(sha256.New, masterSecret, e.sessionSalt, []byte(e.name))
	sessionSecret := make([]byte, secretLen)
	_, err := io.ReadFull(kdf, sessionSecret)
	if err != nil {
		return nil, err
	}

	return sessionSecret, nil
}

func (e *Editor) PublicKey() (*rsa.PublicKey, error) {
	if len(e.publicKeyBytes) == 0 {
		return nil, errors.New("Editor has no public key associated")
	}
	if e.publicKey == nil {
		var err error
		e.publicKey, err = unmarshalPublicKey(e.publicKeyBytes)
		if err != nil {
			return nil, err
		}
	}
	return e.publicKey, nil
}
