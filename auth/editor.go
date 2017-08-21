package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
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

	msg := make([]byte, 8)
	if maxAge < 0 {
		panic("maxAge is negative")
	}
	if maxAge > 0 {
		binary.BigEndian.PutUint64(msg, uint64(time.Now().Add(maxAge).Unix()))
	} else {
		binary.BigEndian.PutUint64(msg, uint64(0))
	}

	var computedMac []byte
	{
		buf := append([]byte(e.name), msg...)
		mac := hmac.New(sha256.New, sessionSecret)
		mac.Write(buf)
		computedMac = mac.Sum(nil)
	}

	msg = append(msg, computedMac...)
	return msg, nil
}

func (e *Editor) VerifySessionToken(masterSecret, token []byte) bool {
	sessionSecret, err := e.sessionSecret(masterSecret)
	if err != nil {
		return false
	}

	offset := len(token) - 32
	if offset < 0 {
		return false
	}

	var expectedMac []byte
	msg, msgMac := token[:offset], token[offset:]

	{
		buf := append([]byte(e.name), msg...)
		mac := hmac.New(sha256.New, sessionSecret)
		mac.Write(buf)
		expectedMac = mac.Sum(nil)
	}

	if !hmac.Equal(msgMac, expectedMac) {
		return false
	}

	// should not happend since the MAC also provides integrity
	if len(msg) < 8 {
		return false
	}

	t := int64(binary.BigEndian.Uint64(msg))
	if t == 0 {
		return true
	}

	return time.Now().Before(time.Unix(t, 0))
}

func (e *Editor) sessionSecret(masterSecret []byte) ([]byte, error) {
	if len(masterSecret) != masterSecretLen {
		panic("master secret has no correct length")
	}

	kdf := hkdf.New(sha256.New, masterSecret, e.sessionSalt, []byte(e.name))
	sessionSecret := make([]byte, sessionSecretLen)
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
