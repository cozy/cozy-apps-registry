package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

func (e *Editor) MarshalJSON() ([]byte, error) {
	v := struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}{
		Name:      e.name,
		PublicKey: e.MarshalPublickKeyPEM(),
	}
	return json.Marshal(v)
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
	return len(e.name) > 0 &&
		len(e.publicKeyBytes) > 0 &&
		len(e.sessionSecret) == sessionSecretLen
}

func (e *Editor) GenerateSignature(message, password []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	privateKey, err := e.privateKey(password)
	if err != nil {
		return nil, err
	}

	return privateKey.Sign(rand.Reader, hashed, crypto.SHA256)
}

func (e *Editor) VerifySignature(message, signature []byte) bool {
	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	publicKey, err := e.PublicKey()
	if err != nil {
		return false
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
	return err == nil
}

func (e *Editor) GenerateSessionToken(password []byte) ([]byte, error) {
	if len(e.sessionSecret) != sessionSecretLen {
		return nil, errors.New("missing session secret")
	}

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(time.Now().Unix()))

	signature, err := e.GenerateSignature(msg, password)
	if err != nil {
		return nil, err
	}

	var computedMac []byte
	msg = append(msg, signature...)

	{
		buf := append([]byte(e.name), msg...)
		mac := hmac.New(sha256.New, e.sessionSecret)
		mac.Write(buf)
		computedMac = mac.Sum(nil)
	}

	msg = append(msg, computedMac...)
	return msg, nil
}

func (e *Editor) VerifySessionToken(token []byte) bool {
	if len(e.sessionSecret) != sessionSecretLen {
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
		mac := hmac.New(sha256.New, e.sessionSecret)
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

	var signature []byte
	msg, signature = msg[:8], msg[8:]
	return e.VerifySignature(msg, signature)
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
