package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/scrypt"
)

func marshalAndEncryptPrivateKey(privateKey *rsa.PrivateKey, editorName string, pass []byte) ([]byte, error) {
	privateKeyBytes, err := marshalPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	salt := readRand(saltLen)
	aead, err := createAEADCipherFromPassWithKeyDerivation(pass, salt)
	if err != nil {
		return nil, err
	}

	nonce := readRand(nonceLen)
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

func decryptPrivateKey(privateKeyBytesEncrypted []byte, editorName string, pass []byte) (*rsa.PrivateKey, error) {
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
	if len(pass) == 0 {
		panic("password is empty")
	}
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

func unmarshalPrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(privateKeyBytes)
}

func marshalPrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(privateKey), nil
}

func marshalPublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

func unmarshalPublicKey(publicKeyBytes []byte) (*rsa.PublicKey, error) {
	var publicKey *rsa.PublicKey

	if bytes.HasPrefix(publicKeyBytes, []byte("ssh-rsa ")) {
		sshFields := bytes.Fields(publicKeyBytes)
		if len(sshFields) < 2 {
			return nil, fmt.Errorf("Failed to parse SSH public key file")
		}
		var ok bool
		publicKey, ok = unmarshalSSHPublicRSAKey(sshFields[1])
		if !ok {
			return nil, fmt.Errorf("Failed to parse SSH public key file")
		}
	} else {
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

		untypedPublicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
		if err != nil {
			return nil, err
		}

		var ok bool
		publicKey, ok = untypedPublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("Not supported public key type: only RSA is supported")
		}
	}

	if bitLen := publicKey.N.BitLen(); bitLen < 2048 {
		return nil, fmt.Errorf("Public key length is too small: %d bits (expecting at least %d bits)", bitLen, 2048)
	}

	return publicKey, nil
}

func unmarshalSSHPublicRSAKey(encoded []byte) (key *rsa.PublicKey, ok bool) {
	data, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return
	}

	var readok bool
	var algo []byte
	algo, data, readok = readSSHMessage(data)
	if !readok || string(algo) != "ssh-rsa" {
		return
	}

	e := new(big.Int)
	n := new(big.Int)

	var buf []byte
	buf, data, readok = readSSHMessage(data)
	if !readok {
		return
	}
	e.SetBytes(buf)

	exp := int(e.Int64())
	if exp < 2 || exp > 1<<31-1 {
		return
	}

	buf, data, readok = readSSHMessage(data)
	if !readok || len(data) != 0 {
		return
	}

	n.SetBytes(buf)

	key = new(rsa.PublicKey)
	key.E = exp
	key.N = n
	ok = true
	return
}

func readSSHMessage(in []byte) (out []byte, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

func readRand(n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return b
}
