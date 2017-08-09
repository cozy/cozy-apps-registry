package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

var (
	errMACTooLong = errors.New("mac: too long")
	errMACExpired = errors.New("mac: expired")
	errMACInvalid = errors.New("mac: the value is not valid")
)

const defaultMaxLen = 4096
const macLen = 32

// MACConfig contains all the options to encode or decode a message along with
// a proof of integrity and authenticity.
//
// Key is the secret used for the HMAC key. It should contain at least 16 bytes
// and should be generated by a PRNG.
//
// Name is an optional message name that won't be contained in the MACed
// messaged itself but will be MACed against.
type MACConfig struct {
	Key    []byte
	Name   string
	MaxLen int
}

func assertMACConfig(c *MACConfig) error {
	if c.Key == nil {
		return errors.New("hash key is not set")
	}
	if len(c.Key) < 16 {
		return errors.New("hash key is not long enough")
	}
	return nil
}

// EncodeAuthMessage associates the given value with a message authentication
// code for integrity and authenticity.
//
// If the value is longer than the configured maximum length, it will panic.
//
// Message format (name prefix is in MAC but removed from message):
//
//  <------- MAC input ------->
//         <---------- message ---------->
//  | name |    time |  blob  |     hmac |
//  |      | 8 bytes |  ----  | 32 bytes |
//
func EncodeAuthMessage(c *MACConfig, maxAge time.Duration, value []byte) ([]byte, error) {
	if err := assertMACConfig(c); err != nil {
		return nil, err
	}

	maxLength := c.MaxLen
	if maxLength == 0 {
		maxLength = defaultMaxLen
	}
	if maxAge < 0 {
		return nil, errors.New("Max age should be greater or equal to zero")
	}

	var ts int64
	if maxAge > 0 {
		ts = time.Now().Add(maxAge).Unix()
	}

	// Create message with MAC
	size := len(c.Name) + binary.Size(ts) + len(value) + macLen
	buf := bytes.NewBuffer(make([]byte, 0, size))
	buf.Write([]byte(c.Name))
	binary.Write(buf, binary.BigEndian, ts)
	buf.Write(value)

	// Append mac
	buf.Write(createMAC(c.Key, buf.Bytes()))

	// Skip name
	buf.Next(len(c.Name))

	return buf.Bytes(), nil
}

// DecodeAuthMessage verifies a message authentified with message
// authentication code and returns the message value algon with the issued time
// of the message.
func DecodeAuthMessage(c *MACConfig, enc []byte) ([]byte, error) {
	if err := assertMACConfig(c); err != nil {
		return nil, err
	}

	maxLength := c.MaxLen
	if maxLength == 0 {
		maxLength = defaultMaxLen
	}

	// Check length
	if len(enc) > maxLength {
		return nil, errMACTooLong
	}

	// Prepend name
	dec := append([]byte(c.Name), enc...)

	// Verify message with MAC
	{
		offset := len(dec) - macLen
		if offset < 0 {
			return nil, errMACInvalid
		}
		var mac = dec[offset:]
		dec = dec[:offset]
		if !verifyMAC(c.Key, dec, mac) {
			return nil, errMACInvalid
		}
	}

	// Skip name prefix
	buf := bytes.NewBuffer(dec)
	buf.Next(len(c.Name))

	// Read time and verify time ranges
	var ts int64
	if err := binary.Read(buf, binary.BigEndian, &ts); err != nil {
		return nil, errMACInvalid
	}
	if ts < 0 {
		return nil, errMACInvalid
	}
	if ts != 0 && time.Unix(ts, 0).Before(time.Now()) {
		return nil, errMACExpired
	}

	// Returns the value
	return buf.Bytes(), nil
}

// createMAC creates a MAC with HMAC-SHA256
func createMAC(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return mac.Sum(nil)
}

// verifyMAC returns true is the MAC is valid
func verifyMAC(key, value []byte, mac []byte) bool {
	expectedMAC := createMAC(key, value)
	return hmac.Equal(mac, expectedMAC)
}
