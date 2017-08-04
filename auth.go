package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const tokenName = "editor-token"

type EditorTokenOptions struct {
	Editor    string
	AppPrefix string
}

type EditorRegistry interface {
	GetEditorSecret(editorName string) ([]byte, error)
}

func GenerateEditorToken(reg EditorRegistry, opts *EditorTokenOptions) ([]byte, error) {
	secret, err := reg.GetEditorSecret(opts.Editor)
	if err != nil {
		return nil, err
	}
	msg := opts.Editor
	if opts.AppPrefix == "" {
		msg = msg + ":*"
	} else {
		msg = msg + ":" + opts.AppPrefix
	}
	return EncodeAuthMessage(tokenConfig(secret), []byte(msg))
}

func VerifyEditorToken(reg EditorRegistry, editorName, appName string, token []byte) error {
	secret, err := reg.GetEditorSecret(editorName)
	if err != nil {
		return err
	}
	msg, err := DecodeAuthMessage(tokenConfig(secret), token)
	if err != nil {
		return err
	}
	msgSplit := strings.SplitN(string(msg), ":", 2)
	if len(msgSplit) != 2 {
		return errUnauthorized
	}
	if msgSplit[0] != editorName {
		return errUnauthorized
	}
	if msgSplit[1] != "*" && !strings.HasPrefix(appName, msgSplit[1]) {
		return errUnauthorized
	}
	return nil
}

func tokenConfig(secret []byte) *MACConfig {
	return &MACConfig{
		Name:   tokenName,
		Key:    secret,
		MaxAge: 0,
		MaxLen: 256,
	}
}

type fileEditorReg struct {
	filename string
}

func NewFileEditorRegistry(filename string) (EditorRegistry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		b := s.Text()
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		fields := strings.Fields(b)
		if len(fields) < 2 {
			return nil, fmt.Errorf("Editor registry in file %s: format of each line should be: \"editorname secret-in-hex\"",
				filename)
		}
		token, err := hex.DecodeString(fields[1])
		if err != nil {
			return nil, fmt.Errorf("Editor registry in file %s: format of each line should be: \"editorname secret-in-hex\": %s",
				filename, err.Error())
		}
		if len(token) < 16 {
			return nil, fmt.Errorf("Editor registry in file %s: editor secret should contain at least 16 bytes",
				filename)
		}
	}
	return &fileEditorReg{filename}, nil
}

func (r *fileEditorReg) GetEditorSecret(editorName string) ([]byte, error) {
	f, err := os.Open(r.filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		b := s.Text()
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		fields := strings.Fields(b)
		if len(fields) < 2 || fields[0] != editorName {
			continue
		}
		return hex.DecodeString(fields[1])
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return nil, errUnknownEditor
}
