package main

import (
	"fmt"
	"net/http"
)

var errUnauthorized = NewError(http.StatusUnauthorized, "Unauthorized")
var errUnknownEditor = NewError(http.StatusUnauthorized, "Editor not found")
var errEditorExists = NewError(http.StatusUnauthorized, "Editor already exists")
var errBadChannel = NewError(http.StatusBadRequest, `Channel should be "stable", "beta" or "dev"`)

var errAppNotFound = NewError(http.StatusNotFound, "Application was not found")
var errAppNameMismatch = NewError(http.StatusBadRequest, "Application name does not match the one specified in the body")
var errBadAppName = NewError(http.StatusBadRequest, "Bad application name: should contain only ascii letters, numbers and -")

var errVersionAlreadyExists = NewError(http.StatusConflict, "Version already exists")
var errVersionNotFound = NewError(http.StatusNotFound, "Version was not found")
var errVersionMismatch = NewError(http.StatusBadRequest, "Version does not match the one specified in the body")
var errBadVersion = NewError(http.StatusBadRequest, "Bad version value")

var errVersionNotReachable = NewError(http.StatusUnprocessableEntity, "Could not reach version on specified url")
var errVersionBadChecksum = NewError(http.StatusUnprocessableEntity, "Checksum does not match the calculated one")
var errVersionBadSize = NewError(http.StatusUnprocessableEntity, "Size of the version does not match with the calculated one")
var errVersionNoManifest = NewError(http.StatusUnprocessableEntity, "Application tarball does not contain a manifest")
var errVersionManifestInvalid = NewError(http.StatusUnprocessableEntity, "Content of the manifest is not JSON valid")

type Error struct {
	c int
	e string
}

func NewError(code int, format string, a ...interface{}) error {
	return &Error{
		c: code,
		e: fmt.Sprintf(format, a...),
	}
}

func (e *Error) Error() string {
	return e.e
}

func (e *Error) StatusCode() int {
	return e.c
}
