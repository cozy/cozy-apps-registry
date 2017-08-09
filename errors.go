package main

import (
	"fmt"
	"net/http"
)

var errUnknownEditor = NewError(http.StatusUnauthorized, "Editor not found")
var errEditorExists = NewError(http.StatusUnauthorized, "Editor already exists")

var errAppNotFound = NewError(http.StatusNotFound, "Application was not found")
var errAppNameMismatch = NewError(http.StatusBadRequest, "Application name does not match the one specified in the body")
var errBadAppName = NewError(http.StatusBadRequest, "Invalid application name: should contain only alphanumeric characters and dashes")

var errVersionAlreadyExists = NewError(http.StatusConflict, "Version already exists")
var errVersionNotFound = NewError(http.StatusNotFound, "Version was not found")
var errVersionMismatch = NewError(http.StatusBadRequest, "Version does not match the one specified in the body")
var errBadVersion = NewError(http.StatusBadRequest, "Invalid version value")
var errBadChannel = NewError(http.StatusBadRequest, `Invalid version channel: should be "stable", "beta" or "dev"`)

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
