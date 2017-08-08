package main

import (
	"net/http"

	"github.com/labstack/echo"
)

var errUnauthorized = echo.NewHTTPError(http.StatusUnauthorized)
var errUnknownEditor = echo.NewHTTPError(http.StatusUnauthorized, "Unknown editor name")
var errEditorExists = echo.NewHTTPError(http.StatusUnauthorized, "Editor already exists")
var errBadChannel = echo.NewHTTPError(http.StatusBadRequest, "Channel should be \"stable\", \"beta\" or \"dev\"")

var errAppNotFound = echo.NewHTTPError(http.StatusNotFound, "Application was not found")
var errAppNameMismatch = echo.NewHTTPError(http.StatusBadRequest, "Application name does not match the one specified in the body")
var errBadAppName = echo.NewHTTPError(http.StatusBadRequest, "Bad application name: should contain only ascii letters, numbers and -")

var errVersionAlreadyExists = echo.NewHTTPError(http.StatusConflict, "Version already exists")
var errVersionNotFound = echo.NewHTTPError(http.StatusNotFound, "Version was not found")
var errVersionMismatch = echo.NewHTTPError(http.StatusBadRequest, "Version does not match the one specified in the body")
var errBadVersion = echo.NewHTTPError(http.StatusBadRequest, "Bad version value")

var errVersionNotReachable = echo.NewHTTPError(http.StatusUnprocessableEntity, "Could not reach version on specified url")
var errVersionBadChecksum = echo.NewHTTPError(http.StatusUnprocessableEntity, "Checksum does not match the calculated one")
var errVersionBadSize = echo.NewHTTPError(http.StatusUnprocessableEntity, "Size of the version does not match with the calculated one")
var errVersionNoManifest = echo.NewHTTPError(http.StatusUnprocessableEntity, "Application tarball does not contain a manifest")
var errVersionManifestInvalid = echo.NewHTTPError(http.StatusUnprocessableEntity, "Content of the manifest is not JSON valid")
