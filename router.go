package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cozy/cozy-registry-v3/auth"
	"github.com/cozy/cozy-registry-v3/errshttp"
	"github.com/cozy/cozy-registry-v3/registry"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var errUnauthorized = errshttp.NewError(http.StatusUnauthorized, "Unauthorized")
var queryFilterReg = regexp.MustCompile(`^filter\[([a-z]+)\]$`)

var (
	oneMinute = 1 * time.Minute
	oneYear   = 365 * 24 * time.Hour
)

func createApp(c echo.Context) (err error) {
	app := &registry.App{}
	if err = c.Bind(app); err != nil {
		return err
	}
	if err = validateAppRequest(c, app); err != nil {
		return err
	}
	editor, err := checkPermissions(c, app.Editor, "")
	if err != nil {
		return err
	}
	if err = registry.CreateOrUpdateApp(app, editor); err != nil {
		return err
	}
	// Do not show internal identifier and revision
	app.ID = ""
	app.Rev = ""
	return c.JSON(http.StatusCreated, app)
}

func createVersion(c echo.Context) (err error) {
	ver := &registry.Version{}
	if err = c.Bind(ver); err != nil {
		return err
	}
	if err = validateVersionRequest(c, ver); err != nil {
		return err
	}
	app, err := registry.FindApp(ver.Name)
	if err != nil {
		return err
	}
	editor, err := checkPermissions(c, app.Editor, ver.Sha256)
	if err != nil {
		return err
	}
	if err = registry.CreateVersion(ver, editor); err != nil {
		return err
	}
	// Do not show internal identifier and revision
	ver.ID = ""
	ver.Rev = ""
	return c.JSON(http.StatusCreated, ver)
}

func checkPermissions(c echo.Context, editorName, versionHash string) (*auth.Editor, error) {
	editor, err := editorRegistry.GetEditor(editorName)
	if err != nil {
		return nil, errUnauthorized
	}
	authHeader := c.Request().Header.Get(echo.HeaderAuthorization)
	if strings.HasPrefix(authHeader, "Token ") {
		tokenStr := authHeader[len("Token "):]
		if len(tokenStr) > 1024 { // tokens should be much less than 128bytes
			return nil, errUnauthorized
		}

		token, err := base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			return nil, errUnauthorized
		}

		ok := editor.VerifySessionToken(sessionSecret, token)
		if !ok {
			return nil, errUnauthorized
		}
		return editor, nil
	}
	return nil, errUnauthorized
}

func getAppsList(c echo.Context) error {
	filter := make(map[string]string)
	var limit, cursor int
	var sort string
	var err error
	for name, vals := range c.QueryParams() {
		if len(vals) == 0 {
			continue
		}
		val := vals[0]
		switch name {
		case "limit":
			limit, err = strconv.Atoi(val)
			if err != nil {
				return errshttp.NewError(http.StatusBadRequest, "Query param limit is invalid: %s", err.Error())
			}
		case "cursor":
			cursor, _ = strconv.Atoi(val)
		case "sort":
			sort = val
		default:
			if queryFilterReg.MatchString(name) {
				subs := queryFilterReg.FindStringSubmatch(name)
				if len(subs) == 2 {
					filter[subs[1]] = val
				}
			}
		}
	}

	next, docs, err := registry.GetAppsList(&registry.AppsListOptions{
		Filters: filter,
		Limit:   limit,
		Cursor:  cursor,
		Sort:    sort,
	})
	if err != nil {
		return err
	}

	for _, doc := range docs {
		// Do not show internal identifier and revision
		doc.ID = ""
		doc.Rev = ""
	}

	type pageInfo struct {
		Count      int    `json:"count"`
		NextCursor string `json:"next_cursor,omitempty"`
	}

	var nextCursor string
	if next >= 0 {
		nextCursor = strconv.Itoa(next)
	}

	j := struct {
		List     []*registry.App `json:"data"`
		PageInfo pageInfo        `json:"meta"`
	}{
		List: docs,
		PageInfo: pageInfo{
			Count:      len(docs),
			NextCursor: nextCursor,
		},
	}

	return c.JSON(http.StatusOK, j)
}

func getApp(c echo.Context) error {
	appName := c.Param("app")
	doc, err := registry.FindApp(appName)
	if err != nil {
		return err
	}

	if cacheControl(c, doc.Rev, oneMinute) {
		return c.NoContent(http.StatusNotModified)
	}

	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.JSON(http.StatusOK, doc)
}

func getAppVersions(c echo.Context) error {
	appName := c.Param("app")
	doc, err := registry.FindAppVersions(appName)
	if err != nil {
		return err
	}

	if cacheControl(c, "", oneMinute) {
		return c.NoContent(http.StatusNotModified)
	}

	return c.JSON(http.StatusOK, doc)
}

func getVersion(c echo.Context) error {
	appName := c.Param("app")
	version := c.Param("version")
	_, err := registry.FindApp(appName)
	if err != nil {
		return err
	}
	doc, err := registry.FindVersion(appName, version)
	if err != nil {
		return err
	}

	if cacheControl(c, doc.Rev, oneYear) {
		return c.NoContent(http.StatusNotModified)
	}

	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.JSON(http.StatusOK, doc)
}

func getLatestVersion(c echo.Context) error {
	appName := c.Param("app")
	channel := c.Param("channel")
	doc, err := registry.FindLatestVersion(appName, channel)
	if err != nil {
		return err
	}

	if cacheControl(c, doc.Rev, oneMinute) {
		return c.NoContent(http.StatusNotModified)
	}

	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.JSON(http.StatusOK, doc)
}

func getEditor(c echo.Context) error {
	editorName := c.Param("editor")
	editor, err := editorRegistry.GetEditor(editorName)
	if err != nil {
		return err
	}

	if cacheControl(c, "", oneMinute) {
		return c.NoContent(http.StatusNotModified)
	}

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.JSON(http.StatusOK, editor)
}

func getEditorsList(c echo.Context) error {
	editors, err := editorRegistry.AllEditors()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, editors)
}

// jsonEndPoint middleware checks that the Content-Type and Accept headers are
// properly set for an application/json endpoint.
func jsonEndpoint(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		switch req.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			contentType := c.Request().Header.Get(echo.HeaderContentType)
			if !strings.HasPrefix(contentType, echo.MIMEApplicationJSON) {
				return errshttp.NewError(http.StatusUnsupportedMediaType, "Content-Type should be application/json")
			}
		}
		acceptHeader := req.Header.Get("Accept")
		if acceptHeader != "" &&
			!strings.Contains(acceptHeader, echo.MIMEApplicationJSON) &&
			!strings.Contains(acceptHeader, "*/*") {
			return errshttp.NewError(http.StatusNotAcceptable, "Accept header does not contain application/json")
		}
		return next(c)
	}
}

func validateAppRequest(c echo.Context, app *registry.App) error {
	appName := c.Param("app")
	if app.Name == "" {
		app.Name = appName
	} else if appName != "" && app.Name != appName {
		return registry.ErrAppNameMismatch
	}
	if err := registry.IsValidApp(app); err != nil {
		return wrapErr(err, http.StatusBadRequest)
	}
	return nil
}

func validateVersionRequest(c echo.Context, ver *registry.Version) error {
	appName := c.Param("app")
	version := c.Param("version")
	if ver.Name == "" {
		ver.Name = appName
	} else if ver.Name != appName {
		return registry.ErrAppNameMismatch
	}
	if ver.Version == "" {
		ver.Version = version
	} else if ver.Version != version {
		return registry.ErrVersionMismatch
	}
	if err := registry.IsValidVersion(ver); err != nil {
		return wrapErr(err, http.StatusBadRequest)
	}
	return nil
}

func httpErrorHandler(err error, c echo.Context) {
	var (
		code = http.StatusInternalServerError
		msg  string
	)

	if he, ok := err.(*errshttp.Error); ok {
		code = he.StatusCode()
		msg = err.Error()
	} else if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		msg = fmt.Sprintf("%s", he.Message)
	} else {
		msg = err.Error()
	}

	respHeaders := c.Response().Header()
	switch err {
	case registry.ErrVersionNotFound, registry.ErrAppNotFound:
		respHeaders.Set("cache-control", "max-age=60")
	default:
		respHeaders.Set("cache-control", "no-cache")
	}

	if !c.Response().Committed {
		if c.Request().Method == echo.HEAD {
			c.NoContent(code)
		} else {
			c.JSON(code, echo.Map{"error": msg})
		}
	}
}

func wrapErr(err error, code int) error {
	if err == nil {
		return nil
	}
	if errHTTP, ok := err.(*errshttp.Error); ok {
		return errHTTP
	}
	return errshttp.NewError(code, err.Error())
}

func cacheControl(c echo.Context, rev string, maxAge time.Duration) bool {
	headers := c.Response().Header()
	headers.Set("cache-control", fmt.Sprintf("max-age=%d", int(maxAge.Seconds())))
	headers.Set("date", time.Now().UTC().Format(http.TimeFormat))

	if rev != "" {
		headers.Set("etag", rev)
		revMatches := strings.Split(c.Request().Header.Get("if-none-match"), ",")
		for _, revMatch := range revMatches {
			if strings.TrimSpace(revMatch) == rev {
				return true
			}
		}
	}

	return false
}

func Router(addr string) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = httpErrorHandler

	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.BodyLimit("100K"))
	e.Use(middleware.LoggerWithConfig(middleware.DefaultLoggerConfig))
	e.Use(middleware.Recover())

	registry := e.Group("/registry", jsonEndpoint)
	registry.POST("", createApp)
	registry.POST("/:app", createApp)
	registry.POST("/:app/:version", createVersion)

	registry.GET("", getAppsList)
	registry.HEAD("/:app", getApp)
	registry.GET("/:app", getApp)
	registry.GET("/:app/versions", getAppVersions)
	registry.HEAD("/:app/:version", getVersion)
	registry.GET("/:app/:version", getVersion)
	registry.HEAD("/:app/:channel/latest", getLatestVersion)
	registry.GET("/:app/:channel/latest", getLatestVersion)

	e.GET("/editors", getEditorsList)
	e.HEAD("/editors/:editor", getEditor)
	e.GET("/editors/:editor", getEditor)

	return e
}
