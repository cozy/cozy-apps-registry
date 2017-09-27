package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
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

const authTokenScheme = "Token "

var queryFilterReg = regexp.MustCompile(`^filter\[([a-z]+)\]$`)

var errUnauthorized = errshttp.NewError(http.StatusUnauthorized,
	http.StatusText(http.StatusUnauthorized))

var (
	oneMinute = 1 * time.Minute
	oneHour   = 1 * time.Hour
	oneYear   = 365 * 24 * time.Hour
)

func createApp(c echo.Context) (err error) {
	if err = checkAuthorized(c); err != nil {
		return err
	}

	app := &registry.App{}
	if err = c.Bind(app); err != nil {
		return err
	}

	if err = validateAppRequest(c, app); err != nil {
		return err
	}

	editor, err := checkPermissions(c, app.Editor)
	if err != nil {
		return err
	}

	var updated bool
	app, updated, err = registry.CreateOrUpdateApp(app, editor)
	if err != nil {
		return err
	}
	if !updated {
		return c.NoContent(http.StatusNotModified)
	}

	// Do not show internal identifier and revision
	app.ID = ""
	app.Rev = ""

	return c.JSON(http.StatusCreated, app)
}

func createVersion(c echo.Context) (err error) {
	if err = checkAuthorized(c); err != nil {
		return err
	}

	opts := &registry.VersionOptions{}
	if err = c.Bind(opts); err != nil {
		return err
	}

	if err = validateVersionRequest(c, opts); err != nil {
		return err
	}

	ver, err := registry.DownloadVersion(opts)
	if err != nil {
		return err
	}

	editor, err := checkPermissions(c, ver.Editor)
	if err != nil {
		return err
	}

	if err = registry.CreateVersion(ver, editor); err != nil {
		return err
	}

	// Do not show internal identifier and revision
	ver.ID = ""
	ver.Rev = ""
	ver.Attachments = nil

	return c.JSON(http.StatusCreated, ver)
}

func checkAuthorized(c echo.Context) error {
	token, err := extractAuthHeader(c)
	if err != nil {
		return err
	}
	if _, ok := auth.VerifyToken(sessionSecret, token, nil); !ok {
		return errUnauthorized
	}
	return nil
}

func checkPermissions(c echo.Context, editorName string) (*auth.Editor, error) {
	token, err := extractAuthHeader(c)
	if err != nil {
		return nil, err
	}

	editor, err := editorRegistry.GetEditor(editorName)
	if err != nil {
		return nil, errUnauthorized
	}

	ok := editor.VerifySessionToken(sessionSecret, token)
	if !ok {
		return nil, errUnauthorized
	}
	return editor, nil
}

func extractAuthHeader(c echo.Context) ([]byte, error) {
	authHeader := c.Request().Header.Get(echo.HeaderAuthorization)
	if !strings.HasPrefix(authHeader, authTokenScheme) {
		return nil, errUnauthorized
	}
	tokenStr := authHeader[len(authTokenScheme):]
	if len(tokenStr) > 1024 { // tokens should be much less than 128bytes
		return nil, errUnauthorized
	}
	token, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, errUnauthorized
	}
	return token, nil
}

func getAppsList(c echo.Context) error {
	var filter map[string]string
	var limit, cursor int
	var sort string
	var err error
	for name, vals := range c.QueryParams() {
		val := vals[0]
		switch name {
		case "limit":
			limit, err = strconv.Atoi(val)
			if err != nil {
				return errshttp.NewError(http.StatusBadRequest,
					`Query param "limit" is invalid: %s`, err)
			}
		case "cursor":
			cursor, err = strconv.Atoi(val)
			if err != nil {
				return errshttp.NewError(http.StatusBadRequest,
					`Query param "cursor" is invalid: %s`, err)
			}
		case "sort":
			sort = val
		default:
			if queryFilterReg.MatchString(name) {
				subs := queryFilterReg.FindStringSubmatch(name)
				if len(subs) == 2 {
					if filter == nil {
						filter = make(map[string]string)
					}
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
	appSlug := c.Param("app")
	doc, err := registry.FindApp(appSlug)
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

func getAppIcon(c echo.Context) error {
	return getAppAttachment(c, "icon")
}

func getAppScreenshot(c echo.Context) error {
	return getAppAttachment(c, path.Join("screenshots", c.Param("filename")))
}

func getAppAttachment(c echo.Context, filename string) error {
	appSlug := c.Param("app")
	channel := c.Param("channel")
	ch, err := registry.StrToChannel(channel)
	if err != nil {
		ch = registry.Stable
	}
	att, err := registry.FindAppAttachment(appSlug, filename, ch)
	if err != nil {
		return err
	}
	defer att.Close()

	if cacheControl(c, hex.EncodeToString(att.MD5[:]), oneHour) {
		return c.NoContent(http.StatusNotModified)
	}

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.Stream(http.StatusOK, att.ContentType, att)
}

func getVersionIcon(c echo.Context) error {
	return getVersionAttachment(c, "icon")
}

func getVersionScreenshot(c echo.Context) error {
	return getVersionAttachment(c, path.Join("screenshots", c.Param("filename")))
}

func getVersionAttachment(c echo.Context, filename string) error {
	appSlug := c.Param("app")
	version := c.Param("version")
	att, err := registry.FindVersionAttachment(appSlug, version, filename)
	if err != nil {
		return err
	}
	defer att.Close()

	if cacheControl(c, hex.EncodeToString(att.MD5[:]), oneHour) {
		return c.NoContent(http.StatusNotModified)
	}

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.Stream(http.StatusOK, att.ContentType, att)
}

func getAppVersions(c echo.Context) error {
	appSlug := c.Param("app")
	doc, err := registry.FindAppVersions(appSlug)
	if err != nil {
		return err
	}

	if cacheControl(c, "", oneMinute) {
		return c.NoContent(http.StatusNotModified)
	}

	return c.JSON(http.StatusOK, doc)
}

func getVersion(c echo.Context) error {
	appSlug := c.Param("app")
	version := stripVersion(c.Param("version"))
	_, err := registry.FindApp(appSlug)
	if err != nil {
		return err
	}

	doc, err := registry.FindVersion(appSlug, version)
	if err != nil {
		return err
	}

	if cacheControl(c, doc.Rev, oneYear) {
		return c.NoContent(http.StatusNotModified)
	}

	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""
	doc.Attachments = nil

	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return c.JSON(http.StatusOK, doc)
}

func getLatestVersion(c echo.Context) error {
	appSlug := c.Param("app")
	channel := c.Param("channel")

	ch, err := registry.StrToChannel(channel)
	if err != nil {
		return err
	}
	doc, err := registry.FindLatestVersion(appSlug, ch)
	if err != nil {
		return err
	}

	if cacheControl(c, doc.Rev, oneMinute) {
		return c.NoContent(http.StatusNotModified)
	}

	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""
	doc.Attachments = nil

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
				return errshttp.NewError(http.StatusUnsupportedMediaType,
					"Content-Type should be application/json")
			}
		}
		acceptHeader := req.Header.Get("Accept")
		if acceptHeader != "" &&
			!strings.Contains(acceptHeader, echo.MIMEApplicationJSON) &&
			!strings.Contains(acceptHeader, "*/*") {
			return errshttp.NewError(http.StatusNotAcceptable,
				"Accept header does not contain application/json")
		}
		return next(c)
	}
}

func validateAppRequest(c echo.Context, app *registry.App) error {
	appSlug := c.Param("app")
	if app.Slug == "" {
		app.Slug = appSlug
	} else if appSlug != "" && app.Slug != appSlug {
		return registry.ErrAppSlugMismatch
	}
	if err := registry.IsValidApp(app); err != nil {
		return wrapErr(err, http.StatusBadRequest)
	}
	return nil
}

func validateVersionRequest(c echo.Context, ver *registry.VersionOptions) error {
	version := stripVersion(c.Param("version"))
	ver.Version = stripVersion(ver.Version)
	if version != "" {
		if ver.Version == "" {
			ver.Version = version
		} else if ver.Version != version {
			return registry.ErrVersionMismatch
		}
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

// stripVersion removes the 'v' prefix if any.
// ex: v1.3.2 -> 1.3.2
func stripVersion(v string) string {
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	return v
}

func Router(addr string) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = httpErrorHandler

	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.BodyLimit("100K"))
	e.Use(middleware.Logger())
	e.Use(middleware.Gzip())
	e.Use(middleware.Recover())

	registry := e.Group("/registry", jsonEndpoint)
	registry.POST("", createApp)
	registry.POST("/versions", createVersion)
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

	registry.GET("/:app/icon", getAppIcon)
	registry.HEAD("/:app/icon", getAppIcon)
	registry.GET("/:app/screenshots/:filename", getAppScreenshot)
	registry.HEAD("/:app/screenshots/:filename", getAppScreenshot)
	registry.GET("/:app/:channel/latest/icon", getAppIcon)
	registry.HEAD("/:app/:channel/latest/icon", getAppIcon)
	registry.HEAD("/:app/:version/icon", getVersionIcon)
	registry.GET("/:app/:version/icon", getVersionIcon)
	registry.HEAD("/:app/:version/screenshots/:filename", getVersionScreenshot)
	registry.GET("/:app/:version/screenshots/:filename", getVersionScreenshot)

	e.GET("/editors", getEditorsList)
	e.HEAD("/editors/:editor", getEditor)
	e.GET("/editors/:editor", getEditor)

	return e
}
