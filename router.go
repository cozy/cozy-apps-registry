package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var validAppTypes = []string{
	"webapp",
	"konnector",
}

var queryFilterReg = regexp.MustCompile(`^filter\[([a-z]+)\]$`)

func createApp(c echo.Context) (err error) {
	app := &App{}
	if err = c.Bind(app); err != nil {
		return err
	}
	if err = validateAppRequest(c, app); err != nil {
		return err
	}
	if err = checkPermissions(c, app.Editor, app.Name); err != nil {
		return err
	}
	if err = CreateOrUpdateApp(app); err != nil {
		return err
	}
	app, err = FindApp(app.Name)
	if err != nil {
		return err
	}
	// Do not show internal identifier and revision
	app.ID = ""
	app.Rev = ""
	return c.JSON(http.StatusCreated, app)
}

func createVersion(c echo.Context) (err error) {
	ver := &Version{}
	if err = c.Bind(ver); err != nil {
		return err
	}
	if err = validateVersionRequest(c, ver); err != nil {
		return err
	}
	app, err := FindApp(ver.Name)
	if err != nil {
		return err
	}
	if err = checkPermissions(c, app.Editor, app.Name); err != nil {
		return err
	}
	if err = CreateVersion(ver); err != nil {
		return err
	}
	ver, err = FindVersion(ver.Name, ver.Version)
	if err != nil {
		return err
	}
	// Do not show internal identifier and revision
	ver.ID = ""
	ver.Rev = ""
	return c.JSON(http.StatusCreated, ver)
}

func checkPermissions(c echo.Context, editorName, appName string) error {
	authHeader := c.Request().Header.Get(echo.HeaderAuthorization)
	if !strings.HasPrefix(authHeader, "Token ") {
		return errUnauthorized
	}
	tokenStr := authHeader[len("Token "):]
	if len(tokenStr) > 1024 { // tokens should be much less than 128bytes
		return errUnauthorized
	}
	token, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return errUnauthorized
	}
	if err := VerifyEditorToken(editorRegistry, editorName, appName, token); err != nil {
		if err != errUnauthorized {
			fmt.Fprintf(os.Stderr, "Received bad token=%s for editor=%s and application=%s: %s\n",
				token, editorName, appName, err.Error())
		}
		return errUnauthorized
	}
	return nil
}

func getAppsList(c echo.Context) error {
	filter := make(map[string]string)
	var limit, skip int
	var err error
	for name, vals := range c.QueryParams() {
		if len(vals) == 0 {
			continue
		}
		val := vals[0]
		if len(val) > 1024 {
			return echo.NewHTTPError(http.StatusBadRequest)
		}
		if name == "limit" {
			limit, err = strconv.Atoi(val)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}
			continue
		}
		if name == "skip" {
			skip, err = strconv.Atoi(val)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}
			continue
		}
		if queryFilterReg.MatchString(name) {
			subs := queryFilterReg.FindStringSubmatch(name)
			if len(subs) == 2 {
				filter[subs[1]] = val
			}
		}
	}

	docs, err := GetAppsList(&AppsListOptions{
		Filters: filter,
		Limit:   limit,
		Skip:    skip,
	})
	if err != nil {
		return err
	}
	for _, doc := range docs {
		doc.ID = ""
		doc.Rev = ""
	}
	return c.JSON(http.StatusOK, docs)
}

func getApp(c echo.Context) error {
	appName := c.Param("app")
	doc, err := FindApp(appName)
	if err != nil {
		return err
	}
	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""
	return c.JSON(http.StatusOK, doc)
}

func getVersion(c echo.Context) error {
	appName := c.Param("app")
	version := c.Param("version")
	doc, err := FindVersion(appName, version)
	if err != nil {
		return err
	}
	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""
	return c.JSON(http.StatusOK, doc)
}

func getLatestVersion(c echo.Context) error {
	appName := c.Param("app")
	channel := c.Param("channel")
	doc, err := FindLatestVersion(appName, channel)
	if err != nil {
		return err
	}
	// Do not show internal identifier and revision
	doc.ID = ""
	doc.Rev = ""
	return c.JSON(http.StatusOK, doc)
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
				return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Content-Type should be application/json")
			}
		}
		acceptHeader := req.Header.Get("Accept")
		if acceptHeader != "" &&
			!strings.Contains(acceptHeader, echo.MIMEApplicationJSON) &&
			!strings.Contains(acceptHeader, "*/*") {
			return echo.NewHTTPError(http.StatusNotAcceptable, "Accept header does not contain application/json")
		}
		return next(c)
	}
}

func validateAppRequest(c echo.Context, app *App) error {
	appName := c.Param("app")
	if app.Name == "" {
		app.Name = appName
	} else if app.Name != appName {
		return errAppNameMismatch
	}
	if err := IsValidApp(app); err != nil {
		return wrapErr(err, http.StatusBadRequest)
	}
	return nil
}

func validateVersionRequest(c echo.Context, ver *Version) error {
	appName := c.Param("app")
	version := c.Param("version")
	if ver.Name == "" {
		ver.Name = appName
	} else if ver.Name != appName {
		return errAppNameMismatch
	}
	if ver.Version == "" {
		ver.Version = version
	} else if ver.Version != version {
		return errVersionMismatch
	}
	if err := IsValidVersion(ver); err != nil {
		return wrapErr(err, http.StatusBadRequest)
	}
	return nil
}

func httpErrorHandler(err error, c echo.Context) {
	var (
		code = http.StatusInternalServerError
		msg  interface{}
	)

	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		msg = he.Message
	} else {
		msg = err.Error()
	}
	if _, ok := msg.(string); ok {
		msg = echo.Map{"message": msg}
	}

	if !c.Response().Committed {
		if c.Request().Method == echo.HEAD {
			c.NoContent(code)
		} else {
			c.JSON(code, msg)
		}
	}
}

func wrapErr(err error, code int) error {
	if err == nil {
		return nil
	}
	if errHTTP, ok := err.(*echo.HTTPError); ok {
		return errHTTP
	}
	return echo.NewHTTPError(code, err.Error())
}

func StartRouter(addr string) error {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = httpErrorHandler
	e.Use(middleware.BodyLimit("100K"))
	e.Use(middleware.LoggerWithConfig(middleware.DefaultLoggerConfig))

	apps := e.Group("/apps", jsonEndpoint)
	apps.POST("", createApp)
	apps.POST("/", createApp)
	apps.POST("/:app", createApp)
	apps.POST("/:app/", createApp)
	apps.POST("/:app/:version", createVersion)
	apps.POST("/:app/:version/", createVersion)

	apps.GET("", getAppsList)
	apps.GET("/", getAppsList)
	apps.GET("/:app", getApp)
	apps.GET("/:app/", getApp)
	apps.GET("/:app/:version", getVersion)
	apps.GET("/:app/:version/", getVersion)
	apps.GET("/:app/:channel/latest", getLatestVersion)
	apps.GET("/:app/:channel/latest/", getLatestVersion)

	return e.Start(addr)
}
