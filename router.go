package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var validAppTypes = []string{
	"webapp",
	"konnector",
}

var editorReg EditorRegistry

var filterReg = regexp.MustCompile(`^filter\[([a-z]+)\]$`)

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
	token, err := base64.StdEncoding.DecodeString(authHeader[len("Token "):])
	if err != nil {
		return errUnauthorized
	}
	if err := VerifyEditorToken(editorReg, editorName, appName, token); err != nil {
		if err != errUnauthorized {
			fmt.Fprintf(os.Stderr, "Received bad token=%s for editor=%s and application=%s\n",
				token, editorName, appName)
		}
		return errUnauthorized
	}
	return nil
}

func getAppsList(c echo.Context) error {
	filter := make(map[string]string)
	for name, val := range c.QueryParams() {
		if len(val) > 1024 {
			return echo.NewHTTPError(http.StatusBadRequest)
		}
		if filterReg.MatchString(name) {
			subs := filterReg.FindStringSubmatch(name)
			if len(subs) == 2 {
				filter[subs[1]] = val[0]
			}
		}
	}
	docs, err := GetAppsList(filter)
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
	apps.GET("/:app/:channel/latest", getLatestVersion)

	return e.Start(addr)
}
