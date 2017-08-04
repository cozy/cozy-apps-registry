package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var validAppNameReg = regexp.MustCompile(`^[a-z0-9\-]+$`)
var validVersionReg = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})(-dev\.[a-f0-9]{5,40}|-beta.(0|[1-9][0-9]{0,4}))?$`)
var validAppTypes = []string{
	"webapp",
	"konnector",
}

func createApp(c echo.Context) (err error) {
	app := &App{}
	if err = c.Bind(app); err != nil {
		return err
	}
	if err = validateAppRequest(c, app); err != nil {
		return err
	}
	// TODO: check permission to create application
	if err = CreateApp(app); err != nil {
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
	// TODO: check permission to create version
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

func getAppsList(c echo.Context) error {
	return errNotImplemented
}

func getApp(c echo.Context) error {
	appName := c.Param("app")
	if !validAppNameReg.MatchString(appName) {
		return errBadAppName
	}
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
	if !validAppNameReg.MatchString(appName) {
		return errBadAppName
	}
	if !validVersionReg.MatchString(version) {
		return errBadVersion
	}
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
	if !validAppNameReg.MatchString(appName) {
		return errBadAppName
	}
	ch, err := validateChannel(channel)
	if err != nil {
		return err
	}
	doc, err := FindLatestVersion(appName, ch)
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
			if !strings.HasPrefix(contentType, "application/json") {
				return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Content-Type should be application/json")
			}
		}
		acceptHeader := req.Header.Get("Accept")
		if acceptHeader == "" || acceptHeader == "*/*" {
			return next(c)
		}
		for {
			acceptHeader = strings.TrimLeftFunc(acceptHeader, func(r rune) bool { return r == ',' || r == ' ' })
			if acceptHeader == "" {
				return echo.NewHTTPError(http.StatusNotAcceptable, "Accept header does not contain application/json")
			}
			if strings.HasPrefix(acceptHeader, echo.MIMEApplicationJSON) {
				return next(c)
			}
			acceptHeader = strings.TrimLeftFunc(acceptHeader, func(r rune) bool { return r != ',' })
			if acceptHeader == "" {
				return echo.NewHTTPError(http.StatusNotAcceptable, "Accept header does not contain application/json")
			}
		}
	}
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

func main() {
	if err := InitDBClient(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = httpErrorHandler
	e.Use(middleware.BodyLimit("100K"))
	e.Use(middleware.LoggerWithConfig(middleware.DefaultLoggerConfig))

	apps := e.Group("/apps", jsonEndpoint)
	apps.POST("", createApp)
	apps.POST("/", createApp)
	apps.POST("/:app", createApp)
	apps.POST("/:app/:version", createVersion)

	apps.GET("", getAppsList)
	apps.GET("/", getAppsList)
	apps.GET("/:app", getApp)
	apps.GET("/:app/:version", getVersion)
	apps.GET("/:app/:channel/latest", getLatestVersion)

	fmt.Println("Listening...")
	if err := e.Start("localhost:8080"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func validateAppRequest(c echo.Context, app *App) error {
	if appName := c.Param("app"); appName != "" && app.Name != appName {
		return errAppNameMismatch
	}
	var fields []string
	if app.Name == "" || !validAppNameReg.MatchString(app.Name) {
		fields = append(fields, "name")
	}
	if app.Editor == "" {
		fields = append(fields, "editor")
	}
	if app.Description == "" {
		fields = append(fields, "description")
	}
	if !stringInArray(app.Type, validAppTypes) {
		fields = append(fields, "type")
	}
	if app.Repository != "" {
		if _, err := url.Parse(app.Repository); err != nil {
			fields = append(fields, "repository")
		}
	}
	if len(fields) > 0 {
		return fmt.Errorf("Application object is not valid, "+
			"the following fields are erroneous: %s", strings.Join(fields, ", "))
	}
	return nil
}

func validateVersionRequest(c echo.Context, ver *Version) error {
	appName := c.Param("app")
	version := c.Param("version")
	if !validAppNameReg.MatchString(appName) {
		return errBadAppName
	}
	if ver.Version == "" {
		ver.Version = version
	} else if ver.Version != version {
		return errVersionMismatch
	}
	if ver.Version == "" || !validVersionReg.MatchString(ver.Version) {
		return errBadVersion
	}
	if ver.Name != appName {
		return errAppNameMismatch
	}
	var fields []string
	if !stringInArray(ver.Type, validAppTypes) {
		fields = append(fields, "type")
	}
	if ver.URL == "" {
		fields = append(fields, "url")
	} else if _, err := url.Parse(ver.URL); err != nil {
		fields = append(fields, "url")
	}
	if ver.Size <= 0 {
		fields = append(fields, "size")
	}
	if ver.Sha256 == "" {
		fields = append(fields, "sha256")
	} else if h, err := hex.DecodeString(ver.Sha256); err != nil || len(h) != 32 {
		fields = append(fields, "sha256")
	}
	if len(fields) > 0 {
		return fmt.Errorf("Application object is not valid, "+
			"the following fields are erroneous: %s", strings.Join(fields, ", "))
	}
	return nil
}

func validateChannel(channel string) (Channel, error) {
	switch channel {
	case string(Stable):
		return Stable, nil
	case string(Beta):
		return Beta, nil
	case string(Dev):
		return Dev, nil
	default:
		return Stable, errBadChannel
	}
}
