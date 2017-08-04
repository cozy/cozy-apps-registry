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

var validAppNameReg = regexp.MustCompile(`^[a-z0-9\-]+$`)
var validVersionReg = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})(-dev\.[a-f0-9]{5,40}|-beta.(0|[1-9][0-9]{0,4}))?$`)
var validAppTypes = []string{
	"webapp",
	"konnector",
}

var editorReg EditorRegistry

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
	if err = checkPermissions(c, app.Editor, ver.Name); err != nil {
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
			fmt.Printf("Received bad token=%s for editor=%s and application=%s\n",
				token, editorName, appName)
		}
		return errUnauthorized
	}
	return nil
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
	var err error
	if err = InitDBClient(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	editorReg, err = NewFileEditorRegistry("./editors")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	token, _ := GenerateEditorToken(editorReg, &EditorTokenOptions{Editor: "Cozy"})
	fmt.Println(base64.StdEncoding.EncodeToString(token))

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

	fmt.Println("Listening...")
	if err := e.Start("localhost:8080"); err != nil {
		fmt.Println(err)
		os.Exit(1)
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
		return echo.NewHTTPError(http.StatusBadRequest, err.Error)
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
		return echo.NewHTTPError(http.StatusBadRequest, err.Error)
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
