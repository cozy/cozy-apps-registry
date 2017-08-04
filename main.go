package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

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
	helpFlag := flag.Bool("h", false, "print usage")
	portFlag := flag.Int("port", 8080, "specify the port to listen on")
	hostFlag := flag.String("host", "localhost", "specify the host to listen on")
	couchFlag := flag.String("couchdb-addr", "localhost:5984", "specify the address of couchdb")
	tokenFlag := flag.String("gen-token", "", "used to generate an editor token")
	flag.Parse()

	if *helpFlag == true {
		flag.PrintDefaults()
		return
	}

	var err error
	editorReg, err = NewFileEditorRegistry("./editors")
	if err != nil {
		printAndExit(err.Error())
	}

	if *tokenFlag != "" {
		token, err := GenerateEditorToken(editorReg, &EditorTokenOptions{
			Editor: *tokenFlag,
		})
		if err != nil {
			printAndExit(err.Error())
		}
		fmt.Println(base64.StdEncoding.EncodeToString(token))
		return
	}

	if err = InitDBClient(*couchFlag); err != nil {
		printAndExit(err.Error())
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
	apps.POST("/:app/", createApp)
	apps.POST("/:app/:version", createVersion)
	apps.POST("/:app/:version/", createVersion)

	apps.GET("", getAppsList)
	apps.GET("/", getAppsList)
	apps.GET("/:app", getApp)
	apps.GET("/:app/", getApp)
	apps.GET("/:app/:version", getVersion)
	apps.GET("/:app/:channel/latest", getLatestVersion)

	address := *hostFlag + ":" + strconv.Itoa(*portFlag)
	fmt.Printf("Listening on %s...", address)
	if err := e.Start(address); err != nil {
		printAndExit(err.Error())
	}
}

func printAndExit(v string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, v, a...)
	os.Exit(1)
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
