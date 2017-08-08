package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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
			if strings.HasPrefix(acceptHeader, echo.MIMEApplicationJSON) ||
				strings.HasPrefix(acceptHeader, "*/*") {
				return next(c)
			}
			acceptHeader = strings.TrimLeftFunc(acceptHeader, func(r rune) bool { return r != ',' })
			if acceptHeader == "" {
				return echo.NewHTTPError(http.StatusNotAcceptable, "Accept header does not contain application/json")
			}
		}
	}
}

func main() {
	portFlag := flag.Int("port", 8080, "specify the port to listen on")
	hostFlag := flag.String("host", "localhost", "specify the host to listen on")
	couchAddrFlag := flag.String("couchdb-addr", "localhost:5984", "specify the address of couchdb")
	couchUserFlag := flag.String("couchdb-user", "", "specify the user of couchdb")
	couchPassFlag := flag.String("couchdb-password", "", "specify the password of couchdb")

	editorRegistryFlag := flag.String("editor-registry", "couchdb", "used to specify the editors registry (text:./filename or couchdb)")

	genTokenFlag := flag.String("gen-token", "", "used to generate an editor token")
	genTokenMaxAgeFlag := flag.String("gen-token-max-age", "", "used to generate an editor token")

	addEditorFlag := flag.String("add-editor", "", "used to add an editor to the editor registry")
	flag.Parse()

	err := InitDBClient(*couchAddrFlag, *couchUserFlag, *couchPassFlag)
	if err != nil {
		printAndExit("Could not reach CouchDB: %s", err.Error())
	}

	if *editorRegistryFlag == "" {
		*editorRegistryFlag = "couchdb"
	}
	regOpts := strings.SplitN(*editorRegistryFlag, ":", 2)
	switch regOpts[0] {
	case "file":
		if len(regOpts) != 2 {
			printAndExit("Bad -editor-registry option: missing filename (ie -editor-registry text:./filename)")
		}
		filename := regOpts[1]
		editorReg, err = NewFileEditorRegistry(filename)
	case "couch", "couchdb":
		editorReg, err = NewCouchdbEditorRegistry(*couchAddrFlag)
	}
	if err != nil {
		printAndExit("Could not initialize the editor registry: %s", err.Error())
	}

	if *addEditorFlag != "" {
		err = editorReg.CreateEditorSecret(*addEditorFlag)
		if err != nil {
			printAndExit("Could not add a new editor: %s", err.Error())
		}
		fmt.Printf(`Editor "%s" was added successfully\n`, *addEditorFlag)
		os.Exit(0)
	}

	if *genTokenFlag != "" {
		var token []byte
		var maxAge time.Duration
		if *genTokenMaxAgeFlag != "" {
			maxAge, err = time.ParseDuration(*genTokenMaxAgeFlag)
			if err != nil {
				printAndExit("Bad -gen-token-max-age option: %s", err.Error())
			}
		}
		token, err = GenerateEditorToken(editorReg, &EditorTokenOptions{
			Editor: *genTokenFlag,
			MaxAge: maxAge,
		})
		if err != nil {
			printAndExit("Could not generate editor token for %s: %s",
				*genTokenFlag, err.Error())
		}
		fmt.Println(base64.StdEncoding.EncodeToString(token))
		return
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
	fmt.Printf("Listening on %s...\n", address)
	if err := e.Start(address); err != nil {
		printAndExit(err.Error())
	}
}

func printAndExit(v string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, v+"\n", a...)
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
