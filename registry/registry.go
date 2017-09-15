package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/cozy/cozy-registry-v3/auth"
	"github.com/cozy/cozy-registry-v3/errshttp"
	multierror "github.com/hashicorp/go-multierror"

	"github.com/flimzy/kivik"
	_ "github.com/flimzy/kivik/driver/couchdb" // for couchdb
	"github.com/labstack/echo"
)

const maxApplicationSize = 20 * 1024 * 1024 // 20 Mo

var (
	validSlugReg    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-]*$`)
	validVersionReg = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})(-dev\.[a-f0-9]{1,40}|-beta.(0|[1-9][0-9]{0,4}))?$`)

	validAppTypes = []string{"webapp", "konnector"}
)

var (
	ErrAppNotFound     = errshttp.NewError(http.StatusNotFound, "Application was not found")
	ErrAppSlugMismatch = errshttp.NewError(http.StatusBadRequest, "Application slug does not match the one specified in the body")
	ErrAppInvalid      = errshttp.NewError(http.StatusBadRequest, "Invalid application name: should contain only alphanumeric characters and dashes")

	ErrVersionAlreadyExists = errshttp.NewError(http.StatusConflict, "Version already exists")
	ErrVersionNotFound      = errshttp.NewError(http.StatusNotFound, "Version was not found")
	ErrVersionMismatch      = errshttp.NewError(http.StatusBadRequest, "Version does not match the one specified in the body")
	ErrVersionInvalid       = errshttp.NewError(http.StatusBadRequest, "Invalid version value")
	ErrChannelInvalid       = errshttp.NewError(http.StatusBadRequest, `Invalid version channel: should be "stable", "beta" or "dev"`)
)

var versionClient = http.Client{
	Timeout: 20 * time.Second,
}

const (
	devSuffix  = "-dev."
	betaSuffix = "-beta."
)

var (
	AppsDB    = "registry-apps"
	VersDB    = "registry-versions"
	EditorsDB = "registry-editors"
)

var (
	client    *kivik.Client
	clientURL *url.URL

	ctx = context.Background()

	appsIndexes = map[string]echo.Map{
		"by-slug":       {"fields": []string{"slug"}},
		"by-type":       {"fields": []string{"type", "slug", "category"}},
		"by-editor":     {"fields": []string{"editor", "slug", "category"}},
		"by-category":   {"fields": []string{"category", "slug", "editor"}},
		"by-created_at": {"fields": []string{"created_at", "slug", "category", "editor"}},
		"by-updated_at": {"fields": []string{"updated_at", "slug", "category", "editor"}},
	}

	versIndex = echo.Map{"fields": []string{"version", "slug", "type"}}
)

type Channel int

const (
	Stable Channel = iota
	Beta
	Dev
)

type App struct {
	ID             string         `json:"_id,omitempty"`
	Rev            string         `json:"_rev,omitempty"`
	Slug           string         `json:"slug"`
	Name           AppName        `json:"name"`
	Type           string         `json:"type"`
	Editor         string         `json:"editor"`
	Developer      *Developer     `json:"developer"`
	Description    AppDescription `json:"description"`
	Category       string         `json:"category"`
	Repository     string         `json:"repository"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	Locales        []string       `json:"locales"`
	Tags           []string       `json:"tags"`
	LogoURL        string         `json:"logo_url"`
	ScreenshotURLs []string       `json:"screenshot_urls"`
	Versions       *AppVersions   `json:"versions,omitempty"`
}

type AppDescription map[string]string
type AppName map[string]string

type AppVersions struct {
	Stable []string `json:"stable"`
	Beta   []string `json:"beta"`
	Dev    []string `json:"dev"`
}

type Developer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Version struct {
	ID        string          `json:"_id,omitempty"`
	Rev       string          `json:"_rev,omitempty"`
	Slug      string          `json:"slug"`
	Editor    string          `json:"editor"`
	Type      string          `json:"type"`
	Version   string          `json:"version"`
	Manifest  json.RawMessage `json:"manifest"`
	CreatedAt time.Time       `json:"created_at"`
	URL       string          `json:"url"`
	Size      int64           `json:"size,string"`
	Sha256    string          `json:"sha256"`
	TarPrefix string          `json:"tar_prefix"`
}

func InitDBClient(addr, user, pass, prefix string) (*kivik.Client, error) {
	var err error

	var userInfo *url.Userinfo
	if user != "" {
		if pass != "" {
			userInfo = url.UserPassword(user, pass)
		} else {
			userInfo = url.User(user)
		}
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	u.User = userInfo

	client, err = kivik.New(ctx, "couch", u.String())
	if err != nil {
		return nil, err
	}
	clientURL = u

	if prefix != "" {
		AppsDB = prefix + "-" + AppsDB
		VersDB = prefix + "-" + VersDB
		EditorsDB = prefix + "-" + EditorsDB
	}

	dbs := []string{AppsDB, VersDB, EditorsDB}
	for _, dbName := range dbs {
		var ok bool
		ok, err = client.DBExists(ctx, dbName)
		if err != nil {
			return nil, err
		}
		if !ok {
			fmt.Printf("Creating database %s...", dbName)
			if err = client.CreateDB(ctx, dbName); err != nil {
				fmt.Println("failed")
				return nil, err
			}
			fmt.Println("ok")
		}
	}

	dbApps, err := client.DB(ctx, AppsDB)
	if err != nil {
		return nil, err
	}

	for name, index := range appsIndexes {
		err = dbApps.CreateIndex(ctx, "apps-index-"+name, "apps-index-"+name, index)
		if err != nil {
			return nil, err
		}
	}

	dbVers, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	err = dbVers.CreateIndex(ctx, "versions-index", "versions-index", versIndex)
	if err != nil {
		return nil, err
	}

	return client, err
}

func IsValidApp(app *App) error {
	var fields []string
	if app.Slug == "" || !validSlugReg.MatchString(app.Slug) {
		return ErrAppInvalid
	}
	if app.Editor == "" {
		fields = append(fields, "editor")
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
		return errshttp.NewError(http.StatusBadRequest, "Invalid application, "+
			"the following fields are missing or erroneous: %s", strings.Join(fields, ", "))
	}
	return nil
}

func IsValidVersion(ver *Version) error {
	if ver.Slug == "" || !validSlugReg.MatchString(ver.Slug) {
		return ErrAppInvalid
	}
	if ver.Version == "" || !validVersionReg.MatchString(ver.Version) {
		return ErrVersionInvalid
	}
	var fields []string
	if ver.URL == "" {
		fields = append(fields, "url")
	} else if _, err := url.Parse(ver.URL); err != nil {
		fields = append(fields, "url")
	}
	if h, err := hex.DecodeString(ver.Sha256); err != nil || len(h) != 32 {
		fields = append(fields, "sha256")
	}
	if len(fields) > 0 {
		return fmt.Errorf("Invalid version, "+
			"the following fields are missing or erroneous: %s", strings.Join(fields, ", "))
	}
	return nil
}

func CreateOrUpdateApp(app *App, editor *auth.Editor) (result *App, updated bool, err error) {
	if err = IsValidApp(app); err != nil {
		return
	}

	db, err := client.DB(ctx, AppsDB)
	if err != nil {
		return
	}
	oldApp, err := FindApp(app.Slug)
	if err != nil && err != ErrAppNotFound {
		return
	}
	now := time.Now().UTC()
	if err == ErrAppNotFound {
		app.ID = getAppID(app.Slug)
		app.Slug = app.ID
		app.Editor = editor.Name()
		app.CreatedAt = now
		app.UpdatedAt = now
		app.Versions = nil
		if app.Name == nil {
			app.Name = make(AppName)
		}
		if app.Description == nil {
			app.Description = make(AppDescription)
		}
		if app.Locales == nil {
			app.Locales = make([]string, 0)
		}
		if app.Tags == nil {
			app.Tags = make([]string, 0)
		}
		if app.ScreenshotURLs == nil {
			app.ScreenshotURLs = make([]string, 0)
		}
		_, _, err = db.CreateDoc(ctx, app)
		if err != nil {
			return
		}
		app.Versions = &AppVersions{
			Stable: make([]string, 0),
			Beta:   make([]string, 0),
			Dev:    make([]string, 0),
		}
		return app, true, nil
	}

	app.ID = oldApp.ID
	app.Rev = oldApp.Rev
	app.Slug = oldApp.Slug
	app.Type = oldApp.Type
	app.Editor = editor.Name()
	app.CreatedAt = oldApp.CreatedAt
	app.Versions = nil
	oldApp.Versions = nil
	oldApp.UpdatedAt = time.Time{}
	if app.Category == "" {
		app.Category = oldApp.Category
	}
	if app.Repository == "" {
		app.Repository = oldApp.Repository
	}
	if app.Name == nil {
		app.Name = oldApp.Name
	}
	if app.Developer == nil {
		app.Developer = oldApp.Developer
	}
	if app.Description == nil {
		app.Description = oldApp.Description
	}
	if app.Locales == nil {
		app.Locales = oldApp.Locales
	}
	if app.Tags == nil {
		app.Tags = oldApp.Tags
	}
	if app.ScreenshotURLs == nil {
		app.ScreenshotURLs = oldApp.ScreenshotURLs
	}
	if reflect.DeepEqual(app, oldApp) {
		return app, false, nil
	}
	app.UpdatedAt = now
	_, err = db.Put(ctx, app.ID, app)
	if err != nil {
		return
	}
	app.Versions, err = FindAppVersions(app.Slug)
	if err != nil {
		return
	}
	return app, true, nil
}

func CreateVersion(ver *Version, editor *auth.Editor) error {
	if err := IsValidVersion(ver); err != nil {
		return err
	}

	app, err := FindApp(ver.Slug)
	if err != nil {
		return err
	}
	_, err = FindVersion(ver.Slug, ver.Version)
	if err != ErrVersionNotFound {
		if err == nil {
			return ErrVersionAlreadyExists
		}
		return err
	}

	ver.Type = app.Type

	man, prefix, size, err := downloadAndCheckVersion(app, ver, editor)
	if err != nil {
		return err
	}

	ver.ID = getVersionID(app.Slug, ver.Version)
	ver.Slug = app.Slug
	ver.Editor = editor.Name()
	ver.Manifest = man
	ver.Size = size
	ver.TarPrefix = prefix
	ver.CreatedAt = time.Now().UTC()

	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return err
	}
	_, _, err = db.CreateDoc(ctx, ver)
	return err
}

func downloadAndCheckVersion(app *App, ver *Version, editor *auth.Editor) (manifestContent []byte, prefix string, size int64, err error) {
	req, err := http.NewRequest(http.MethodGet, ver.URL, nil)
	if err != nil {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Could not reach version on specified url %s: %s", ver.URL, err)
		return
	}
	res, err := versionClient.Do(req)
	if err != nil {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Could not reach version on specified url %s: %s", ver.URL, err)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Could not reach version on specified url %s: server responded with code %d",
			ver.URL, res.StatusCode)
		return
	}

	h := sha256.New()
	var reader io.Reader
	counter := &Counter{}
	reader = io.LimitReader(res.Body, maxApplicationSize)
	reader = io.TeeReader(reader, counter)
	reader = io.TeeReader(reader, h)

	contentType := res.Header.Get("Content-Type")
	switch contentType {
	case
		"application/gzip",
		"application/x-gzip",
		"application/x-tgz",
		"application/tar+gzip":
		reader, err = gzip.NewReader(reader)
		if err != nil {
			err = errshttp.NewError(http.StatusUnprocessableEntity,
				"Could not reach version on specified url %s: %s", ver.URL, err)
			return
		}
	case "application/octet-stream":
		var r io.Reader
		if r, err = gzip.NewReader(reader); err == nil {
			reader = r
		}
	}

	manName := getManifestName(ver.Type)
	tarReader := tar.NewReader(reader)
	for {
		var hdr *tar.Header
		hdr, err = tarReader.Next()
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			err = errshttp.NewError(http.StatusUnprocessableEntity,
				"Could not reach version on specified url %s: file is too big %s", ver.URL, err)
			return
		}
		if err != nil {
			err = errshttp.NewError(http.StatusUnprocessableEntity,
				"Could not reach version on specified url %s: %s", ver.URL, err)
			return
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue
		}

		name := hdr.Name

		if split := strings.SplitN(name, "/", 2); len(split) == 2 {
			if prefix == "" {
				prefix = split[0]
			} else if prefix != split[0] {
				prefix = ""
			}
			name = split[1]
		}

		if name == manName {
			manifestContent, err = ioutil.ReadAll(tarReader)
			if err != nil {
				err = errshttp.NewError(http.StatusUnprocessableEntity,
					"Could not reach version on specified url %s: %s", ver.URL, err)
				return
			}
		}
	}

	shasum, _ := hex.DecodeString(ver.Sha256)
	if !bytes.Equal(shasum, h.Sum(nil)) {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Checksum does not match the calculated one")
		return
	}

	if ver.Size > 0 && counter.Written() != ver.Size {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Size of the version does not match with the calculated one: expected %d and got %d",
			ver.Size, counter.Written())
		return
	}

	if len(manifestContent) == 0 {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Application tarball does not contain a manifest")
		return
	}

	var manifest map[string]interface{}
	if err = json.Unmarshal(manifestContent, &manifest); err != nil {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Content of the manifest is not JSON valid: %s", err)
		return
	}

	var errm error
	if editor, ok := manifest["editor"].(string); !ok ||
		strings.ToLower(editor) != strings.ToLower(app.Editor) {
		errm = multierror.Append(errm,
			fmt.Errorf("%q fied does not match (%q != %q)",
				"editor", editor, app.Editor))
	}
	{
		version, ok := manifest["version"].(string)
		var match bool
		if ok {
			// nothing
		} else if getVersionChannel(ver.Version) != Dev {
			match = ver.Version == version
		} else {
			match = versionMatch(ver.Version, version)
		}
		if !match {
			errm = multierror.Append(errm,
				fmt.Errorf("%q fied does not match (%q != %q)",
					"version", version, ver.Version))
		}
	}
	if errm != nil {
		err = errshttp.NewError(http.StatusUnprocessableEntity,
			"Content of the manifest does not match version object: %s", errm)
		return
	}

	size = counter.Written()
	return
}

func versionMatch(ver1, ver2 string) bool {
	ver1 = stripVersionSuffix(ver1)
	ver2 = stripVersionSuffix(ver2)
	v1 := strings.SplitN(ver1, ".", 3)
	v2 := strings.SplitN(ver2, ".", 3)
	if len(v1) != 3 || len(v2) != 3 {
		return false
	}
	return v1[0] == v2[0] && v1[1] == v2[1] && v1[2] == v2[2]
}

func getVersionChannel(version string) Channel {
	if strings.Contains(version, devSuffix) {
		return Dev
	}
	if strings.Contains(version, betaSuffix) {
		return Beta
	}
	return Stable
}

func stripVersionSuffix(version string) string {
	switch getVersionChannel(version) {
	case Stable:
		return version
	case Beta:
		return version[:strings.Index(version, betaSuffix)]
	case Dev:
		return version[:strings.Index(version, devSuffix)]
	}
	panic(fmt.Errorf("Unknown version suffix %q", version))
}

func getManifestName(appType string) string {
	switch appType {
	case "webapp":
		return "manifest.webapp"
	case "konnector":
		return "manifest.konnector"
	}
	panic(fmt.Errorf("Uknown application type %s", appType))
}

func strToChannel(channel string) (Channel, error) {
	switch channel {
	case "stable":
		return Stable, nil
	case "beta":
		return Beta, nil
	case "dev":
		return Dev, nil
	default:
		return Stable, ErrChannelInvalid
	}
}

func channelToStr(channel Channel) string {
	switch channel {
	case Stable:
		return "stable"
	case Beta:
		return "beta"
	case Dev:
		return "dev"
	}
	panic("Unknown channel")
}
