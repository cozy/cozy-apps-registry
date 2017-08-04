package main

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
	"strings"
	"time"

	"github.com/flimzy/kivik"
	_ "github.com/flimzy/kivik/driver/couchdb"
	_ "github.com/flimzy/kivik/driver/memory"
)

const maxManifestSize = 10 * 1024 * 1024

var client *kivik.Client
var ctx = context.Background()
var dbs = []string{appsDB, versDB, editorsDB}
var versionClient = http.Client{
	Timeout: 20 * time.Second,
}

const (
	appsDB    = "registry-apps"
	versDB    = "registry-versions"
	editorsDB = "registry-editors"
)

type Channel string

const (
	Beta   Channel = "beta"
	Stable Channel = "stable"
	Dev    Channel = "dev"
)

type App struct {
	ID          string       `json:"_id,omitempty"`
	Rev         string       `json:"_rev,omitempty"`
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	Editor      string       `json:"editor"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Repository  string       `json:"repository"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Tags        []string     `json:"tags"`
	Versions    *AppVersions `json:"versions,omitempty"`
}

type AppVersions struct {
	Stable []string `json:"stable"`
	Beta   []string `json:"beta"`
	Dev    []string `json:"dev"`
}

type Version struct {
	ID        string          `json:"_id,omitempty"`
	Rev       string          `json:"_rev,omitempty"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Version   string          `json:"version"`
	Manifest  json.RawMessage `json:"manifest"`
	CreatedAt time.Time       `json:"created_at"`
	URL       string          `json:"url"`
	Size      int64           `json:"size,string"`
	Sha256    string          `json:"sha256"`
	TarPrefix string          `json:"tar_prefix"`
}

func InitDBClient() error {
	var err error
	client, err = kivik.New(ctx, "couch", "http://localhost:5984/")
	if err != nil {
		return err
	}

	for _, dbName := range dbs {
		ok, err := client.DBExists(ctx, dbName)
		if err != nil {
			return err
		}
		if !ok {
			if err = client.CreateDB(ctx, dbName); err != nil {
				return err
			}
			fmt.Printf("Created database %s\n", dbName)
		}
	}

	return nil
}

func CreateVersion(ver *Version) error {
	app, err := FindApp(ver.Name)
	if err != nil {
		return err
	}
	if _, err = FindVersion(ver.Name, ver.Version); err != errVersionNotFound {
		if err == nil {
			return errVersionAlreadyExists
		}
		return err
	}

	man, prefix, err := downloadAndCheckVersion(app, ver)
	if err != nil {
		return err
	}

	ver.Manifest = man
	ver.TarPrefix = prefix
	ver.CreatedAt = time.Now()

	db, err := client.DB(ctx, versDB)
	if err != nil {
		return err
	}
	_, _, err = db.CreateDoc(ctx, ver)
	return err
}

func CreateApp(app *App) error {
	db, err := client.DB(ctx, appsDB)
	if err != nil {
		return err
	}
	oldApp, err := FindApp(app.Name)
	if err != nil && err != errAppNotFound {
		return err
	}
	if err == errAppNotFound {
		app.CreatedAt = time.Now()
		app.UpdatedAt = time.Now()
		app.Versions = nil
		if app.Tags == nil {
			app.Tags = make([]string, 0)
		}
		_, _, err = db.CreateDoc(ctx, app)
		return err
	}
	app.ID = oldApp.ID
	app.Rev = oldApp.Rev
	app.Type = oldApp.Type
	app.Editor = oldApp.Editor
	app.Versions = oldApp.Versions
	app.CreatedAt = oldApp.CreatedAt
	app.UpdatedAt = time.Now()
	app.Versions = nil
	if app.Category == "" {
		app.Category = oldApp.Category
	}
	if app.Repository == "" {
		app.Repository = oldApp.Repository
	}
	if app.Description == "" {
		app.Description = oldApp.Description
	}
	if app.Tags == nil {
		app.Tags = oldApp.Tags
	}
	_, err = db.Put(ctx, app.ID, app)
	return err
}

func downloadAndCheckVersion(app *App, ver *Version) (manRaw []byte, prefix string, err error) {
	req, err := http.NewRequest(http.MethodGet, ver.URL, nil)
	if err != nil {
		return
	}
	res, err := versionClient.Do(req)
	if err != nil {
		err = errVersionNotReachable
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		err = errVersionNotReachable
		return
	}

	h := sha256.New()
	var reader io.Reader
	counter := &Counter{}
	reader = io.LimitReader(res.Body, maxManifestSize)
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
			return nil, "", err
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
		if err != nil {
			return
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue
		}
		name := hdr.Name
		if name == "" {
			continue
		}
		nameSplit := strings.SplitN(name, "/", 2)
		if len(nameSplit) == 1 {
			continue
		}
		// len(nameSplit) == 2
		if prefix == "" {
			prefix = nameSplit[0]
		} else if prefix != nameSplit[0] {
			prefix = ""
		}
		if nameSplit[1] == manName {
			manRaw, err = ioutil.ReadAll(tarReader)
			if err != nil {
				return
			}
		}
	}

	if counter.Written() != ver.Size {
		err = errVersionBadSize
		return
	}

	shasum, _ := hex.DecodeString(ver.Sha256)
	if !bytes.Equal(shasum, h.Sum(nil)) {
		err = errVersionBadChecksum
		return
	}

	if len(manRaw) == 0 {
		err = errVersionNoManifest
		return
	}

	var manifest map[string]interface{}
	if err = json.Unmarshal(manRaw, &manifest); err != nil {
		err = errVersionManifestInvalid
		return
	}

	checkVals := map[string]interface{}{}
	checkVals["editor"] = app.Editor
	if getVersionChannel(ver.Version) == Stable {
		checkVals["version"] = ver.Version
	}

	if err = assertValues(manifest, checkVals); err != nil {
		err = fmt.Errorf("Content of the manifest does not match version object: %s",
			err.Error())
		return
	}

	return
}

func getVersionChannel(version string) Channel {
	if strings.Contains(version, "-dev.") {
		return Dev
	}
	if strings.Contains(version, "-beta.") {
		return Beta
	}
	return Stable
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
