package registry

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cozy/cozy-apps-registry/auth"
	"github.com/cozy/cozy-apps-registry/cache"
	"github.com/cozy/cozy-apps-registry/config"
	"github.com/cozy/swift/swifttest"
	"github.com/go-kivik/kivik"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const testSpaceName = "test-space"

var editor *auth.Editor
var app *App
var err error

func TestFindPreviousMinorExisting(t *testing.T) {
	ver := "1.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.1.3", "1.2.3", "1.1.2"}

	v, ok := findPreviousMinor(ver, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.1.3", v)

	ver = "1.15.2"
	versions = []string{"1.5.6", "1.15.0", "25.26.27", "1.1.3", "1.2.3", "1.1.2"}

	v, ok = findPreviousMinor(ver, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.15.0", v)

}

func TestFindPreviousMinorNotExisting(t *testing.T) {
	ver := "1.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.2.3"}

	v, ok := findPreviousMinor(ver, versions)
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestFindPreviousMajorExisting(t *testing.T) {
	ver := "2.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.2.3"}

	v, ok := findPreviousMajor(ver, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.5.6", v)
}

func TestFindPreviousMajorNotExisting(t *testing.T) {
	ver := "1.2.0"
	versions := []string{"1.5.6", "25.26.27", "1.2.3"}

	v, ok := findPreviousMajor(ver, versions)
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestDownloadVersion(t *testing.T) {
	manifest := defaultManifest()
	tmpFile, shasum, err := generateTarball(&manifest, defaultPackage())
	assert.NoError(t, err)
	defer os.Remove(tmpFile)

	opts := &VersionOptions{
		URL:     "file://" + tmpFile,
		Sha256:  shasum,
		Version: "1.0.0",
	}

	ver, att, err := DownloadVersion(opts)
	assert.NoError(t, err)
	assert.Empty(t, att)
	assert.Equal(t, "1.0.0", ver.Version)
}

func TestDownloadVersionWithoutEditor(t *testing.T) {
	// Generating a bad tarball with a missing editor in the manifest
	manifest := defaultManifest()
	manifest.Editor = ""

	tmpFile, shasum, err := generateTarball(&manifest, defaultPackage())
	assert.NoError(t, err)
	defer os.Remove(tmpFile)

	opts := &VersionOptions{
		URL:     "file://" + tmpFile,
		Sha256:  shasum,
		Version: "1.0.0",
	}

	_, _, err = DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "\"editor\" field is empty")
}

// Apps
func TestCreateApp(t *testing.T) {
	space, _ := GetSpace(testSpaceName)
	opts := &AppOptions{
		Editor: "cozy",
		Slug:   "app-test",
		Type:   "webapp",
	}

	app, err = CreateApp(space, opts, editor)
	assert.NoError(t, err)
}

func TestCreateAppBadType(t *testing.T) {
	space, _ := GetSpace(testSpaceName)
	opts := &AppOptions{
		Editor: "cozy",
		Slug:   "app-test",
		Type:   "foobar",
	}

	_, err := CreateApp(space, opts, editor)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "got type")
}

func TestDownloadVersionWithVersionsNotMatching(t *testing.T) {
	// Generating a tarball with not matching expected and downloaded
	// versions
	manifest := defaultManifest()
	tmpFile, shasum, err := generateTarball(&manifest, defaultPackage())
	assert.NoError(t, err)
	defer os.Remove(tmpFile)

	opts := &VersionOptions{
		URL:     "file://" + tmpFile,
		Sha256:  shasum,
		Version: "2.0.0",
	}

	_, _, err = DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestDownloadVersionBadURL(t *testing.T) {
	opts := &VersionOptions{
		URL:     "foobar",
		Sha256:  "aaa",
		Version: "2.0.0",
	}

	_, _, err := DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version on specified url foobar")
}

func TestCreateVersion(t *testing.T) {
	s, _ := GetSpace(testSpaceName)
	db := s.VersDB()

	// Create the test app
	testApp, err := findApp(s, "app-test")
	assert.NoError(t, err)

	ver := new(Version)
	ver.Version = "1.0.0"
	ver.Slug = "app-test"
	ver.ID = getVersionID(ver.Slug, ver.Version)
	err = createVersion(s, db, ver, []*kivik.Attachment{}, testApp, true)
	assert.NoError(t, err)
}

func TestCreateVersionBadSlug(t *testing.T) {
	// Should fail because slugs are not matching
	s, _ := GetSpace(testSpaceName)
	db := s.VersDB()

	testApp, err := findApp(s, "app-test")
	assert.NoError(t, err)

	ver := new(Version)
	ver.Slug = "foobar"
	err = createVersion(s, db, ver, []*kivik.Attachment{}, testApp, true)
	assert.Error(t, err)
	assert.Equal(t, ErrVersionSlugMismatch, err)
}

func TestCreateVersionAlreadyExists(t *testing.T) {
	// Try to create the same version, should fail because the version already
	// exists
	s, _ := GetSpace(testSpaceName)
	db := s.VersDB()

	testApp, err := findApp(s, "app-test")
	assert.NoError(t, err)

	ver := new(Version)
	ver.Version = "1.0.0"
	ver.Slug = "app-test"
	err = createVersion(s, db, ver, []*kivik.Attachment{}, testApp, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestCreateVersionWithAttachment(t *testing.T) {
	// Create a Version with attachment and check it is created
	s, _ := GetSpace(testSpaceName)
	db := s.VersDB()

	testApp, err := findApp(s, "app-test")
	assert.NoError(t, err)

	ver := new(Version)
	ver.Version = "2.0.0"
	ver.Slug = "app-test"

	att1Content := ioutil.NopCloser(strings.NewReader("this is the file content of attachment 1"))
	attachments := []*kivik.Attachment{{
		Filename:    "myfile1",
		ContentType: "text/plain",
		Content:     att1Content,
	}}

	err = createVersion(s, db, ver, attachments, testApp, true)
	assert.NoError(t, err)

	conf, err := config.GetConfig()
	sc := conf.SwiftConnection

	var buf = new(bytes.Buffer)
	prefix := GetPrefixOrDefault(s)
	fp := filepath.Join(ver.Slug, ver.Version, "myfile1")
	headers, err := sc.ObjectGet(prefix, fp, buf, false, nil)
	assert.NoError(t, err)
	assert.Equal(t, "text/plain", headers["Content-Type"])
	content, err := ioutil.ReadAll(buf)
	assert.NoError(t, err)
	assert.Equal(t, "this is the file content of attachment 1", string(content))
}

func TestDownloadVersioNoManifest(t *testing.T) {
	missingManifestFile, _ := ioutil.TempFile(os.TempDir(), "cozy-registry-test")
	tarWriter := tar.NewWriter(missingManifestFile)
	defer func() {
		tarWriter.Close()
		missingManifestFile.Close()
		os.Remove(missingManifestFile.Name())
	}()
	packageContent, err := json.Marshal(defaultPackage())
	packageHeaders := &tar.Header{
		Name: "package.json",
		Size: int64(len(packageContent)),
		Mode: 777,
	}

	err = tarWriter.WriteHeader(packageHeaders)
	assert.NoError(t, err)
	_, err = tarWriter.Write(packageContent)
	assert.NoError(t, err)
	tarWriter.Flush()

	h := sha256.New()
	fileContent, _ := ioutil.ReadFile(missingManifestFile.Name())
	_, err = h.Write(fileContent)
	assert.NoError(t, err)

	// Generating a bad tarball with a missing editor in the manifest
	opts := &VersionOptions{
		URL:     "file://" + missingManifestFile.Name(),
		Sha256:  hex.EncodeToString(h.Sum(nil)),
		Version: "2.0.0",
	}

	_, _, err = DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain a manifest")
}

func TestIsValidVersion(t *testing.T) {
	ver := &VersionOptions{
		Version: "1.0.0",
		URL:     "http://foobar.com",
		Sha256:  "D5AFEAF17396050E17C40E640DBD26DD2B103B5FBC1BB97D3306ED6254322481",
	}
	assert.NoError(t, IsValidVersion(ver))
}

func TestIsValidVersionBadVersion(t *testing.T) {
	ver := &VersionOptions{
		Version: "abc",
		URL:     "",
		Sha256:  "azerty",
	}
	res := IsValidVersion(ver)
	assert.Error(t, res)
	assert.Contains(t, res.Error(), "version", "sha256", "url")
}

func TestMain(m *testing.M) {
	var err error
	// Ensure kivik is launched
	viper.SetDefault("couchdb.url", "http://localhost:5984")
	configFile, ok := config.FindConfigFile("cozy-registry-test")
	if ok {
		viper.SetConfigFile(configFile)
		err := viper.ReadInConfig()
		if err != nil {
			fmt.Println("Errorwhile parsing viper config:", err)
		}
	}
	url := viper.GetString("couchdb.url")
	user := viper.GetString("couchdb.user")
	pass := viper.GetString("couchdb.password")
	prefix := viper.GetString("couchdb.prefix")
	editorsDB, err := InitGlobalClient(url, user, pass, prefix)
	if err != nil {
		fmt.Println("Error accessing CouchDB:", err)
	}

	// Preparing test space
	if err := RegisterSpace(testSpaceName); err != nil {
		fmt.Println("Error registering space:", err)
	}

	s, ok := GetSpace(testSpaceName)
	if ok {
		db := s.VersDB()
		if err := CreateVersionsDateView(db); err != nil {
			fmt.Println("Error creating views:", err)
		}
	}

	// Creating a default editor
	vault := auth.NewCouchDBVault(editorsDB)
	editorRegistry, err := auth.NewEditorRegistry(vault)
	if err != nil {
		fmt.Println("Error while creating editor:", err)
	}
	editor, _ = editorRegistry.CreateEditorWithoutPublicKey("cozytesteditor", true)

	// Mocking a Swift in memory for versions creation tests
	swiftSrv, err := swifttest.NewSwiftServer("localhost")
	if err != nil {
		fmt.Printf("failed to create swift server %s", err)
	}

	viper.Set("swift.username", "swifttest")
	viper.Set("swift.api_key", "swifttest")
	viper.Set("swift.auth_url", swiftSrv.AuthURL)

	_, err = config.New()
	if err != nil {
		fmt.Printf("Error while creating config %s ", err)
	}

	// Forcing in-memory cache
	viper.Set("cacheVersionsLatest", cache.NewLRUCache(256, 5*time.Minute))
	viper.Set("cacheVersionsList", cache.NewLRUCache(256, 5*time.Minute))

	out := m.Run()

	// Delete test app
	defer func() {
		appsDB := s.AppsDB()
		appsDB.Delete(ctx, app.ID, app.Rev)
	}()

	os.Exit(out)
}

// Helpers
//
func generatePackageJSON(tw *tar.Writer, content map[string]interface{}) error {
	packageContent, _ := json.Marshal(content)
	packageHeaders := &tar.Header{
		Name: "package.json",
		Size: int64(len(packageContent)),
		Mode: 777,
	}

	err := tw.WriteHeader(packageHeaders)
	if err != nil {
		return err
	}
	_, err = tw.Write(packageContent)
	if err != nil {
		return err
	}
	tw.Flush()
	return nil
}

func generateManifestJSON(tw *tar.Writer, manifest *Manifest) error {
	manifestContent, _ := json.Marshal(manifest)
	manifestHeaders := &tar.Header{
		Name: "manifest.webapp",
		Size: int64(len(manifestContent)),
		Mode: 777,
	}

	err := tw.WriteHeader(manifestHeaders)
	if err != nil {
		return err
	}
	_, err = tw.Write(manifestContent)
	if err != nil {
		return err
	}
	tw.Flush()
	return nil
}

func generateTarball(manifestContent *Manifest, packageContent map[string]interface{}) (string, string, error) {
	var err error
	// Creating a test tarball
	tmpFile, _ := ioutil.TempFile(os.TempDir(), "cozy-registry-test")
	tarWriter := tar.NewWriter(tmpFile)
	defer tarWriter.Close()

	err = generatePackageJSON(tarWriter, packageContent)
	if err != nil {
		return "", "", err
	}
	err = generateManifestJSON(tarWriter, manifestContent)
	if err != nil {
		return "", "", err
	}

	tmpFile.Close()

	// Computes the SHA256 sum of the tarball
	h := sha256.New()
	filename := tmpFile.Name()
	fileContent, _ := ioutil.ReadFile(filename)
	_, err = h.Write(fileContent)
	if err != nil {
		return "", "", err
	}

	return filename, hex.EncodeToString(h.Sum(nil)), nil
}

// Return a simple validated manifest
func defaultManifest() Manifest {
	return Manifest{
		Slug:    "cozy-test-app",
		Editor:  "cozy-test-editor",
		Version: "1.0.0",
	}
}

// Return a simple validated package
func defaultPackage() map[string]interface{} {
	return map[string]interface{}{
		"version": "1.0.0",
	}
}
