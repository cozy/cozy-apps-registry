package asset_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	assetpkg "github.com/cozy/cozy-apps-registry/asset"
	"github.com/cozy/cozy-apps-registry/base"
	"github.com/cozy/cozy-apps-registry/config"
	_ "github.com/go-kivik/couchdb/v3" // The CouchDB driver
	"github.com/go-kivik/kivik/v3"
	"github.com/stretchr/testify/assert"
)

var testStore base.AssetStore
var testDB *kivik.DB
var shasum string

func TestAddAsset(t *testing.T) {
	content := "foobar content"

	asset := &base.Asset{
		Name:        "icon",
		AppSlug:     "app1",
		ContentType: "image/jpeg",
	}

	err := testStore.Add(asset, strings.NewReader(content), "app1")
	assert.NoError(t, err)
	shasum = asset.Shasum

	// Check CouchDB
	row := testDB.Get(context.Background(), shasum)
	err = row.ScanDoc(asset)
	assert.NoError(t, err)
	assert.Equal(t, len(asset.UsedBy), 1)

	// Check the storage
	buf, hdrs, err := base.Storage.Get(assetpkg.AssetContainerName, shasum)
	assert.NoError(t, err)
	assert.Equal(t, "foobar content", buf.String())
	assert.Equal(t, "image/jpeg", hdrs["Content-Type"])
}

func TestGetAsset(t *testing.T) {
	buf, hdrs, err := testStore.Get(shasum)
	assert.NoError(t, err)
	assert.Equal(t, "image/jpeg", hdrs["Content-Type"])
	assert.Equal(t, "foobar content", buf.String())
}

func TestAddAssetAlreadyExists(t *testing.T) {
	content := "foobar content"
	asset := &base.Asset{
		Name:        "icon",
		AppSlug:     "app1",
		ContentType: "image/jpeg",
	}

	err := testStore.Add(asset, strings.NewReader(content), "app2")
	assert.NoError(t, err)

	// Check CouchDB
	row := testDB.Get(context.Background(), shasum)
	err = row.ScanDoc(asset)
	assert.NoError(t, err)
	assert.Equal(t, len(asset.UsedBy), 2)
}

func TestAddAssetSameApp(t *testing.T) {
	content := "foobar content"
	asset := &base.Asset{
		Name:        "icon",
		AppSlug:     "app1",
		ContentType: "image/jpeg",
	}

	err := testStore.Add(asset, strings.NewReader(content), "app1")
	assert.NoError(t, err)

	// Check CouchDB
	row := testDB.Get(context.Background(), shasum)
	err = row.ScanDoc(asset)
	assert.NoError(t, err)
	assert.Equal(t, len(asset.UsedBy), 2)
}

func TestRemoveAssetRemainingOthers(t *testing.T) {
	err := testStore.Remove(shasum, "app2")
	assert.NoError(t, err)

	asset := &base.Asset{}
	row := testDB.Get(context.Background(), shasum)
	err = row.ScanDoc(asset)
	assert.NoError(t, err)

	// Assert asset in FS
	buf, _, err := base.Storage.Get(assetpkg.AssetContainerName, shasum)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf)
}

func TestRemoveAsset(t *testing.T) {
	err := testStore.Remove(shasum, "app1")
	assert.NoError(t, err)

	asset := &base.Asset{}
	row := testDB.Get(context.Background(), shasum)
	err = row.ScanDoc(asset)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, kivik.StatusCode(err))

	_, _, err = base.Storage.Get(assetpkg.AssetContainerName, shasum)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, base.ErrFileNotFound))
}

func TestComputeSource(t *testing.T) {
	assert.Equal(t, "foo/1.0.0", assetpkg.ComputeSource("__default__", "foo", "1.0.0"))
	assert.Equal(t, "myspace/foo/2.0.0", assetpkg.ComputeSource("myspace", "foo", "2.0.0"))
}

func TestMain(m *testing.M) {
	config.SetDefaults()
	if err := config.ReadFile("", "cozy-registry-test"); err != nil {
		fmt.Println("Cannot load test config:", err)
	}

	if err := config.SetupForTests(); err != nil {
		fmt.Println("Cannot configure the services:", err)
		os.Exit(1)
	}

	if err := config.PrepareSpaces(true); err != nil {
		fmt.Println("Cannot prepare the spaces:", err)
		os.Exit(1)
	}

	testStore = base.GlobalAssetStore
	testDB = testStore.GetDB()

	out := m.Run()

	if err := config.CleanupTests(); err != nil {
		fmt.Println("Error while cleaning:", err)
	}

	os.Exit(out)
}
