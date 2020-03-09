package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cozy/cozy-apps-registry/auth"
	"github.com/cozy/cozy-apps-registry/config"
	"github.com/cozy/cozy-apps-registry/registry"
	"github.com/cozy/cozy-apps-registry/space"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const testSpaceName = "test-space"
const virtualSpaceName = "test-virtual"
const appKept = "kept"
const appRejected = "rejected"
const appOverwritten = "overwritten"

var server *httptest.Server

func TestListAppsFromVirtualSpace(t *testing.T) {
	u := fmt.Sprintf("%s/%s/registry/", server.URL, virtualSpaceName)
	res, err := http.Get(u)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	defer res.Body.Close()
	var body map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&body)
	assert.NoError(t, err)
	meta, ok := body["meta"].(map[string]interface{})
	assert.True(t, ok)
	assert.EqualValues(t, 2, meta["count"])
	data, ok := body["data"].([]interface{})
	assert.True(t, ok)

	var kept, over map[string]interface{}
	one := data[0].(map[string]interface{})
	two := data[1].(map[string]interface{})
	if one["slug"] == appKept {
		kept = one
		over = two
	} else {
		over = one
		kept = two
	}
	assert.Equal(t, appKept, kept["slug"])
	assert.Equal(t, appOverwritten, over["slug"])
}

func TestMain(m *testing.M) {
	config.SetDefaults()
	viper.Set("spaces", []string{"__default__", testSpaceName})
	viper.Set("virtual_spaces", map[string]interface{}{
		virtualSpaceName: map[string]interface{}{
			"source": testSpaceName,
			"filter": "reject",
			"slugs":  []interface{}{appRejected},
		},
	})

	if err := config.ReadFile("", "cozy-registry-test"); err != nil {
		fmt.Println("Cannot load test config:", err)
	}

	if err := config.SetupForTests(); err != nil {
		fmt.Println("Cannot configure the services:", err)
		os.Exit(1)
	}

	if err := config.PrepareSpaces(); err != nil {
		fmt.Println("Cannot prepare the spaces:", err)
		os.Exit(1)
	}

	if err := createApps(); err != nil {
		fmt.Println("Cannot create apps:", err)
		os.Exit(1)
	}

	router := Router()
	server = httptest.NewServer(router)

	out := m.Run()

	server.Close()

	if err := config.CleanupTests(); err != nil {
		fmt.Println("Error while cleaning:", err)
	}

	os.Exit(out)
}

func createApps() error {
	space, _ := space.GetSpace(testSpaceName)
	editor := auth.NewEditorForTest("cozy")

	apps := []string{appKept, appRejected, appOverwritten}
	for _, app := range apps {
		opts := &registry.AppOptions{
			Editor: "cozy",
			Slug:   app,
			Type:   "webapp",
		}
		if _, err := registry.CreateApp(space, opts, editor); err != nil {
			return err
		}
	}
	return nil
}
