package registry

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"

	"github.com/cozy/cozy-apps-registry/auth"
	"github.com/cozy/cozy-apps-registry/config"
)

var testSpaceName = "test-space"
var editor *auth.Editor
var app *App
var err error

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

	os.Exit(m.Run())
}
