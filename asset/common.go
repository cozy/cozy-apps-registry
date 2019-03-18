package asset

import (
	"context"
	"fmt"
	"net/url"

	"github.com/cozy/cozy-apps-registry/config"
	"github.com/go-kivik/couchdb/chttp"
	"github.com/go-kivik/kivik"
)

type AssetStorage interface {
	New(*GlobalAsset) error
	StoreAsset()
	GetAsset()
}

type GlobalAsset struct {
	ID          string   `json:"_id,omitempty"`
	Rev         string   `json:"_rev,omitempty"`
	Name        string   `json:"name"`
	MD5         string   `json:"md5"`
	AppSlug     string   `json:"appslug,omitempty"`
	ContentType string   `json:"content_type"`
	UsedBy      []string `json:"used_by"`
}

var client *kivik.Client
var ctx context.Context = context.Background()
var globalAssetStoreDB *kivik.DB

const assetStoreDBSuffix string = "assets"

// InitGlobalAssetStore initializes the global asset store database
func InitGlobalAssetStore(addr, user, pass, prefix string) (*kivik.DB, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	u.User = nil

	client, err = kivik.New("couch", u.String())
	if err != nil {
		return nil, err
	}

	if user != "" {
		err = client.Authenticate(ctx, &chttp.BasicAuth{
			Username: user,
			Password: pass,
		})
		if err != nil {
			return nil, err
		}
	}

	assetsStoreDBName := "registry-" + assetStoreDBSuffix
	exists, err := client.DBExists(ctx, assetsStoreDBName)
	if err != nil {
		return nil, err
	}
	if !exists {
		fmt.Printf("Creating database %q...", assetsStoreDBName)
		db := client.CreateDB(ctx, assetsStoreDBName)
		if err = db.Err(); err != nil {
			return nil, err
		}
		fmt.Println("ok.")
	}

	globalAssetStoreDB = client.DB(ctx, assetsStoreDBName)
	if err = globalAssetStoreDB.Err(); err != nil {
		return nil, err
	}

	// Create view for assetsDB
	_, err = globalAssetStoreDB.Put(context.Background(), "_design/by-md5", map[string]interface{}{
		"_id": "_design/by-md5",
		"views": map[string]interface{}{
			"by-md5": map[string]interface{}{
				"map": "function (doc) { emit(doc.md5); }",
			},
		},
	})
	if err != nil && kivik.StatusCode(err) != 409 { // Ignore conflicts
		return nil, err
	}

	// Create swift container for asset
	conf, err := config.GetConfig()
	sc := conf.SwiftConnection

	if err := sc.ContainerCreate(assetContainerName, nil); err != nil {
		return nil, err
	}

	return globalAssetStoreDB, nil
}
