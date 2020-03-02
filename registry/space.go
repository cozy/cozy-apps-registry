package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/cozy/cozy-apps-registry/base"
	"github.com/go-kivik/kivik/v3"
	"github.com/labstack/echo/v4"
)

const (
	appsDBSuffix        = "apps"
	versDBSuffix        = "versions"
	pendingVersDBSuffix = "pending"
	editorsDBSuffix     = "editors"
)

var appsIndexes = map[string][]string{
	"slug":        {"slug", "editor", "type"},
	"type":        {"type", "slug", "editor"},
	"editor":      {"editor", "slug", "type"},
	"created_at":  {"created_at", "slug", "editor", "type"},
	"maintenance": {"maintenance_activated"},
}

type Space struct {
	Prefix        string
	dbApps        *kivik.DB
	dbVers        *kivik.DB
	dbPendingVers *kivik.DB
}

func NewSpace(prefix string) *Space {
	return &Space{Prefix: prefix}
}

func (c *Space) init() (err error) {
	for _, suffix := range []string{appsDBSuffix, versDBSuffix, pendingVersDBSuffix} {
		var ok bool
		dbName := c.dbName(suffix)
		ok, err = Client.DBExists(ctx, dbName)
		if err != nil {
			return
		}
		if !ok {
			fmt.Printf("Creating database %q...", dbName)
			if err = Client.CreateDB(ctx, dbName); err != nil {
				fmt.Println("failed")
				return err
			}
			fmt.Println("ok.")
		}
		db := Client.DB(context.Background(), dbName)
		if err = db.Err(); err != nil {
			return
		}
		switch suffix {
		case appsDBSuffix:
			c.dbApps = db
		case versDBSuffix:
			c.dbVers = db
		case pendingVersDBSuffix:
			c.dbPendingVers = db
		default:
			panic("unreachable")
		}
	}

	for name, fields := range appsIndexes {
		err = c.AppsDB().CreateIndex(ctx, appIndexName(name), appIndexName(name), echo.Map{"fields": fields})
		if err != nil {
			err = fmt.Errorf("Error while creating index %q: %s", appIndexName(name), err)
			return
		}
	}

	return
}

func appIndexName(name string) string {
	return "apps-index-by-" + name + "-v2"
}

// Clone takes an optionnal prefix parameter
// If empty, use the original space prefix
func (c *Space) Clone(prefix string) Space {
	if prefix == "" {
		prefix = c.Prefix
	}
	return Space{
		Prefix:        prefix,
		dbApps:        c.dbApps,
		dbVers:        c.dbVers,
		dbPendingVers: c.dbPendingVers,
	}
}

func (c *Space) AppsDB() *kivik.DB {
	return c.dbApps
}

func (c *Space) VersDB() *kivik.DB {
	return c.dbVers
}

func (c *Space) PendingVersDB() *kivik.DB {
	return c.dbPendingVers
}

func (c *Space) DBs() []*kivik.DB {
	return []*kivik.DB{c.AppsDB(), c.VersDB(), c.PendingVersDB()}
}

func (c *Space) dbName(suffix string) string {
	name := suffix
	if c.Prefix != "" {
		name = c.Prefix + "-" + name
	}
	return base.DBName(name)
}

func RemoveSpace(c *Space) error {
	// Removing the applications versions
	var cursor int = 0
	for cursor != -1 {
		next, apps, err := GetAppsList(c, &AppsListOptions{
			Limit:                200,
			Cursor:               cursor,
			LatestVersionChannel: Stable,
			VersionsChannel:      Dev,
		})

		if err != nil {
			return err
		}
		cursor = next

		for _, app := range apps { // Iterate over 200 apps
			// Skipping app with no versions
			if !app.Versions.HasVersions {
				continue
			}

			for _, version := range app.Versions.GetAll() {
				v, err := FindVersion(c, app.Slug, version)
				if err != nil {
					continue
				}
				fmt.Printf("Removing %s/%s\n", v.Slug, v.Version)
				err = v.Delete(c)
				if err != nil {
					return err
				}
			}
		}
	}

	// Removing swift container
	prefix := GetPrefixOrDefault(c)
	if err := base.Storage.EnsureDeleted(base.Prefix(prefix)); err != nil {
		return err
	}

	// Removing databases
	if err := Client.DestroyDB(ctx, c.PendingVersDB().Name()); err != nil {
		return err
	}

	if err := Client.DestroyDB(ctx, c.VersDB().Name()); err != nil {
		return err
	}

	return Client.DestroyDB(ctx, c.AppsDB().Name())
}

var Spaces map[string]*Space

func InitializeSpaces() error {
	for _, c := range Spaces {
		if err := c.init(); err != nil {
			return err
		}
	}

	return nil
}

func RegisterSpace(name string) error {
	if Spaces == nil {
		Spaces = make(map[string]*Space)
	}
	name = strings.TrimSpace(name)
	if name == base.DefaultSpacePrefix {
		name = ""
	} else {
		if !validSpaceReg.MatchString(name) {
			return fmt.Errorf("Space named %q contains invalid characters", name)
		}
	}
	if _, ok := Spaces[name]; ok {
		return fmt.Errorf("Space %q already registered", name)
	}
	c := NewSpace(name)
	Spaces[name] = c
	return c.init()
}

func GetSpacesNames() (cs []string) {
	cs = make([]string, 0, len(Spaces))
	for n := range Spaces {
		cs = append(cs, n)
	}
	return cs
}

func GetSpace(name string) (*Space, bool) {
	c, ok := Spaces[name]
	return c, ok
}

func GetPrefixOrDefault(c *Space) string {
	prefix := c.Prefix
	if prefix == "" {
		prefix = base.DefaultSpacePrefix
	}
	return prefix
}
