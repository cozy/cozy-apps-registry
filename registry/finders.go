package registry

import (
	"net/http"
	"sort"
	"strings"

	"github.com/flimzy/kivik"
)

var validFilters = []string{
	"type",
	"editor",
	"category",
	"tags",
}

const maxLimit = 200

func getVersionID(appName, version string) string {
	return getAppID(appName) + "-" + version
}

func getAppID(appName string) string {
	return strings.ToLower(appName)
}

func FindApp(appName string) (*App, error) {
	if !validAppNameReg.MatchString(appName) {
		return nil, ErrAppInvalid
	}
	db, err := client.DB(ctx, AppsDB)
	if err != nil {
		return nil, err
	}

	row, err := db.Get(ctx, getAppID(appName))
	if kivik.StatusCode(err) == http.StatusNotFound {
		return nil, ErrAppNotFound
	}
	if err != nil {
		return nil, err
	}

	var doc *App
	if err = row.ScanDoc(&doc); err != nil {
		return nil, err
	}

	doc.Versions, err = FindAppVersions(appName)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func FindVersion(appName, version string) (*Version, error) {
	if !validAppNameReg.MatchString(appName) {
		return nil, ErrAppInvalid
	}
	if !validVersionReg.MatchString(version) {
		return nil, ErrVersionMismatch
	}

	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	row, err := db.Get(ctx, getVersionID(appName, version))
	if kivik.StatusCode(err) == http.StatusNotFound {
		return nil, ErrVersionNotFound
	}
	if err != nil {
		return nil, err
	}

	var doc *Version
	if err := row.ScanDoc(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func FindLatestVersion(appName string, channel string) (*Version, error) {
	ch, err := strToChannel(channel)
	if err != nil {
		return nil, err
	}
	if !validAppNameReg.MatchString(appName) {
		return nil, ErrAppInvalid
	}
	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	var latest *Version
	req := sprintfJSON(`{
  "selector": { "name": %s },
  "limit": 2000
}`, appName)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var doc *Version
		if err = rows.ScanDoc(&doc); err != nil {
			return nil, err
		}
		if strings.HasPrefix(doc.ID, "_design") {
			continue
		}
		switch ch {
		case Stable:
			if c := getVersionChannel(doc.Version); c != Stable {
				continue
			}
		case Beta:
			if c := getVersionChannel(doc.Version); c != Stable && c != Beta {
				continue
			}
		}
		if latest == nil || isVersionLess(latest, doc) {
			latest = doc
		}
	}
	if latest == nil {
		return nil, ErrVersionNotFound
	}
	return latest, nil
}

func FindAppVersions(appName string) (*AppVersions, error) {
	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	var allVersions versionsSlice

	req := sprintfJSON(`{
  "selector": { "name": %s },
  "fields": ["version", "created_at"],
  "limit": 2000
}`, appName)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var doc *Version
		if err = rows.ScanDoc(&doc); err != nil {
			return nil, err
		}
		if strings.HasPrefix(doc.ID, "_design") {
			continue
		}
		allVersions = append(allVersions, doc)
	}
	sort.Sort(allVersions)

	stable := make([]string, 0)
	beta := make([]string, 0)
	dev := make([]string, 0)

	for _, v := range allVersions {
		switch getVersionChannel(v.Version) {
		case Stable:
			stable = append(stable, v.Version)
			fallthrough
		case Beta:
			beta = append(beta, v.Version)
			fallthrough
		case Dev:
			dev = append(dev, v.Version)
		}
	}

	return &AppVersions{
		Stable: stable,
		Beta:   beta,
		Dev:    dev,
	}, nil
}

type AppsListOptions struct {
	Limit   int
	Skip    int
	Filters map[string]string
}

func GetAppsList(opts *AppsListOptions) ([]*App, error) {
	db, err := client.DB(ctx, AppsDB)
	if err != nil {
		return nil, err
	}

	var selector string
	for name, val := range opts.Filters {
		if !stringInArray(name, validFilters) {
			continue
		}
		if selector != "" {
			selector += ","
		}
		selector += string(sprintfJSON("%s: %s", name, val))
	}

	if opts.Limit == 0 {
		opts.Limit = 50
	} else if opts.Limit > maxLimit {
		opts.Limit = maxLimit
	}

	req := sprintfJSON(`{
  "selector": {`+selector+`},
  "sort": [{ "name": "asc" }],
  "limit": %s,
  "skip": %s
}`, opts.Limit+1, opts.Skip)
	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := make([]*App, 0)
	for rows.Next() {
		var doc *App
		if err = rows.ScanDoc(&doc); err != nil {
			return nil, err
		}
		if strings.HasPrefix(doc.ID, "_design") {
			continue
		}
		res = append(res, doc)
	}
	return res, nil
}
