package registry

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/flimzy/kivik"
)

var validFilters = []string{
	"type",
	"editor",
	"category",
	"tags",
	"locales",
}

var validSorts = []string{
	"name",
	"type",
	"editor",
	"category",
	"created_at",
	"updated_at",
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

	doc.Versions, err = FindAppVersions(doc.Name)
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
		return nil, ErrVersionInvalid
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

func versionViewQuery(db *kivik.DB, appName, channel string, opts map[string]interface{}) (*kivik.Rows, error) {
	rows, err := db.Query(ctx, versViewDocName(appName), channel, opts)
	if err != nil {
		if kivik.StatusCode(err) == http.StatusNotFound {
			if err = createVersionsViews(appName); err != nil {
				return nil, err
			}
			return versionViewQuery(db, appName, channel, opts)
		}
		return nil, err
	}
	return rows, nil
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

	rows, err := versionViewQuery(db, appName, channelToStr(ch), map[string]interface{}{
		"limit":      1,
		"descending": true,
	})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrVersionNotFound
	}

	var latestVersion string
	if err = rows.ScanValue(&latestVersion); err != nil {
		return nil, err
	}

	row, err := db.Get(ctx, getVersionID(appName, latestVersion))
	if err != nil {
		return nil, err
	}

	var latest *Version
	if err = row.ScanDoc(&latest); err != nil {
		return nil, err
	}

	return latest, nil
}

func FindAppVersions(appName string) (*AppVersions, error) {
	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	var allVersions []string
	rows, err := versionViewQuery(db, appName, "dev", map[string]interface{}{
		"limit":        2000,
		"descending":   false,
		"include_docs": true,
	})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		if err = rows.ScanValue(&version); err != nil {
			return nil, err
		}
		allVersions = append(allVersions, version)
	}

	stable := make([]string, 0)
	beta := make([]string, 0)
	dev := make([]string, 0)

	for _, v := range allVersions {
		switch getVersionChannel(v) {
		case Stable:
			stable = append(stable, v)
			fallthrough
		case Beta:
			beta = append(beta, v)
			fallthrough
		case Dev:
			dev = append(dev, v)
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
	Cursor  int
	Sort    string
	Filters map[string]string
}

func GetAppsList(opts *AppsListOptions) (int, []*App, error) {
	db, err := client.DB(ctx, AppsDB)
	if err != nil {
		return 0, nil, err
	}

	order := "asc"
	sortField := opts.Sort
	if len(sortField) > 0 && sortField[0] == '-' {
		order = "desc"
		sortField = sortField[1:]
	}
	if sortField == "" || !stringInArray(sortField, validSorts) {
		sortField = "name"
	}
	sort := fmt.Sprintf(`{"%s": "%s"}`, sortField, order)
	if sortField != "name" {
		sort += fmt.Sprintf(`,{"name": "%s"}`, order)
	}

	selector := string(sprintfJSON(`%s: {"$gt": null}`, sortField))
	for name, val := range opts.Filters {
		if !stringInArray(name, validFilters) {
			continue
		}
		if selector != "" {
			selector += ","
		}
		switch name {
		case "tags", "locales":
			tags := strings.Split(val, ",")
			selector += string(sprintfJSON(`%s: {"$all": %s}`, name, tags))
		default:
			selector += string(sprintfJSON("%s: %s", name, val))
		}
	}

	if opts.Limit == 0 {
		opts.Limit = 50
	} else if opts.Limit > maxLimit {
		opts.Limit = maxLimit
	}

	designsCount := len(appsIndexes)
	limit := opts.Limit + designsCount + 1
	cursor := opts.Cursor
	useIndex := "apps-index-by-" + sortField
	req := sprintfJSON(`{
  "use_index": %s,
  "selector": {`+selector+`},
  "skip": %s,
  "sort": [`+sort+`],
  "limit": %s
}`, useIndex, cursor, limit)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	res := make([]*App, 0)
	for rows.Next() {
		var doc *App
		if err = rows.ScanDoc(&doc); err != nil {
			return 0, nil, err
		}
		if strings.HasPrefix(doc.ID, "_design") {
			continue
		}
		res = append(res, doc)
	}
	if len(res) == 0 {
		return -1, res, nil
	}

	if len(res) > opts.Limit {
		res = res[:opts.Limit]
		cursor += len(res)
	} else {
		// we fetch one more element so we know in this case the end of the list
		// has been reached.
		cursor = -1
	}

	for _, app := range res {
		app.Versions, err = FindAppVersions(app.Name)
		if err != nil {
			return 0, nil, err
		}
	}

	return cursor, res, nil
}
