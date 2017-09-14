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
	"slug",
	"type",
	"editor",
	"category",
	"created_at",
	"updated_at",
}

const maxLimit = 200

func getVersionID(appSlug, version string) string {
	return getAppID(appSlug) + "-" + version
}

func getAppID(appSlug string) string {
	return strings.ToLower(appSlug)
}

func FindApp(appSlug string) (*App, error) {
	if !validSlugReg.MatchString(appSlug) {
		return nil, ErrAppInvalid
	}
	db, err := client.DB(ctx, AppsDB)
	if err != nil {
		return nil, err
	}

	row, err := db.Get(ctx, getAppID(appSlug))
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

	doc.Versions, err = FindAppVersions(doc.Slug)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func FindVersion(appSlug, version string) (*Version, error) {
	if !validSlugReg.MatchString(appSlug) {
		return nil, ErrAppInvalid
	}
	if !validVersionReg.MatchString(version) {
		return nil, ErrVersionInvalid
	}

	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	row, err := db.Get(ctx, getVersionID(appSlug, version))
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

func versionViewQuery(db *kivik.DB, appSlug, channel string, opts map[string]interface{}) (*kivik.Rows, error) {
	rows, err := db.Query(ctx, versViewDocName(appSlug), channel, opts)
	if err != nil {
		if kivik.StatusCode(err) == http.StatusNotFound {
			if err = createVersionsViews(appSlug); err != nil {
				return nil, err
			}
			return versionViewQuery(db, appSlug, channel, opts)
		}
		return nil, err
	}
	return rows, nil
}

func FindLatestVersion(appSlug string, channel string) (*Version, error) {
	ch, err := strToChannel(channel)
	if err != nil {
		return nil, err
	}
	if !validSlugReg.MatchString(appSlug) {
		return nil, ErrAppInvalid
	}
	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	rows, err := versionViewQuery(db, appSlug, channelToStr(ch), map[string]interface{}{
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

	row, err := db.Get(ctx, getVersionID(appSlug, latestVersion))
	if err != nil {
		return nil, err
	}

	var latest *Version
	if err = row.ScanDoc(&latest); err != nil {
		return nil, err
	}

	return latest, nil
}

func FindAppVersions(appSlug string) (*AppVersions, error) {
	db, err := client.DB(ctx, VersDB)
	if err != nil {
		return nil, err
	}

	var allVersions []string
	rows, err := versionViewQuery(db, appSlug, "dev", map[string]interface{}{
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
		sortField = "slug"
	}
	sort := fmt.Sprintf(`{"%s": "%s"}`, sortField, order)
	if sortField != "slug" {
		sort += fmt.Sprintf(`,{"slug": "%s"}`, order)
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
		app.Versions, err = FindAppVersions(app.Slug)
		if err != nil {
			return 0, nil, err
		}
	}

	return cursor, res, nil
}
