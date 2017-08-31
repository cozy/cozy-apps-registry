package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/flimzy/kivik"
)

var validFilters = []string{
	"type",
	"editor",
	"category",
	"tags",
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
	Cursor  string
	Sort    string
	Filters map[string]string
}

type Cursor struct {
	skip  int
	field string
	value string
}

func ParseCursor(c, field string) *Cursor {
	splits := strings.SplitN(c, ",", 2)
	cursor := new(Cursor)
	cursor.field = field
	if len(splits) == 2 {
		cursor.value = splits[0]
		cursor.skip, _ = strconv.Atoi(splits[1])
	} else if len(splits) == 1 {
		cursor.value = splits[0]
	}
	return cursor
}

func (c *Cursor) ToSelector() string {
	if c.value != "" {
		return string(sprintfJSON(`%s: {"$gt": %s}`, c.field, c.value))
	}
	return string(sprintfJSON(`%s: {"$gt": null}`, c.field))
}

func (c *Cursor) Skip() int {
	return c.skip
}

func GetAppsList(opts *AppsListOptions) (string, []*App, error) {
	db, err := client.DB(ctx, AppsDB)
	if err != nil {
		return "", nil, err
	}

	var descending bool
	sortField := opts.Sort
	if len(sortField) > 0 && sortField[0] == '-' {
		descending = true
		sortField = sortField[1:]
	}
	if sortField == "" || !stringInArray(sortField, validSorts) {
		sortField = "name"
	}
	sort := []string{sortField}
	if sortField != "name" {
		sort = append(sort, "name")
	}
	if descending {
		for i, field := range sort {
			sort[i] = string(sprintfJSON(`{%: "desc"}`, field))
		}
	}

	cursor := ParseCursor(opts.Cursor, sortField)

	selector := cursor.ToSelector()
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

	limit := opts.Limit + len(appsIndexes) // for _design doc

	useIndex := "apps-index-by-" + sortField
	req := sprintfJSON(`{
  "use_index": %s,
  "selector": {`+selector+`},
  "skip": %s,
  "sort": %s,
  "limit": %s
}`, useIndex, cursor.Skip(), sort, limit)
	fmt.Println("REQ", string(req))
	rows, err := db.Find(ctx, req)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()

	res := make([]*App, 0)
	for rows.Next() {
		var doc *App
		if err = rows.ScanDoc(&doc); err != nil {
			return "", nil, err
		}
		if strings.HasPrefix(doc.ID, "_design") {
			continue
		}
		res = append(res, doc)
	}
	if len(res) == 0 {
		return "", res, nil
	}

	if len(res) > opts.Limit {
		res = res[:opts.Limit]
	}

	lastApp := res[len(res)-1]
	var nextCursor string
	switch sortField {
	case "name":
		nextCursor = lastApp.Name
	case "type":
		nextCursor = lastApp.Type
	case "editor":
		nextCursor = lastApp.Editor
	case "category":
		nextCursor = lastApp.Category
	case "created_at":
		nextCursor = timeMarshal(lastApp.CreatedAt)
	case "updated_at":
		nextCursor = timeMarshal(lastApp.UpdatedAt)
	}

	return nextCursor, res, nil
}

func timeMarshal(t time.Time) string {
	b, _ := json.Marshal(t)
	return string(b[1 : len(b)-1])
}
