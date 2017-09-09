package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/flimzy/kivik/driver/couchdb/chttp"
)

const (
	viewsHelpers = `
function key(version) {
  var vs = version.split(".");
  return [
    parseInt(vs[0], 10),
    parseInt(vs[1], 10),
    parseInt(vs[2], 10),
  ];
}
function getVersionChannel(version) {
  if (version.indexOf("-dev.") >= 0) {
    return "dev";
  }
  if (version.indexOf("-beta.") >= 0) {
    return "beta";
  }
  return "stable";
}`

	devView = `
function(doc) {
  ` + viewsHelpers + `
  var version = doc.version;
  var channel = getVersionChannel(version);
  if (channel == "dev") {
    emit(key(version.split("-dev.")[0]));
  } else if (channel == "beta") {
    emit(key(version.split("-beta.")[0]));
  } else {
    emit(key(version));
  }
}`

	betaView = `
function(doc) {
  ` + viewsHelpers + `
  var version = doc.version;
  var channel = getVersionChannel(version);
  if (channel == "beta") {
    emit(key(version.split("-beta.")[0]));
  } else if (channel == "stable") {
    emit(key(version));
  }
}`

	stableView = `
function(doc) {
  ` + viewsHelpers + `
  var version = doc.version;
  var channel = getVersionChannel(version);
  if (channel == "stable") {
    emit(key(version));
  }
}`
)

var versionsViews = map[string]string{
	"dev":    devView,
	"beta":   betaView,
	"stable": stableView,
}

func versViewDocName(appName string) string {
	return "versions-" + appName
}

func versViewsLazyCreate(appName string) error {
	return createViews(VersDB, versViewDocName(appName), versionsViews)
}

func createViews(dbName, ddoc string, views map[string]string) error {
	chttpClient, err := chttp.New(ctx, clientURL.String())
	if err != nil {
		return err
	}

	var object struct {
		Rev   string `json:"_rev"`
		Views map[string]struct {
			Map string `json:"map"`
		}
	}

	ddocID := fmt.Sprintf("_design/%s", url.PathEscape(ddoc))
	path := fmt.Sprintf("/%s/%s", dbName, ddocID)
	_, err = chttpClient.DoJSON(ctx, http.MethodGet, path, nil, &object)
	if err != nil {
		httperr, ok := err.(*chttp.HTTPError)
		if !ok {
			return err
		}
		if httperr.StatusCode() != 404 {
			return err
		}
	}
	if err == nil {
		var unequal bool
		for name, code := range views {
			if view, ok := object.Views[name]; !ok || view.Map != code {
				unequal = true
				break
			}
		}
		if unequal {
			return nil
		}
	}

	var viewsBodies []string
	for name, code := range views {
		viewsBodies = append(viewsBodies,
			string(sprintfJSON(`%s: {"map": %s}`, name, code)))
	}

	viewsBody := `{` + strings.Join(viewsBodies, ",") + `}`

	body, _ := json.Marshal(struct {
		ID       string          `json:"_id"`
		Rev      string          `json:"_rev,omitempty"`
		Views    json.RawMessage `json:"views"`
		Language string          `json:"language"`
	}{
		ID:       ddocID,
		Rev:      object.Rev,
		Views:    json.RawMessage(viewsBody),
		Language: "javascript",
	})

	_, err = chttpClient.DoError(ctx, http.MethodPut, path, &chttp.Options{
		Body: bytes.NewReader(body),
	})
	return err
}
