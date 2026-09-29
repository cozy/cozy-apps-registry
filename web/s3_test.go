package web

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cozy/cozy-apps-registry/auth"
	"github.com/cozy/cozy-apps-registry/base"
	"github.com/cozy/cozy-apps-registry/internal/testutils"
	"github.com/cozy/cozy-apps-registry/registry"
	"github.com/cozy/cozy-apps-registry/space"
	"github.com/cozy/cozy-apps-registry/storage"
	"github.com/go-kivik/kivik/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s3App is published by TestS3EndToEnd only, so that it does not interfere
// with the applications the rest of this package publishes on the in-memory
// storage.
const s3App = "s3-app"

// TestS3EndToEnd publishes an application on an S3 storage and downloads its
// icon back over HTTP.
//
// Every other test of this package runs on the in-memory storage, which
// reports no Etag. The conditional request below is therefore the only
// coverage of an Etag travelling from the storage through
// registry.FindVersionAttachment up to a 304 response.
func TestS3EndToEnd(t *testing.T) {
	client, bucket := testutils.MinioBucket(t)

	// base.Storage is read on every call, so swapping it is enough to move the
	// whole publish and download path onto S3 for the duration of this test.
	previous := base.Storage
	base.Storage = storage.NewS3(client, bucket, "registry")
	t.Cleanup(func() { base.Storage = previous })

	require.NoError(t, base.GlobalAssetStore.Prepare())

	s, ok := space.GetSpace(allAppsSpace)
	require.True(t, ok)

	editor := auth.NewEditorForTest("cozy")
	opts := &registry.AppOptions{Editor: "cozy", Slug: s3App, Type: "webapp"}
	_, err := registry.CreateApp(s, opts, editor)
	require.NoError(t, err)

	app, err := registry.FindApp(nil, s, s3App, registry.Stable)
	require.NoError(t, err)

	// The content has to be unique to this run. The asset store deduplicates
	// by shasum and only writes to the storage when CouchDB does not already
	// know the content, while MinioBucket hands out a fresh bucket every run:
	// reusing a payload another test published would skip the write and leave
	// nothing to download here.
	icon := []byte(fmt.Sprintf(
		`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><!-- %d --></svg>`,
		time.Now().UnixNano(),
	))

	version := &registry.Version{
		ID:      s3App + "-1.0.0",
		Slug:    s3App,
		Version: "1.0.0",
		URL:     "http://example.org/registry/dummy.tar.gz",
	}
	attachments := []*kivik.Attachment{{
		Filename:    "icon",
		ContentType: "image/svg+xml",
		Size:        int64(len(icon)),
		Content:     io.NopCloser(bytes.NewReader(icon)),
	}}
	require.NoError(t, registry.CreateReleaseVersion(s, version, attachments, app, false))

	u := fmt.Sprintf("%s/%s/registry/%s/1.0.0/icon", server.URL, allAppsSpace, s3App)

	res, err := http.Get(u)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, icon, body, "the icon served from S3 must be the one published")

	etag := res.Header.Get("etag")
	require.NotEmpty(t, etag, "the S3 storage must report an Etag for conditional requests")

	req, err := http.NewRequest(http.MethodGet, u, nil)
	require.NoError(t, err)
	req.Header.Set("if-none-match", etag)
	cached, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer cached.Body.Close()
	assert.Equal(t, http.StatusNotModified, cached.StatusCode)
}
