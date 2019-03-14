package registry

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindPreviousMinorExisting(t *testing.T) {
	ver := "1.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.1.3", "1.2.3", "1.1.2"}

	v, ok := findPreviousMinor(ver, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.1.3", v)

	ver = "1.15.2"
	versions = []string{"1.5.6", "1.15.0", "25.26.27", "1.1.3", "1.2.3", "1.1.2"}

	v, ok = findPreviousMinor(ver, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.15.0", v)

}

func TestFindPreviousMinorNotExisting(t *testing.T) {
	ver := "1.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.2.3"}

	v, ok := findPreviousMinor(ver, versions)
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestFindPreviousMajorExisting(t *testing.T) {
	ver := "2.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.2.3"}

	v, ok := findPreviousMajor(ver, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.5.6", v)
}

func TestFindPreviousMajorNotExisting(t *testing.T) {
	ver := "1.2.0"
	versions := []string{"1.5.6", "25.26.27", "1.2.3"}

	v, ok := findPreviousMajor(ver, versions)
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestDownloadVersion(t *testing.T) {
	manifest := defaultManifest()
	tmpFile, shasum := generateTarball(&manifest, defaultPackage())
	defer os.Remove(tmpFile)

	opts := &VersionOptions{
		URL:     "file://" + tmpFile,
		Sha256:  shasum,
		Version: "1.0.0",
	}

	ver, att, err := DownloadVersion(opts)
	assert.NoError(t, err)
	assert.Empty(t, att)
	assert.Equal(t, "1.0.0", ver.Version)
}

func TestDownloadVersionWithoutEditor(t *testing.T) {
	// Generating a bad tarball with a missing editor in the manifest
	manifest := defaultManifest()
	manifest.Editor = ""

	tmpFile, shasum := generateTarball(&manifest, defaultPackage())
	defer os.Remove(tmpFile)

	opts := &VersionOptions{
		URL:     "file://" + tmpFile,
		Sha256:  shasum,
		Version: "1.0.0",
	}

	_, _, err := DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "\"editor\" field is empty")
}

func TestDownloadVersionWithVersionsNotMatching(t *testing.T) {
	// Generating a tarball with not matching expected and downloaded
	// versions
	manifest := defaultManifest()
	tmpFile, shasum := generateTarball(&manifest, defaultPackage())
	defer os.Remove(tmpFile)

	opts := &VersionOptions{
		URL:     "file://" + tmpFile,
		Sha256:  shasum,
		Version: "2.0.0",
	}

	_, _, err := DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestDownloadVersionBadURL(t *testing.T) {
	opts := &VersionOptions{
		URL:     "foobar",
		Sha256:  "aaa",
		Version: "2.0.0",
	}

	_, _, err := DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version on specified url foobar")
}
func TestDownloadVersioNoManifest(t *testing.T) {
	missingManifestFile, _ := ioutil.TempFile(os.TempDir(), "cozy-registry-test")
	tarWriter := tar.NewWriter(missingManifestFile)
	defer func() {
		tarWriter.Close()
		missingManifestFile.Close()
		os.Remove(missingManifestFile.Name())
	}()
	packageContent, err := json.Marshal(defaultPackage())
	packageHeaders := &tar.Header{
		Name: "package.json",
		Size: int64(len(packageContent)),
		Mode: 777,
	}

	tarWriter.WriteHeader(packageHeaders)
	tarWriter.Write(packageContent)
	tarWriter.Flush()

	h := sha256.New()
	fileContent, _ := ioutil.ReadFile(missingManifestFile.Name())
	h.Write(fileContent)

	// Generating a bad tarball with a missing editor in the manifest
	opts := &VersionOptions{
		URL:     "file://" + missingManifestFile.Name(),
		Sha256:  hex.EncodeToString(h.Sum(nil)),
		Version: "2.0.0",
	}

	_, _, err = DownloadVersion(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain a manifest")
}

// Helpers
//
func generatePackageJSON(tw *tar.Writer, content map[string]interface{}) {
	packageContent, _ := json.Marshal(content)
	packageHeaders := &tar.Header{
		Name: "package.json",
		Size: int64(len(packageContent)),
		Mode: 777,
	}

	tw.WriteHeader(packageHeaders)
	tw.Write(packageContent)
	tw.Flush()
}

func generateManifestJSON(tw *tar.Writer, manifest *Manifest) {
	manifestContent, _ := json.Marshal(manifest)
	manifestHeaders := &tar.Header{
		Name: "manifest.webapp",
		Size: int64(len(manifestContent)),
		Mode: 777,
	}

	tw.WriteHeader(manifestHeaders)
	tw.Write(manifestContent)
	tw.Flush()
}

func generateTarball(manifestContent *Manifest, packageContent map[string]interface{}) (filepath string, shasum string) {
	// Creating a test tarball
	tmpFile, _ := ioutil.TempFile(os.TempDir(), "cozy-registry-test")
	tarWriter := tar.NewWriter(tmpFile)
	defer tarWriter.Close()

	generatePackageJSON(tarWriter, packageContent)
	generateManifestJSON(tarWriter, manifestContent)

	tmpFile.Close()

	// Computes the SHA256 sum of the tarball
	h := sha256.New()
	filename := tmpFile.Name()
	fileContent, _ := ioutil.ReadFile(filename)
	h.Write(fileContent)

	return filename, hex.EncodeToString(h.Sum(nil))
}

// Return a simple validated manifest
func defaultManifest() Manifest {
	return Manifest{
		Slug:    "cozy-test-app",
		Editor:  "cozy-test-editor",
		Version: "1.0.0",
	}
}

// Return a simple validated package
func defaultPackage() map[string]interface{} {
	return map[string]interface{}{
		"version": "1.0.0",
	}
}
