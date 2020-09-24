package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/cozy/cozy-apps-registry/asset"

	"github.com/cozy/cozy-apps-registry/space"

	"github.com/cozy/cozy-apps-registry/base"
	"github.com/go-kivik/kivik/v3"
)

func findOverwrittenVersion(s base.VirtualSpace, version *Version) (*Version, error) {
	db := s.VersionDB()
	ctx := context.Background()
	row := db.Get(ctx, version.ID)
	var t Version
	if err := row.ScanDoc(&t); err != nil {
		if kivik.StatusCode(err) == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func DeleteOverwrittenVersion(s base.VirtualSpace, version *Version) error {
	overwritten, err := findOverwrittenVersion(s, version)
	if err != nil {
		return err
	}
	if overwritten == nil {
		return nil
	}
	if err := deleteOverwrittenTarball(s, overwritten); err != nil {
		return err
	}
	db := s.VersionDB()
	_, err = db.Delete(context.Background(), overwritten.ID, overwritten.Version)
	return err
}

func storeOverwrittenTarball(s base.VirtualSpace, tarball string) (hash string, err error) {
	file, err := os.Open(tarball)
	if err != nil {
		return "", err
	}
	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	h := hasher.Sum(nil)
	hash = hex.EncodeToString(h)

	prefix := base.Prefix(s.Name)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	if err = base.Storage.EnsureExists(prefix); err != nil {
		return "", err
	}
	if err = base.Storage.Create(prefix, hash, "application/gzip", file); err != nil {
		return "", err
	}

	return hash, nil
}

func deleteOverwrittenTarball(s base.VirtualSpace, version *Version) error {
	h, ok := version.AttachmentReferences["tarball"]
	if ok {
		prefix := base.Prefix(s.Name)
		if err := base.Storage.Remove(prefix, h); err != nil {
			return err
		}
	}
	return nil
}

func getOriginalTarball(space *space.Space, version *Version) (*bytes.Buffer, error) {
	var content *bytes.Buffer
	url, err := url.Parse(version.URL)
	if err != nil {
		return nil, err
	}
	filename := filepath.Base(url.Path)
	hash, ok := version.AttachmentReferences[filename]
	if !ok {
		// Asset was not already migrate to global store
		path := filepath.Join(version.Slug, version.Version, filename)
		prefix := space.GetPrefix()
		if content, _, err = base.Storage.Get(prefix, path); err != nil {
			return nil, err
		}
	} else {
		if content, _, err = base.GlobalAssetStore.Get(hash); err != nil {
			return nil, err
		}
	}
	return content, nil
}

func generateOverwrittenTarball(version *Version, overwrite map[string]interface{}, input *bytes.Buffer) (file string, manifest map[string]interface{}, icon string, err error) {
	var newManifest map[string]interface{}

	iconFilename := manifest["icon"]
	manifestFilename := "manifest." + version.Type

	icon, iconOverwritten := overwrite["icon"].(string)
	name, nameOverwritten := overwrite["name"].(string)

	inputGzip, err := gzip.NewReader(input)
	if err != nil {
		return "", nil, "", err
	}
	defer inputGzip.Close()
	inputTar := tar.NewReader(inputGzip)

	prefix := fmt.Sprintf("%s_%s_*.tar.gz", version.Slug, version.Version)
	outputFile, err := ioutil.TempFile("", prefix)
	if err != nil {
		return "", nil, "", err
	}
	file = outputFile.Name()
	// Tricky return case from here. Never `return nil, err`.
	// File is already created on filesystem, so we need to return it in all case to be able to clean it on the caller.
	// We can'm `defer os.Remove` here, because caller need the file for storage…

	outputGzip := gzip.NewWriter(outputFile)
	if err != nil {
		return "", nil, "", err
	}
	defer func() {
		cerr := outputGzip.Close()
		if err == nil {
			err = cerr
		}
	}()

	outputTar := tar.NewWriter(outputGzip)
	defer func() {
		cerr := outputTar.Close()
		if err == nil {
			err = cerr
		}
	}()

out:
	for {
		header, err := inputTar.Next()
		switch {
		case err == io.EOF:
			break out
		case err != nil:
			return file, nil, "", err
		case header == nil:
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err = outputTar.WriteHeader(header); err != nil {
				return file, nil, "", err
			}
		case tar.TypeReg:
			switch header.Name {
			case iconFilename:
				if iconOverwritten {
					bytes := []byte(icon)
					header.Size = int64(len(bytes))
					if err = outputTar.WriteHeader(header); err != nil {
						return file, nil, "", err
					}
					if _, err := outputTar.Write(bytes); err != nil {
						return file, nil, "", err
					}
				} else {
					if err = outputTar.WriteHeader(header); err != nil {
						return file, nil, "", err
					}
					if _, err = io.Copy(outputTar, inputTar); err != nil {
						return file, nil, "", err
					}
				}
			case manifestFilename:
				if nameOverwritten {
					decoder := json.NewDecoder(inputTar)
					if err = decoder.Decode(&newManifest); err != nil {
						return file, nil, "", err
					}
					newManifest["name"] = name
					j, err := json.Marshal(newManifest)
					if err != nil {
						return file, nil, "", err
					}
					header.Size = int64(len(j))
					if err = outputTar.WriteHeader(header); err != nil {
						return file, nil, "", err
					}
					if _, err = outputTar.Write(j); err != nil {
						return file, nil, "", err
					}
				} else {
					if err = outputTar.WriteHeader(header); err != nil {
						return file, nil, "", err
					}
					if _, err = io.Copy(outputTar, inputTar); err != nil {
						return file, nil, "", err
					}
				}
			default:
				if err = outputTar.WriteHeader(header); err != nil {
					return file, nil, "", err
				}
				if _, err = io.Copy(outputTar, inputTar); err != nil {
					return file, nil, "", err
				}
			}
		}
	}

	return file, newManifest, icon, err
}

func versionOverwrittenAlreadyProcessed(versions []*Version, version *Version) bool {
	for _, curr := range versions {
		if version.Version == curr.Version {
			return true
		}
	}
	return false
}

func regenerateOverwrittenTarballs(virtualSpaceName string, appSlug string) (err error) {
	db, err := getDBForVirtualSpace(virtualSpaceName)
	if err != nil {
		return err
	}

	virtualSpace, ok := base.Config.VirtualSpaces[virtualSpaceName]
	if !ok {
		return fmt.Errorf("unable to find virtual space %s", virtualSpaceName)
	}

	spaceName := virtualSpace.Source
	s, ok := space.GetSpace(spaceName)
	if !ok {
		return fmt.Errorf("unable to find %s space", spaceName)
	}

	overwrite, err := findOverwrite(db, appSlug)
	if err != nil {
		return err
	}

	var regenerated []*Version

	for _, channel := range Channels {
		lastVersion, err := FindLatestVersion(s, appSlug, channel)
		if err != nil {
			return err
		}
		if lastVersion == nil || versionOverwrittenAlreadyProcessed(regenerated, lastVersion) {
			continue
		}

		tarball, err := getOriginalTarball(s, lastVersion)
		if err != nil {
			return err
		}
		file, manifest, icon, err := generateOverwrittenTarball(lastVersion, overwrite, tarball)
		// Tricky return, last part
		// Even in case of error, we must to take care of any file returned to be sure to erase it from the fs
		if file != "" {
			defer func() {
				cerr := os.Remove(file)
				if err == nil {
					err = cerr
				}
			}()
		}
		if err != nil {
			return err
		}

		hash, err := storeOverwrittenTarball(virtualSpace, file)
		if err != nil {
			return err
		}

		newVersion := lastVersion.Clone()
		newVersion.Rev = ""
		newVersion.AttachmentReferences = map[string]string{"tarball": hash}
		if icon != "" {
			newVersion.AttachmentReferences["icon"] = icon
		}
		j, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		newVersion.Manifest = j

		existingVersion, err := findOverwrittenVersion(virtualSpace, lastVersion)
		if err != nil {
			return err
		}
		if existingVersion != nil {
			newVersion.Rev = existingVersion.Rev
			// We already have a version, destroy the old tarball if changed
			h, ok := existingVersion.AttachmentReferences["tarball"]
			if ok && hash != h {
				prefix := base.Prefix(virtualSpace.Name)
				if err := base.Storage.Remove(prefix, h); err != nil {
					return err
				}
			}
		}

		db := virtualSpace.VersionDB()
		if _, err = db.Put(context.Background(), newVersion.ID, newVersion); err != nil {
			return err
		}

		regenerated = append(regenerated, lastVersion)
	}

	return nil
}

// FindAppOverride finds if the app have overwritten value in the virtual space
func FindAppOverride(virtualSpaceName, appSlug, name string) (*string, error) {
	db, err := getDBForVirtualSpace(virtualSpaceName)
	if err != nil {
		return nil, err
	}

	overwrite, err := findOverwrite(db, appSlug)
	if err != nil {
		return nil, err
	}

	value, ok := overwrite[name].(string)
	if !ok {
		return nil, nil
	}

	return &value, nil
}

// FindAppIconAttachmentFromOverwrite finds if the app icon was overwritten in the
// virtual space.
func FindAppIconAttachmentFromOverwrite(virtualSpaceName, appSlug, filename string) *Attachment {
	if filename != "icon" {
		return nil
	}

	shasum, err := FindAppOverride(virtualSpaceName, appSlug, filename)
	if err != nil || shasum == nil {
		return nil
	}

	content, headers, err := base.GlobalAssetStore.Get(*shasum)
	if err != nil {
		return nil
	}

	return &Attachment{
		ContentType:   headers["Content-Type"],
		Content:       content,
		Etag:          headers["Etag"],
		ContentLength: headers["Content-Length"],
	}
}

// OverwriteAppName tells that an app will have a different name in the virtual
// space.
func OverwriteAppName(virtualSpaceName, appSlug, newName string) error {
	db, err := getDBForVirtualSpace(virtualSpaceName)
	if err != nil {
		return err
	}

	overwrite, err := findOverwrite(db, appSlug)
	if err != nil {
		return err
	}
	overwrite["name"] = newName

	id := getAppID(appSlug)
	if _, err = db.Put(context.Background(), id, overwrite); err != nil {
		return err
	}

	if err := regenerateOverwrittenTarballs(virtualSpaceName, appSlug); err != nil {
		return err
	}

	return nil
}

// OverwriteAppIcon tells that an app will have a different icon in the virtual
// space.
func OverwriteAppIcon(virtualSpaceName, appSlug, file string) error {
	icon, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		cerr := icon.Close()
		if err == nil {
			err = cerr
		}
	}()

	db, err := getDBForVirtualSpace(virtualSpaceName)
	if err != nil {
		return err
	}

	overwrite, err := findOverwrite(db, appSlug)
	if err != nil {
		return err
	}

	source := asset.ComputeSource(base.Prefix(virtualSpaceName), appSlug, "*")
	a := &base.Asset{
		Name:        filepath.Base(file),
		AppSlug:     appSlug,
		ContentType: getMIMEType(file, []byte{}),
	}
	if err = base.GlobalAssetStore.Add(a, icon, source); err != nil {
		return err
	}
	overwrite["icon"] = a.Shasum

	id := getAppID(appSlug)
	_, err = db.Put(context.Background(), id, overwrite)

	if err := regenerateOverwrittenTarballs(virtualSpaceName, appSlug); err != nil {
		return err
	}

	return err
}

// ActivateMaintenanceVirtualSpace tells that an app is in maintenance in the
// given virtual space.
func ActivateMaintenanceVirtualSpace(virtualSpaceName, appSlug string, opts MaintenanceOptions) error {
	db, err := getDBForVirtualSpace(virtualSpaceName)
	if err != nil {
		return err
	}

	overwrite, err := findOverwrite(db, appSlug)
	if err != nil {
		return err
	}
	overwrite["maintenance_activated"] = true
	overwrite["maintenance_options"] = opts

	id := getAppID(appSlug)
	_, err = db.Put(context.Background(), id, overwrite)
	return err
}

// DeactivateMaintenanceVirtualSpace tells that an app is no longer in
// maintenance in the given virtual space.
func DeactivateMaintenanceVirtualSpace(virtualSpaceName, appSlug string) error {
	db, err := getDBForVirtualSpace(virtualSpaceName)
	if err != nil {
		return err
	}

	overwrite, err := findOverwrite(db, appSlug)
	if err != nil {
		return err
	}
	delete(overwrite, "maintenance_activated")
	delete(overwrite, "maintenance_options")

	id := getAppID(appSlug)
	_, err = db.Put(context.Background(), id, overwrite)
	return err
}

func getDBForVirtualSpace(virtualSpaceName string) (*kivik.DB, error) {
	dbName := base.VirtualDBName(virtualSpaceName)
	ok, err := base.DBClient.DBExists(context.Background(), dbName)
	if err != nil {
		return nil, err
	}
	if !ok {
		fmt.Printf("Creating database %q...", dbName)
		if err = base.DBClient.CreateDB(context.Background(), dbName); err != nil {
			fmt.Println("failed")
			return nil, err
		}
		fmt.Println("ok.")
	}
	db := base.DBClient.DB(context.Background(), dbName)
	if err = db.Err(); err != nil {
		return nil, err
	}
	return db, nil
}

func findOverwrite(db *kivik.DB, appSlug string) (map[string]interface{}, error) {
	if !validSlugReg.MatchString(appSlug) {
		return nil, ErrAppSlugInvalid
	}

	doc := map[string]interface{}{}
	row := db.Get(context.Background(), getAppID(appSlug))
	err := row.ScanDoc(&doc)
	if err != nil && kivik.StatusCode(err) != http.StatusNotFound {
		return nil, err
	}

	return doc, nil
}
