package main

import (
	"sort"
	"strconv"
	"strings"
)

func FindApp(appName string) (*App, error) {
	db, err := client.DB(ctx, appsDB)
	if err != nil {
		return nil, err
	}
	req := sprintfJSON(`
{
  "selector": { "name": %s },
  "limit": 1
}`, appName)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, errAppNotFound
	}
	var doc *App
	if err = rows.ScanDoc(&doc); err != nil {
		return nil, err
	}

	doc.Versions, err = FindAppVersions(appName)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func FindVersion(appName, version string) (*Version, error) {
	db, err := client.DB(ctx, versDB)
	if err != nil {
		return nil, err
	}

	req := sprintfJSON(`
{
  "selector": { "name": %s, "version": %s },
  "limit": 1
}`, appName, version)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, errVersionNotFound
	}
	var doc *Version
	if err := rows.ScanDoc(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func FindLatestVersion(appName string, channel Channel) (*Version, error) {
	db, err := client.DB(ctx, versDB)
	if err != nil {
		return nil, err
	}

	var latest *Version
	req := sprintfJSON(`
{
  "selector": { "name": %s },
  "limit": 2000
}`, appName)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var doc *Version
		if err = rows.ScanDoc(&doc); err != nil {
			return nil, err
		}
		switch channel {
		case Stable:
			if ch := getVersionChannel(doc.Version); ch != Stable {
				continue
			}
		case Beta:
			if ch := getVersionChannel(doc.Version); ch != Stable && ch != Beta {
				continue
			}
		}
		if latest == nil || !isVersionLess(doc, latest) {
			latest = doc
		}
	}
	if latest == nil {
		return nil, errVersionNotFound
	}
	return latest, nil
}

func FindAppVersions(appName string) (*AppVersions, error) {
	db, err := client.DB(ctx, versDB)
	if err != nil {
		return nil, err
	}

	var allVersions versionsSlice

	req := sprintfJSON(`
{
  "selector": { "name": %s },
  "fields": ["version", "created_at"],
  "limit": 2000
}`, appName)

	rows, err := db.Find(ctx, req)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var doc *Version
		if err = rows.ScanDoc(&doc); err != nil {
			return nil, err
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

type versionsSlice []*Version

func (v versionsSlice) Len() int           { return len(v) }
func (v versionsSlice) Swap(i, j int)      { v[i], v[j] = v[j], v[i] }
func (v versionsSlice) Less(i, j int) bool { return isVersionLess(v[i], v[j]) }

func isVersionLess(a, b *Version) bool {
	vi, expi, err := expandVersion(a.Version)
	if err != nil {
		panic(err)
	}
	vj, expj, err := expandVersion(b.Version)
	if err != nil {
		panic(err)
	}
	if vi[0] < vj[0] {
		return true
	}
	if vi[0] == vj[0] && vi[1] < vj[1] {
		return true
	}
	if vi[0] == vj[0] && vi[1] == vj[1] && vi[2] < vj[2] {
		return true
	}
	if vi[0] == vj[0] && vi[1] == vj[1] && vi[2] == vj[2] {
		chi := getVersionChannel(a.Version)
		chj := getVersionChannel(b.Version)
		if chi == Beta && chj == Beta {
			return expi < expj
		}
		if chi != chj {
			if chi == Stable {
				return true
			}
			if chj == Stable {
				return false
			}
		}
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return false
}

func expandVersion(version string) (v [3]int, exp int, err error) {
	sp := strings.SplitN(version, ".", 3)
	if len(sp) != 3 {
		goto ERROR
	}
	v[0], err = strconv.Atoi(sp[0])
	if err != nil {
		goto ERROR
	}
	v[1], err = strconv.Atoi(sp[1])
	if err != nil {
		goto ERROR
	}
	switch getVersionChannel(version) {
	case Stable:
		v[2], err = strconv.Atoi(sp[2])
		if err != nil {
			goto ERROR
		}
	case Beta:
		sp = strings.SplitN(sp[2], "-beta.", 2)
		if len(sp) != 2 {
			goto ERROR
		}
		v[2], err = strconv.Atoi(sp[0])
		if err != nil {
			goto ERROR
		}
		exp, err = strconv.Atoi(sp[1])
		if err != nil {
			goto ERROR
		}
	case Dev:
		sp = strings.SplitN(sp[2], "-dev.", 2)
		if len(sp) != 2 {
			goto ERROR
		}
		v[2], err = strconv.Atoi(sp[0])
		if err != nil {
			goto ERROR
		}
	}
	return

ERROR:
	err = errBadVersion
	return
}
