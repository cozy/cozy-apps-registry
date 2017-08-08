package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func stringInArray(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

func assertValues(data map[string]interface{}, check map[string]interface{}) error {
	for checkedKey, checkedVal := range check {
		actualVal, ok := data[checkedKey]
		if !ok {
			return fmt.Errorf("key %s is not present", checkedKey)
		}
		switch v := checkedVal.(type) {
		case int:
			i, ok := actualVal.(int)
			if !ok || i != v {
				return fmt.Errorf("\"%s\" field does not match (%v != %v)",
					checkedKey, i, v)
			}
		case string:
			i, ok := actualVal.(string)
			if !ok || i != v {
				return fmt.Errorf("\"%s\" field does not match (%v != %v)",
					checkedKey, i, v)
			}
		default:
			panic("Not supported type")
		}
	}
	return nil
}

func sprintfJSON(format string, a ...interface{}) json.RawMessage {
	for i, input := range a {
		b, _ := json.Marshal(input)
		a[i] = string(b)
	}
	return json.RawMessage([]byte(fmt.Sprintf(format, a...)))
}

type Counter struct {
	total int64
}

func (c *Counter) Write(p []byte) (int, error) {
	n := len(p)
	c.total += int64(n)
	return n, nil
}

func (c *Counter) Written() int64 {
	return c.total
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
