package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
			if !ok || strings.ToLower(i) != strings.ToLower(v) {
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

func UserHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func AbsPath(inPath string) string {
	inPath = strings.TrimSpace(inPath)

	if strings.HasPrefix(inPath, "~") {
		inPath = UserHomeDir() + inPath[len("~"):]
	}

	p, err := filepath.Abs(inPath)
	if err == nil {
		return filepath.Clean(p)
	}

	return ""
}
