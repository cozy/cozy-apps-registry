// Package utils regroups a few functions that can be useful, but don't deserve
// their own package.
package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// AbsPath returns an absolute path.
func AbsPath(inPath string) string {
	if strings.HasPrefix(inPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		inPath = home + inPath[len("~"):]
	} else if strings.HasPrefix(inPath, "$HOME") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		inPath = home + inPath[len("$HOME"):]
	}

	if strings.HasPrefix(inPath, "$") {
		end := strings.Index(inPath, string(os.PathSeparator))
		inPath = os.Getenv(inPath[1:end]) + inPath[end:]
	}

	p, err := filepath.Abs(inPath)
	if err == nil {
		return filepath.Clean(p)
	}

	return ""
}
