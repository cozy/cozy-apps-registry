package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindPreviousMinorExisting(t *testing.T) {
	v := "1.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.1.3", "1.2.3", "1.1.2"}

	v, ok := findPreviousMinor(v, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.1.3", v)
}

func TestFindPreviousMinorNotExisting(t *testing.T) {
	v := "1.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.2.3"}

	v, ok := findPreviousMinor(v, versions)
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestFindPreviousMajorExisting(t *testing.T) {
	v := "2.2.0"
	versions := []string{"1.5.6", "0.0.1", "25.26.27", "1.2.3"}

	v, ok := findPreviousMajor(v, versions)
	assert.True(t, ok)
	assert.Equal(t, "1.5.6", v)
}

func TestFindPreviousMajorNotExisting(t *testing.T) {
	v := "1.2.0"
	versions := []string{"1.5.6", "25.26.27", "1.2.3"}

	v, ok := findPreviousMajor(v, versions)
	assert.False(t, ok)
	assert.Empty(t, v)
}
