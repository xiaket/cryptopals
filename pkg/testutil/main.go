package testutil

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func VerifyPrefixAndLength(str string, prefix string, length int, test *testing.T) {
	assert.True(test, strings.HasPrefix(str, prefix), "Incorrect result: prefix %s, want: %s.", str[:len(prefix)], prefix)
	assert.True(test, len(str) == length, "Incorrect result: length %d, want: %d.", len(str), length)
}
