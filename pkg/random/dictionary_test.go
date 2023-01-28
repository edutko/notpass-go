package random

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultDictionary(t *testing.T) {
	assert.Len(t, DefaultDictionary, 8192)
}

func TestLoadDictionary(t *testing.T) {
	f, _ := os.Open("testdata/test_dictionary.txt")
	defer func() { _ = f.Close() }()

	dict := LoadDictionary(f)

	assert.Len(t, dict, 10)
	for _, word := range dict {
		assert.NotEmpty(t, word)
	}
}
