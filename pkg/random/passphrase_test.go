package random

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPassphrase(t *testing.T) {
	dictionary := []string{
		"one",
		"two",
		"three",
		"four",
	}
	testCases := []struct {
		words           int
		digits          int
		base            int
		separator       string
		expectedEntropy float64
		expectError     bool
	}{
		{0, 0, 10, ".", 0, false},
		{1, 0, 10, "-", 2.0, false},
		{0, 6, 10, "_", math.Log2(1_000_000), false},
		{4, 5, 10, "+", 8.0 + math.Log2(100_000), false},
		{3, 5, 16, ",,,", 6.0 + 20.0, false},
	}

	for _, tc := range testCases {
		p, err := Passphrase(dictionary, tc.words, tc.digits, tc.base, tc.separator)
		assert.Nil(t, err)
		assert.True(t, closeEnough(p.Entropy, tc.expectedEntropy))

		parts := splitPassphrase(p.Value, tc.separator)
		if tc.digits == 0 {
			assert.Len(t, parts, tc.words)
		} else if tc.words == 0 {
			assert.Len(t, parts, 1)
		} else {
			assert.Len(t, parts, tc.words+1)
		}
	}
}

func closeEnough(f1, f2 float64) bool {
	return math.Abs(f1-f2) < 0.0001
}

func splitPassphrase(p, sep string) []string {
	if p == "" {
		return []string{}
	}
	return strings.Split(p, sep)
}
