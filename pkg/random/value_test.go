package random

import (
	"encoding/hex"
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChoice(t *testing.T) {
	options := []string{
		"one",
		"two",
		"three",
		"four",
	}

	choice, err := Choice(options)
	assert.Nil(t, err)
	assert.Contains(t, options, choice.Value)
	assert.Equal(t, 2.0, choice.Entropy)

	choice, err = Choice([]string{})
	assert.Nil(t, err)
	assert.Zero(t, choice)
}

func TestDigits(t *testing.T) {
	testCases := []struct {
		digits          int
		expectedEntropy float64
		expectError     bool
	}{
		{0, 0, false},
		{1, math.Log2(10), false},
		{5, math.Log2(100000), false},
		{19, math.Log2(10000000000000000000), false},

		{-1, 0, true},
		{20, 0, true},
	}

	for _, tc := range testCases {
		r, err := Digits(tc.digits)
		if tc.expectError {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Len(t, r.Value, tc.digits)

			if r.Value != "" {
				_, err = strconv.ParseInt(r.Value, 10, 64)
				assert.Nil(t, err)
			}
		}
	}
}

func TestHex(t *testing.T) {
	testCases := []struct {
		length          int
		expectedEntropy float64
		expectError     bool
	}{
		{0, 0, false},
		{1, math.Log2(10), false},
		{5, math.Log2(100000), false},
		{99, math.Log2(math.Pow10(99)), false},

		{-1, 0, true},
	}

	for _, tc := range testCases {
		r, err := Hex(tc.length)
		if tc.expectError {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Len(t, r.Value, tc.length)

			if tc.length%2 == 1 {
				_, err = hex.DecodeString(r.Value + "0")
			} else {
				_, err = hex.DecodeString(r.Value)
			}
			assert.Nil(t, err)
		}
	}
}
