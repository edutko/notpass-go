package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_parseTimestamp(t *testing.T) {
	testCases := []struct {
		ts        []byte
		expected  time.Time
		expectErr bool
	}{
		{[]byte{0xbc, 0x95, 0x27, 0xff}, time.Date(1969, 7, 20, 20, 17, 0, 0, time.UTC).Local(), false},
		{[]byte{0, 0, 0, 0}, time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Local(), false},
		{[]byte{0xe0, 0x63, 0x71, 0x0e}, time.Date(1977, 9, 5, 12, 56, 0, 0, time.UTC).Local(), false},

		{[]byte{0x01}, time.Time{}, true},
	}

	for _, tc := range testCases {
		actual, err := ParseTimestamp(tc.ts)
		assert.Equal(t, tc.expected, actual)
		if tc.expectErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}
