package dbfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGuessFormat(t *testing.T) {
	testCases := []struct {
		name      string
		dbFile    string
		password  string
		expected  Format
		expectErr bool
	}{
		{"non-existent file", "testdata/does-not-exist", "hunter2", UnknownFormat, true},
		{"empty file", "testdata/empty.dat", "hunter2", UnknownFormat, true},
		{"bad password", "testdata/test-v1.dat", "wrongpassword", UnknownFormat, false},
		{"v1 db", "testdata/test-v1.dat", "hunter2", V1V2Format, false},
		{"v2 db", "testdata/test-v2.dat", "hunter2", V1V2Format, false},
		{"v3 db", "testdata/test-v3.psafe3", "hunter2", V3Format, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := GuessFormat(tc.dbFile, tc.password)
			if tc.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tc.expected, actual)
		})
	}
}
