package yubikey

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_crc16(t *testing.T) {
	testCases := []struct {
		data []byte
		crc  uint16
	}{
		{[]byte(""), 0xffff},
		{[]byte("this is a test"), 0xcb0d},
		{[]byte("aaaa"), 0xd7ed},
		{[]byte("aaaaa"), 0x4eb3},
		{[]byte("aaaaaa"), 0xf5d1},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 0x9dfd},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.crc, crc16(tc.data))
	}
}
