package testutil

import (
	"encoding/hex"
)

func UnHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}
