package util

import (
	"encoding/binary"
	"errors"
	"time"
)

func ParseTimestamp(ts []byte) (time.Time, error) {
	if len(ts) == 4 {
		return time.Unix(int64(int32LE(ts)), 0), nil
	} else {
		return time.Time{}, errors.New("expected 4 bytes for timestamp")
	}
}

func int32LE(b []byte) int32 {
	return int32(binary.LittleEndian.Uint32(b))
}
