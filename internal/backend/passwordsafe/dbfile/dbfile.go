package dbfile

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"log"
	"os"

	"notpass-go/internal/backend/passwordsafe/crypto"
	"notpass-go/internal/backend/passwordsafe/v3"
)

func GuessFormat(dbPath, password string) (Format, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return UnknownFormat, fmt.Errorf("os.Open: %w", err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Printf("failed to close \"%s\": %v", dbPath, err)
		}
	}()

	var isV3 bool
	if isV3, err = isV3File(f); isV3 {
		return V3Format, nil
	}

	var isV1V2 bool
	if isV1V2, err = isV1V2File(f, password); isV1V2 {
		return V1V2Format, nil
	}

	return UnknownFormat, err
}

func isV1V2File(f *os.File, password string) (bool, error) {
	hdr := make([]byte, v1v2RndSize+sha1.Size)
	_, err := f.ReadAt(hdr, 0)
	if err != nil {
		return false, fmt.Errorf("f.Read: %w", err)
	}

	rnd := hdr[:v1v2RndSize]
	expectedHash := hdr[v1v2RndSize:]
	computedHash := crypto.V1V2Mac([]byte(password), rnd)

	return bytes.Equal(computedHash, expectedHash), nil
}

func isV3File(f *os.File) (bool, error) {
	magic := make([]byte, len(v3.Magic))
	_, err := f.ReadAt(magic, 0)
	if err != nil {
		return false, fmt.Errorf("f.Read: %w", err)
	}
	return bytes.Equal(magic, []byte(v3.Magic)), nil
}

type Format int

const (
	UnknownFormat Format = 0
	V1V2Format    Format = 1 // V1 and V2 formats are indistinguishable prior to decryption
	V3Format      Format = 3
)

const (
	v1v2RndSize = 8
)
