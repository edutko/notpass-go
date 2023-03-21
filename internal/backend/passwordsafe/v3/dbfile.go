package v3

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
)

const Magic = tag

// dbFile represents a PasswordSafe V3 database file
//
// Format: A V3 format PasswordSafe is structured as follows:
// TAG|SALT|ITER|H(P')|B1|B2|B3|B4|IV|HDR|R1|R2|...|Rn|EOF|HMAC
//
// https://github.com/pwsafe/pwsafe/blob/809a171cde0c7d984d81bfc911e5c4378d47cd7b/docs/formatV3.txt
type dbFile struct {
	tag        [len(tag)]byte
	salt       [32]byte
	iter       [4]byte // unsigned little endian
	hp         [sha256.Size]byte
	b1         [16]byte
	b2         [16]byte
	b3         [16]byte
	b4         [16]byte
	iv         [16]byte
	ciphertext []byte
	eof        [len(eof)]byte
	hmac       [sha256.Size]byte
}

func readDbFile(dbPath string) (*dbFile, error) {
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile: %w", err)
	}

	dbf := dbFile{
		ciphertext: make([]byte, len(data)-prefixLen-suffixLen),
	}

	r := bytes.NewReader(data)
	_, _ = r.Read(dbf.tag[:])
	_, _ = r.Read(dbf.salt[:])
	_, _ = r.Read(dbf.iter[:])
	_, _ = r.Read(dbf.hp[:])
	_, _ = r.Read(dbf.b1[:])
	_, _ = r.Read(dbf.b2[:])
	_, _ = r.Read(dbf.b3[:])
	_, _ = r.Read(dbf.b4[:])
	_, _ = r.Read(dbf.iv[:])
	_, _ = r.Read(dbf.ciphertext)
	_, _ = r.Read(dbf.eof[:])
	_, _ = r.Read(dbf.hmac[:])

	if !bytes.Equal(dbf.tag[:], []byte(tag)) {
		return nil, fmt.Errorf("invalid PasswordSafe db file (expected tag: %s)", tag)
	}

	if !bytes.Equal(dbf.eof[:], []byte(eof)) {
		return nil, fmt.Errorf("invalid PasswordSafe db file (expected eof: %s)", eof)
	}

	return &dbf, nil
}

func (d *dbFile) Salt() []byte {
	return d.salt[:]
}

func (d *dbFile) Iterations() uint {
	return uint(binary.LittleEndian.Uint32(d.iter[:]))
}

func (d *dbFile) MasterKeyHash() []byte {
	return d.hp[:]
}

func (d *dbFile) EncryptionKey() []byte {
	return append(d.b1[:], d.b2[:]...)
}

func (d *dbFile) HmacKey() []byte {
	return append(d.b3[:], d.b4[:]...)
}

func (d *dbFile) Iv() []byte {
	return d.iv[:]
}

func (d *dbFile) Hmac() []byte {
	return d.hmac[:]
}

func (d *dbFile) Ciphertext() []byte {
	return d.ciphertext
}

const (
	prefixLen = len(tag) + 32 + 4 + sha256.Size + 16*4 + 16
	suffixLen = len(eof) + sha256.Size
	tag       = "PWS3"
	eof       = "PWS3-EOFPWS3-EOF"
)
