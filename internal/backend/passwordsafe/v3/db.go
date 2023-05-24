package v3

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"

	"notpass-go/internal/backend/passwordsafe/crypto"
	"notpass-go/internal/backend/passwordsafe/crypto/twofish"
	"notpass-go/pkg/vault"
)

func OpenDb(dbPath, password string) (*DB, error) {
	dbf, err := readDbFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("readDbFile: %w", err)
	}

	return decrypt(dbf, password)
}

func (d *DB) Close() error {
	return nil
}

func (d *DB) UUID() uuid.UUID {
	return d.hdr.uuid
}

func (d *DB) Name() string {
	return d.hdr.name
}

func (d *DB) Description() string {
	return d.hdr.description
}

func (d *DB) Get(id string) (vault.Entry, bool) {
	r, ok := d.entries[id]
	return r, ok
}

func (d *DB) List() []vault.Entry {
	var list []vault.Entry
	for _, e := range d.entries {
		list = append(list, e.WithoutSecrets())
	}
	return list
}

func (d *DB) Find(c func(vault.Entry) bool) []vault.Entry {
	list := make([]vault.Entry, 0)
	for _, e := range d.List() {
		if c(e) {
			list = append(list, e)
		}
	}
	return list
}

func decrypt(dbf *dbFile, password string) (*DB, error) {
	masterKey, err := crypto.DeriveKeySha256([]byte(password), dbf.Salt(), dbf.Iterations(), dbf.MasterKeyHash())
	if err != nil {
		return nil, fmt.Errorf("crypto.DeriveKeySha256: %w", err)
	}

	encryptionKey, err := twofish.DecryptECB(masterKey, dbf.EncryptionKey())
	if err != nil {
		return nil, fmt.Errorf("crypto.DecryptECB(encryptionKey): %w", err)
	}

	hmacKey, err := twofish.DecryptECB(masterKey, dbf.HmacKey())
	if err != nil {
		return nil, fmt.Errorf("crypto.DecryptECB(hmacKey): %w", err)
	}

	plaintext, err := twofish.DecryptCBC(encryptionKey, dbf.Iv(), dbf.Ciphertext())
	if err != nil {
		return nil, fmt.Errorf("crypto.DecryptCBC: %w", err)
	}

	d, err := parse(plaintext, hmacKey, dbf.Hmac())
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return d, nil
}

func parse(data, hmacKey, mac []byte) (*DB, error) {

	h := hmac.New(sha256.New, hmacKey)
	r := bytes.NewReader(data)

	hdr, err := readRecord(r, h, endOfHeader)
	if err != nil {
		return nil, fmt.Errorf("readRecord: %w", err)
	}

	var records []record
	for {
		recordFields, err := readRecord(r, h, endOfRecord)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return nil, fmt.Errorf("readRecord: %w", err)
			}
		}
		records = append(records, recordFields)
	}

	s := h.Sum(nil)
	if !hmac.Equal(mac, s) {
		return nil, fmt.Errorf("failed to authenticate data")
	}

	d := &DB{
		entries: make(map[string]vault.Entry, 0),
	}
	var errs *multierror.Error

	d.hdr, err = parseHeader(hdr)
	if err != nil {
		errs = multierror.Append(errs, err)
	}

	entries, err := parseEntries(records)
	if err != nil {
		errs = multierror.Append(errs, err)
	}

	for _, e := range entries {
		d.entries[e.Id()] = e
	}

	return d, errs.ErrorOrNil()
}

type DB struct {
	hdr     header
	entries map[string]vault.Entry
}
