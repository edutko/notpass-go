package v3

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/google/uuid"

	"notpass-go/internal/backend/passwordsafe/crypto/twofish"
	"notpass-go/internal/backend/passwordsafe/util"
	"notpass-go/pkg/sensitive"
	"notpass-go/pkg/vault"
)

type record struct {
	fields []field
}

type field struct {
	typ  byte
	data []byte
}

const chunkSize = twofish.BlockSize

func readRecord(r io.Reader, h hash.Hash, eor byte) (record, error) {
	var rec record
	for {
		f, err := readField(r, h)
		if err != nil {
			return record{}, fmt.Errorf("readField: %w", err)
		}
		if f.typ == eor {
			return rec, nil
		}
		rec.fields = append(rec.fields, f)
	}
}

func readField(r io.Reader, h hash.Hash) (field, error) {
	lt := make([]byte, 5)
	_, err := r.Read(lt)
	if err != nil {
		return field{}, fmt.Errorf("r.Read: %w", err)
	}

	recLen := int(binary.LittleEndian.Uint32(lt))
	f := field{
		typ: lt[4],
	}

	f.data = make([]byte, recLen)
	_, err = r.Read(f.data)
	if err != nil {
		return field{}, fmt.Errorf("r.Read: %w", err)
	}

	padLen := chunkSize - ((len(lt) + recLen) % chunkSize)
	if padLen != chunkSize {
		padding := make([]byte, padLen)
		_, err = r.Read(padding)
	}

	h.Write(f.data)

	return f, nil
}

func asTimestamp(b []byte) (vault.Value, error) {
	t, err := util.ParseTimestamp(b)
	return vault.Timestamp(t), err
}

func asUUIDString(b []byte) (vault.Value, error) {
	u, err := uuid.FromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("uuid.FromBytes: %w", err)
	}
	return vault.String(u.String()), nil
}

func asSensitiveString(b []byte) (vault.Value, error) {
	return sensitive.String(b), nil
}

func asString(b []byte) (vault.Value, error) {
	return vault.String(b), nil
}

func asHexString(b []byte) (vault.Value, error) {
	return vault.String(hex.EncodeToString(b)), nil
}
