package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

func DeriveKeySha256(password, salt []byte, iterations uint, masterKeyHash []byte) ([]byte, error) {
	k := sha256.Sum256(append(password, salt...))
	for i := uint(0); i < iterations; i++ {
		k = sha256.Sum256(k[:])
	}

	kh := sha256.Sum256(k[:])
	if bytes.Equal(kh[:], masterKeyHash) {
		return k[:], nil
	} else {
		return nil, fmt.Errorf("incorrect password")
	}
}
