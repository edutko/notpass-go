package twofish

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/twofish"
)

const BlockSize = twofish.BlockSize

func DecryptECB(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%twofish.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext: expected a multiple of %d", twofish.BlockSize)
	}

	c, err := twofish.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("twofish.NewCipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += twofish.BlockSize {
		c.Decrypt(plaintext[i:], ciphertext[i:])
	}

	return plaintext, nil
}

func DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != twofish.BlockSize {
		return nil, fmt.Errorf("invalid iv: expected %d bytes", twofish.BlockSize)
	}
	if len(ciphertext)%twofish.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext: expected a multiple of %d", twofish.BlockSize)
	}

	c, err := twofish.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("twofish.NewCipher: %w", err)
	}

	d := cipher.NewCBCDecrypter(c, iv)
	plaintext := make([]byte, len(ciphertext))
	d.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}
