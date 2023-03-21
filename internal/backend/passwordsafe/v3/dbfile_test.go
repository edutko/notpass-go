package v3

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/internal/testutil"
)

func Test_readDbFile(t *testing.T) {
	salt := testutil.UnHex("af781eea29fb826447bc7e043b6d0c75c4133b2a3a779f72b51a8083084e857e")
	iterations := uint(1353000)
	masterKeyHash := testutil.UnHex("c100e1168e276dc05d4e2f336fef5510006e815ee296c2485fb4f5af75cf9069")
	encryptionKey := testutil.UnHex("6a5c99c629d4c95b04bfdbd7e8ebda434cbff8fb4805297c1013ad362b7ec101")
	hmacKey := testutil.UnHex("fe591ea2d1b994708c5cd6da4a0541e2c302b71dfccc9324274af7b4bf4ff00c")
	iv := testutil.UnHex("a2be453213088b5f86adab5538902bda")
	hmac := testutil.UnHex("59d5bfcbbd9e31cafb86a0b71a51fe3630ffb36bd09d76f5b64168501e4a30e4")
	ciphertextLen := 3472

	dbf, err := readDbFile("testdata/test.psafe3")

	assert.Nil(t, err)
	assert.Equal(t, []byte(tag), dbf.tag[:])
	assert.Equal(t, []byte(eof), dbf.eof[:])

	assert.Equal(t, salt, dbf.Salt())
	assert.Equal(t, iterations, dbf.Iterations())
	assert.Equal(t, masterKeyHash, dbf.MasterKeyHash())
	assert.Equal(t, encryptionKey, dbf.EncryptionKey())
	assert.Equal(t, hmacKey, dbf.HmacKey())
	assert.Equal(t, iv, dbf.Iv())
	assert.Equal(t, hmac, dbf.Hmac())

	assert.Len(t, dbf.Ciphertext(), ciphertextLen)
}

func Test_readDbFile_errors(t *testing.T) {
	testCases := []struct {
		dbFile string
	}{
		{"testdata/nonexistent"},
		{"testdata/test-bad-tag.psafe3"},
		{"testdata/test-bad-eof.psafe3"},
	}

	for _, tc := range testCases {
		dbf, err := readDbFile(tc.dbFile)
		assert.NotNil(t, err)
		assert.Nil(t, dbf)
	}
}
