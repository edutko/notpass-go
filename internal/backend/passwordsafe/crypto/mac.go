package crypto

import (
	"bytes"
	"crypto/sha1"
	"encoding"
	"hash"

	"golang.org/x/crypto/blowfish"
)

// V1V2Mac uses the database password and the random nonce (RND) to compute the value referred to
// as H(RND) in the PasswordSafe V1 and V2 specifications.
//
// See https://github.com/pwsafe/pwsafe/blob/809a171cde0c7d984d81bfc911e5c4378d47cd7b/docs/formatV1.txt
func V1V2Mac(passphrase, rnd []byte) []byte {
	iterations := 1000

	h := sha1.New()
	h.Write(rnd)
	h.Write([]byte{0x00, 0x00})
	h.Write(passphrase)

	// The only error case is invalid key length, which can't happen.
	c, _ := blowfish.NewCipher(h.Sum(nil))

	buf := byteSwapHack(rnd)
	for i := 0; i < iterations; i++ {
		c.Encrypt(buf, buf)
	}
	buf = byteSwapHack(buf)
	buf = append(buf, 0x00, 0x00)

	h = newSha1InitStateZero()
	h.Write(buf)
	return h.Sum(nil)
}

// newSha1InitStateZero replicates the behavior of reusing an instance of PasswordSafe's SHA1 class
// after SHA1::Final has been called.
//
// See https://github.com/pwsafe/pwsafe/blob/809a171cde0c7d984d81bfc911e5c4378d47cd7b/src/core/Util.cpp#L118-L158
// and https://github.com/pwsafe/pwsafe/blob/809a171cde0c7d984d81bfc911e5c4378d47cd7b/src/core/crypto/sha1.cpp#L148-L151
func newSha1InitStateZero() hash.Hash {
	h := sha1.New()
	b, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	copy(b[4:4+sha1.Size], bytes.Repeat([]byte{0x00}, sha1.Size))
	_ = h.(encoding.BinaryUnmarshaler).UnmarshalBinary(b)
	return h
}

func byteSwapHack(b []byte) []byte {
	le := make([]byte, len(b))
	le[0] = b[3]
	le[1] = b[2]
	le[2] = b[1]
	le[3] = b[0]
	le[4] = b[7]
	le[5] = b[6]
	le[6] = b[5]
	le[7] = b[4]
	return le
}
