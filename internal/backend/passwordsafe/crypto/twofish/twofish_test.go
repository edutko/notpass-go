package twofish

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/internal/testutil"
)

func TestDecryptECB(t *testing.T) {
	key := testutil.UnHex("d5791ed849e4e678b663cf4550d3a5cb50cef1dfe883e21303c77448ab12e538")
	ciphertext := testutil.UnHex("5e0c1bc065597a53c8b6c053f222288688bc688e1d1b8b3e7bf45091bb48f863")
	plaintext := testutil.UnHex("f685bc4d2639e930658d7957b34e3394e713bc1269eb06801ffc1fdd9d984f7d")

	p, err := DecryptECB(key, ciphertext)

	assert.Nil(t, err)
	assert.Equal(t, plaintext, p)
}

func TestDecryptECB_ShortCiphertext(t *testing.T) {
	key := testutil.UnHex("d5791ed849e4e678b663cf4550d3a5cb50cef1dfe883e21303c77448ab12e538")
	ciphertext := testutil.UnHex("00010203040506070809")

	p, err := DecryptECB(key, ciphertext)

	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestDecryptECB_InvalidKey(t *testing.T) {
	key := testutil.UnHex("d5791ed849e4e678b663cf4550d3a5cb50cef1dfe883e21303")
	ciphertext := testutil.UnHex("5e0c1bc065597a53c8b6c053f222288688bc688e1d1b8b3e7bf45091bb48f863")

	p, err := DecryptECB(key, ciphertext)

	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestDecryptCBC(t *testing.T) {
	key := testutil.UnHex("f685bc4d2639e930658d7957b34e3394e713bc1269eb06801ffc1fdd9d984f7d")
	iv := testutil.UnHex("0e266716df85f52c2a8e9440a999c05b")
	ciphertext := testutil.UnHex("f244f638845a2042a70d1af162edb8566ae5ea87813e9ac75969e646bce56b0d93133bb985fefc7e20c6942b76709ee69369f6ec991438b011358789618b07ec")
	plaintext := testutil.UnHex("0600000003582d57696e6710ee68095f04000000046c756b656c33f284e5c4ac0c000000064d794f594677653d357d2f40912cd5b7611fc7be03f74fe11fc332")

	p, err := DecryptCBC(key, iv, ciphertext)

	assert.Nil(t, err)
	assert.Equal(t, plaintext, p)
}

func TestDecryptCBC_ShortCiphertext(t *testing.T) {
	key := testutil.UnHex("f685bc4d2639e930658d7957b34e3394e713bc1269eb06801ffc1fdd9d984f7d")
	iv := testutil.UnHex("e664e426aee2485bb047abdead314aa7")
	ciphertext := testutil.UnHex("f244f638845a2042a70d1af162edb8566ae5ea87813e9ac759")

	p, err := DecryptCBC(key, iv, ciphertext)

	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestDecryptCBC_InvalidKey(t *testing.T) {
	key := testutil.UnHex("f685bc4d2639e930658d7957b34e3394e713bc")
	iv := testutil.UnHex("e664e426aee2485bb047abdead314aa7")
	ciphertext := testutil.UnHex("f244f638845a2042a70d1af162edb8566ae5ea87813e9ac75969e646bce56b0d")

	p, err := DecryptCBC(key, iv, ciphertext)

	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestDecryptCBC_InvalidIv(t *testing.T) {
	key := testutil.UnHex("f685bc4d2639e930658d7957b34e3394e713bc")
	iv := testutil.UnHex("e664e426aee2485bb047")
	ciphertext := testutil.UnHex("f244f638845a2042a70d1af162edb8566ae5ea87813e9ac75969e646bce56b0d")

	p, err := DecryptCBC(key, iv, ciphertext)

	assert.NotNil(t, err)
	assert.Nil(t, p)
}
