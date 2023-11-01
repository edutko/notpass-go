package yubikey

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/internal/testutil"
)

func TestNewEmulator(t *testing.T) {
	yk, err := NewEmulator(map[int][]byte{1: testutil.UnHex("601598b189be7abaf383e5cb15f0429caf20da6a")})
	assert.NotNil(t, yk)
	assert.Nil(t, err)

	_, err = NewEmulator(map[int][]byte{1: {}})
	assert.NotNil(t, err)

	_, err = NewEmulator(map[int][]byte{1: bytes.Repeat([]byte{0}, 21)})
	assert.NotNil(t, err)
}

func TestEmulatedYubiKey_Serial(t *testing.T) {
	yk, _ := NewEmulator(map[int][]byte{1: testutil.UnHex("601598b189be7abaf383e5cb15f0429caf20da6a")})

	s, err := yk.Serial()

	assert.Nil(t, err)
	assert.NotEmpty(t, s)
}

func TestEmulatedYubiKey_Type(t *testing.T) {
	yk, _ := NewEmulator(map[int][]byte{1: testutil.UnHex("601598b189be7abaf383e5cb15f0429caf20da6a")})

	typ, err := yk.Type()

	assert.Nil(t, err)
	assert.NotEmpty(t, typ)
}

func TestEmulatedYubiKey_Version(t *testing.T) {
	yk, _ := NewEmulator(map[int][]byte{1: testutil.UnHex("601598b189be7abaf383e5cb15f0429caf20da6a")})

	v, err := yk.Version()

	assert.Nil(t, err)
	assert.NotEmpty(t, v)
}

func TestEmulatedYubiKey_Close(t *testing.T) {
	yk, _ := NewEmulator(map[int][]byte{1: testutil.UnHex("601598b189be7abaf383e5cb15f0429caf20da6a")})

	err := yk.Close()

	assert.Nil(t, err)
}

func TestEmulatedYubiKey_ChallengeResponseHmacSha1(t *testing.T) {
	yk, _ := NewEmulator(map[int][]byte{1: testutil.UnHex("10dcf4302055070304ea2acce986f46bb0bc1524")})

	testCases := []struct {
		challenge []byte
		expected  []byte
		expectErr bool
	}{
		{[]byte{}, testutil.UnHex("44227681484fca6f84ea45df0326c7168c58e9f2"), false},
		{[]byte{0x00}, testutil.UnHex("44227681484fca6f84ea45df0326c7168c58e9f2"), false},
		{[]byte{0x00, 0x00}, testutil.UnHex("44227681484fca6f84ea45df0326c7168c58e9f2"), false},
		{testutil.UnHex("0000000000000000"), testutil.UnHex("44227681484fca6f84ea45df0326c7168c58e9f2"), false},
		{[]byte{0x01}, testutil.UnHex("d568476a07a16f01f3dfa5893d0748e17f589c94"), false},
		{[]byte{0x01, 0x00, 0x00, 0x00}, testutil.UnHex("d568476a07a16f01f3dfa5893d0748e17f589c94"), false},
		{testutil.UnHex("0100000000000000"), testutil.UnHex("d568476a07a16f01f3dfa5893d0748e17f589c94"), false},
		{[]byte{0x01, 0x01}, testutil.UnHex("fdc00f7bce181b011b99ba8a20c06bc4301ce84d"), false},
		{[]byte("password"), testutil.UnHex("2b8de6f8bd229e9f1750a7a327c338c95c5332f4"), false},
		{[]byte("monkey12"), testutil.UnHex("6b24fda1132a406d4e1ce80fbc45adf6b350651f"), false},
		{[]byte("hunter2"), testutil.UnHex("82edc0e3e5aeaa268cbdd8ec191d962f8259daf0"), false},
		{testutil.UnHex("7f7eaad12509717fa940ab6103813bd5f5e872a8b79e848f58924804ebcf468a00e76a4e73798cfb3b5e48d555f0be428a719a4a421d8bb93967a23e08236996"), testutil.UnHex("dcee3c181222cc44c749f7aaf1c0c50192e07639"), false},
		{testutil.UnHex("7f7eaad12509717fa940ab6103813bd5f5e872a8b79e848f58924804ebcf468a00e76a4e73798cfb3b5e48d555f0be428a719a4a421d8bb93967a23e082369"), testutil.UnHex("dcee3c181222cc44c749f7aaf1c0c50192e07639"), false},

		{[]byte("this challenge is too long and should be rejected by the yubikey."), nil, true},
	}
	for _, tc := range testCases {
		actual, err := yk.ChallengeResponseHmacSha1(1, tc.challenge)
		if tc.expectErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
		assert.Equal(t, tc.expected, actual)
	}
}
