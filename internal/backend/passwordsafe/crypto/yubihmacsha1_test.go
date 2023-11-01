package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYubiHmacSha1(t *testing.T) {
	credential := mustDecodeHex("10dcf4302055070304ea2acce986f46bb0bc1524")
	testCases := []struct {
		challenge []byte
		expected  []byte
	}{
		{[]byte{}, mustDecodeHex("44227681484fca6f84ea45df0326c7168c58e9f2")},
		{[]byte{0x00}, mustDecodeHex("44227681484fca6f84ea45df0326c7168c58e9f2")},
		{[]byte{0x00, 0x00}, mustDecodeHex("44227681484fca6f84ea45df0326c7168c58e9f2")},
		{mustDecodeHex("0000000000000000"), mustDecodeHex("44227681484fca6f84ea45df0326c7168c58e9f2")},
		{[]byte{0x01}, mustDecodeHex("d568476a07a16f01f3dfa5893d0748e17f589c94")},
		{[]byte{0x01, 0x00, 0x00, 0x00}, mustDecodeHex("d568476a07a16f01f3dfa5893d0748e17f589c94")},
		{mustDecodeHex("0100000000000000"), mustDecodeHex("d568476a07a16f01f3dfa5893d0748e17f589c94")},
		{[]byte{0x01, 0x01}, mustDecodeHex("fdc00f7bce181b011b99ba8a20c06bc4301ce84d")},
		{[]byte("password"), mustDecodeHex("2b8de6f8bd229e9f1750a7a327c338c95c5332f4")},
		{[]byte("monkey12"), mustDecodeHex("6b24fda1132a406d4e1ce80fbc45adf6b350651f")},
		{[]byte("hunter2"), mustDecodeHex("82edc0e3e5aeaa268cbdd8ec191d962f8259daf0")},
		{mustDecodeHex("7f7eaad12509717fa940ab6103813bd5f5e872a8b79e848f58924804ebcf468a00e76a4e73798cfb3b5e48d555f0be428a719a4a421d8bb93967a23e08236996"), mustDecodeHex("dcee3c181222cc44c749f7aaf1c0c50192e07639")},
		{mustDecodeHex("7f7eaad12509717fa940ab6103813bd5f5e872a8b79e848f58924804ebcf468a00e76a4e73798cfb3b5e48d555f0be428a719a4a421d8bb93967a23e082369"), mustDecodeHex("dcee3c181222cc44c749f7aaf1c0c50192e07639")},
	}
	for _, tc := range testCases {
		actual, err := YubiHmacSha1(credential, tc.challenge)
		assert.Nil(t, err)
		assert.Equal(t, tc.expected, actual)
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
