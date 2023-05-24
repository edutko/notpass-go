package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/internal/testutil"
)

func TestDeriveKeySha256(t *testing.T) {
	salt := testutil.UnHex("2da694c7adff6775c75931ca2bee48250cbf5155ac3cd590c558ebc4037b5d59")
	iterations := uint(2048)
	masterKeyHash := testutil.UnHex("2530aa9771dddf52fd79748835ce9cabc6031bcbb525dc662bb30a6d53314b22")
	expectedKey := testutil.UnHex("0f5e35994851339029a5b508cda1fa0413c07d8b68976c03513a1b240319922a")

	k, err := DeriveKeySha256([]byte("hunter2"), salt, iterations, masterKeyHash)

	assert.Nil(t, err)
	assert.Equal(t, expectedKey, k)
}

func TestDeriveKeySha256_WrongPassword(t *testing.T) {
	salt := testutil.UnHex("2da694c7adff6775c75931ca2bee48250cbf5155ac3cd590c558ebc4037b5d59")
	iterations := uint(2048)
	masterKeyHash := testutil.UnHex("2530aa9771dddf52fd79748835ce9cabc6031bcbb525dc662bb30a6d53314b22")

	k, err := DeriveKeySha256([]byte("hunter3"), salt, iterations, masterKeyHash)

	assert.NotNil(t, err)
	assert.Nil(t, k)
}
