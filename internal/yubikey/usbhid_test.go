package yubikey

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/internal/testutil"
)

func TestUsbHidYubiKey_Serial(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	yk, err := Open()
	if yk == nil {
		t.Fatalf(err.Error())
	}
	defer func() { _ = yk.Close() }()

	serial, err := yk.Serial()

	_, found := cfg.YubiKeys[serial]
	assert.Nil(t, err)
	assert.True(t, found)
}

func TestUsbHidYubiKey_Type(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	yk, err := Open()
	if yk == nil {
		t.Fatalf(err.Error())
	}
	defer func() { _ = yk.Close() }()
	serial, _ := yk.Serial()
	info, found := cfg.YubiKeys[serial]
	if !found {
		t.Fatalf("YubiKey with serial number %s is not listed in %s", serial, configFile)
	}

	typ, err := yk.Type()
	assert.Nil(t, err)
	assert.Equal(t, info.Type, typ)
}

func TestUsbHidYubiKey_Version(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	yk, err := Open()
	if yk == nil {
		t.Fatalf(err.Error())
	}
	defer func() { _ = yk.Close() }()
	serial, _ := yk.Serial()
	info, found := cfg.YubiKeys[serial]
	if !found {
		t.Fatalf("YubiKey with serial number %s is not listed in %s", serial, configFile)
	}

	version, err := yk.Version()
	assert.Nil(t, err)
	assert.Equal(t, info.Version, version)
}

func TestUsbHidYubikey_ChallengeResponseHmacSha1(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	yk, err := Open()
	if yk == nil {
		t.Fatalf(err.Error())
	}
	defer func() { _ = yk.Close() }()
	serial, _ := yk.Serial()
	info, found := cfg.YubiKeys[serial]
	if !found {
		t.Fatalf("YubiKey with serial number %s is not listed in %s", serial, configFile)
	}

	ykEm, err := NewEmulator(map[int][]byte{info.Hmacsha1.Slot: testutil.UnHex(info.Hmacsha1.Secret)})
	assert.Nil(t, err)
	challenge := make([]byte, 64)
	_, err = rand.Read(challenge)
	assert.Nil(t, err)
	expected, err := ykEm.ChallengeResponseHmacSha1(info.Hmacsha1.Slot, challenge)
	assert.Nil(t, err)

	actual, err := yk.ChallengeResponseHmacSha1(info.Hmacsha1.Slot, challenge)

	assert.Nil(t, err)
	assert.Len(t, actual, 20)
	assert.Equal(t, expected, actual)
}
