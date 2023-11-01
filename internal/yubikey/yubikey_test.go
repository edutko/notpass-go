package yubikey

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const configFile = "testdata/yubikeys.json"

func init() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			skipYubikeyTestsReason = configFile + " does not exist"
		}
		panic(err)
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		panic(err)
	}

	if !cfg.Enabled {
		skipYubikeyTestsReason = "config.Enabled is false"
	}

	if v := os.Getenv("SKIP_YUBIKEY_TESTS"); v != "" && v != "0" {
		skipYubikeyTestsReason = "SKIP_YUBIKEY_TESTS environment variable is set to a non-zero value"
	}
}

func TestList(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	l, err := List()
	assert.Nil(t, err)
	assert.Len(t, l, len(cfg.YubiKeys))
}

func TestOpen(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	yk, err := Open()
	assert.Nil(t, err)
	assert.NotNil(t, yk)

	if yk != nil {
		err = yk.Close()
		assert.Nil(t, err)
	}
}

func TestOpenBySerialNumber(t *testing.T) {
	if skipYubikeyTestsReason != "" {
		t.Skipf("YubiKey tests are disabled because %s.", skipYubikeyTestsReason)
	}

	for serial := range cfg.YubiKeys {
		yk, err := OpenBySerialNumber(serial)
		assert.Nil(t, err)
		if err != nil {
			continue
		}

		s, err := yk.Serial()
		assert.Nil(t, err)
		assert.Equal(t, serial, s)

		_ = yk.Close()
	}
}

var skipYubikeyTestsReason string
var cfg testConfig

type testConfig struct {
	Enabled  bool
	YubiKeys map[string]testKeyInfo
}

type testKeyInfo struct {
	Type     string
	Version  string `json:"version"`
	Hmacsha1 struct {
		Slot   int    `json:"slot"`
		Secret string `json:"secret"`
	} `json:"hmacsha1"`
}
