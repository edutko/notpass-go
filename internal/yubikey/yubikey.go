package yubikey

import (
	"fmt"
	"io"
	"time"

	"github.com/google/gousb"
)

const MaxChallengeLen = slotDataSize

type YubiKey interface {
	io.Closer
	ChallengeResponseHmacSha1(slot int, challenge []byte) ([]byte, error)
	Serial() (string, error)
	Type() (string, error)
	Version() (string, error)
}

type Info struct {
	Serial  string
	Type    string
	Version string
}

func List() ([]Info, error) {
	ctx := gousb.NewContext()
	defer func() {
		_ = ctx.Close()
	}()

	yks, err := findYubikeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("findYubikeys: %w", err)
	}

	var infos []Info
	for _, yk := range yks {
		info, err := yk.info()
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
		_ = yk.Close()
	}

	return infos, nil
}

func Open() (YubiKey, error) {
	ctx := gousb.NewContext()
	yks, err := findYubikeys(ctx)
	if err != nil {
		_ = ctx.Close()
		return nil, fmt.Errorf("findYubikeys: %w", err)
	}

	if len(yks) == 0 {
		_ = ctx.Close()
		return nil, fmt.Errorf("no Yubikeys found")
	}

	yk := yks[0]
	yk.ctx = ctx
	yk.dev.ControlTimeout = 2 * time.Second

	for i, yk := range yks {
		if i == 0 {
			continue
		}
		_ = yk.Close()
	}

	return yk, nil
}

func OpenBySerialNumber(serial string) (YubiKey, error) {
	ctx := gousb.NewContext()
	yks, err := findYubikeys(ctx)
	if err != nil {
		_ = ctx.Close()
		return nil, fmt.Errorf("findYubikeys: %w", err)
	}

	index := -1
	for i, yk := range yks {
		s, _ := yk.Serial()
		if s == serial {
			index = i
		} else {
			_ = yk.Close()
		}
	}

	if index == -1 {
		_ = ctx.Close()
		return nil, fmt.Errorf("no Yubikey with serial number %s", serial)
	}

	yk := yks[index]
	yk.ctx = ctx
	yk.dev.ControlTimeout = 2 * time.Second

	return yk, nil
}
