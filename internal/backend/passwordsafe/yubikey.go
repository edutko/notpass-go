package passwordsafe

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"unicode/utf16"

	"notpass-go/internal/yubikey"
)

func PasswordFromYubikey(userPassword string) (string, error) {
	challenge := encodeChallenge(userPassword)

	yk, err := yubikey.Open()
	if err != nil {
		return "", fmt.Errorf("yubikey.Open: %w", err)
	}
	defer func() {
		err := yk.Close()
		if err != nil {
			log.Printf("failed to close YubiKey: %v", err)
		}
	}()

	h, err := yk.ChallengeResponseHmacSha1(2, challenge)
	if err != nil {
		return "", fmt.Errorf("yubikey.ChallengeResponseHmacSha1: %w", err)
	}

	return hex.EncodeToString(h), nil
}

func PasswordFromEmulatedYubikey(credential []byte, userPassword string) (string, error) {
	challenge := encodeChallenge(userPassword)

	yk, err := yubikey.NewEmulator(map[int][]byte{2: credential})
	if err != nil {
		return "", fmt.Errorf("yubikey.NewEmulator: %w", err)
	}

	h, err := yk.ChallengeResponseHmacSha1(2, challenge)
	if err != nil {
		return "", fmt.Errorf("yubikey.ChallengeResponseHmacSha1: %w", err)
	}

	return hex.EncodeToString(h), nil
}

func encodeChallenge(challenge string) []byte {
	b := toUtf16leBytes(challenge)
	if len(b) > yubikey.MaxChallengeLen {
		return b[:yubikey.MaxChallengeLen]
	}
	return b
}

func toUtf16leBytes(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, r := range codes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}
