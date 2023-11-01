package yubikey

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

// NewEmulator returns a software implementation of the YubiKey interface.
func NewEmulator(secrets map[int][]byte) (YubiKey, error) {
	yk := emulatedYubiKey{
		slots: make(map[int]emulatedSlot, len(secrets)),
	}
	for slot, secret := range secrets {
		if len(secret) != 20 {
			return nil, fmt.Errorf("expected secret to be exactly 20 bytes")
		}
		yk.slots[slot] = emulatedSlot{secret}
	}

	return &yk, nil
}

// ChallengeResponseHmacSha1 computes the HMAC-SHA1 of challenge using the corresponding slot's secret as the key.
//
// Given a challenge and a secret from a YubiKey HMAC challenge-response slot, YubiHmacSha1 will
// produce the same response as the YubiKey would.
func (y *emulatedYubiKey) ChallengeResponseHmacSha1(slot int, challenge []byte) ([]byte, error) {
	if len(challenge) > MaxChallengeLen {
		return nil, fmt.Errorf("expected challenge to be no more than %d bytes", MaxChallengeLen)
	}

	// If the challenge is exactly MaxChallengeLength bytes, YubiKeys assume all bytes with the
	// same value at the end are padding. If the challenge is shorter than the max length, YubiKeys
	// trim all trailing null bytes.
	if len(challenge) == MaxChallengeLen || len(challenge) > 0 && challenge[len(challenge)-1] == 0 {
		i := len(challenge) - 1
		lastByte := challenge[i]
		for ; i >= 0 && challenge[i] == lastByte; i -= 1 {
		}
		challenge = challenge[:i+1]
	}

	h := hmac.New(sha1.New, y.slots[slot].secret)
	h.Write(challenge)

	return h.Sum(nil), nil
}

func (y *emulatedYubiKey) Serial() (string, error) {
	return "000000", nil
}

func (y *emulatedYubiKey) Type() (string, error) {
	return "Emulator", nil
}

func (y *emulatedYubiKey) Version() (string, error) {
	return "0.0.0", nil
}

func (y *emulatedYubiKey) Close() error {
	return nil
}

type emulatedYubiKey struct {
	slots map[int]emulatedSlot
}

type emulatedSlot struct {
	secret []byte
}
