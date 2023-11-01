package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

// YubiHmacSha1 computes the HMAC-SHA1 of challenge using credential as the key.
//
// Given a credential from a YubiKey HMAC challenge-response slot and a challenge, YubiHmacSha1
// will produce the same response as the YubiKey would.
func YubiHmacSha1(credential, challenge []byte) ([]byte, error) {
	if len(credential) != 20 {
		return nil, fmt.Errorf("expected credential to be exactly 20 bytes")
	}

	if len(challenge) > 64 {
		return nil, fmt.Errorf("expected challenge to be no more than 64 bytes")
	}

	if len(challenge) == 64 || len(challenge) > 0 && challenge[len(challenge)-1] == 0 {
		i := len(challenge) - 1
		lastByte := challenge[i]
		for ; i >= 0 && challenge[i] == lastByte; i -= 1 {
		}
		challenge = challenge[:i+1]
	}

	h := hmac.New(sha1.New, credential)
	h.Write(challenge)
	return h.Sum(nil), nil
}
