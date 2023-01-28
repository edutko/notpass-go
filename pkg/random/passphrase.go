package random

import (
	"fmt"
	"strings"
)

func Passphrase(dictionary []string, words, digits, base int, separator string) (Value, error) {
	password := make([]string, words)
	entropy := 0.0

	for j := 0; j < words; j++ {
		v, err := Choice(dictionary)
		if err != nil {
			return Value{}, fmt.Errorf("random.Choice: %w", err)
		}
		password[j] = v.Value
		entropy += v.Entropy
	}

	if digits > 0 {
		var h Value
		var err error

		if base == 16 {
			h, err = Hex(digits)
			if err != nil {
				return Value{}, fmt.Errorf("random.Hex: %w", err)
			}
		} else if base == 10 {
			h, err = Digits(digits)
			if err != nil {
				return Value{}, fmt.Errorf("random.Digits: %w", err)
			}
		}

		password = append(password, h.Value)
		entropy += h.Entropy
	}

	return Value{strings.Join(password, separator), entropy}, nil
}
