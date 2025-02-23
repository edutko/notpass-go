package random

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
)

type Value struct {
	Value   string
	Entropy float64
}

func Choice(options []string) (Value, error) {
	if len(options) == 0 {
		return Value{}, nil
	}

	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(options))))
	if err != nil {
		return Value{}, fmt.Errorf("rand.Int: %w", err)
	}

	return Value{options[i.Int64()], math.Log2(float64(len(options)))}, nil
}

func Hex(length int) (Value, error) {
	if length < 0 {
		return Value{}, fmt.Errorf("length must be non-negative")
	}
	if length == 0 {
		return Value{}, nil
	}

	b := make([]byte, (length+1)/2)
	_, err := rand.Read(b)
	if err != nil {
		return Value{}, fmt.Errorf("rand.Int: %w", err)
	}

	return Value{hex.EncodeToString(b)[:length], float64(4 * length)}, nil
}

func Digits(length int) (Value, error) {
	if length < 0 || length > 99 {
		return Value{}, fmt.Errorf("length must be between 0 and 99, inclusive")
	}
	if length == 0 {
		return Value{}, nil
	}

	exclusiveMax, _ := big.NewInt(0).SetString("1"+strings.Repeat("0", length), 10)
	n, err := rand.Int(rand.Reader, exclusiveMax)
	if err != nil {
		return Value{}, fmt.Errorf("rand.Int: %w", err)
	}

	format := fmt.Sprintf("%%0%dd", length)
	return Value{fmt.Sprintf(format, n.Int64()), float64(length) / math.Log10(2)}, nil
}
