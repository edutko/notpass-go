package random

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
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
	if length < 0 || length > 19 {
		return Value{}, fmt.Errorf("length must be between 0 and 19, inclusive")
	}
	if length == 0 {
		return Value{}, nil
	}

	maxF := math.Pow10(length)
	max := big.NewInt(int64(maxF))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return Value{}, fmt.Errorf("rand.Int: %w", err)
	}

	format := fmt.Sprintf("%%0%dd", length)
	return Value{fmt.Sprintf(format, n.Int64()), math.Log2(maxF)}, nil
}
