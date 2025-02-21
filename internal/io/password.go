package io

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func ReadPassword(prompt string) ([]byte, error) {
	var password []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print(prompt)
		password, err = term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, fmt.Errorf("term.ReadPassword: %w", err)
		}
		fmt.Println()
	} else {
		r := bufio.NewReader(os.Stdin)
		password, err = r.ReadBytes(byte('\n'))
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("r.ReadBytes: %w", err)
		}
	}
	return password, nil
}

func ReadOtp(prompt string) (string, error) {
	if prompt != "" {
		fmt.Printf(prompt)
	}
	r := bufio.NewReader(os.Stdin)
	otp, err := r.ReadString(byte('\n'))
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("r.ReadString: %w", err)
	}
	return strings.TrimSpace(otp), nil
}
