package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func GenPSK(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("random bytes generation failed: %w", err)
	}

	return b, nil
}

func GenPSKHex(length int) (string, error) {
	b, err := GenPSK(length)
	if err != nil {
		return "", fmt.Errorf("can't generate hex key: %w", err)
	}

	return hex.EncodeToString(b), nil
}

func PSKFromHex(input string) ([]byte, error) {
	return hex.DecodeString(input)
}
