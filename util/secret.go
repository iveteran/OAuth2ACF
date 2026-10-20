package util

import (
	"os"
	"strings"
)

func loadSecret(valueEnvironment, fileEnvironment string) string {
	value := strings.TrimSpace(os.Getenv(valueEnvironment))
	path := strings.TrimSpace(os.Getenv(fileEnvironment))
	if value != "" && path != "" {
		panic(valueEnvironment + " and " + fileEnvironment + " cannot both be set")
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(fileEnvironment + " unavailable")
		}
		value = strings.TrimSpace(string(raw))
	}
	if value == "" {
		panic(valueEnvironment + " or " + fileEnvironment + " must be set")
	}
	return value
}
