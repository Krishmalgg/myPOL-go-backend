package config

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// loadDotEnv copies KEY=VALUE lines from path into the process environment so
// a bare `go run ./cmd/server` gets the same settings as scripts/run-dev.ps1.
//
// A variable already set in the environment wins over the file, so the script,
// a container, or a one-off `HTTP_ADDR=:9000 go run ...` still overrides it. A
// missing file is not an error: production supplies real environment variables
// and ships no .env.
func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = unquote(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, set := os.LookupEnv(key); set {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func unquote(value string) string {
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' || first == '\'') && first == last {
			return value[1 : len(value)-1]
		}
	}
	return value
}
