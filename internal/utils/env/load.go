package env

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// LoadDotEnv reads KEY=VALUE entries from the given file and sets them into
// the process environment only if the key is not already defined.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		idx := strings.IndexRune(line, '=')
		if idx <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		if key == "" {
			continue
		}

		if _, exists := os.LookupEnv(key); exists {
			continue
		}

		raw := strings.TrimSpace(line[idx+1:])
		value := parseEnvValue(raw)
		_ = os.Setenv(key, value)
	}

	return scanner.Err()
}

func parseEnvValue(raw string) string {
	if raw == "" {
		return ""
	}

	// Try quoted string semantics first.
	if (strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`)) ||
		(strings.HasPrefix(raw, `'`) && strings.HasSuffix(raw, `'`)) {
		if unquoted, err := strconv.Unquote(raw); err == nil {
			return unquoted
		}
		return raw[1 : len(raw)-1]
	}

	return raw
}
