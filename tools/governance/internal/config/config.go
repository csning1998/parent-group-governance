// Package config manages serialization of the repository .env file.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var envLineRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*"|[^\r\n]*)\s*$`)

// Env stores entries from a .env file in declaration order and serializes entries as KEY="VALUE" lines.
type Env struct {
	path   string
	order  []string
	values map[string]string
}

// Load parses the .env file at path. Missing files return an empty Env without error.
func Load(path string) (*Env, error) {
	e := &Env{path: path, values: map[string]string{}}

	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	// Closing a file opened for reading ignores any late close error.
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := envLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		e.set(m[1], decodeValue(m[2]))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return e, nil
}

// Get returns the value for key, or an empty string when key is unset.
func (e *Env) Get(key string) string {
	if e == nil || e.values == nil {
		return ""
	}
	return e.values[key]
}

// Save writes all entries atomically to path in insertion order using KEY="VALUE" format.
func (e *Env) Save() error {
	var b strings.Builder
	for _, key := range e.order {
		fmt.Fprintf(&b, "%s=%q\n", key, e.values[key])
	}

	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, e.path); err != nil {
		return fmt.Errorf("config: replace %s: %w", e.path, err)
	}
	return nil
}

// Set updates key to value in place and appends key to the write order when previously absent.
func (e *Env) Set(key, value string) {
	e.set(key, value)
}

func decodeValue(raw string) string {
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		if unquoted, err := strconv.Unquote(raw); err == nil {
			return unquoted
		}
	}
	return raw
}

func (e *Env) set(key, value string) {
	if _, exists := e.values[key]; !exists {
		e.order = append(e.order, key)
	}
	e.values[key] = value
}
