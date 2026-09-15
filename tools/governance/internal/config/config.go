// Package config manages serialization of the repository .env file.
package config

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Env represents an environment configuration file structure, preserving key declaration
// order via a slice and mapping key-value pairs using double-quoted KEY="VALUE" formatting.
type Env struct {
	path   string
	order  []string
	values map[string]string
}

var envLineRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*"|[^\r\n]*)\s*$`)

func decodeValue(raw string) string {
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		if unquoted, err := strconv.Unquote(raw); err == nil {
			return unquoted
		}
	}
	return raw
}

// Load parses the environment configuration file at path. Non-existent target paths return
// an initialized, empty Env structure without error.
func Load(path string) (*Env, error) {
	e := &Env{path: path, values: map[string]string{}}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return e, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
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

func (e *Env) set(key, value string) {
	if _, exists := e.values[key]; !exists {
		e.order = append(e.order, key)
	}
	e.values[key] = value
}

// Get returns the value associated with key, or an empty string if undefined.
func (e *Env) Get(key string) string {
	if e == nil || e.values == nil {
		return ""
	}
	return e.values[key]
}

// Set mutates key to value in place, inserting key into ordering sequence if previously undefined.
func (e *Env) Set(key, value string) {
	e.set(key, value)
}

// Save atomically writes all key-value pairs back to path in insertion order using KEY="VALUE" format.
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

var envRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Environ expands variable references within key-value pairs against local configuration keys and
// host environment variables, returning a formatted KEY=value slice.
func (e *Env) Environ() []string {
	resolved := map[string]string{}
	out := make([]string, 0, len(e.order))

	for _, key := range e.order {
		expanded := envRefRe.ReplaceAllStringFunc(e.values[key], func(ref string) string {
			refKey := envRefRe.FindStringSubmatch(ref)[1]
			if v, ok := resolved[refKey]; ok {
				return v
			}
			return os.Getenv(refKey)
		})
		resolved[key] = expanded
		out = append(out, key+"="+expanded)
	}
	return out
}
