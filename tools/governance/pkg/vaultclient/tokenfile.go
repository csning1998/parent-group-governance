package vaultclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const tokenFileName = ".vault-token"

// ReadTokenFile reads the Vault root token from ~/.vault-token beneath homeDir.
func ReadTokenFile(homeDir string) string {
	data, err := os.ReadFile(resolveTokenFile(homeDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// PersistTokenFile writes token to homeDir/.vault-token at 0600 through a unique temporary file.
func PersistTokenFile(homeDir, token string) error {
	return writeTokenFile(resolveTokenFile(homeDir), token)
}

// RemoveTokenFile deletes homeDir/.vault-token. An absent file counts as removed.
func RemoveTokenFile(homeDir string) error {
	err := os.Remove(resolveTokenFile(homeDir))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("vaultclient: remove %s: %w", resolveTokenFile(homeDir), err)
	}
	return nil
}

func finalizeTokenTemp(f *os.File, path, token string) error {
	tmp := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close() // Close failure is secondary to the preceding chmod error.
		return fmt.Errorf("vaultclient: chmod %s: %w", tmp, err)
	}
	if _, err := f.Write([]byte(token)); err != nil {
		_ = f.Close() // Close failure is secondary to the preceding write error.
		return fmt.Errorf("vaultclient: write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vaultclient: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("vaultclient: replace %s: %w", path, err)
	}
	return nil
}

func resolveTokenFile(homeDir string) string {
	return filepath.Join(homeDir, tokenFileName)
}

func writeTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("vaultclient: create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	if err := finalizeTokenTemp(f, path, token); err != nil {
		// Temporary file removal on finalization failure is best effort.
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
