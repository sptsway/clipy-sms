// Package config persists the daemon's non-secret settings
// (ARCHITECTURE.md §3.4's config.json). It has no crypto dependency —
// pairing/session key storage is a separate concern, left for the
// crypto/pairing implementation described in docs/CRYPTO_IMPLEMENTATION.md.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the settings shown in the SwiftUI Settings window.
type Config struct {
	MaxMessages           int  `json:"max_messages"`
	AutoCopyNewest        bool `json:"auto_copy_newest"`
	ClipboardClearSeconds int  `json:"clipboard_clear_seconds"`
	Port                  int  `json:"port"`
	LaunchAtLogin         bool `json:"launch_at_login"`
	NotificationsEnabled  bool `json:"notifications_enabled"`
}

// Default returns the documented defaults: N=100 messages, 30s clipboard
// clear, port 47820.
func Default() Config {
	return Config{
		MaxMessages:           100,
		AutoCopyNewest:        false,
		ClipboardClearSeconds: 30,
		Port:                  47820,
		LaunchAtLogin:         false,
		NotificationsEnabled:  true,
	}
}

// Clamp enforces the documented bounds (10-1000 max messages, valid port) in place.
func (c *Config) Clamp() {
	if c.MaxMessages < 10 {
		c.MaxMessages = 10
	}
	if c.MaxMessages > 1000 {
		c.MaxMessages = 1000
	}
	if c.ClipboardClearSeconds < 0 {
		c.ClipboardClearSeconds = 0
	}
	if c.Port <= 0 || c.Port > 65535 {
		c.Port = Default().Port
	}
}

func path(dir string) string { return filepath.Join(dir, "config.json") }

// Load reads config.json from dir, returning Default() if it does not exist.
func Load(dir string) (Config, error) {
	data, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	c.Clamp()
	return c, nil
}

// Save atomically writes cfg to config.json in dir, mode 0600.
func Save(dir string, cfg Config) error {
	cfg.Clamp()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path(dir), data, 0o600)
}

// writeFileAtomic writes data to a temp file in the same directory as p,
// then renames it over p, so a crash mid-write never leaves a truncated
// config file behind.
func writeFileAtomic(p string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, p)
}

// DefaultDir returns ~/Library/Application Support/OTPForwarder, creating it
// (mode 0700) if it does not already exist.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "Application Support", "OTPForwarder")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}
