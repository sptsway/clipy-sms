package config

import "testing"

func TestDefaultsAndClamp(t *testing.T) {
	dir := t.TempDir()

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on empty dir: %v", err)
	}
	if cfg != Default() {
		t.Fatalf("expected defaults, got %+v", cfg)
	}

	cfg.MaxMessages = 5 // below the documented minimum of 10
	cfg.Port = 99999    // out of range
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.MaxMessages != 10 {
		t.Errorf("expected MaxMessages clamped to 10, got %d", loaded.MaxMessages)
	}
	if loaded.Port != Default().Port {
		t.Errorf("expected out-of-range port reset to default, got %d", loaded.Port)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		MaxMessages:           250,
		AutoCopyNewest:        true,
		ClipboardClearSeconds: 15,
		Port:                  47821,
		LaunchAtLogin:         true,
		NotificationsEnabled:  false,
	}
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded != cfg {
		t.Fatalf("Load() = %+v, want %+v", loaded, cfg)
	}
}
