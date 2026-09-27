package main

import (
	"encoding/json"
	"os"
)

// State is fakephone's persisted identity for one pairing — everything a
// real phone app would keep after pairing, so `send` can be run repeatedly
// as a separate process invocation.
type State struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	PhonePriv  []byte `json:"phone_priv"`
	PhonePub   []byte `json:"phone_pub"`
	MacPub     []byte `json:"mac_pub"`
	KP2M       []byte `json:"k_p2m"`
	KM2P       []byte `json:"k_m2p"`
	KeyID      []byte `json:"key_id"`
	NextCtr    uint64 `json:"next_ctr"`
	DeviceName string `json:"device_name"`
}

const defaultStatePath = "fakephone-state.json"

func loadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveState(path string, s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
