package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
)

// sendOpts controls one `fakephone send` invocation, including the
// deliberately-invalid overrides used for negative testing (PROTOCOL.md's
// validation rules: replay, counter, timestamp, tamper).
type sendOpts struct {
	sender      string
	body        string
	sim         int
	idOverride  string  // "" = generate a fresh random id
	ctrOverride *uint64 // nil = use and advance the persisted next counter
	tsOffset    int     // seconds added to now; negative = a stale message
	tamper      bool    // flips a ciphertext byte after sealing
}

// msgPlaintext mirrors PROTOCOL.md §4.3.
type msgPlaintext struct {
	ID     string `json:"id"`
	Ts     int64  `json:"ts"`
	Ctr    uint64 `json:"ctr"`
	Sender string `json:"sender"`
	Body   string `json:"body"`
	Sim    int    `json:"sim,omitempty"`
}

func doSend(opts sendOpts, statePath string) error {
	state, err := loadState(statePath)
	if err != nil {
		return fmt.Errorf("loading state (did you run `fakephone pair` first?): %w", err)
	}

	id := opts.idOverride
	if id == "" {
		idBytes, err := otpcrypto.RandomBytes(16)
		if err != nil {
			return err
		}
		id = hex.EncodeToString(idBytes)
	}

	ctr := state.NextCtr
	advanceCounter := true
	if opts.ctrOverride != nil {
		ctr = *opts.ctrOverride
		advanceCounter = false // an explicit override is for negative testing; don't let it perturb the real sequence
	}

	ts := time.Now().Add(time.Duration(opts.tsOffset) * time.Second)

	plaintext, err := json.Marshal(msgPlaintext{
		ID: id, Ts: ts.UnixMilli(), Ctr: ctr, Sender: opts.sender, Body: opts.body, Sim: opts.sim,
	})
	if err != nil {
		return err
	}

	var keyID [otpcrypto.KeyIDSize]byte
	copy(keyID[:], state.KeyID)
	envelope, err := otpcrypto.SealEnvelope(state.KP2M, keyID, plaintext)
	if err != nil {
		return err
	}
	if opts.tamper {
		envelope[len(envelope)-1] ^= 0xff
		fmt.Println("(tamper requested: flipped the last ciphertext byte)")
	}

	endpoint := fmt.Sprintf("http://%s:%d/v1/msg", state.Host, state.Port)
	resp, err := http.Post(endpoint, "application/octet-stream", bytes.NewReader(envelope))
	if err != nil {
		return fmt.Errorf("POST /v1/msg: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("rejected: HTTP %d (expected if you asked for tamper/replay/bad-ctr/stale-ts)\n", resp.StatusCode)
		return nil
	}

	ackBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading ack body: %w", err)
	}
	ackPlain, err := otpcrypto.OpenEnvelope(state.KM2P, keyID, ackBody)
	if err != nil {
		return fmt.Errorf("decrypting ack (server accepted the message but the ack didn't decrypt — that's a real bug): %w", err)
	}
	fmt.Printf("ok: id=%s ctr=%d, server ack=%s\n", id, ctr, string(ackPlain))

	if advanceCounter {
		state.NextCtr = ctr + 1
		if err := saveState(statePath, state); err != nil {
			return fmt.Errorf("saving updated counter: %w", err)
		}
	}
	return nil
}
