package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
)

// pairRequestBody/pairResponseBody mirror PROTOCOL.md §3.3/§3.4 exactly —
// duplicated here rather than imported from internal/server, since a real
// phone app (this stands in for one) has no access to the daemon's Go
// packages and must build these from the spec alone.
type pairRequestBody struct {
	V          int    `json:"v"`
	PhonePub   string `json:"phone_pub"`
	DeviceName string `json:"device_name"`
	Mac        string `json:"mac"`
}

type pairResponseBody struct {
	OK      bool   `json:"ok"`
	Confirm string `json:"confirm"`
}

func doPair(uri, deviceName, statePath string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("parsing pairing URI: %w", err)
	}
	if u.Scheme != "otpfwd" {
		return fmt.Errorf("not an otpfwd:// pairing URI: %q", uri)
	}
	q := u.Query()
	if q.Get("v") != "1" {
		return fmt.Errorf("unsupported pairing version %q", q.Get("v"))
	}

	macPub, err := base64.RawURLEncoding.DecodeString(q.Get("mac_pub"))
	if err != nil {
		return fmt.Errorf("decoding mac_pub: %w", err)
	}
	token, err := base64.RawURLEncoding.DecodeString(q.Get("token"))
	if err != nil {
		return fmt.Errorf("decoding token: %w", err)
	}
	port, err := strconv.Atoi(q.Get("port"))
	if err != nil {
		return fmt.Errorf("parsing port: %w", err)
	}
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil {
		return fmt.Errorf("parsing exp: %w", err)
	}
	if time.Now().Unix() > exp {
		return fmt.Errorf("pairing window already expired (exp=%d)", exp)
	}
	hosts := strings.Split(q.Get("hosts"), ",")

	phonePriv, err := otpcrypto.GenerateMacKeypair() // any P-256 keypair; name is mac-side-centric but the function is generic
	if err != nil {
		return fmt.Errorf("generating phone keypair: %w", err)
	}
	phonePub := phonePriv.PublicKey().Bytes()
	mac := otpcrypto.PairingMAC(token, macPub, phonePub)

	reqBody, err := json.Marshal(pairRequestBody{
		V:          1,
		PhonePub:   base64.RawURLEncoding.EncodeToString(phonePub),
		DeviceName: deviceName,
		Mac:        base64.RawURLEncoding.EncodeToString(mac),
	})
	if err != nil {
		return err
	}

	workingHost, respBody, err := tryHosts(hosts, port, reqBody)
	if err != nil {
		return err
	}

	confirm, err := base64.RawURLEncoding.DecodeString(respBody.Confirm)
	if err != nil {
		return fmt.Errorf("decoding confirm: %w", err)
	}

	macPubKey, err := otpcrypto.ParsePublicKey(macPub)
	if err != nil {
		return fmt.Errorf("parsing mac_pub: %w", err)
	}
	ikm, err := phonePriv.ECDH(macPubKey)
	if err != nil {
		return fmt.Errorf("ECDH: %w", err)
	}
	keys, err := otpcrypto.DeriveSessionKeysFromIKM(ikm, token, macPub, phonePub)
	if err != nil {
		return fmt.Errorf("deriving session keys: %w", err)
	}
	if !bytes.Equal(confirm, otpcrypto.ConfirmMAC(keys.KM2P[:])) {
		return fmt.Errorf("confirm mismatch: the Mac's response doesn't match our derived key — pairing not trustworthy, aborting")
	}

	return saveState(statePath, &State{
		Host:       workingHost,
		Port:       port,
		PhonePriv:  phonePriv.Bytes(),
		PhonePub:   phonePub,
		MacPub:     macPub,
		KP2M:       keys.KP2M[:],
		KM2P:       keys.KM2P[:],
		KeyID:      keys.KeyID[:],
		NextCtr:    0,
		DeviceName: deviceName,
	})
}

// tryHosts POSTs the pairing request to each host in turn (PROTOCOL.md §3.2:
// a Mac can have more than one active LAN interface), returning the first
// one that answers with a decodable 200.
func tryHosts(hosts []string, port int, reqBody []byte) (string, pairResponseBody, error) {
	var lastErr error
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		endpoint := fmt.Sprintf("http://%s:%d/v1/pair", host, port)
		resp, err := http.Post(endpoint, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", host, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", host, resp.StatusCode)
			resp.Body.Close()
			continue
		}
		var body pairResponseBody
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("%s: decoding response: %w", host, err)
			continue
		}
		return host, body, nil
	}
	return "", pairResponseBody{}, fmt.Errorf("could not pair with any host in %v: %w", hosts, lastErr)
}
