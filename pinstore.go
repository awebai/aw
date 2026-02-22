package aweb

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	LifetimeEphemeral  = "ephemeral"
	LifetimePersistent = "persistent"
)

// PinResult describes the outcome of a TOFU pin check.
type PinResult string

const (
	PinOK       PinResult = "ok"       // DID matches stored pin.
	PinNew      PinResult = "new"      // No pin existed; caller should store one.
	PinMismatch PinResult = "mismatch" // DID differs from stored pin.
	PinSkipped  PinResult = "skipped"  // Ephemeral agent — no pin check.
)

// Pin records an agent's TOFU-pinned identity.
type Pin struct {
	Address   string `yaml:"address"`
	Handle    string `yaml:"handle,omitempty"`
	StableID  string `yaml:"stable_id,omitempty"`
	FirstSeen string `yaml:"first_seen"`
	LastSeen  string `yaml:"last_seen"`
	Server    string `yaml:"server"`
}

// PinStore manages TOFU identity pins for known agents.
// Pins are keyed by did:key. The Addresses map is a reverse index from
// address to did:key for the identity-mismatch check.
type PinStore struct {
	Pins      map[string]*Pin `yaml:"pins"`
	Addresses map[string]string `yaml:"addresses"`
}

// NewPinStore returns an empty pin store.
func NewPinStore() *PinStore {
	return &PinStore{
		Pins:      make(map[string]*Pin),
		Addresses: make(map[string]string),
	}
}

// LoadPinStore reads a pin store from disk. Returns an empty store if
// the file does not exist.
func LoadPinStore(path string) (*PinStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewPinStore(), nil
		}
		return nil, err
	}
	var ps PinStore
	if err := yaml.Unmarshal(data, &ps); err != nil {
		return nil, err
	}
	if ps.Pins == nil {
		ps.Pins = make(map[string]*Pin)
	}
	if ps.Addresses == nil {
		ps.Addresses = make(map[string]string)
	}
	return &ps, nil
}

// Save writes the pin store to disk atomically. Creates parent
// directories if needed. The file is written with 0600 permissions.
func (ps *PinStore) Save(path string) error {
	data, err := yaml.Marshal(ps)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// CheckPin checks whether a DID matches the stored pin for an address.
// Ephemeral agents always return PinSkipped. If no pin exists for the
// address, returns PinNew. If the stored DID matches, returns PinOK.
// If it differs, returns PinMismatch.
func (ps *PinStore) CheckPin(address, did, lifetime string) PinResult {
	if lifetime == LifetimeEphemeral {
		return PinSkipped
	}
	pinnedDID, ok := ps.Addresses[address]
	if !ok {
		return PinNew
	}
	if pinnedDID == did {
		return PinOK
	}
	return PinMismatch
}

// StorePin records or updates a TOFU pin. If a pin for this DID already
// exists, only last_seen is updated. Otherwise a new pin is created and
// the reverse index is updated.
func (ps *PinStore) StorePin(did, address, handle, server string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if existing, ok := ps.Pins[did]; ok {
		if existing.Address != address {
			delete(ps.Addresses, existing.Address)
			ps.Addresses[address] = did
			existing.Address = address
		}
		existing.LastSeen = now
		existing.Handle = handle
		existing.Server = server
		return
	}
	ps.Pins[did] = &Pin{
		Address:   address,
		Handle:    handle,
		FirstSeen: now,
		LastSeen:  now,
		Server:    server,
	}
	ps.Addresses[address] = did
}
