// Package auth holds the connector's link to the user's AI2SQL account: the
// per-user API key handed over by the browser sign-in flow, persisted so a
// restart does not ask the user to sign in again.
package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Credentials struct {
	Key   string `json:"key"`
	Email string `json:"email"`
	Plan  string `json:"plan"`
	// UserID is the AI2SQL numeric user id — the identity analytics keys on.
	UserID string `json:"user_id,omitempty"`
	// InstallID survives sign-outs so one machine stays one install in
	// analytics regardless of account churn.
	InstallID string `json:"install_id,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	creds Credentials
}

// NewStore loads any previously saved sign-in. A missing or unreadable file
// just means "not signed in" — never an error the user has to see.
func NewStore() *Store {
	s := &Store{}
	if home, err := os.UserHomeDir(); err == nil {
		s.path = filepath.Join(home, ".ai2sql-connector.json")
		if b, err := os.ReadFile(s.path); err == nil {
			_ = json.Unmarshal(b, &s.creds)
		}
	}
	return s
}

func (s *Store) Get() Credentials {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creds
}

func (s *Store) Set(c Credentials) {
	s.mu.Lock()
	s.creds = c
	path := s.path
	s.mu.Unlock()
	if path != "" {
		b, _ := json.Marshal(c)
		// 0600: the key authorizes spend against the user's plan quota; no
		// other account on the machine gets to read it.
		_ = os.WriteFile(path, b, 0o600)
	}
}

// Clear drops the sign-in but keeps the install id on disk.
func (s *Store) Clear() {
	s.mu.Lock()
	install := s.creds.InstallID
	s.creds = Credentials{InstallID: install}
	path := s.path
	creds := s.creds
	s.mu.Unlock()
	if path != "" {
		b, _ := json.Marshal(creds)
		_ = os.WriteFile(path, b, 0o600)
	}
}
