// Package analytics sends product events to Mixpanel from the connector.
// Everything is fire-and-forget: analytics must never slow down or break the
// tool, so failures are silently dropped.
//
// Identity: before sign-in events carry a random per-install id; after
// sign-in they use the AI2SQL numeric user id, which is what the funnel
// scripts key on. The install id stays attached as a property, and the
// first SetUser also sends Mixpanel a $create_alias so the pre-sign-in
// events merge into the user rather than sitting in a separate cohort.
// This mirrors the mixpanel.alias() call the web signup makes; the project
// is on Original ID Merge, where identify() alone does not merge history.
package analytics

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// The Mixpanel project token is the same public value every AI2SQL web page
// embeds — it can only write events, never read them.
const token = "41f9b3fe6258f5cff96df6d01f1dd636"

// Overridden by tests; there is no other reason to point this anywhere else.
var endpoint = "https://api.mixpanel.com/track"

type Client struct {
	mu        sync.Mutex
	userID    string
	installID string
	version   string
	disabled  bool
	aliased   bool
}

func New(installID, version string) *Client {
	if installID == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err == nil {
			installID = "inst_" + base64.RawURLEncoding.EncodeToString(b)
		}
	}
	return &Client{installID: installID, version: version}
}

func (c *Client) InstallID() string { return c.installID }

// SetUser switches this client to the AI2SQL user id. The first time it is
// called with a new id it also links the install id to that user, so the
// events already sent under the install id stop looking like a stranger.
func (c *Client) SetUser(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	first := !c.aliased && c.userID != id && c.installID != "" && c.installID != id
	c.userID = id
	if first {
		c.aliased = true
	}
	install := c.installID
	c.mu.Unlock()

	if first {
		c.alias(install, id)
	}
}

// alias tells Mixpanel that these two ids are the same person. It is sent
// once per process; Mixpanel treats repeated aliases of the same value as an
// error, and an install that signs in twice is the same link either way.
func (c *Client) alias(installID, userID string) {
	if c.disabled {
		return
	}
	body, err := json.Marshal([]map[string]any{{
		"event": "$create_alias",
		"properties": map[string]any{
			"token":       token,
			"distinct_id": installID,
			"alias":       userID,
		},
	}})
	if err != nil {
		return
	}
	go func() {
		client := &http.Client{Timeout: 8 * time.Second}
		req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if res, err := client.Do(req); err == nil {
			res.Body.Close()
		}
	}()
}

func (c *Client) Disable() { c.disabled = true }

// Track queues one event and returns immediately.
func (c *Client) Track(event string, props map[string]any) {
	if c.disabled {
		return
	}
	c.mu.Lock()
	distinct := c.userID
	c.mu.Unlock()
	if distinct == "" {
		distinct = c.installID
	}

	p := map[string]any{
		"token":             token,
		"distinct_id":       distinct,
		"time":              time.Now().Unix(),
		"$insert_id":        newInsertID(),
		"source":            "connector",
		"connector_version": c.version,
		"os":                runtime.GOOS,
		"install_id":        c.installID,
	}
	for k, v := range props {
		p[k] = v
	}
	body, err := json.Marshal([]map[string]any{{"event": event, "properties": p}})
	if err != nil {
		return
	}
	go func() {
		client := &http.Client{Timeout: 8 * time.Second}
		req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
		}
	}()
}

// newInsertID gives Mixpanel a dedup key — the export pipeline relies on
// $insert_id being present and unique per logical event.
func newInsertID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
