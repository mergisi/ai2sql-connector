// Package analytics sends product events to Mixpanel from the connector.
// Everything is fire-and-forget: analytics must never slow down or break the
// tool, so failures are silently dropped.
//
// Identity: before sign-in events carry a random per-install id; after
// sign-in they use the AI2SQL numeric user id, which is what the funnel
// scripts key on. The install id stays attached as a property so the two
// halves of a journey can be joined by hand when it matters.
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

type Client struct {
	mu        sync.Mutex
	userID    string
	installID string
	version   string
	disabled  bool
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

func (c *Client) SetUser(id string) {
	c.mu.Lock()
	c.userID = id
	c.mu.Unlock()
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
		req, err := http.NewRequest("POST", "https://api.mixpanel.com/track", bytes.NewReader(body))
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
