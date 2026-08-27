package analytics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu   sync.Mutex
	body []map[string]any
}

func (c *capture) all() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]map[string]any, len(c.body))
	copy(out, c.body)
	return out
}

// serve stands in for api.mixpanel.com and records what the client posts.
func serve(t *testing.T) *capture {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload []map[string]any
		if err := json.Unmarshal(raw, &payload); err == nil {
			cap.mu.Lock()
			cap.body = append(cap.body, payload...)
			cap.mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	old := endpoint
	endpoint = srv.URL
	t.Cleanup(func() { endpoint = old; srv.Close() })
	return cap
}

// settle waits for the fire-and-forget goroutines to land.
func settle(t *testing.T, c *capture, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.all(); len(got) >= want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c.all()
}

func TestSetUserAliasesOnce(t *testing.T) {
	cap := serve(t)
	c := New("inst_abc", "0.2.0")

	c.SetUser("30967")
	c.SetUser("30967") // a second sign-in must not alias again
	c.SetUser("30967")

	events := settle(t, cap, 1)
	aliases := 0
	for _, e := range events {
		if e["event"] != "$create_alias" {
			continue
		}
		aliases++
		p := e["properties"].(map[string]any)
		if p["distinct_id"] != "inst_abc" {
			t.Errorf("distinct_id = %v, want inst_abc", p["distinct_id"])
		}
		if p["alias"] != "30967" {
			t.Errorf("alias = %v, want 30967", p["alias"])
		}
	}
	if aliases != 1 {
		t.Fatalf("sent %d aliases, want exactly 1", aliases)
	}
}

func TestSetUserIgnoresEmpty(t *testing.T) {
	cap := serve(t)
	c := New("inst_abc", "0.2.0")
	c.SetUser("")
	time.Sleep(150 * time.Millisecond)
	for _, e := range cap.all() {
		if e["event"] == "$create_alias" {
			t.Fatal("empty user id must not produce an alias")
		}
	}
	if c.userID != "" {
		t.Fatalf("userID = %q, want empty", c.userID)
	}
}

// After SetUser, ordinary events must carry the user id, not the install id.
func TestTrackUsesUserAfterSetUser(t *testing.T) {
	cap := serve(t)
	c := New("inst_abc", "0.2.0")

	c.Track("connector_app_started", nil)
	c.SetUser("30967")
	c.Track("connector_schema_load_failed", map[string]any{"driver": "sqlserver"})

	events := settle(t, cap, 3)
	var before, after map[string]any
	for _, e := range events {
		p, _ := e["properties"].(map[string]any)
		switch e["event"] {
		case "connector_app_started":
			before = p
		case "connector_schema_load_failed":
			after = p
		}
	}
	if before == nil || after == nil {
		t.Fatalf("missing events, got %d", len(events))
	}
	if before["distinct_id"] != "inst_abc" {
		t.Errorf("pre-signin distinct_id = %v, want inst_abc", before["distinct_id"])
	}
	if after["distinct_id"] != "30967" {
		t.Errorf("post-signin distinct_id = %v, want 30967", after["distinct_id"])
	}
	// The install id must stay on every event so a hand-join is still possible.
	if after["install_id"] != "inst_abc" {
		t.Errorf("install_id = %v, want inst_abc", after["install_id"])
	}
	if after["driver"] != "sqlserver" {
		t.Errorf("driver property lost: %v", after["driver"])
	}
}

func TestDisabledSendsNothing(t *testing.T) {
	cap := serve(t)
	c := New("inst_abc", "0.2.0")
	c.Disable()
	c.SetUser("30967")
	c.Track("connector_app_started", nil)
	time.Sleep(150 * time.Millisecond)
	if got := cap.all(); len(got) != 0 {
		t.Fatalf("disabled client sent %d events", len(got))
	}
}
