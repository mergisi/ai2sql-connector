// Package update asks AI2SQL which Connector version people should be on.
//
// The check is answered by the AI2SQL API rather than the GitHub release, so
// a breaking API change can raise min_supported and tell old copies to update
// instead of failing at them with an error they cannot act on. Nothing is
// downloaded or replaced here — the user is told, and decides.
package update

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Status struct {
	Current     string `json:"current"`
	Latest      string `json:"latest,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	Notes       string `json:"notes,omitempty"`
	// Outdated means a newer version exists; Unsupported means this one is old
	// enough that AI2SQL no longer guarantees it works.
	Outdated    bool `json:"outdated"`
	Unsupported bool `json:"unsupported"`
	// Checked stays false when the check could not run — offline, or the API
	// unreachable. The UI shows nothing then rather than guessing.
	Checked bool `json:"checked"`
}

type Checker struct {
	mu      sync.Mutex
	status  Status
	current string
	baseURL string
}

func New(currentVersion, builderURL string) *Checker {
	return &Checker{current: currentVersion, baseURL: builderURL,
		status: Status{Current: currentVersion}}
}

func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Check runs once in the background at startup. A failure is silent by design:
// being offline is not something to interrupt the user about.
func (c *Checker) Check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/connector/version", nil)
	if err != nil {
		return
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return
	}
	var v struct {
		Latest       string `json:"latest"`
		MinSupported string `json:"min_supported"`
		DownloadURL  string `json:"download_url"`
		Notes        string `json:"notes"`
	}
	if json.NewDecoder(res.Body).Decode(&v) != nil || v.Latest == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = Status{
		Current:     c.current,
		Latest:      v.Latest,
		DownloadURL: v.DownloadURL,
		Notes:       v.Notes,
		Outdated:    compare(c.current, v.Latest) < 0,
		Unsupported: v.MinSupported != "" && compare(c.current, v.MinSupported) < 0,
		Checked:     true,
	}
}

// compare returns -1, 0 or 1 for two dotted versions. Missing parts count as
// zero, so "0.2" and "0.2.0" are the same version, and any part that is not a
// number compares as zero rather than panicking on a malformed release tag.
func compare(a, b string) int {
	as := strings.Split(strings.TrimPrefix(strings.TrimSpace(a), "v"), ".")
	bs := strings.Split(strings.TrimPrefix(strings.TrimSpace(b), "v"), ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		x, y := part(as, i), part(bs, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func part(s []string, i int) int {
	if i >= len(s) {
		return 0
	}
	// A pre-release suffix like "1.2.0-beta" compares on its numeric head.
	f := strings.FieldsFunc(s[i], func(r rune) bool { return r < '0' || r > '9' })
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return 0
	}
	return n
}
