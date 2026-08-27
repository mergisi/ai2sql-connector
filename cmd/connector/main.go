// The AI2SQL Connector: a single binary the user downloads and runs. It
// serves a small local web UI, takes a pairing code, opens one outbound
// WebSocket to the relay, and forwards tunnel streams to the local database.
// Credentials never pass through here — the backend sends them over the
// tunnel inside the database's own wire protocol, exactly as it would to a
// public host.
//
//	connector                          (UI on 127.0.0.1:5533, browser opens)
//	connector --relay wss://relay.ai2sql.io/ws
//	connector --code 4F7K2M --target localhost:1433 --no-ui   (headless)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"bytes"
	"io"

	"github.com/coder/websocket"

	"github.com/mergisi/ai2sql-connector/internal/analytics"
	"github.com/mergisi/ai2sql-connector/internal/auth"
	"github.com/mergisi/ai2sql-connector/internal/dbexec"
	"github.com/mergisi/ai2sql-connector/internal/dbinspect"
	"github.com/mergisi/ai2sql-connector/internal/tunnel"
	"github.com/mergisi/ai2sql-connector/internal/update"
	"github.com/mergisi/ai2sql-connector/ui"
)

var apiKey string

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

const version = "0.2.0"

type state struct {
	mu         sync.Mutex
	state      string // idle | connecting | connected | reconnecting | error
	code       string
	target     string
	publicAddr string
	lastError  string
	attempt    int
	cancel     context.CancelFunc
}

func (s *state) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"state": s.state, "target": s.target,
		"public_addr": s.publicAddr, "error": s.lastError, "attempt": s.attempt,
	}
}

func (s *state) set(fn func(*state)) {
	s.mu.Lock()
	fn(s)
	s.mu.Unlock()
}

func main() {
	relayURL := flag.String("relay", "ws://127.0.0.1:8090/ws", "relay WebSocket URL (tunnel mode only)")
	uiAddr := flag.String("ui", "127.0.0.1:5533", "local UI address")
	code := flag.String("code", "", "pairing code (headless tunnel mode)")
	target := flag.String("target", "", "local database address, e.g. localhost:1433")
	noUI := flag.Bool("no-ui", false, "run headless tunnel; requires --code and --target")
	noBrowser := flag.Bool("no-browser", false, "do not auto-open the browser")
	keyFlag := flag.String("api-key", os.Getenv("AI2SQL_API_KEY"), "AI2SQL API key override (normally set by Sign in with AI2SQL)")
	builderURL := flag.String("builder", envOr("AI2SQL_BUILDER_URL", "https://builder.ai2sql.io"), "AI2SQL web app base URL, used for sign-in")
	flag.Parse()
	apiKey = *keyFlag

	creds := auth.NewStore()
	st := &state{state: "idle"}

	// Analytics identity: reuse the persisted install id (minting one on
	// first run), and bind the user id when a sign-in is present.
	track := analytics.New(creds.Get().InstallID, version)
	if c := creds.Get(); c.InstallID == "" {
		c.InstallID = track.InstallID()
		creds.Set(c)
	}
	if c := creds.Get(); c.UserID != "" {
		track.SetUser(c.UserID)
	}
	track.Track("connector_app_started", map[string]any{"signed_in": creds.Get().Key != ""})

	// Ask AI2SQL what version people should be on. Runs in the background so a
	// slow or unreachable API never delays the window opening.
	updates := update.New(version, *builderURL)
	go func() {
		updates.Check(context.Background())
		s := updates.Status()
		if s.Unsupported {
			log.Printf("this version (%s) is no longer supported — update to %s: %s", s.Current, s.Latest, s.DownloadURL)
		} else if s.Outdated {
			log.Printf("a newer version is available: %s (you have %s)", s.Latest, s.Current)
		}
		if s.Checked && (s.Outdated || s.Unsupported) {
			track.Track("connector_update_available", map[string]any{
				"latest": s.Latest, "unsupported": s.Unsupported})
		}
	}()

	// A stored sign-in is a snapshot; the account is not. Revalidate against
	// the API on startup so a revoked key signs itself out and a plan change
	// (free→pro, cancellations) shows correctly instead of last month's truth.
	if c := creds.Get(); c.Key != "" {
		go func() {
			req, err := http.NewRequest("GET", *builderURL+"/api/connector/me", nil)
			if err != nil {
				return
			}
			req.Header.Set("X-API-Key", c.Key)
			client := &http.Client{Timeout: 10 * time.Second}
			res, err := client.Do(req)
			if err != nil {
				return // offline — keep the stored session, generation will surface real errors
			}
			defer res.Body.Close()
			if res.StatusCode == http.StatusUnauthorized {
				log.Printf("stored sign-in is no longer valid, signing out")
				creds.Clear()
				return
			}
			var me struct {
				ID    string `json:"id"`
				Email string `json:"email"`
				Plan  string `json:"plan"`
			}
			if json.NewDecoder(res.Body).Decode(&me) == nil && me.Email != "" {
				cur := creds.Get()
				cur.Email, cur.Plan, cur.UserID = me.Email, me.Plan, me.ID
				creds.Set(cur)
				track.SetUser(me.ID)
			}
		}()
	}

	if *noUI {
		if *code == "" || *target == "" {
			log.Fatal("--no-ui requires --code and --target")
		}
		runTunnel(context.Background(), st, *relayURL, *code, *target)
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	mux.HandleFunc("POST /api/connect", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Code, Target string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "bad request"})
			return
		}
		// Check the local database is actually there before claiming success.
		// Without this the tunnel comes up against a dead port and the UI says
		// "active" while nothing can ever flow through it.
		probe, err := net.DialTimeout("tcp", req.Target, 5*time.Second)
		if err != nil {
			writeJSON(w, map[string]any{"ok": false,
				"error": "Nothing is listening on " + req.Target + ". Check the database is running and the port is right."})
			return
		}
		probe.Close()

		st.mu.Lock()
		if st.cancel != nil {
			st.cancel() // drop a previous tunnel before starting over
		}
		ctx, cancel := context.WithCancel(context.Background())
		st.cancel = cancel
		st.mu.Unlock()
		go runTunnel(ctx, st, *relayURL, req.Code, req.Target)
		writeJSON(w, map[string]any{"ok": true})
	})

	// Lets the user change the target and pair again without restarting the
	// app — the first build left them stuck once a tunnel was up.
	mux.HandleFunc("POST /api/disconnect", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		if st.cancel != nil {
			st.cancel()
			st.cancel = nil
		}
		st.state, st.publicAddr, st.lastError, st.attempt = "idle", "", "", 0
		st.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, st.snapshot())
	})
	mux.HandleFunc("GET /api/update/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, updates.Status())
	})

	// --- account sign-in ------------------------------------------------
	// "Sign in with AI2SQL" opens the browser at the web app, which is where
	// the user's session lives; the web app issues their personal Connector
	// API key and sends the browser back here. Generation then runs against
	// their own account and plan quota.
	mux.HandleFunc("GET /api/auth/start", func(w http.ResponseWriter, r *http.Request) {
		_, port, _ := net.SplitHostPort(*uiAddr)
		writeJSON(w, map[string]any{"url": *builderURL + "/connector-auth?port=" + port})
	})
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, _ *http.Request) {
		// The key travels in the URL fragment, which never reaches this
		// server — this tiny page reads it in the browser and posts it back.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>AI2SQL Connector</title>
<body style="background:#0d0d14;color:#e8e8f0;font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh">
<div id="m" style="text-align:center"><h2>Finishing sign-in…</h2></div>
<script>
(function(){
  var p = new URLSearchParams(location.hash.slice(1));
  fetch('/api/auth', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({key:p.get('key')||'', email:p.get('email')||'', plan:p.get('plan')||'', user_id:p.get('user_id')||''})})
    .then(function(r){return r.json()})
    .then(function(d){
      document.getElementById('m').innerHTML = d.ok
        ? '<h2 style="color:#2fbf71">✓ Signed in</h2><p>You can close this tab — the Connector window is ready.</p>'
        : '<h2 style="color:#e05252">Sign-in failed</h2><p>'+(d.error||'')+'</p>';
      if (d.ok) setTimeout(function(){ location.href = '/'; }, 1200);
    });
})();
</script></body>`)
	})
	mux.HandleFunc("POST /api/auth", func(w http.ResponseWriter, r *http.Request) {
		var c auth.Credentials
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil || !strings.HasPrefix(c.Key, "sql_") {
			writeJSON(w, map[string]any{"ok": false, "error": "invalid key"})
			return
		}
		c.InstallID = creds.Get().InstallID // never let a sign-in reset the install identity
		creds.Set(c)
		if c.UserID != "" {
			track.SetUser(c.UserID)
		}
		track.Track("connector_signin_completed", map[string]any{"plan": c.Plan})
		log.Printf("signed in as %s (%s plan)", c.Email, c.Plan)
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/auth/status", func(w http.ResponseWriter, _ *http.Request) {
		c := creds.Get()
		writeJSON(w, map[string]any{"authenticated": c.Key != "" || apiKey != "", "email": c.Email, "plan": c.Plan})
	})
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, _ *http.Request) {
		track.Track("connector_signed_out", nil)
		creds.Clear()
		writeJSON(w, map[string]any{"ok": true})
	})

	// UI-side events (button clicks the Go side cannot see). Allowlisted so
	// the local page cannot mint arbitrary event names into the project.
	uiEvents := map[string]bool{"connector_sql_copied": true, "connector_signin_clicked": true, "connector_query_run_clicked": true, "connector_update_clicked": true}
	mux.HandleFunc("POST /api/track", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Event string `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && uiEvents[req.Event] {
			track.Track(req.Event, nil)
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	// Reads the schema of the user's LOCAL database. Credentials arrive from
	// the local UI, are used for one introspection round-trip on this
	// machine, and are not stored or sent anywhere.
	mux.HandleFunc("POST /api/db/inspect", func(w http.ResponseWriter, r *http.Request) {
		var cfg dbinspect.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "bad request"})
			return
		}
		tables, err := dbinspect.Inspect(r.Context(), cfg)
		if err != nil {
			// Category and driver code only — the raw message can carry the
			// host, the user and the password.
			reason, code := dbinspect.Classify(err)
			track.Track("connector_schema_load_failed", map[string]any{
				"driver": cfg.Driver, "failure_reason": reason, "error_code": code})
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		track.Track("connector_schema_loaded", map[string]any{"driver": cfg.Driver, "tables": len(tables)})
		writeJSON(w, map[string]any{"ok": true, "tables": tables, "schema": dbinspect.SchemaString(tables)})
	})

	// Runs the generated SQL against the user's local database, read-only.
	// Rows are read here and returned to the local UI — they never go to
	// AI2SQL, which is what keeps the promise the page makes.
	mux.HandleFunc("POST /api/db/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			dbinspect.Config
			SQL string `json:"sql"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "bad request"})
			return
		}
		res, err := dbexec.Execute(r.Context(), req.Config, req.SQL)
		if err != nil {
			var blocked *dbexec.ErrBlocked
			if errors.As(err, &blocked) {
				track.Track("connector_query_failed", map[string]any{
					"driver": req.Driver, "failure_reason": "blocked", "query_mode": "read_only"})
				writeJSON(w, map[string]any{"ok": false, "blocked": true, "error": blocked.Reason})
				return
			}
			reason, code := dbinspect.Classify(err)
			track.Track("connector_query_failed", map[string]any{
				"driver": req.Driver, "failure_reason": reason, "error_code": code,
				"query_mode": "read_only"})
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		// Counts and timings only — never the SQL, the column names or a row.
		track.Track("connector_query_succeeded", map[string]any{
			"driver": req.Driver, "row_count": res.RowCount,
			"execution_time_ms": res.ElapsedMs, "was_truncated": res.Truncated,
			"query_mode": "read_only"})
		writeJSON(w, map[string]any{"ok": true, "result": res})
	})

	// Proxies one generation call to the AI2SQL API with the local schema as
	// context. Proxying (rather than calling from the browser) keeps the UI
	// same-origin and leaves room to attach an API key later without
	// exposing it to the page.
	mux.HandleFunc("POST /api/generate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt  string `json:"prompt"`
			Dialect string `json:"dialect"`
			Schema  string `json:"schema"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Prompt) == "" {
			writeJSON(w, map[string]any{"ok": false, "error": "prompt is required"})
			return
		}
		if req.Dialect == "" {
			req.Dialect = "postgres"
		}
		// The signed-in user's own key — generation counts against their own
		// AI2SQL plan quota, exactly as if they used the web app's API.
		key := creds.Get().Key
		if key == "" {
			key = apiKey // --api-key / env override, mainly for development
		}
		if key == "" {
			writeJSON(w, map[string]any{"ok": false, "error": "not_authenticated",
				"detail": "Sign in with your AI2SQL account first."})
			return
		}
		body, _ := json.Marshal(map[string]any{"text": req.Prompt, "dialect": req.Dialect, "schema": req.Schema, "prettify": true})
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		apiReq, _ := http.NewRequestWithContext(ctx, "POST", *builderURL+"/api/sql/generate", bytes.NewReader(body))
		apiReq.Header.Set("Content-Type", "application/json")
		apiReq.Header.Set("X-API-Key", key)
		res, err := http.DefaultClient.Do(apiReq)
		if err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "AI2SQL API unreachable: " + err.Error()})
			return
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if res.StatusCode == http.StatusTooManyRequests {
			// Surface the plan-quota message as-is: it names the plan, the
			// limit, and the upgrade link.
			var q struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(raw, &q)
			track.Track("connector_generate_failed", map[string]any{"reason": "quota", "dialect": req.Dialect})
			writeJSON(w, map[string]any{"ok": false, "error": q.Message, "quota": true})
			return
		}
		if res.StatusCode == http.StatusUnauthorized {
			creds.Clear() // the key was revoked server-side; force a fresh sign-in
			track.Track("connector_generate_failed", map[string]any{"reason": "auth", "dialect": req.Dialect})
			writeJSON(w, map[string]any{"ok": false, "error": "not_authenticated",
				"detail": "Your sign-in is no longer valid. Sign in again."})
			return
		}
		if res.StatusCode != http.StatusOK {
			track.Track("connector_generate_failed", map[string]any{"reason": "api_" + fmt.Sprint(res.StatusCode), "dialect": req.Dialect})
			writeJSON(w, map[string]any{"ok": false, "error": fmt.Sprintf("API error (%d): %s", res.StatusCode, truncate(string(raw), 300))})
			return
		}
		var parsed struct {
			SQL   string `json:"sql"`
			Query string `json:"query"`
		}
		_ = json.Unmarshal(raw, &parsed)
		sqlText := parsed.SQL
		if sqlText == "" {
			sqlText = parsed.Query
		}
		if sqlText == "" {
			writeJSON(w, map[string]any{"ok": false, "error": "API returned no SQL: " + truncate(string(raw), 300)})
			return
		}
		track.Track("connector_sql_generated", map[string]any{"dialect": req.Dialect, "has_schema": req.Schema != ""})
		writeJSON(w, map[string]any{"ok": true, "sql": sqlText})
	})

	// A second launch is the common case here (double-click twice, or a copy
	// left running in a terminal). Point at the window that already exists
	// rather than dying with a port number the user has to decode.
	ln, err := net.Listen("tcp", *uiAddr)
	if err != nil {
		existing := "http://" + *uiAddr
		if resp, e := http.Get(existing + "/api/status"); e == nil {
			resp.Body.Close()
			log.Printf("The AI2SQL Connector is already running. Opening %s", existing)
			if !*noBrowser {
				openBrowser(existing)
				time.Sleep(time.Second)
			}
			return
		}
		log.Fatalf("Port %s is in use by another program. Start the connector on a different port:\n"+
			"    ai2sql-connector --ui 127.0.0.1:5534", *uiAddr)
	}
	url := "http://" + *uiAddr
	log.Printf("AI2SQL Connector %s — UI at %s", version, url)
	if !*noBrowser {
		go openBrowser(url)
	}
	if *code != "" && *target != "" {
		ctx, cancel := context.WithCancel(context.Background())
		st.cancel = cancel
		go runTunnel(ctx, st, *relayURL, *code, *target)
	}
	log.Fatal(http.Serve(ln, mux))
}

// runTunnel keeps one tunnel alive until ctx is cancelled: dial, serve
// streams, and on any drop retry with capped backoff. A rejected pairing code
// is terminal — retrying a code the relay refused would loop forever.
func runTunnel(ctx context.Context, st *state, relayURL, code, target string) {
	attempt := 0
	for {
		attempt++
		st.set(func(s *state) {
			s.code, s.target, s.attempt = code, target, attempt
			if attempt == 1 {
				s.state, s.lastError = "connecting", ""
			} else {
				s.state = "reconnecting"
			}
		})

		err := serveOnce(ctx, st, relayURL, code, target)
		if ctx.Err() != nil {
			st.set(func(s *state) { s.state = "idle"; s.publicAddr = "" })
			return
		}
		var pr *pairingRejected
		if errors.As(err, &pr) {
			st.set(func(s *state) { s.state = "error"; s.lastError = pr.reason; s.publicAddr = "" })
			return
		}
		if err != nil {
			st.set(func(s *state) { s.lastError = err.Error(); s.publicAddr = "" })
		}
		// Exponential backoff, capped: a laptop waking from sleep should
		// recover in seconds, a dead relay shouldn't be hammered.
		delay := time.Duration(1<<min(attempt, 5)) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

type pairingRejected struct{ reason string }

func (e *pairingRejected) Error() string { return e.reason }

func serveOnce(ctx context.Context, st *state, relayURL, code, target string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	ws, _, err := websocket.Dial(dialCtx, relayURL, nil)
	cancel()
	if err != nil {
		return fmt.Errorf("relay unreachable: %w", err)
	}
	// Tunnels move database result sets; the default 32KB read limit would
	// kill the socket mid-query.
	ws.SetReadLimit(-1)

	if err := tunnel.WriteJSON(ctx, ws, tunnel.Hello{Code: strings.ToUpper(strings.TrimSpace(code)), Target: target, Version: version}); err != nil {
		ws.Close(websocket.StatusInternalError, "")
		return err
	}
	var reply tunnel.HelloReply
	if err := tunnel.ReadJSON(ctx, ws, &reply); err != nil {
		ws.Close(websocket.StatusInternalError, "")
		return err
	}
	if !reply.OK {
		ws.Close(websocket.StatusNormalClosure, "")
		return &pairingRejected{reason: reply.Error}
	}

	sess, err := tunnel.Session(ctx, ws, true) // connector accepts streams => yamux server
	if err != nil {
		ws.Close(websocket.StatusInternalError, "")
		return err
	}
	defer sess.Close()

	st.set(func(s *state) { s.state = "connected"; s.publicAddr = reply.PublicAddr })
	log.Printf("tunnel active: %s -> %s", reply.PublicAddr, target)

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return fmt.Errorf("tunnel closed: %w", err)
		}
		go func() {
			local, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				// The one failure the user must see: tunnel is fine but the
				// database itself is not listening where they said.
				st.set(func(s *state) { s.lastError = "local database not reachable at " + target })
				stream.Close()
				return
			}
			tunnel.Pipe(stream, local)
		}()
	}
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond) // let the listener come up first
	var err error
	switch runtime.GOOS {
	case "darwin":
		err = exec.Command("open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = exec.Command("xdg-open", url).Start()
	}
	if err != nil {
		log.Printf("open %s in your browser", url)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
