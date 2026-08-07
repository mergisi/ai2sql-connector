// The AI2SQL relay: connectors dial in over an outbound WebSocket, each
// paired tunnel gets its own public TCP port, and the AI2SQL backend connects
// to that port exactly as it would to any customer database. No change to the
// existing connection code is required — that is the point of the design.
//
//	relay --listen :8090 --public-host relay.ai2sql.io --api-secret <secret>
//
// HTTP API (all under --listen):
//	POST /pair                     -> {code, expires_at}         (X-Api-Secret)
//	GET  /tunnel/{code}            -> {active, public_addr}      (X-Api-Secret)
//	GET  /ws                       -> connector WebSocket endpoint
//	GET  /healthz                  -> ok
//
// The AI2SQL backend calls /pair when it shows the "local database detected"
// screen, displays the code, and polls /tunnel/{code} until active, then
// saves the returned public_addr as the connection host.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/mergisi/ai2sql-connector/internal/tunnel"
)

const (
	codeTTL     = 15 * time.Minute
	codeAlpha   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O/1/I
	codeLen     = 6
	dialTimeout = 10 * time.Second
)

type pairing struct {
	code      string
	createdAt time.Time
	mu        sync.Mutex
	sess      *yamux.Session
	listener  net.Listener
	publicAdr string
}

func (p *pairing) expired() bool { return time.Since(p.createdAt) > codeTTL && p.session() == nil }

func (p *pairing) session() *yamux.Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sess
}

type relay struct {
	apiSecret  string
	publicHost string
	mu         sync.Mutex
	pairings   map[string]*pairing
}

func main() {
	listen := flag.String("listen", ":8090", "HTTP listen address (ws + api)")
	publicHost := flag.String("public-host", "127.0.0.1", "hostname the backend should dial tunnels on")
	apiSecret := flag.String("api-secret", "", "shared secret for /pair and /tunnel (required)")
	flag.Parse()
	if *apiSecret == "" {
		log.Fatal("--api-secret is required")
	}

	r := &relay{apiSecret: *apiSecret, publicHost: *publicHost, pairings: map[string]*pairing{}}
	go r.reapLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("POST /pair", r.auth(r.handlePair))
	mux.HandleFunc("GET /tunnel/{code}", r.auth(r.handleTunnelStatus))
	mux.HandleFunc("GET /ws", r.handleWS)

	log.Printf("relay listening on %s, public host %s", *listen, *publicHost)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func (r *relay) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("X-Api-Secret") != r.apiSecret {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, req)
	}
}

func (r *relay) handlePair(w http.ResponseWriter, _ *http.Request) {
	code := newCode()
	p := &pairing{code: code, createdAt: time.Now()}
	r.mu.Lock()
	r.pairings[code] = p
	r.mu.Unlock()
	writeJSON(w, map[string]any{"code": code, "expires_at": p.createdAt.Add(codeTTL).UTC().Format(time.RFC3339)})
}

func (r *relay) handleTunnelStatus(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	p := r.pairings[strings.ToUpper(req.PathValue("code"))]
	r.mu.Unlock()
	if p == nil {
		http.Error(w, `{"error":"unknown_code"}`, http.StatusNotFound)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	writeJSON(w, map[string]any{"active": p.sess != nil && !p.sess.IsClosed(), "public_addr": p.publicAdr})
}

// handleWS is the connector's entry point: validate the pairing code, wrap
// the socket in yamux, open a public TCP listener, and from then on every
// inbound TCP connection becomes one yamux stream piped by the connector to
// the customer's local database.
func (r *relay) handleWS(w http.ResponseWriter, req *http.Request) {
	ws, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		// The connector is a native app, not a browser; origin checks add
		// nothing here.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	ctx := context.Background()

	var hello tunnel.Hello
	if err := tunnel.ReadJSON(ctx, ws, &hello); err != nil {
		ws.Close(websocket.StatusPolicyViolation, "expected hello")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(hello.Code))

	r.mu.Lock()
	p := r.pairings[code]
	r.mu.Unlock()

	reject := func(msg string) {
		_ = tunnel.WriteJSON(ctx, ws, tunnel.HelloReply{OK: false, Error: msg})
		ws.Close(websocket.StatusPolicyViolation, msg)
	}
	if p == nil {
		reject("unknown pairing code")
		return
	}
	if p.expired() {
		reject("pairing code expired")
		return
	}
	p.mu.Lock()
	if p.sess != nil && !p.sess.IsClosed() {
		p.mu.Unlock()
		reject("code already in use")
		return
	}
	p.mu.Unlock()

	// Port 0 lets the OS pick a free port; that port is the tunnel's public
	// identity for as long as the connector stays up.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		reject("relay cannot allocate a port")
		return
	}
	sess, err := tunnel.Session(ctx, ws, false) // relay opens streams => yamux client
	if err != nil {
		ln.Close()
		reject("session setup failed")
		return
	}
	publicAdr := net.JoinHostPort(r.publicHost, fmt.Sprint(ln.Addr().(*net.TCPAddr).Port))

	p.mu.Lock()
	p.sess, p.listener, p.publicAdr = sess, ln, publicAdr
	p.mu.Unlock()

	if err := tunnel.WriteJSON(ctx, ws, tunnel.HelloReply{OK: true, PublicAddr: publicAdr}); err != nil {
		r.teardown(p)
		return
	}
	log.Printf("tunnel up: code=%s target=%s public=%s", code, hello.Target, publicAdr)

	go r.acceptLoop(p, ln, sess)

	// Hold until the connector goes away, then free the port so it cannot
	// linger pointing at nothing.
	<-sess.CloseChan()
	r.teardown(p)
	log.Printf("tunnel down: code=%s", code)
}

func (r *relay) acceptLoop(p *pairing, ln net.Listener, sess *yamux.Session) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on teardown
		}
		go func() {
			stream, err := sess.Open()
			if err != nil {
				conn.Close()
				return
			}
			tunnel.Pipe(conn, stream)
		}()
	}
}

func (r *relay) teardown(p *pairing) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		p.listener.Close()
		p.listener = nil
	}
	if p.sess != nil {
		p.sess.Close()
		p.sess = nil
	}
	p.publicAdr = ""
}

// reapLoop drops expired never-connected codes so the map cannot grow
// unboundedly from abandoned pairing screens.
func (r *relay) reapLoop() {
	for range time.Tick(time.Minute) {
		r.mu.Lock()
		for code, p := range r.pairings {
			if p.expired() {
				delete(r.pairings, code)
			}
		}
		r.mu.Unlock()
	}
}

func newCode() string {
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = codeAlpha[int(b[i])%len(codeAlpha)]
	}
	return string(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
