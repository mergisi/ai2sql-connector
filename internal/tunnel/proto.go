// Package tunnel is the shared wire protocol between the relay and the
// connector. The design goal is that the AI2SQL backend needs to know nothing
// about any of this: the relay exposes each tunnel as an ordinary TCP
// host:port, so the existing database-connection code dials it like any
// public database.
package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Hello is the first frame the connector sends after the WebSocket opens.
// The pairing code is the whole MVP auth story: the web app displays it to a
// logged-in user, the user types it into the connector, and whoever presents
// it owns the tunnel. It is single-use and expires.
type Hello struct {
	Code string `json:"code"`
	// Target is the local address the connector will forward to, e.g.
	// "localhost:1433". Sent for display/telemetry; the connector is the one
	// that actually dials it, so the relay never needs to reach it.
	Target string `json:"target"`
	// Version of the connector build, for support conversations.
	Version string `json:"version"`
}

// HelloReply tells the connector whether pairing succeeded and where the
// tunnel is exposed, so the UI can show "your database is now reachable at
// relay.ai2sql.io:14321".
type HelloReply struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	PublicAddr string `json:"public_addr,omitempty"`
}

// Session wraps a WebSocket in a yamux session. Both sides use the same
// wrapping; who is client and who is server only decides who opens streams.
// The relay opens one stream per inbound TCP connection; the connector
// accepts streams and pipes each to a fresh local TCP dial.
func Session(ctx context.Context, ws *websocket.Conn, isServer bool) (*yamux.Session, error) {
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.EnableKeepAlive = true
	// yamux logs to stderr by default on stream errors; keep it quiet, the
	// callers surface errors where a human will see them.
	cfg.LogOutput = nil
	cfg.Logger = discardLogger
	if isServer {
		return yamux.Server(nc, cfg)
	}
	return yamux.Client(nc, cfg)
}

// ReadJSON / WriteJSON frame small control messages over the raw WebSocket
// before yamux takes over the connection.
func ReadJSON(ctx context.Context, ws *websocket.Conn, v any) error {
	_, data, err := ws.Read(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func WriteJSON(ctx context.Context, ws *websocket.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageText, data)
}

// Pipe copies both directions until either side closes, then closes both.
// This is the entire data plane of the product.
func Pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { copyAndSignal(a, b, done) }()
	go func() { copyAndSignal(b, a, done) }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func copyAndSignal(dst, src net.Conn, done chan<- struct{}) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	done <- struct{}{}
}
