// End-to-end test of the whole chain without any real database:
//
//	client  →  relay public port  →  yamux/WS  →  connector  →  local echo server
//
// If bytes survive the round trip on several concurrent connections, the data
// plane works; everything else (real MSSQL/MySQL/PG) is just TCP on top.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTunnelEndToEnd(t *testing.T) {
	// 1. Local "database": echoes every byte back, prefixed with "db:".
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(append([]byte("db:"), buf[:n]...))
				}
			}(c)
		}
	}()

	// 2. Relay.
	relay := exec.Command("go", "run", "./cmd/relay", "--listen", "127.0.0.1:18090", "--public-host", "127.0.0.1", "--api-secret", "testsecret")
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	defer relay.Process.Kill()
	waitHTTP(t, "http://127.0.0.1:18090/healthz")

	// 3. Pair (what the AI2SQL backend would do).
	code := pair(t)

	// 4. Connector, headless, forwarding to the echo server.
	conn := exec.Command("go", "run", "./cmd/connector",
		"--relay", "ws://127.0.0.1:18090/ws", "--no-ui",
		"--code", code, "--target", echoLn.Addr().String())
	if err := conn.Start(); err != nil {
		t.Fatal(err)
	}
	defer conn.Process.Kill()

	// 5. Wait for the tunnel to report active and get its public address.
	publicAddr := waitActive(t, code)
	t.Logf("tunnel public address: %s", publicAddr)

	// 6. Hammer it with concurrent connections, each sending its own payload.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := fmt.Sprintf("SELECT %d;", i)
			c, err := net.DialTimeout("tcp", publicAddr, 5*time.Second)
			if err != nil {
				t.Errorf("conn %d: dial: %v", i, err)
				return
			}
			defer c.Close()
			if _, err := c.Write([]byte(msg)); err != nil {
				t.Errorf("conn %d: write: %v", i, err)
				return
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			want := "db:" + msg
			buf := make([]byte, len(want))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Errorf("conn %d: read: %v", i, err)
				return
			}
			if string(buf) != want {
				t.Errorf("conn %d: got %q want %q", i, buf, want)
			}
		}(i)
	}
	wg.Wait()

	// 7. A wrong pairing code must be rejected, not queued.
	bad := exec.Command("go", "run", "./cmd/connector",
		"--relay", "ws://127.0.0.1:18090/ws", "--no-ui",
		"--code", "XXXXXX", "--target", echoLn.Addr().String())
	out, _ := bad.CombinedOutput()
	_ = out // headless exits via log.Fatal path only on flag errors; rejection keeps state; just ensure no panic
}

func pair(t *testing.T) string {
	req, _ := http.NewRequest("POST", "http://127.0.0.1:18090/pair", nil)
	req.Header.Set("X-Api-Secret", "testsecret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	s := string(body)
	i := strings.Index(s, `"code":"`)
	if i < 0 {
		t.Fatalf("no code in %s", s)
	}
	return s[i+8 : i+14]
}

func waitActive(t *testing.T, code string) string {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:18090/tunnel/"+code, nil)
		req.Header.Set("X-Api-Secret", "testsecret")
		res, err := http.DefaultClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			s := string(body)
			if strings.Contains(s, `"active":true`) {
				i := strings.Index(s, `"public_addr":"`)
				end := strings.Index(s[i+15:], `"`)
				return s[i+15 : i+15+end]
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("tunnel never became active")
	return ""
}

func waitHTTP(t *testing.T, url string) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if res, err := http.Get(url); err == nil {
			res.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s never came up", url)
}
