package dbinspect

import (
	"context"
	"strings"
	"testing"
	"time"
)

// No Oracle server in CI — the point is that the driver is registered, the
// DSN parses, and a connection attempt reaches the network layer instead of
// dying at "unknown driver".
func TestOracleDriverWired(t *testing.T) {
	cfg := Config{Driver: "oracle", Host: "127.0.0.1", Port: "1", User: "u", Password: "p", Database: "XEPDB1"}
	d, dsn, err := Plan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d != "oracle" || !strings.Contains(dsn, "oracle://") || !strings.Contains(dsn, "/XEPDB1") {
		t.Fatalf("unexpected plan: %s %s", d, dsn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = Inspect(ctx, cfg)
	if err == nil {
		t.Fatal("expected a connection error against port 1")
	}
	if strings.Contains(err.Error(), "unknown driver") {
		t.Fatalf("driver not registered: %v", err)
	}
	t.Logf("reached the network layer as expected: %v", err)
}
