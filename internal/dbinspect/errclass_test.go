package dbinspect

import (
	"errors"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		msg        string
		wantReason string
		wantCode   string
	}{
		{"ORA-01017: invalid username/password; logon denied", "auth_failed", "ORA-01017"},
		{"Error 1045: Access denied for user 'root'@'localhost'", "auth_failed", "1045"},
		{"mssql: Login failed for user 'sa'.", "auth_failed", ""},
		{`failed to connect: FATAL: password authentication failed for user "app" (SQLSTATE 28P01)`, "auth_failed", "28P01"},
		{"dial tcp 127.0.0.1:5432: connection refused", "host_unreachable", ""},
		{"ORA-12154: TNS:could not resolve the connect identifier specified", "host_unreachable", "ORA-12154"},
		{"dial tcp: lookup db.internal: no such host", "host_unreachable", ""},
		{"read tcp 10.0.0.2:1433: i/o timeout", "timeout", ""},
		{"x509: certificate signed by unknown authority", "tls", ""},
		{"Error 1049: Unknown database 'shop'", "database_missing", "1049"},
		{"ORA-00942: table or view does not exist", "permission_denied", "ORA-00942"},
		{"something nobody has seen before", "unknown", ""},
	}
	for _, c := range cases {
		gotReason, gotCode := Classify(errors.New(c.msg))
		if gotReason != c.wantReason {
			t.Errorf("Classify(%q) reason = %q, want %q", c.msg, gotReason, c.wantReason)
		}
		if gotCode != c.wantCode {
			t.Errorf("Classify(%q) code = %q, want %q", c.msg, gotCode, c.wantCode)
		}
	}
}

// The whole point of classifying is that the raw DSN never reaches analytics.
func TestClassifyLeaksNothing(t *testing.T) {
	err := errors.New(`failed to connect to postgres://admin:hunter2@10.1.2.3:5432/payroll: FATAL: password authentication failed (SQLSTATE 28P01)`)
	reason, code := Classify(err)
	for _, secret := range []string{"hunter2", "admin", "10.1.2.3", "payroll"} {
		if strings.Contains(reason+code, secret) {
			t.Fatalf("Classify leaked %q in %q/%q", secret, reason, code)
		}
	}
	if reason != "auth_failed" {
		t.Fatalf("reason = %q, want auth_failed", reason)
	}
}

func TestClassifyNil(t *testing.T) {
	if r, c := Classify(nil); r != "" || c != "" {
		t.Fatalf("Classify(nil) = %q/%q, want empty", r, c)
	}
}
