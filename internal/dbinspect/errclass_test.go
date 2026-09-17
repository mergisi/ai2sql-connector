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

func TestShapeRedactsValuesAndKeepsWording(t *testing.T) {
	cases := []struct {
		msg  string
		want []string // substrings that must survive
		deny []string // values that must not
	}{
		{
			msg:  `failed to connect to host=db.internal user=app database=shop: password authentication failed for user "app"`,
			want: []string{"failed to connect to", "password authentication failed"},
			deny: []string{"db.internal", "app", "shop"},
		},
		{
			msg:  "dial tcp 10.0.0.2:5432: connect: connection refused",
			want: []string{"connection refused"},
			deny: []string{"10.0.0.2", "5432"},
		},
		{
			msg:  `Error 1045: Access denied for user 'root'@'localhost' (using password: YES)`,
			want: []string{"access denied for user"},
			deny: []string{"root", "localhost"},
		},
		{
			msg:  `open /Users/ben/.pgpass: permission denied`,
			want: []string{"permission denied"},
			deny: []string{"/Users/ben", ".pgpass"},
		},
	}
	for _, c := range cases {
		got := Shape(errors.New(c.msg))
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("Shape(%q) = %q, expected it to keep %q", c.msg, got, w)
			}
		}
		for _, d := range c.deny {
			if strings.Contains(got, strings.ToLower(d)) {
				t.Errorf("Shape(%q) = %q, leaked %q", c.msg, got, d)
			}
		}
	}
}

func TestShapeIsBounded(t *testing.T) {
	long := strings.Repeat("wordy ", 200)
	if got := Shape(errors.New(long)); len(got) > 160 {
		t.Errorf("Shape did not bound its output: %d chars", len(got))
	}
	if Shape(nil) != "" {
		t.Error("Shape(nil) should be empty")
	}
}
