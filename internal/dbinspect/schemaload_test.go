package dbinspect

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// SQL Server Express is a named instance on a dynamic port. The instance has
// to travel as the URL path with no port, so go-mssqldb asks SQL Browser.
// Before this, `localhost\SQLEXPRESS` failed with "invalid URL format".
func TestSQLServerNamedInstance(t *testing.T) {
	cases := []struct {
		host, port   string
		wantHost     string
		wantInstance string
	}{
		{`localhost\SQLEXPRESS`, "1433", "localhost", "/SQLEXPRESS"},
		{`.\SQLEXPRESS`, "", "localhost", "/SQLEXPRESS"},
		{`(local)\SQLEXPRESS`, "1433", "localhost", "/SQLEXPRESS"},
		{`db01\REPORTING`, "14330", "db01:14330", "/REPORTING"},
		{`localhost`, "1433", "localhost:1433", ""},
	}
	for _, c := range cases {
		_, dsn, err := Plan(Config{Driver: "sqlserver", Host: c.host, Port: c.port, User: "sa", Password: "p", Database: "shop"})
		if err != nil {
			t.Fatalf("%s: %v", c.host, err)
		}
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("%s: dsn does not parse: %v", c.host, err)
		}
		if u.Host != c.wantHost || u.Path != c.wantInstance {
			t.Errorf("%s port %q: host=%q path=%q, want host=%q path=%q", c.host, c.port, u.Host, u.Path, c.wantHost, c.wantInstance)
		}
		if u.Query().Get("database") != "shop" {
			t.Errorf("%s: database dropped: %s", c.host, u.RawQuery)
		}
	}
}

func TestOracleNeedsServiceName(t *testing.T) {
	_, err := Inspect(context.Background(), Config{Driver: "oracle", Host: "localhost", User: "system", Password: "p", Database: "  "})
	if !errors.Is(err, ErrOracleServiceName) {
		t.Fatalf("got %v, want ErrOracleServiceName", err)
	}
	if !strings.Contains(err.Error(), "XEPDB1") {
		t.Errorf("message gives no hint: %q", err)
	}
	if r, _ := Classify(err); r != "missing_service_name" {
		t.Errorf("Classify = %q, want missing_service_name", r)
	}
	if _, _, err := Plan(Config{Driver: "oracle", Database: "XEPDB1"}); err != nil {
		t.Errorf("service name given, still refused: %v", err)
	}
}

// The wording people saw in Mixpanel's failure_shape, plus the Windows text
// that the old friendly() missed because it only knew "connection refused".
func TestFriendlyMessages(t *testing.T) {
	cases := []struct {
		cfg        Config
		raw        string
		wantIn     string
		wantReason string
	}{
		{Config{Driver: "postgres"}, "failed to connect to `user=u database=d`: [::1]:5432 (localhost): dial error: dial tcp [::1]:5432: connectex: No connection could be made because the target machine actively refused it.",
			"Nothing is answering at localhost:5432", "host_unreachable"},
		{Config{Driver: "sqlserver", Host: "localhost"}, "unable to open tcp connection with host 'localhost:1433': dial tcp [::1]:1433: connectex: No connection could be made because the target machine actively refused it.",
			`localhost\SQLEXPRESS`, "host_unreachable"},
		{Config{Driver: "mysql", Host: "db.example.com", Port: "3307"}, "dial tcp: lookup db.example.com: no such host",
			"db.example.com:3307", "host_unreachable"},
		{Config{Driver: "postgres", Host: "10.0.0.5"}, "dial tcp 10.0.0.5:5432: i/o timeout",
			"within 10 seconds", "timeout"},
		{Config{Driver: "postgres", Port: "3306"}, "failed to connect to `user=u database=d`: 127.0.0.1:3306 (localhost): failed to receive message: unknown message type: j",
			"isn't PostgreSQL", "wrong_protocol"},
		{Config{Driver: "sqlserver"}, "unable to parse connection string: invalid URL format",
			"Host field should hold only", "bad_input"},
		{Config{Driver: "mysql"}, "Error 1524 (HY000): Plugin 'auth_gssapi_client' is not loaded",
			"authentication plugin", "auth_plugin"},
		{Config{Driver: "sqlserver"}, "mssql: login error: 无法打开登录所请求的数据库 \"x\"。登录失败。",
			"database name does not exist", "database_missing"},
		{Config{Driver: "oracle", Database: "XE"}, "ORA-28009: connection as SYS should be as SYSDBA or SYSOPER",
			"SYSDBA", "auth_failed"},
	}
	for _, c := range cases {
		err := friendly(c.cfg, errors.New(c.raw))
		if !strings.Contains(err.Error(), c.wantIn) {
			t.Errorf("%q\n  shown as %q\n  want it to contain %q", c.raw, err.Error(), c.wantIn)
		}
		if r, _ := Classify(err); r != c.wantReason {
			t.Errorf("%q: Classify = %q, want %q", c.raw, r, c.wantReason)
		}
		// Shape must describe the driver's text, never our own sentence.
		if strings.Contains(Shape(err), "nothing is answering") {
			t.Errorf("Shape picked up the friendly text: %q", Shape(err))
		}
	}
}

func TestDescribeCarriesNoValues(t *testing.T) {
	d := Describe(Config{Driver: "sqlserver", Host: `corp-db.internal\SALES`, Port: "1433", User: "alice", Password: "s3cret", Database: "crm"})
	for _, v := range d {
		s, ok := v.(string)
		if ok && (strings.Contains(s, "corp") || strings.Contains(s, "alice") || strings.Contains(s, "s3cret") || strings.Contains(s, "crm") || strings.Contains(s, "SALES")) {
			t.Fatalf("Describe leaked a value: %v", d)
		}
	}
	if d["host_kind"] != "hostname" || d["port_is_default"] != true || d["has_instance"] != true || d["has_database"] != true {
		t.Errorf("Describe = %v", d)
	}
	for host, want := range map[string]string{"": "localhost", "127.0.0.1": "localhost", "192.168.1.20": "private_ip", "8.8.8.8": "ip", "db.example.com": "hostname", "https://db.example.com": "malformed"} {
		if got := Describe(Config{Driver: "postgres", Host: host})["host_kind"]; got != want {
			t.Errorf("host_kind(%q) = %v, want %v", host, got, want)
		}
	}
}
