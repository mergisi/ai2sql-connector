// Package dbinspect reads table/column metadata from the user's LOCAL
// database. This runs inside the connector, on the user's machine — the
// credentials it takes never leave the process, and only the resulting
// schema outline (names and types, no data) is ever sent to the AI2SQL API
// as generation context.
package dbinspect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
	_ "github.com/sijms/go-ora/v2"
)

type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Table struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
}

type Config struct {
	Driver   string `json:"driver"` // postgres | mysql | sqlserver | oracle
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// Inspect connects, lists user tables with their columns, and disconnects.
func Inspect(ctx context.Context, c Config) ([]Table, error) {
	driverName, dsn, query, err := plan(c)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetConnMaxLifetime(time.Minute)

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, friendly(c, err)
	}
	defer rows.Close()

	byTable := map[string][]Column{}
	var order []string
	for rows.Next() {
		var table, col, typ string
		if err := rows.Scan(&table, &col, &typ); err != nil {
			return nil, err
		}
		if _, seen := byTable[table]; !seen {
			order = append(order, table)
		}
		byTable[table] = append(byTable[table], Column{Name: col, Type: typ})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sort.Strings(order)
	out := make([]Table, 0, len(order))
	for _, t := range order {
		out = append(out, Table{Name: t, Columns: byTable[t]})
	}
	return out, nil
}

// SchemaString flattens tables into the compact format the AI2SQL API takes
// as generation context: "table1:col1(type),col2(type);table2:..."
func SchemaString(tables []Table) string {
	parts := make([]string, 0, len(tables))
	for _, t := range tables {
		cols := make([]string, 0, len(t.Columns))
		for _, c := range t.Columns {
			cols = append(cols, fmt.Sprintf("%s(%s)", c.Name, c.Type))
		}
		parts = append(parts, t.Name+":"+strings.Join(cols, ","))
	}
	return strings.Join(parts, ";")
}

// Plan exposes the driver name and DSN for a config so the query executor can
// open a connection the same way introspection does, without duplicating the
// per-dialect DSN rules.
func Plan(c Config) (driverName, dsn string, err error) {
	d, s, _, e := plan(c)
	return d, s, e
}

func plan(c Config) (driverName, dsn, query string, err error) {
	host := strings.TrimSpace(c.Host)
	if host == "" {
		host = "localhost"
	}
	switch c.Driver {
	case "postgres":
		port := defaultPort(c.Port, "5432")
		u := &url.URL{
			Scheme: "postgres",
			Host:   net.JoinHostPort(host, port),
			Path:   "/" + c.Database,
			// Local databases rarely speak TLS; requiring it here would fail
			// the exact machines this tool exists for.
			RawQuery: "sslmode=disable&connect_timeout=10",
		}
		if c.User != "" {
			if c.Password != "" {
				u.User = url.UserPassword(c.User, c.Password)
			} else {
				u.User = url.User(c.User)
			}
		}
		return "pgx", u.String(),
			`SELECT table_name, column_name, data_type
			   FROM information_schema.columns
			  WHERE table_schema NOT IN ('pg_catalog','information_schema')
			  ORDER BY table_name, ordinal_position`, nil
	case "mysql":
		port := defaultPort(c.Port, "3306")
		return "mysql",
			fmt.Sprintf("%s:%s@tcp(%s)/%s?timeout=10s", c.User, c.Password, net.JoinHostPort(host, port), c.Database),
			`SELECT table_name, column_name, data_type
			   FROM information_schema.columns
			  WHERE table_schema = DATABASE()
			  ORDER BY table_name, ordinal_position`, nil
	case "sqlserver":
		// SQL Server Express installs as a named instance (localhost\SQLEXPRESS)
		// on a dynamic port, so neither "localhost:1433" nor the raw
		// "host\instance" in a URL host works. go-mssqldb takes the instance as
		// the URL path and asks SQL Browser for its port, which only happens
		// when no port is given. The UI fills in 1433 on its own, so that value
		// is treated as "not chosen" when an instance is named.
		h, instance := SplitInstance(host)
		hostPort := net.JoinHostPort(h, defaultPort(c.Port, "1433"))
		path := ""
		if instance != "" {
			path = "/" + instance
			if p := strings.TrimSpace(c.Port); p == "" || p == "1433" {
				hostPort = h
			}
		}
		u := &url.URL{
			Scheme:   "sqlserver",
			Host:     hostPort,
			Path:     path,
			RawQuery: url.Values{"database": {c.Database}, "encrypt": {"disable"}, "dial timeout": {"10"}}.Encode(),
		}
		if c.User != "" {
			u.User = url.UserPassword(c.User, c.Password)
		}
		return "sqlserver", u.String(),
			`SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE
			   FROM INFORMATION_SCHEMA.COLUMNS
			  ORDER BY TABLE_NAME, ORDINAL_POSITION`, nil
	case "oracle":
		// go-ora is pure Go — no Oracle Instant Client on the user's machine,
		// which is the whole point of a single downloadable binary. The
		// "database" field is Oracle's service name (ORCLPDB1, XEPDB1, ...).
		// Without a service name go-ora fails with "empty SID and service
		// name", which tells nobody which field to fill. Stop before dialling.
		if strings.TrimSpace(c.Database) == "" {
			return "", "", "", ErrOracleServiceName
		}
		port := defaultPort(c.Port, "1521")
		u := &url.URL{
			Scheme: "oracle",
			Host:   net.JoinHostPort(host, port),
			Path:   "/" + strings.TrimSpace(c.Database),
		}
		if c.User != "" {
			if c.Password != "" {
				u.User = url.UserPassword(c.User, c.Password)
			} else {
				u.User = url.User(c.User)
			}
		}
		// user_tab_columns: the tables the signed-in schema owns. all_tab_columns
		// would drag in thousands of SYS/SYSTEM dictionary rows on a stock install.
		return "oracle", u.String(),
			`SELECT table_name, column_name, data_type
			   FROM user_tab_columns
			  ORDER BY table_name, column_id`, nil
	default:
		return "", "", "", fmt.Errorf("unsupported driver %q", c.Driver)
	}
}

func defaultPort(p, def string) string {
	if strings.TrimSpace(p) == "" {
		return def
	}
	return strings.TrimSpace(p)
}

// ErrOracleServiceName is returned before any connection is tried when Oracle
// is selected and the Database field (the service name) is empty.
var ErrOracleServiceName = errors.New("Oracle needs a service name in the Database field. It is often XEPDB1 (Oracle XE), FREEPDB1 (Oracle Free) or ORCLPDB1.")

// SplitInstance separates a SQL Server named instance from the host, the way
// people copy it out of SSMS: `localhost\SQLEXPRESS`, `.\SQLEXPRESS` or
// `(local)\SQLEXPRESS`. "." and "(local)" both mean this machine.
func SplitInstance(host string) (h, instance string) {
	h = strings.TrimSpace(host)
	if i := strings.Index(h, `\`); i >= 0 {
		h, instance = strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:])
	}
	switch strings.ToLower(h) {
	case "", ".", "(local)":
		h = "localhost"
	}
	return h, instance
}

// FriendlyError is what Inspect returns for a failed connection: a message a
// non-DBA can act on, plus the driver's own error. Classify and Shape read the
// driver error, so the wording here can change without moving the analytics.
type FriendlyError struct {
	Msg string
	Raw error
}

func (e *FriendlyError) Error() string { return e.Msg + " (" + e.Raw.Error() + ")" }
func (e *FriendlyError) Unwrap() error { return e.Raw }

// friendly rewrites the errors a non-DBA will actually hit into something
// they can act on. Matching runs on the lower-cased driver text, because the
// same failure is worded differently on Windows ("connectex: No connection
// could be made because the target machine actively refused it") than on
// macOS and Linux ("connection refused").
func friendly(c Config, err error) error {
	s := strings.ToLower(err.Error())
	where := address(c)
	wrap := func(msg string) error { return &FriendlyError{Msg: msg, Raw: err} }

	switch {
	case strings.Contains(s, "password authentication failed"), strings.Contains(s, "access denied"),
		strings.Contains(s, "login failed"), strings.Contains(s, "ora-01017"):
		return wrap("The database rejected the username or password.")
	// PostgreSQL words a wrong username as `role "x" does not exist`. It has to
	// be caught before the database-name case below, which would send the
	// person to fix a name that is already right.
	case strings.Contains(s, `role "`) && strings.Contains(s, "does not exist"):
		return wrap("The database has no user with that username.")
	case strings.Contains(s, "sysdba"), strings.Contains(s, "ora-28009"):
		return wrap("Oracle's SYS user can only sign in as SYSDBA. Use a regular user such as SYSTEM or the schema that owns your tables.")
	case strings.Contains(s, "plugin") && strings.Contains(s, "not loaded"),
		strings.Contains(s, "unknown auth plugin"), strings.Contains(s, "authentication plugin"):
		return wrap("This MySQL user signs in with an authentication plugin the connector can't use. Use a user set up with mysql_native_password or caching_sha2_password.")
	case strings.Contains(s, "does not exist"), strings.Contains(s, "unknown database"),
		strings.Contains(s, "ora-12514"), strings.Contains(s, "cannot open database"),
		strings.Contains(s, "无法打开登录所请求的数据库"):
		return wrap("That database name does not exist on the server. Check the Database field.")
	case strings.Contains(s, "unknown message type"), strings.Contains(s, "malformed packet"),
		strings.Contains(s, "unexpected eof"):
		return wrap(fmt.Sprintf("Something answered at %s, but it isn't %s. Check the database type and the port.", where, label(c.Driver)))
	case strings.Contains(s, "invalid url format"), strings.Contains(s, "invalid port"),
		strings.Contains(s, "missing port"), strings.Contains(s, "too many colons"):
		return wrap("The Host field should hold only a name or address, such as localhost or db.example.com, with the port in the Port field.")
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"),
		strings.Contains(s, "timed out"), strings.Contains(s, "timeout expired"):
		return wrap(fmt.Sprintf("Nothing answered at %s within 10 seconds. Check the address, and whether a firewall or VPN is blocking it.", where))
	case strings.Contains(s, "connection refused"), strings.Contains(s, "actively refused"),
		strings.Contains(s, "no connection could be made"), strings.Contains(s, "connectex"),
		strings.Contains(s, "no such host"), strings.Contains(s, "network is unreachable"),
		strings.Contains(s, "host is unreachable"), strings.Contains(s, "ora-12541"),
		strings.Contains(s, "ora-12154"), strings.Contains(s, "server does not exist"),
		strings.Contains(s, "dial tcp"):
		return wrap(unreachable(c, where))
	}
	return err
}

func unreachable(c Config, where string) string {
	msg := fmt.Sprintf("Nothing is answering at %s. Is the database running on this computer? If it's on another server or in the cloud, enter that server's address in Host.", where)
	if c.Driver == "sqlserver" {
		if _, instance := SplitInstance(c.Host); instance == "" {
			msg += ` SQL Server Express runs as a named instance: try localhost\SQLEXPRESS.`
		} else {
			msg += " For a named instance, check that the SQL Server Browser service is running and TCP/IP is enabled in SQL Server Configuration Manager."
		}
	}
	return msg
}

// address is the place the connector tried, as the person typed it.
func address(c Config) string {
	if c.Driver == "sqlserver" {
		if h, instance := SplitInstance(c.Host); instance != "" {
			return h + `\` + instance
		}
	}
	host := strings.TrimSpace(c.Host)
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, defaultPort(c.Port, defaultPorts[c.Driver]))
}

var defaultPorts = map[string]string{"postgres": "5432", "mysql": "3306", "sqlserver": "1433", "oracle": "1521"}

func label(driver string) string {
	switch driver {
	case "postgres":
		return "PostgreSQL"
	case "mysql":
		return "MySQL"
	case "sqlserver":
		return "SQL Server"
	case "oracle":
		return "Oracle"
	}
	return "that database type"
}

// Describe is the shape of a connection attempt, safe to send to analytics:
// what kind of host, whether the port was left at its default, which fields
// were filled. It never carries a host name, an address, a user or a password.
func Describe(c Config) map[string]any {
	h, instance := c.Host, ""
	if c.Driver == "sqlserver" {
		h, instance = SplitInstance(c.Host)
	}
	p := strings.TrimSpace(c.Port)
	return map[string]any{
		"host_kind":       hostKind(h),
		"port_is_default": p == "" || p == defaultPorts[c.Driver],
		"has_instance":    instance != "",
		"has_database":    strings.TrimSpace(c.Database) != "",
		"has_user":        strings.TrimSpace(c.User) != "",
	}
}

func hostKind(host string) string {
	h := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	switch {
	case h == "", h == "localhost", h == ".", h == "(local)", h == "127.0.0.1", h == "::1":
		return "localhost"
	case net.ParseIP(h) != nil:
		if ip := net.ParseIP(h); ip.IsPrivate() {
			return "private_ip"
		}
		return "ip"
	case strings.Contains(h, "://"), strings.Contains(h, "/"):
		return "malformed"
	}
	return "hostname"
}
