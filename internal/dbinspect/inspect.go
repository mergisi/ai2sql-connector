// Package dbinspect reads table/column metadata from the user's LOCAL
// database. This runs inside the connector, on the user's machine — the
// credentials it takes never leave the process, and only the resulting
// schema outline (names and types, no data) is ever sent to the AI2SQL API
// as generation context.
package dbinspect

import (
	"context"
	"database/sql"
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
		return nil, friendly(err)
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
		port := defaultPort(c.Port, "1433")
		u := &url.URL{
			Scheme:   "sqlserver",
			Host:     net.JoinHostPort(host, port),
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
		port := defaultPort(c.Port, "1521")
		u := &url.URL{
			Scheme: "oracle",
			Host:   net.JoinHostPort(host, port),
			Path:   "/" + c.Database,
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

// friendly rewrites the errors a non-DBA will actually hit into something
// they can act on.
func friendly(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return fmt.Errorf("nothing is listening there — is the database running? (%s)", s)
	case strings.Contains(s, "password authentication failed"), strings.Contains(s, "Access denied"), strings.Contains(s, "Login failed"), strings.Contains(s, "ORA-01017"):
		return fmt.Errorf("the database rejected the username or password (%s)", s)
	case strings.Contains(s, "does not exist"), strings.Contains(s, "Unknown database"), strings.Contains(s, "ORA-12514"):
		return fmt.Errorf("that database name does not exist on the server (%s)", s)
	default:
		return err
	}
}
