package dbexec

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mergisi/ai2sql-connector/internal/dbinspect"
)

const (
	MaxRows      = 500
	QueryTimeout = 30 * time.Second
)

type Result struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	RowCount  int      `json:"row_count"`
	Truncated bool     `json:"truncated"`
	ElapsedMs int64    `json:"elapsed_ms"`
}

// One query at a time, as the product promises. A second Run while one is in
// flight is refused rather than queued, so a slow query cannot pile up behind
// an impatient user.
var running sync.Mutex

var ErrBusy = errors.New("A query is already running. Wait for it to finish.")

// Execute validates the SQL, opens a connection to the user's local database,
// and runs it read-only. Nothing leaves the machine: rows are read here and
// returned to the local UI.
func Execute(ctx context.Context, cfg dbinspect.Config, query string) (*Result, error) {
	if err := Validate(query); err != nil {
		return nil, err
	}
	if !running.TryLock() {
		return nil, ErrBusy
	}
	defer running.Unlock()

	driverName, dsn, err := dbinspect.Plan(cfg)
	if err != nil {
		return nil, err
	}
	if driverName == "oracle" {
		// Oracle rejects a trailing semicolon (ORA-00933); every other engine
		// tolerates it, and generated SQL almost always carries one.
		query = strings.TrimRight(strings.TrimSpace(query), ";")
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	started := time.Now()
	rows, err := queryReadOnly(ctx, db, driverName, query)
	if err != nil {
		return nil, friendly(err, ctx)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, friendly(err, ctx)
	}

	out := &Result{Columns: cols, Rows: [][]any{}}
	// Truncation happens by stopping the read, not by rewriting the query —
	// adding a LIMIT would change results that already carry their own LIMIT
	// or ORDER BY semantics.
	for rows.Next() {
		if len(out.Rows) >= MaxRows {
			out.Truncated = true
			break
		}
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, friendly(err, ctx)
		}
		out.Rows = append(out.Rows, normalize(raw))
	}
	if err := rows.Err(); err != nil {
		return nil, friendly(err, ctx)
	}
	out.RowCount = len(out.Rows)
	out.ElapsedMs = time.Since(started).Milliseconds()
	return out, nil
}

// queryReadOnly asks the server to enforce read-only where the engine can.
// PostgreSQL and MySQL both support a read-only transaction, which rejects a
// write even if the classifier somehow let one through — the second layer of
// defense. SQL Server has no equivalent, so there the classifier and a
// read-only login are what stand in the way, which is why the UI recommends one.
// Oracle sits with SQL Server: go-ora does not honor TxOptions.ReadOnly, and
// claiming a protection the driver silently drops would be worse than not
// having it.
func queryReadOnly(ctx context.Context, db *sql.DB, driverName, query string) (*sql.Rows, error) {
	switch driverName {
	case "pgx", "mysql":
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			// An engine that refuses the read-only transaction is not a reason
			// to silently run without one.
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		// The rows outlive this call; the transaction is rolled back when the
		// caller closes them, which database/sql does via the tx's connection.
		go func() {
			<-ctx.Done()
			tx.Rollback()
		}()
		return rows, nil
	default:
		return db.QueryContext(ctx, query)
	}
}

// normalize turns driver types into values that survive JSON. []byte is the
// common one: MySQL returns almost everything as bytes, which would otherwise
// arrive in the UI as base64.
func normalize(raw []any) []any {
	out := make([]any, len(raw))
	for i, v := range raw {
		switch t := v.(type) {
		case []byte:
			out[i] = string(t)
		case time.Time:
			out[i] = t.Format(time.RFC3339)
		default:
			out[i] = v
		}
	}
	return out
}

// friendly turns driver errors into something a person can act on, without
// leaking a stack trace or the driver's internal phrasing.
func friendly(err error, ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("The query took longer than %d seconds and was stopped.", int(QueryTimeout.Seconds()))
	}
	s := err.Error()
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "connection refused"), strings.Contains(low, "no such host"):
		return errors.New("Could not reach the database. Is it still running?")
	case strings.Contains(low, "password authentication failed"), strings.Contains(low, "access denied"),
		strings.Contains(low, "login failed"), strings.Contains(low, "ora-01017"):
		return errors.New("The database rejected the username or password.")
	case strings.Contains(low, "permission denied"), strings.Contains(low, "must be owner"):
		return errors.New("This database user is not allowed to read that: " + s)
	case strings.Contains(low, "does not exist"), strings.Contains(low, "unknown column"),
		strings.Contains(low, "unknown table"), strings.Contains(low, "invalid object name"),
		strings.Contains(low, "doesn't exist"):
		return errors.New(s) // the engine's own wording is the useful part here
	case strings.Contains(low, "syntax error"):
		return errors.New(s)
	case strings.Contains(low, "read-only"), strings.Contains(low, "read only"):
		return errors.New("The database refused a write. AI2SQL Connector runs queries read-only.")
	default:
		return errors.New(s)
	}
}
