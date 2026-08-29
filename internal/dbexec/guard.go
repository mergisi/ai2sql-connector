// Package dbexec runs a generated query against the user's local database and
// refuses anything that could change it.
//
// The guard is deliberately not "does it start with SELECT". That check passes
// for `SELECT * INTO backup FROM users` (which creates a table), for
// `SELECT 1; DROP TABLE users` (two statements), and for a data-modifying CTE
// like `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d`, which
// PostgreSQL executes happily. Everything here exists because one of those
// slips past the obvious check.
//
// Classification is only the first layer. Execute() also asks the server to
// enforce read-only where the engine supports it, and the product tells users
// to connect with a read-only role. Any one layer failing should not be enough.
package dbexec

import (
	"fmt"
	"regexp"
	"strings"
)

// ErrBlocked is returned for anything the guard will not run. The message is
// written for the person reading it, not for a log.
type ErrBlocked struct{ Reason string }

func (e *ErrBlocked) Error() string { return e.Reason }

// Words that make a statement dangerous no matter where they appear, because
// a read-looking statement can still carry them: a data-modifying CTE hides
// DELETE in the middle, and EXPLAIN ANALYZE INSERT executes the INSERT.
//
// Everything that is only dangerous as the opening keyword — SET, BEGIN,
// COMMIT, LOCK, VACUUM, BACKUP and friends — is deliberately absent. The
// first-word allowlist below already rejects those, and listing them here
// would block an ordinary query against a table called "backup" or a column
// called "start".
var forbiddenAnywhere = []string{
	"insert", "update", "delete", "drop", "alter", "truncate", "create",
	"grant", "revoke", "merge", "upsert",
	"exec", "execute", "call",
	"copy", "outfile", "dumpfile", "infile",
	"attach", "detach", "pragma", "shutdown",
}

// Functions that reach outside the query even inside a SELECT. Matched as
// whole identifiers, not substrings: this list used to be checked with
// strings.Contains, which blocked an ordinary read of a column called
// exp_date (it contains "xp_") or bulk_qty (it contains "bulk"). A Pro trial
// on a 537-table SQL Server schema hit exactly that and cancelled.
var dangerousExact = []string{
	"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
	"lo_import", "lo_export", "dblink", "pg_terminate_backend", "pg_cancel_backend",
	"load_file", "sys_exec", "sys_eval",
	"openrowset", "opendatasource", "bulk",
	// Oracle: packages that reach outside the database from inside a SELECT.
	// dbms_ as a family is deliberately NOT here — dbms_random and dbms_lob
	// appear in ordinary read queries; only the escape hatches are named.
	"dbms_scheduler", "dbms_java", "dbms_pipe", "dbms_backup_restore",
}

// Families where the danger is the prefix of the identifier itself —
// xp_cmdshell, sp_OACreate, sp_executesql. The identifier has to START with
// these, so exp_date and resp_time are left alone.
// utl_ covers Oracle's utl_file/utl_http/utl_tcp/utl_smtp family — every one
// of them is an exfiltration or file-access vector, and no ordinary column
// starts with utl_.
var dangerousPrefixes = []string{"xp_", "sp_oa", "sp_execute", "utl_"}

var (
	lineComment  = regexp.MustCompile(`--[^\n]*`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	wordRe       = regexp.MustCompile(`[a-z_][a-z0-9_]*`)
	// SELECT ... INTO <name> creates a table in PostgreSQL and SQL Server, and
	// writes a file in MySQL. INSERT INTO is caught by the "insert" keyword, so
	// any remaining INTO is the dangerous kind.
	intoRe = regexp.MustCompile(`\binto\b`)
)

// strip removes comments and the contents of string/identifier literals, so
// keyword matching cannot be fooled by a value like '; DROP TABLE users --'
// and cannot false-positive on a legitimate string containing "delete".
func strip(sql string) string {
	s := blockComment.ReplaceAllString(sql, " ")
	s = lineComment.ReplaceAllString(s, " ")

	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '\'', '"', '`', '[':
			closing := c
			if c == '[' {
				closing = ']'
			}
			i++
			for i < len(runes) {
				// Doubled quote is an escaped quote inside the literal.
				if runes[i] == closing {
					if closing != ']' && i+1 < len(runes) && runes[i+1] == closing {
						i += 2
						continue
					}
					break
				}
				if runes[i] == '\\' && closing != ']' {
					i++ // skip the escaped character
				}
				i++
			}
			b.WriteRune(' ') // literals become whitespace
		default:
			b.WriteRune(c)
		}
	}
	return strings.ToLower(b.String())
}

// splitStatements returns the non-empty statements in the stripped SQL. A
// trailing semicolon is normal and does not count as a second statement.
func splitStatements(stripped string) []string {
	var out []string
	for _, part := range strings.Split(stripped, ";") {
		if strings.TrimSpace(part) != "" {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return out
}

// Validate reports whether the SQL is safe to run in read-only mode.
func Validate(sql string) error {
	if strings.TrimSpace(sql) == "" {
		return &ErrBlocked{Reason: "There is no query to run."}
	}
	stripped := strip(sql)
	stmts := splitStatements(stripped)

	if len(stmts) == 0 {
		return &ErrBlocked{Reason: "There is no query to run."}
	}
	if len(stmts) > 1 {
		return &ErrBlocked{Reason: "Only one statement can be run at a time. This query contains " +
			fmt.Sprint(len(stmts)) + " statements."}
	}

	stmt := stmts[0]
	words := wordRe.FindAllString(stmt, -1)
	if len(words) == 0 {
		return &ErrBlocked{Reason: "This does not look like a query."}
	}

	// Must read, not act. WITH is allowed because CTEs are ordinary in
	// generated SQL, but the keyword scan below still catches a CTE that
	// writes — which PostgreSQL would otherwise execute.
	switch words[0] {
	case "select", "with", "show", "explain", "describe", "desc", "table", "values":
	default:
		return &ErrBlocked{Reason: "AI2SQL Connector is read-only, so it only runs queries that read data. This one starts with " +
			strings.ToUpper(words[0]) + "."}
	}

	for _, w := range words {
		for _, f := range forbiddenAnywhere {
			if w == f {
				// EXPLAIN ANALYZE actually executes the statement it explains,
				// which is exactly the hole this catches.
				return &ErrBlocked{Reason: "AI2SQL Connector is read-only. This query uses " +
					strings.ToUpper(w) + ", which can change your database."}
			}
		}
	}

	if intoRe.MatchString(stmt) {
		return &ErrBlocked{Reason: "AI2SQL Connector is read-only. SELECT ... INTO writes a new table or file."}
	}

	for _, w := range words {
		for _, d := range dangerousExact {
			if w == d {
				return &ErrBlocked{Reason: "AI2SQL Connector is read-only. This query calls " +
					strings.ToUpper(d) + ", which can reach outside the database."}
			}
		}
		for _, p := range dangerousPrefixes {
			if strings.HasPrefix(w, p) {
				return &ErrBlocked{Reason: "AI2SQL Connector is read-only. This query calls " +
					strings.ToUpper(w) + ", which can reach outside the database."}
			}
		}
	}
	return nil
}
