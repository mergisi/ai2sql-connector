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
//
// Rule and Word say which check fired, for analytics. Without them every
// rejection arrived as a bare "blocked": 18 of them since September against
// 11 successful runs, and no way to tell a real DELETE from a column the
// guard mistook for one. Word is only ever one of our own list entries or a
// known keyword, never an identifier from the user's schema.
type ErrBlocked struct {
	Reason string
	Rule   string // empty, multi_statement, not_a_query, first_word, keyword, select_into, dangerous_fn, dangerous_prefix
	Word   string
}

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
	wordRe = regexp.MustCompile(`[a-z_][a-z0-9_]*`)
	// SELECT ... INTO <name> creates a table in PostgreSQL and SQL Server, and
	// writes a file in MySQL. INSERT INTO is caught by the "insert" keyword, so
	// any remaining INTO is the dangerous kind.
	intoRe = regexp.MustCompile(`\binto\b`)
)

// strip removes comments and the contents of string/identifier literals, so
// keyword matching cannot be fooled by a value like '; DROP TABLE users --'
// and cannot false-positive on a legitimate string containing "delete".
//
// Comments and literals are read in one left-to-right pass, the way the
// database reads them. They used to be removed in two steps — comments by
// regex first, then literals — and a literal holding "--" or "/*" lost its
// closing quote to the comment step. Everything after it then looked like the
// inside of a string: SELECT '/*' AS x; DELETE FROM users; SELECT '*/' passed
// as one harmless statement. On SQL Server and Oracle the guard is the only
// layer, so that DELETE would have run.
//
// backslashEscapes says whether a backslash-quote continues a literal. MySQL reads it that
// way by default; PostgreSQL, SQL Server and Oracle do not. Validate does not
// know the engine, so it checks both readings.
func strip(sql string, backslashEscapes bool) string {
	var b strings.Builder
	runes := []rune(sql)
	n := len(runes)
	for i := 0; i < n; i++ {
		c := runes[i]
		switch {
		case c == '-' && i+1 < n && runes[i+1] == '-':
			for i < n && runes[i] != '\n' {
				i++
			}
			b.WriteRune('\n')
		case c == '/' && i+1 < n && runes[i+1] == '*':
			// An unclosed comment swallows the rest, as the engine would.
			i += 2
			for i < n && !(runes[i] == '*' && i+1 < n && runes[i+1] == '/') {
				i++
			}
			i++ // past the closing '/'
			b.WriteRune(' ')
		case c == '\'' || c == '"' || c == '`' || c == '[':
			closing := c
			if c == '[' {
				closing = ']'
			}
			i++
			for i < n {
				// Doubled quote is an escaped quote inside the literal.
				if runes[i] == closing {
					if closing != ']' && i+1 < n && runes[i+1] == closing {
						i += 2
						continue
					}
					break
				}
				if backslashEscapes && runes[i] == '\\' && closing != ']' {
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

// Validate reports whether the SQL is safe to run in read-only mode. It must
// be safe under both readings of a backslash inside a literal (see strip).
func Validate(sql string) error {
	if strings.TrimSpace(sql) == "" {
		return &ErrBlocked{Reason: "There is no query to run.", Rule: "empty"}
	}
	if err := validateStripped(strip(sql, false)); err != nil {
		return err
	}
	return validateStripped(strip(sql, true))
}

func validateStripped(stripped string) error {
	stmts := splitStatements(stripped)

	if len(stmts) == 0 {
		return &ErrBlocked{Reason: "There is no query to run.", Rule: "empty"}
	}
	if len(stmts) > 1 {
		return &ErrBlocked{Reason: "Only one statement can be run at a time. This query contains " +
			fmt.Sprint(len(stmts)) + " statements.", Rule: "multi_statement"}
	}

	stmt := stmts[0]
	words := wordRe.FindAllString(stmt, -1)
	if len(words) == 0 {
		return &ErrBlocked{Reason: "This does not look like a query.", Rule: "not_a_query"}
	}

	// Must read, not act. WITH is allowed because CTEs are ordinary in
	// generated SQL, but the keyword scan below still catches a CTE that
	// writes — which PostgreSQL would otherwise execute.
	switch words[0] {
	case "select", "with", "show", "explain", "describe", "desc", "table", "values":
	default:
		return &ErrBlocked{Reason: "AI2SQL Connector is read-only, so it only runs queries that read data. This one starts with " +
			strings.ToUpper(words[0]) + ".", Rule: "first_word", Word: knownFirstWord(words[0])}
	}

	for _, w := range words {
		for _, f := range forbiddenAnywhere {
			if w == f {
				// EXPLAIN ANALYZE actually executes the statement it explains,
				// which is exactly the hole this catches.
				return &ErrBlocked{Reason: "AI2SQL Connector is read-only. This query uses " +
					strings.ToUpper(w) + ", which can change your database.", Rule: "keyword", Word: w}
			}
		}
	}

	if intoRe.MatchString(stmt) {
		return &ErrBlocked{Reason: "AI2SQL Connector is read-only. SELECT ... INTO writes a new table or file.", Rule: "select_into"}
	}

	for _, w := range words {
		for _, d := range dangerousExact {
			if w == d {
				return &ErrBlocked{Reason: "AI2SQL Connector is read-only. This query calls " +
					strings.ToUpper(d) + ", which can reach outside the database.", Rule: "dangerous_fn", Word: d}
			}
		}
		for _, p := range dangerousPrefixes {
			if strings.HasPrefix(w, p) {
				return &ErrBlocked{Reason: "AI2SQL Connector is read-only. This query calls " +
					strings.ToUpper(w) + ", which can reach outside the database.", Rule: "dangerous_prefix", Word: p}
			}
		}
	}
	return nil
}

// Statement openers worth naming in analytics. Anything else — most likely a
// word the model wrote as prose, or an identifier — is reported as "other" so
// no part of the user's schema leaves the machine.
var firstWords = map[string]bool{
	"declare": true, "use": true, "set": true, "begin": true, "if": true,
	"go": true, "print": true, "commit": true, "rollback": true, "lock": true,
	"vacuum": true, "analyze": true, "backup": true, "restore": true, "dbcc": true,
}

func knownFirstWord(w string) string {
	if firstWords[w] {
		return w
	}
	for _, f := range forbiddenAnywhere {
		if w == f {
			return w
		}
	}
	return "other"
}
