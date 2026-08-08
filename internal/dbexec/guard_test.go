package dbexec

import "testing"

// The allowed cases are ordinary generated SQL. If the guard rejects these the
// feature is useless; if it accepts anything in the blocked list the feature is
// dangerous.
func TestValidateAllows(t *testing.T) {
	ok := []string{
		`SELECT * FROM customers`,
		`select id, name from customers where country = 'DE';`,
		`SELECT c.name, SUM(o.total) AS revenue
		   FROM customers c JOIN orders o ON o.customer_id = c.id
		  GROUP BY c.name ORDER BY revenue DESC`,
		`WITH recent AS (SELECT * FROM orders WHERE ordered_at > now() - interval '30 days')
		 SELECT customer_id, count(*) FROM recent GROUP BY customer_id`,
		// A string literal that happens to contain scary words.
		`SELECT * FROM logs WHERE message = 'delete from users'`,
		// A column whose name embeds a keyword.
		`SELECT created_at, updated_at FROM orders`,
		`SELECT * FROM "user-updates"`,
		`-- a comment mentioning DROP TABLE
		 SELECT 1`,
		`EXPLAIN SELECT * FROM orders`,
		`SHOW TABLES`,
	}
	for _, q := range ok {
		if err := Validate(q); err != nil {
			t.Errorf("should allow but blocked:\n  %s\n  reason: %v", q, err)
		}
	}
}

func TestValidateBlocks(t *testing.T) {
	bad := []struct{ name, sql string }{
		{"plain delete", `DELETE FROM users`},
		{"update", `UPDATE users SET name = 'x'`},
		{"insert", `INSERT INTO users (name) VALUES ('x')`},
		{"drop", `DROP TABLE users`},
		{"truncate", `TRUNCATE users`},
		{"grant", `GRANT ALL ON users TO public`},

		// The cases a startsWith("SELECT") check would wave through:
		{"second statement", `SELECT 1; DROP TABLE users`},
		{"second statement with comment", `SELECT 1; -- x
		 DELETE FROM users`},
		{"select into table", `SELECT * INTO backup FROM users`},
		{"mysql outfile", `SELECT * FROM users INTO OUTFILE '/tmp/x.csv'`},
		{"data-modifying CTE", `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d`},
		{"explain analyze executes", `EXPLAIN ANALYZE DELETE FROM users`},
		{"comment hiding a write", `/* SELECT */ DROP TABLE users`},
		{"file read", `SELECT pg_read_file('/etc/passwd')`},
		{"mysql load_file", `SELECT load_file('/etc/passwd')`},
		{"mssql xp_cmdshell", `SELECT * FROM openrowset('x','y','z')`},
		{"call procedure", `CALL do_something()`},
		{"set session", `SET search_path = evil`},
		{"empty", `   `},
	}
	for _, c := range bad {
		if err := Validate(c.sql); err == nil {
			t.Errorf("should block %s but allowed: %s", c.name, c.sql)
		}
	}
}

// A quoted identifier must not let a keyword through, and an escaped quote
// must not end the literal early.
func TestStripHandlesLiterals(t *testing.T) {
	cases := map[string]bool{
		`SELECT 'it''s fine; DROP TABLE users' AS note`: true,  // allowed
		`SELECT "drop" FROM t`:                          true,  // quoted identifier
		`SELECT 'a' ; DROP TABLE t`:                     false, // real second statement
	}
	for sql, wantAllow := range cases {
		err := Validate(sql)
		if wantAllow && err != nil {
			t.Errorf("should allow: %s (%v)", sql, err)
		}
		if !wantAllow && err == nil {
			t.Errorf("should block: %s", sql)
		}
	}
}

// A guard that blocks legitimate queries is its own kind of failure. These use
// words that are only dangerous as an opening keyword, as ordinary identifiers.
func TestValidateDoesNotOverBlock(t *testing.T) {
	ok := []string{
		`SELECT * FROM backup_runs`,
		`SELECT start, "end" FROM sessions`,
		`SELECT set_name FROM collections`,
		`SELECT * FROM analyze_results WHERE cluster = 'a'`,
		`SELECT lock_status FROM doors`,
		`SELECT COUNT(*) FROM load_history`,
	}
	for _, q := range ok {
		if err := Validate(q); err != nil {
			t.Errorf("over-blocked a legitimate query:\n  %s\n  reason: %v", q, err)
		}
	}
}

// SELECT ... INTO must still be caught on its own merit, not because the
// target table happens to be named after a keyword.
func TestSelectIntoBlockedByItself(t *testing.T) {
	if err := Validate(`SELECT * INTO snapshot_2026 FROM customers`); err == nil {
		t.Error("SELECT INTO should be blocked")
	}
}
