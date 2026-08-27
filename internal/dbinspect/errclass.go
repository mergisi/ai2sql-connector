package dbinspect

import (
	"regexp"
	"strings"
)

// Classify turns a driver error into a category and, where the driver
// supplies one, its error code.
//
// The raw message is never returned: a failed DSN can carry a host, a
// username or a password, and these values are sent to analytics. The
// category plus the code is enough to tell an unreachable host from a
// rejected password, which is the distinction the funnel needs.
func Classify(err error) (reason, code string) {
	if err == nil {
		return "", ""
	}
	msg := strings.ToLower(err.Error())
	code = extractCode(err.Error())

	switch {
	// Ordered so the most specific match wins: a TLS failure often also
	// mentions the connection, and an auth failure often mentions the user.
	case containsAny(msg, "ora-01017", "error 1045", "error 18456", "28p01",
		"access denied", "authentication failed", "login failed",
		"password authentication", "invalid username", "auth failed"):
		return "auth_failed", code

	case containsAny(msg, "tls", "ssl", "x509", "certificate"):
		return "tls", code

	case containsAny(msg, "i/o timeout", "context deadline exceeded",
		"timeout expired", "connection timed out", "handshake timeout"):
		return "timeout", code

	case containsAny(msg, "connection refused", "no such host", "network is unreachable",
		"host is unreachable", "no connection could be made", "dial tcp",
		"ora-12154", "ora-12541", "server does not exist", "connectex"):
		return "host_unreachable", code

	case containsAny(msg, "unknown database", "database does not exist",
		"cannot open database", "ora-01017: invalid", "does not exist and login failed",
		"error 1049", "3d000"):
		return "database_missing", code

	case containsAny(msg, "permission denied", "insufficient privileges",
		"ora-00942", "not authorized", "42501", "error 1044"):
		return "permission_denied", code

	case containsAny(msg, "unsupported driver", "unknown driver"):
		return "driver_unsupported", code
	}
	return "unknown", code
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// Driver error codes, in the shapes the four supported drivers emit them.
// Anything not matched here is dropped rather than guessed at.
var codePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bORA-\d{5}\b`),               // Oracle
	regexp.MustCompile(`\bSQLSTATE (\w{5})\b`),        // pgx
	regexp.MustCompile(`\(SQLSTATE (\w{5})\)`),        // pgx, parenthesised
	regexp.MustCompile(`\bError (\d{4})\b`),           // MySQL
	regexp.MustCompile(`\bmssql: .*?Number: (\d+)\b`), // go-mssqldb
	regexp.MustCompile(`\bError Number: ?(\d+)\b`),
}

func extractCode(msg string) string {
	for _, re := range codePatterns {
		if m := re.FindStringSubmatch(msg); m != nil {
			if len(m) > 1 && m[1] != "" {
				return m[1]
			}
			return m[0]
		}
	}
	return ""
}
