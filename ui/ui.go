// Package ui embeds the connector's local web interface. It lives in its own
// package because go:embed cannot reference parent directories from
// cmd/connector.
package ui

import "embed"

//go:embed index.html
var FS embed.FS
