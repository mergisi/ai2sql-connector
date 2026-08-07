package tunnel

import (
	"io"
	"log"
)

// discardLogger satisfies yamux's *log.Logger requirement without writing
// anywhere.
var discardLogger = log.New(io.Discard, "", 0)
