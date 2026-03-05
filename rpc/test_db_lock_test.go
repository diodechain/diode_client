package rpc

import "sync"

// testDBMu serializes tests that swap the global db.DB handle.
// Several rpc tests rely on process-wide state, so they cannot run concurrently under -race.
var testDBMu sync.Mutex
