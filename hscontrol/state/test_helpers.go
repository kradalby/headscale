package state

import (
	"time"
)

// Batch tuning for test configs, favouring speed over production values.
const (
	TestBatchSize    = 5
	TestBatchTimeout = 5 * time.Millisecond
)
