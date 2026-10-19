package db

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fiveHundred = 500 * time.Millisecond
	oneHundred  = 100 * time.Millisecond
	fifty       = 50 * time.Millisecond
)

type ephemeralCollectorForTest interface {
	Schedule(nodeID types.NodeID, expiry time.Duration)
	Cancel(nodeID types.NodeID)
	IsScheduled(nodeID types.NodeID) bool
	Start()
	Close()
}

func newEphemeralCollectorForTest(original bool, deleted func(types.NodeID)) ephemeralCollectorForTest {
	if original {
		return newReferenceEphemeralGarbageCollector(deleted)
	}

	return NewEphemeralGarbageCollector(deleted)
}

type ephemeralObservation struct {
	deleted []types.NodeID
	pending []types.NodeID
	queued  int
}

//nolint:gocyclo // Shared deterministic lifecycle traces for the original and current collectors.
func ephemeralTrace(t *testing.T, original bool, scenario string) []ephemeralObservation {
	t.Helper()

	var observations []ephemeralObservation

	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex

		var deleted []types.NodeID

		gc := newEphemeralCollectorForTest(original, func(id types.NodeID) {
			mu.Lock()
			defer mu.Unlock()

			deleted = append(deleted, id)
		})

		closed := false
		defer func() {
			if !closed {
				gc.Close()
			}

			synctest.Wait()
		}()

		observe := func(sorted bool) {
			synctest.Wait()
			mu.Lock()
			ids := slices.Clone(deleted)
			mu.Unlock()

			if sorted {
				slices.Sort(ids)
			}

			var pending []types.NodeID

			for id := types.NodeID(1); id <= 16; id++ {
				if gc.IsScheduled(id) {
					pending = append(pending, id)
				}
			}

			var queued int

			switch e := gc.(type) {
			case *referenceEphemeralGarbageCollector:
				queued = len(e.deleteCh)
			case *EphemeralGarbageCollector:
				queued = len(e.deleteCh)
			}

			observations = append(observations, ephemeralObservation{ids, pending, queued})
		}

		switch scenario {
		case "ordered":
			go gc.Start()

			gc.Schedule(1, 3*time.Second)
			gc.Schedule(2, time.Second)
			gc.Schedule(3, 2*time.Second)
			gc.Cancel(2)
			time.Sleep(2 * time.Second) //nolint:forbidigo // Advance the synctest clock.
			observe(false)
			time.Sleep(time.Second) //nolint:forbidigo // Advance the synctest clock.
			observe(false)
			require.Equal(t, []types.NodeID{3, 1}, observations[1].deleted)
		case "zero":
			gc.Schedule(1, 0)
			observe(false)
			require.Equal(t, 1, observations[0].queued)
			require.Equal(t, []types.NodeID{1}, observations[0].pending)

			go gc.Start()

			observe(false)
			gc.Schedule(1, 0)
			observe(false)
			require.Equal(t, []types.NodeID{1, 1}, observations[2].deleted)
			require.Empty(t, observations[2].pending)
		case "queued_cancel_reschedule":
			gc.Schedule(1, 0)
			gc.Schedule(2, 0)
			observe(false)
			gc.Cancel(1)

			gc.Schedule(2, time.Hour)
			go gc.Start()

			observe(false)
			require.Empty(t, observations[1].deleted)
			gc.Schedule(2, 0)
			observe(false)
			require.Equal(t, []types.NodeID{2}, observations[2].deleted)
		case "full_cancel", "full_reschedule", "full_close":
			for id := types.NodeID(1); id <= 16; id++ {
				gc.Schedule(id, 0)
			}

			observe(true)
			require.Equal(t, 10, observations[0].queued)
			require.Len(t, observations[0].pending, 16)

			if scenario == "full_close" {
				gc.Close()

				closed = true

				gc.Schedule(16, 0)
				gc.Schedule(17, 0)
				require.False(t, gc.IsScheduled(17))
				observe(true)
				require.Equal(t, observations[0], observations[1])

				return
			}

			for id := types.NodeID(1); id <= 16; id++ {
				if scenario == "full_cancel" {
					gc.Cancel(id)
				} else {
					gc.Schedule(id, time.Hour)
				}
			}

			synctest.Wait()

			go gc.Start()

			observe(true)
			require.Empty(t, observations[1].deleted)
			require.Zero(t, observations[1].queued)
			time.Sleep(time.Hour) //nolint:forbidigo // Advance the synctest clock.
			observe(true)

			if scenario == "full_reschedule" {
				var want []types.NodeID
				for id := types.NodeID(1); id <= 16; id++ {
					want = append(want, id)
				}

				require.Equal(t, want, observations[2].deleted)
			} else {
				require.Empty(t, observations[2].deleted)
			}

			require.Empty(t, observations[2].pending)
		}
	})

	return observations
}

func TestEphemeralGarbageCollectorDifferential(t *testing.T) {
	for _, scenario := range []string{
		"ordered", "zero", "queued_cancel_reschedule",
		"full_cancel", "full_reschedule", "full_close",
	} {
		t.Run(scenario, func(t *testing.T) {
			original := ephemeralTrace(t, true, scenario)
			current := ephemeralTrace(t, false, scenario)
			require.Equal(t, original, current)
		})
	}
}

// Count only this collector's timer workers, not unrelated runtime goroutines.
func ephemeralWorkerCount(parkedOnly bool) int {
	stacks := make([]byte, 64*1024)

	for {
		n := runtime.Stack(stacks, true)
		if n == len(stacks) {
			stacks = make([]byte, 2*len(stacks))
			continue
		}

		count := 0

		for stack := range strings.SplitSeq(string(stacks[:n]), "\n\n") {
			if !strings.Contains(stack, "EphemeralGarbageCollector).Schedule.func") {
				continue
			}

			header, _, _ := strings.Cut(stack, "\n")
			if !parkedOnly || strings.Contains(header, "[select") {
				count++
			}
		}

		return count
	}
}

func waitEphemeralWorkers(tb testing.TB, want int) {
	tb.Helper()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		// Let cancelled workers exit before stopping the world to sample stacks.
		runtime.Gosched()

		got := ephemeralWorkerCount(false)
		if got == want {
			return
		}

		select {
		case <-deadline.C:
			tb.Fatalf("timer worker count: got %d, want %d", got, want)
		case <-tick.C:
		}
	}
}

func TestEphemeralGarbageCollectorPendingHasNoWatchers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gc := NewEphemeralGarbageCollector(func(types.NodeID) {
			t.Error("pending timer deleted a node")
		})
		defer gc.Close()

		for id := types.NodeID(1); id <= 100; id++ {
			gc.Schedule(id, time.Hour)
		}

		synctest.Wait()
		require.Zero(t, ephemeralWorkerCount(false))
	})
}

func TestEphemeralGarbageCollectorConcurrentCancelReschedule(t *testing.T) {
	for _, original := range []bool{true, false} {
		t.Run(fmt.Sprintf("original=%v", original), func(t *testing.T) {
			const nodes = 32

			deleted := make(chan types.NodeID, nodes+1)

			gc := newEphemeralCollectorForTest(original, func(id types.NodeID) {
				deleted <- id
			})
			defer gc.Close()

			var wg sync.WaitGroup

			start := make(chan struct{})

			for id := types.NodeID(1); id <= nodes; id++ {
				wg.Go(func() {
					<-start

					for range 16 {
						gc.Schedule(id, 0)
					}
				})
				wg.Go(func() {
					<-start

					for range 16 {
						gc.Cancel(id)
						gc.Schedule(id, time.Hour)
					}
				})
			}

			close(start)
			wg.Wait()

			for id := types.NodeID(1); id <= nodes; id++ {
				gc.Cancel(id)
			}

			waitEphemeralWorkers(t, 0)

			go gc.Start()

			for id := types.NodeID(1); id <= nodes; id++ {
				gc.Schedule(id, 0)
			}

			seen := make(map[types.NodeID]bool, nodes)
			for range nodes {
				select {
				case id := <-deleted:
					require.False(t, seen[id], "duplicate deletion for %d", id)
					require.True(t, id >= 1 && id <= nodes)
					seen[id] = true
				case <-time.After(10 * time.Second):
					t.Fatal("deletion burst did not complete")
				}
			}

			waitEphemeralWorkers(t, 0)
			require.Empty(t, deleted)

			for id := types.NodeID(1); id <= nodes; id++ {
				require.False(t, gc.IsScheduled(id))
			}
		})
	}
}

func TestEphemeralGarbageCollectorConcurrentCloseFullQueue(t *testing.T) {
	for _, original := range []bool{true, false} {
		t.Run(fmt.Sprintf("original=%v", original), func(t *testing.T) {
			var deleted atomic.Int64

			gc := newEphemeralCollectorForTest(original, func(types.NodeID) {
				deleted.Add(1)
			})

			var closeOnce sync.Once

			closeGC := func() { closeOnce.Do(gc.Close) }
			defer closeGC()

			for id := types.NodeID(1); id <= 16; id++ {
				gc.Schedule(id, 0)
			}

			waitEphemeralWorkers(t, 6) // ten queued, six blocked enqueuing

			var wg sync.WaitGroup

			start := make(chan struct{})

			wg.Go(func() {
				<-start

				for range 32 {
					gc.Schedule(16, 0)
				}
			})
			wg.Go(func() {
				<-start

				for range 32 {
					gc.Cancel(16)
				}
			})
			wg.Go(func() {
				<-start
				closeGC()
			})
			close(start)
			wg.Wait()
			waitEphemeralWorkers(t, 0)
			gc.Schedule(17, 0)
			require.False(t, gc.IsScheduled(17))
			require.Zero(t, deleted.Load())
		})
	}
}

// Run one implementation/population per fresh test process: runtime memory
// statistics include the whole process and cannot isolate adjacent subtests.
// HEADSCALE_EPHEMERAL_MEMORY_IMPL=original|current
// HEADSCALE_EPHEMERAL_MEMORY_N=1|100|1000|10000
// Use -count=1 for each invocation.
func TestEphemeralGarbageCollectorRetainedMemory(t *testing.T) {
	impl := os.Getenv("HEADSCALE_EPHEMERAL_MEMORY_IMPL")
	if impl == "" {
		t.Skip("opt-in retained-memory probe; run each population in a fresh process")
	}

	require.Contains(t, []string{"original", "current"}, impl)

	n, err := strconv.ParseUint(os.Getenv("HEADSCALE_EPHEMERAL_MEMORY_N"), 10, 64)
	require.NoError(t, err)
	require.Contains(t, []uint64{1, 100, 1000, 10000}, n)

	waitEphemeralWorkers(t, 0)
	runtime.GC()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	goroutinesBefore := runtime.NumGoroutine()

	var deleted atomic.Int64

	gc := newEphemeralCollectorForTest(impl == "original", func(types.NodeID) {
		deleted.Add(1)
	})
	stopped := make(chan struct{})

	go func() {
		gc.Start()
		close(stopped)
	}()

	defer func() {
		gc.Close()
		<-stopped
		waitEphemeralWorkers(t, 0)
	}()

	for id := types.NodeID(1); id <= types.NodeID(n); id++ {
		gc.Schedule(id, time.Hour)
	}

	wantWorkers := 0
	if impl == "original" {
		wantWorkers = int(n) //nolint:gosec // The allowed populations are at most 10000.
	}

	waitEphemeralWorkers(t, wantWorkers)
	// Include the original workers' select allocations, not just runnable goroutines.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, wantWorkers, ephemeralWorkerCount(true))
	}, 10*time.Second, time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)

	goroutinesAfter := runtime.NumGoroutine()

	for id := types.NodeID(1); id <= types.NodeID(n); id++ {
		require.True(t, gc.IsScheduled(id))
	}

	require.Zero(t, deleted.Load())
	runtime.KeepAlive(gc)
	t.Logf("impl=%s pending=%d workers=%d heap_bytes=%.0f heap_objects=%.0f stack_bytes=%.0f goroutines=%d",
		impl, n, wantWorkers,
		float64(after.HeapAlloc)-float64(before.HeapAlloc),
		float64(after.HeapObjects)-float64(before.HeapObjects),
		float64(after.StackInuse)-float64(before.StackInuse),
		goroutinesAfter-goroutinesBefore)
}

// Time scheduling/churn and complete deletion bursts. Fixture allocation and
// shutdown/reaping are outside timing for both implementations; every iteration
// waits for its workers to exit before the next one starts.
func BenchmarkEphemeralGarbageCollector(b *testing.B) {
	for _, impl := range []string{"original", "current"} {
		for _, mode := range []string{
			"pending", "schedulecancel", "repeatedreschedule", "expirationburst",
		} {
			for _, n := range []types.NodeID{1, 100, 1000, 10000} {
				b.Run(fmt.Sprintf("%s/%s/n=%d", impl, mode, n), func(b *testing.B) {
					b.ReportAllocs()
					b.StopTimer()

					for range b.N {
						func() {
							counts := make([]atomic.Uint32, n+1)
							completed := make(chan types.NodeID, n+1)
							gc := newEphemeralCollectorForTest(impl == "original", func(id types.NodeID) {
								counts[id].Add(1)

								completed <- id
							})
							stopped := make(chan struct{})

							go func() {
								gc.Start()
								close(stopped)
							}()

							defer func() {
								gc.Close()
								<-stopped
								waitEphemeralWorkers(b, 0)
							}()

							b.StartTimer()

							for id := types.NodeID(1); id <= n; id++ {
								switch mode {
								case "pending":
									gc.Schedule(id, time.Hour)
								case "schedulecancel":
									gc.Schedule(id, time.Hour)
									gc.Cancel(id)
								case "repeatedreschedule":
									gc.Schedule(1, time.Hour)
								case "expirationburst":
									gc.Schedule(id, 0)
								}
							}

							if mode == "expirationburst" {
								for range n {
									<-completed
								}
							}

							b.StopTimer()

							for id := types.NodeID(1); id <= n; id++ {
								wantDeleted := uint32(0)
								if mode == "expirationburst" {
									wantDeleted = 1
								}

								if got := counts[id].Load(); got != wantDeleted {
									b.Fatalf("node %d deleted %d times, want %d", id, got, wantDeleted)
								}

								wantPending := mode == "pending" || (mode == "repeatedreschedule" && id == 1)
								if gc.IsScheduled(id) != wantPending {
									b.Fatalf("node %d pending state differs", id)
								}
							}

							if len(completed) != 0 {
								b.Fatal("unexpected deletion callbacks")
							}
						}()
					}
				})
			}
		}
	}
}

// TestEphemeralGarbageCollectorGoRoutineLeak is a test for a goroutine leak in [EphemeralGarbageCollector].
// It creates a new [EphemeralGarbageCollector], schedules several nodes for deletion with a short expiry,
// and verifies that the nodes are deleted when the expiry time passes, and then
// for any leaked goroutines after the garbage collector is closed.
func TestEphemeralGarbageCollectorGoRoutineLeak(t *testing.T) {
	// Count goroutines at the start
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial number of goroutines: %d", initialGoroutines)

	// Basic deletion tracking mechanism
	var (
		deletedIDs  []types.NodeID
		deleteMutex sync.Mutex
		deletionWg  sync.WaitGroup
	)

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()

		deletedIDs = append(deletedIDs, nodeID)

		deleteMutex.Unlock()
		deletionWg.Done()
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	// Schedule several nodes for deletion with short expiry
	const (
		expiry   = fifty
		numNodes = 100
	)

	// Set up wait group for expected deletions

	deletionWg.Add(numNodes)

	for i := 1; i <= numNodes; i++ {
		gc.Schedule(types.NodeID(i), expiry) //nolint:gosec // safe conversion in test
	}

	// Wait for all scheduled deletions to complete
	deletionWg.Wait()

	// Check nodes are deleted
	deleteMutex.Lock()
	assert.Len(t, deletedIDs, numNodes, "Not all nodes were deleted")
	deleteMutex.Unlock()

	// Schedule and immediately cancel to test that part of the code
	for i := numNodes + 1; i <= numNodes*2; i++ {
		nodeID := types.NodeID(i) //nolint:gosec // safe conversion in test
		gc.Schedule(nodeID, time.Hour)
		gc.Cancel(nodeID)
	}

	// Close GC
	gc.Close()

	// Wait for goroutines to clean up and verify no leaks
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		finalGoroutines := runtime.NumGoroutine()
		// NB: We have to allow for a small number of extra goroutines because of test itself
		assert.LessOrEqual(c, finalGoroutines, initialGoroutines+5,
			"There are significantly more goroutines after GC usage, which suggests a leak")
	}, time.Second, 10*time.Millisecond, "goroutines should clean up after GC close")

	t.Logf("Final number of goroutines: %d", runtime.NumGoroutine())
}

// TestEphemeralGarbageCollectorCancelReapsGoroutine verifies that Cancel (and
// reschedule) reaps the per-node watcher goroutine while the collector is still
// running, rather than leaking it until Close. The production churn path is an
// ephemeral node disconnecting (Schedule) then reconnecting (Cancel) before the
// long expiry timer fires; a stopped timer never fires, so a watcher parked
// only on <-timer.C would otherwise leak on every cycle.
func TestEphemeralGarbageCollectorCancelReapsGoroutine(t *testing.T) {
	gc := NewEphemeralGarbageCollector(func(types.NodeID) {})

	go gc.Start()
	defer gc.Close()

	baseline := runtime.NumGoroutine()

	const (
		iterations = 1000
		nodeID     = types.NodeID(42)
	)

	for range iterations {
		gc.Schedule(nodeID, time.Hour) // disconnect: long timer, will not fire
		gc.Cancel(nodeID)              // reconnect: must reap the watcher
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.LessOrEqual(c, runtime.NumGoroutine(), baseline+10,
			"per-node goroutines leaked on Cancel/reschedule")
	}, 2*time.Second, 20*time.Millisecond, "watcher goroutines should be reaped")
}

// TestEphemeralGarbageCollectorCancelBeatsQueuedDeletion verifies that a node
// reconnecting (Cancel) after its deletion has already been queued on the
// internal channel is not deleted. The timer fires and enqueues the deletion;
// Cancel then runs before Start drains it. Start must drop the now-superseded
// deletion rather than removing the freshly reconnected node.
func TestEphemeralGarbageCollectorCancelBeatsQueuedDeletion(t *testing.T) {
	const targetNode types.NodeID = 42

	var (
		mu      sync.Mutex
		deleted []types.NodeID
	)

	e := NewEphemeralGarbageCollector(func(ni types.NodeID) {
		mu.Lock()
		defer mu.Unlock()

		deleted = append(deleted, ni)
	})

	// Schedule with a tiny expiry but do not drain yet: the watcher fires and
	// enqueues the deletion onto the buffered channel.
	e.Schedule(targetNode, time.Millisecond)
	require.Eventually(t, func() bool {
		return len(e.deleteCh) == 1
	}, time.Second, time.Millisecond, "deletion should be queued")

	// Node reconnects before the queue is drained.
	e.Cancel(targetNode)

	go e.Start()
	defer e.Close()

	require.Eventually(t, func() bool {
		return len(e.deleteCh) == 0
	}, time.Second, time.Millisecond, "Start should drain the queued deletion")

	assert.Never(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		return slices.Contains(deleted, targetNode)
	}, 200*time.Millisecond, 10*time.Millisecond,
		"cancelled node must not be deleted")
}

// TestEphemeralGarbageCollectorReschedule is a test for the rescheduling of nodes in [EphemeralGarbageCollector].
// It creates a new [EphemeralGarbageCollector], schedules a node for deletion with a longer expiry,
// and then reschedules it with a shorter expiry, and verifies that the node is deleted only once.
func TestEphemeralGarbageCollectorReschedule(t *testing.T) {
	// Deletion tracking mechanism
	var (
		deletedIDs  []types.NodeID
		deleteMutex sync.Mutex
	)

	deletionNotifier := make(chan types.NodeID, 1)

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()

		deletedIDs = append(deletedIDs, nodeID)

		deleteMutex.Unlock()

		deletionNotifier <- nodeID
	}

	// Start GC
	gc := NewEphemeralGarbageCollector(deleteFunc)

	go gc.Start()
	defer gc.Close()

	const (
		shortExpiry = fifty
		longExpiry  = 1 * time.Hour
	)

	nodeID := types.NodeID(1)

	// Schedule node for deletion with long expiry
	gc.Schedule(nodeID, longExpiry)

	// Reschedule the same node with a shorter expiry
	gc.Schedule(nodeID, shortExpiry)

	// Wait for deletion notification with timeout
	select {
	case deletedNodeID := <-deletionNotifier:
		assert.Equal(t, nodeID, deletedNodeID, "The correct node should be deleted")
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for node deletion")
	}

	// Verify that the node was deleted exactly once
	deleteMutex.Lock()
	assert.Len(t, deletedIDs, 1, "Node should be deleted exactly once")
	assert.Equal(t, nodeID, deletedIDs[0], "The correct node should be deleted")
	deleteMutex.Unlock()
}

// TestEphemeralGarbageCollectorCancelAndReschedule is a test for the cancellation and rescheduling of nodes in [EphemeralGarbageCollector].
// It creates a new [EphemeralGarbageCollector], schedules a node for deletion, cancels it, and then reschedules it,
// and verifies that the node is deleted only once.
func TestEphemeralGarbageCollectorCancelAndReschedule(t *testing.T) {
	// Deletion tracking mechanism
	var (
		deletedIDs  []types.NodeID
		deleteMutex sync.Mutex
	)

	deletionNotifier := make(chan types.NodeID, 1)

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()

		deletedIDs = append(deletedIDs, nodeID)

		deleteMutex.Unlock()

		deletionNotifier <- nodeID
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)

	go gc.Start()
	defer gc.Close()

	nodeID := types.NodeID(1)

	const expiry = fifty

	// Schedule node for deletion
	gc.Schedule(nodeID, expiry)

	// Cancel the scheduled deletion
	gc.Cancel(nodeID)

	// Use a timeout to verify no deletion occurred
	select {
	case <-deletionNotifier:
		t.Fatal("Node was deleted after cancellation")
	case <-time.After(expiry * 2): // Still need a timeout for negative test
		// This is expected - no deletion should occur
	}

	deleteMutex.Lock()
	assert.Empty(t, deletedIDs, "Node should not be deleted after cancellation")
	deleteMutex.Unlock()

	// Reschedule the node
	gc.Schedule(nodeID, expiry)

	// Wait for deletion with timeout
	select {
	case deletedNodeID := <-deletionNotifier:
		// Verify the correct node was deleted
		assert.Equal(t, nodeID, deletedNodeID, "The correct node should be deleted")
	case <-time.After(time.Second): // Longer timeout as a safety net
		t.Fatal("Timed out waiting for node deletion")
	}

	// Verify final state
	deleteMutex.Lock()
	assert.Len(t, deletedIDs, 1, "Node should be deleted after rescheduling")
	assert.Equal(t, nodeID, deletedIDs[0], "The correct node should be deleted")
	deleteMutex.Unlock()
}

// TestEphemeralGarbageCollectorCloseBeforeTimerFires is a test for the closing of the [EphemeralGarbageCollector] before the timer fires.
// It creates a new [EphemeralGarbageCollector], schedules a node for deletion, closes the GC, and verifies that the node is not deleted.
func TestEphemeralGarbageCollectorCloseBeforeTimerFires(t *testing.T) {
	// Deletion tracking
	var (
		deletedIDs  []types.NodeID
		deleteMutex sync.Mutex
	)

	deletionNotifier := make(chan types.NodeID, 1)

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()

		deletedIDs = append(deletedIDs, nodeID)

		deleteMutex.Unlock()

		deletionNotifier <- nodeID
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	const (
		longExpiry = 1 * time.Hour
		shortWait  = fifty * 2
	)

	// Schedule node deletion with a long expiry
	gc.Schedule(types.NodeID(1), longExpiry)

	// Close the GC before the timer
	gc.Close()

	// Verify that no deletion occurred within a reasonable time
	select {
	case <-deletionNotifier:
		t.Fatal("Node was deleted after GC was closed, which should not happen")
	case <-time.After(shortWait):
		// Expected: no deletion should occur
	}

	// Verify that no deletion occurred
	deleteMutex.Lock()
	assert.Empty(t, deletedIDs, "No node should be deleted when GC is closed before timer fires")
	deleteMutex.Unlock()
}

// TestEphemeralGarbageCollectorScheduleAfterClose verifies that calling [EphemeralGarbageCollector.Schedule] after [EphemeralGarbageCollector.Close]
// is a no-op and doesn't cause any panics, goroutine leaks, or other issues.
func TestEphemeralGarbageCollectorScheduleAfterClose(t *testing.T) {
	// Count initial goroutines to check for leaks
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial number of goroutines: %d", initialGoroutines)

	// Deletion tracking
	var (
		deletedIDs  []types.NodeID
		deleteMutex sync.Mutex
	)

	nodeDeleted := make(chan struct{})

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()

		deletedIDs = append(deletedIDs, nodeID)

		deleteMutex.Unlock()
		close(nodeDeleted) // Signal that deletion happened
	}

	// Start new GC
	gc := NewEphemeralGarbageCollector(deleteFunc)

	// Use a WaitGroup to ensure the GC has started
	var startWg sync.WaitGroup
	startWg.Add(1)

	go func() {
		startWg.Done() // Signal that the goroutine has started
		gc.Start()
	}()

	startWg.Wait() // Wait for the GC to start

	// Close GC right away
	gc.Close()

	// Now try to schedule node for deletion with a very short expiry
	// If the Schedule operation incorrectly creates a timer, it would fire quickly
	nodeID := types.NodeID(1)
	gc.Schedule(nodeID, 1*time.Millisecond)

	// Check if any node was deleted (which shouldn't happen)
	// Use timeout to wait for potential deletion
	select {
	case <-nodeDeleted:
		t.Fatal("Node was deleted after GC was closed, which should not happen")
	case <-time.After(fiveHundred):
		// This is the expected path - no deletion should occur
	}

	// Check no node was deleted
	deleteMutex.Lock()

	nodesDeleted := len(deletedIDs)

	deleteMutex.Unlock()
	assert.Equal(t, 0, nodesDeleted, "No nodes should be deleted when Schedule is called after Close")

	// Check for goroutine leaks after GC is fully closed
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		finalGoroutines := runtime.NumGoroutine()
		// Allow for small fluctuations in goroutine count for testing routines etc
		assert.LessOrEqual(c, finalGoroutines, initialGoroutines+2,
			"There should be no significant goroutine leaks when Schedule is called after Close")
	}, time.Second, 10*time.Millisecond, "goroutines should clean up after GC close")

	t.Logf("Final number of goroutines: %d", runtime.NumGoroutine())
}

// TestEphemeralGarbageCollectorConcurrentScheduleAndClose tests the behavior of the garbage collector
// when [EphemeralGarbageCollector.Schedule] and [EphemeralGarbageCollector.Close] are called concurrently from multiple goroutines.
func TestEphemeralGarbageCollectorConcurrentScheduleAndClose(t *testing.T) {
	// Count initial goroutines
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial number of goroutines: %d", initialGoroutines)

	// Deletion tracking mechanism
	var (
		deletedIDs  []types.NodeID
		deleteMutex sync.Mutex
	)

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()

		deletedIDs = append(deletedIDs, nodeID)

		deleteMutex.Unlock()
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	// Number of concurrent scheduling goroutines
	const (
		numSchedulers     = 10
		nodesPerScheduler = 50
	)

	const closeAfterNodes = 25 // Close GC after this many nodes per scheduler

	// Use WaitGroup to wait for all scheduling goroutines to finish
	var wg sync.WaitGroup
	wg.Add(numSchedulers + 1) // +1 for the closer goroutine

	// Create a stopper channel to signal scheduling goroutines to stop
	stopScheduling := make(chan struct{})

	// Track how many nodes have been scheduled
	var scheduledCount atomic.Int64

	// Launch goroutines that continuously schedule nodes
	for schedulerIndex := range numSchedulers {
		go func(schedulerID int) {
			defer wg.Done()

			baseNodeID := schedulerID * nodesPerScheduler

			// Keep scheduling nodes until signaled to stop
			for j := range nodesPerScheduler {
				select {
				case <-stopScheduling:
					return
				default:
					nodeID := types.NodeID(baseNodeID + j + 1) //nolint:gosec // safe conversion in test
					gc.Schedule(nodeID, 1*time.Hour)           // Long expiry to ensure it doesn't trigger during test
					scheduledCount.Add(1)

					// Yield to other goroutines to introduce variability
					runtime.Gosched()
				}
			}
		}(schedulerIndex)
	}

	// Close the garbage collector after some nodes have been scheduled
	go func() {
		defer wg.Done()

		// Wait until enough nodes have been scheduled
		for scheduledCount.Load() < int64(numSchedulers*closeAfterNodes) {
			runtime.Gosched()
		}

		// Close GC
		gc.Close()

		// Signal schedulers to stop
		close(stopScheduling)
	}()

	// Wait for all goroutines to complete
	wg.Wait()

	// Check for leaks using EventuallyWithT
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		finalGoroutines := runtime.NumGoroutine()
		// Allow for a reasonable small variable routine count due to testing
		assert.LessOrEqual(c, finalGoroutines, initialGoroutines+5,
			"There should be no significant goroutine leaks during concurrent Schedule and Close operations")
	}, time.Second, 10*time.Millisecond, "goroutines should clean up")

	t.Logf("Final number of goroutines: %d", runtime.NumGoroutine())
}

// Frozen from 1096abfc8 before the AfterFunc change; only identifiers differ.
// referenceEphemeralGarbageCollector is a garbage collector that will delete nodes after
// a certain amount of time.
// It is used to delete ephemeral nodes ([types.Node.IsEphemeral]) that have disconnected and should be
// cleaned up.
type referenceEphemeralGarbageCollector struct {
	mu sync.Mutex

	deleteFunc  func(types.NodeID)
	toBeDeleted map[types.NodeID]referenceEphemeralTimer
	// gen is bumped for every scheduled deletion so a queued deletion that
	// was superseded by a Cancel or reschedule can be recognised and dropped.
	gen uint64

	deleteCh chan referencePendingDeletion
	cancelCh chan struct{}
}

// referenceEphemeralTimer pairs a node's pending-deletion timer with a done channel
// used to reap its watcher goroutine on Cancel or reschedule, plus the
// generation identifying this particular scheduling. Without the done channel
// a stopped timer never fires and the goroutine leaks until Close.
type referenceEphemeralTimer struct {
	timer *time.Timer
	done  chan struct{}
	gen   uint64
}

// referencePendingDeletion is the generation-stamped deletion a watcher enqueues when
// its timer fires. Start drops it if the node's current generation no longer
// matches, i.e. it was cancelled or rescheduled in the meantime.
type referencePendingDeletion struct {
	nodeID types.NodeID
	gen    uint64
}

// newReferenceEphemeralGarbageCollector creates a new [referenceEphemeralGarbageCollector], it takes
// a deleteFunc that will be called when a node is scheduled for deletion.
func newReferenceEphemeralGarbageCollector(deleteFunc func(types.NodeID)) *referenceEphemeralGarbageCollector {
	return &referenceEphemeralGarbageCollector{
		toBeDeleted: make(map[types.NodeID]referenceEphemeralTimer),
		deleteCh:    make(chan referencePendingDeletion, 10),
		cancelCh:    make(chan struct{}),
		deleteFunc:  deleteFunc,
	}
}

// Close stops the garbage collector.
func (e *referenceEphemeralGarbageCollector) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop all timers
	for _, t := range e.toBeDeleted {
		t.timer.Stop()
	}

	// Close the cancel channel to signal all goroutines to exit
	close(e.cancelCh)
}

// Schedule schedules a node for deletion after the expiry duration.
// If the garbage collector is already closed, this is a no-op.
func (e *referenceEphemeralGarbageCollector) Schedule(nodeID types.NodeID, expiry time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't schedule new timers if the garbage collector is already closed
	select {
	case <-e.cancelCh:
		// The cancel channel is closed, meaning the GC is shutting down
		// or already shut down, so we shouldn't schedule anything new
		return
	default:
		// Continue with scheduling
	}

	// If a timer already exists for this node, stop it and reap its
	// watcher goroutine before scheduling a fresh one.
	if old, exists := e.toBeDeleted[nodeID]; exists {
		old.timer.Stop()
		close(old.done)
	}

	e.gen++
	gen := e.gen
	timer := time.NewTimer(expiry)
	done := make(chan struct{})
	e.toBeDeleted[nodeID] = referenceEphemeralTimer{timer: timer, done: done, gen: gen}
	// Start a goroutine to handle the timer completion
	go func() {
		select {
		case <-timer.C:
			// This is to handle the situation where the GC is shutting down and
			// we are trying to schedule a new node for deletion at the same time
			// i.e. We don't want to send to deleteCh if the GC is shutting down
			// So, we try to send to deleteCh, but also watch for cancelCh
			select {
			case e.deleteCh <- referencePendingDeletion{nodeID: nodeID, gen: gen}:
				// Successfully sent to deleteCh
			case <-e.cancelCh:
				// GC is shutting down, don't send to deleteCh
				return
			case <-done:
				// Cancelled or rescheduled before the send landed.
				return
			}
		case <-done:
			// Cancelled or rescheduled before the timer fired.
			return
		case <-e.cancelCh:
			// If the GC is closed, exit the goroutine
			return
		}
	}()
}

// Cancel cancels the deletion of a node.
func (e *referenceEphemeralGarbageCollector) Cancel(nodeID types.NodeID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if t, ok := e.toBeDeleted[nodeID]; ok {
		t.timer.Stop()
		close(t.done)
		delete(e.toBeDeleted, nodeID)
	}
}

// IsScheduled reports whether a deletion timer is currently armed for nodeID.
func (e *referenceEphemeralGarbageCollector) IsScheduled(nodeID types.NodeID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, ok := e.toBeDeleted[nodeID]

	return ok
}

// Start starts the garbage collector.
func (e *referenceEphemeralGarbageCollector) Start() {
	for {
		select {
		case <-e.cancelCh:
			return
		case pd := <-e.deleteCh:
			e.mu.Lock()

			entry, ok := e.toBeDeleted[pd.nodeID]
			if !ok || entry.gen != pd.gen {
				// Cancelled or rescheduled after this deletion was queued;
				// drop it so a reconnected node is not removed.
				e.mu.Unlock()

				continue
			}

			delete(e.toBeDeleted, pd.nodeID)
			e.mu.Unlock()

			go e.deleteFunc(pd.nodeID)
		}
	}
}
