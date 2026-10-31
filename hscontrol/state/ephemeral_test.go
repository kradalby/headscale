package state

import (
	"bytes"
	"database/sql"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestEphemeralNodeDeleteWithConcurrentUpdate races UpdateNode against
// DeleteNode, as UpdateNodeFromMapRequest races an ephemeral node's logout.
// Whichever commits first, the node ends deleted: an update never re-inserts
// a node, and one that runs after the delete reports the node gone.
func TestEphemeralNodeDeleteWithConcurrentUpdate(t *testing.T) {
	for i := range 20 {
		id := types.NodeID(i + 1) //nolint:gosec // small test ids
		w := newTestWorld(t, createTestNode(id, 1, "test-user", "test-node"))

		var (
			wg      sync.WaitGroup
			updated types.NodeView
			ok      bool
		)

		start := make(chan struct{})

		wg.Go(func() {
			<-start

			updated, ok = w.UpdateNode(id, func(n *types.Node) { n.LastSeen = new(time.Now()) })
		})
		wg.Go(func() {
			<-start

			w.DeleteNode(id)
		})
		close(start)
		wg.Wait()

		_, found := w.snapshot().GetNode(id)
		require.False(t, found, "node must stay deleted")
		require.Equal(t, ok, updated.Valid(), "UpdateNode must report the node it wrote, or none")
	}
}

// registerEphemeralNode registers a node with an ephemeral pre-auth key, as
// a container joining with one does.
func registerEphemeralNode(t *testing.T, s *State, hostname string) types.NodeView {
	t.Helper()

	user, err := s.GetUserByName("persist-user")
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)

	node, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}, key.NewMachine().Public())
	require.NoError(t, err)
	require.True(t, node.IsEphemeral(), "precondition: node is ephemeral")

	return node
}

// registerPersistedNode registers a non-ephemeral node, for tests that need
// an ordinary persisted node besides the ephemeral one.
func registerPersistedNode(t *testing.T, s *State, hostname string) types.NodeView {
	t.Helper()

	user, err := s.GetUserByName("persist-user")
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	node, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}, key.NewMachine().Public())
	require.NoError(t, err)

	return node
}

// stackContains reports whether any goroutine dump contains both want frames.
// The buffer grows until the whole dump fits, so a busy process cannot hide
// the target goroutine past the cut.
func stackContains(want ...string) bool {
	buf := make([]byte, 64<<10)

	n := runtime.Stack(buf, true)
	for n == len(buf) {
		buf = make([]byte, 2*len(buf))
		n = runtime.Stack(buf, true)
	}

	for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
		all := true
		for _, w := range want {
			all = all && strings.Contains(g, w)
		}

		if all {
			return true
		}
	}

	return false
}

// TestGCWaitingOnSessionsKeepsTheControlPlaneRunning pins the lock order of
// DeleteEphemeralNode: a Connect whose world write queues behind a held batch
// keeps connectMu's read lock, and the GC delete waiting on session admission
// must not be holding persistMu while it waits — or every persist, expiry and
// registration in the tailnet stalls behind one inactivity timer.
func TestGCWaitingOnSessionsKeepsTheControlPlaneRunning(t *testing.T) {
	dbPath, s, id := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	probe := registerPersistedNode(t, s, "gc-stall-probe")

	eph := registerEphemeralNode(t, s, "gc-stall-target")
	require.Zero(t, eph.ActiveSessions(), "precondition: the ephemeral node has no session")

	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })

	var wg sync.WaitGroup

	t.Cleanup(func() { unblock(); wg.Wait() })

	wg.Go(func() {
		s.world.update(func(*nodeEdit) { close(entered); <-release })
	})
	<-entered

	// A session queues its world write behind the held batch, holding
	// connectMu's read lock while it waits.
	epoch := make(chan uint64, 1)

	wg.Go(func() { epoch <- s.Connect(id) })

	require.Eventually(t, func() bool {
		s.world.writeMu.Lock()
		defer s.world.writeMu.Unlock()

		return len(s.world.writes) == 1
	}, 5*time.Second, time.Millisecond, "the session's world write must queue behind the held batch")

	gcDone := make(chan error, 1)

	wg.Go(func() {
		_, err := s.DeleteEphemeralNode(eph.ID())
		gcDone <- err
	})

	require.Eventually(t, func() bool {
		return stackContains("(*State).DeleteEphemeralNode(", "[sync.RWMutex.Lock")
	}, 5*time.Second, time.Millisecond, "the GC must park on session admission")

	// While the GC waits, an unrelated persist must complete: persistMu may
	// not be held across the wait.
	persistDone := make(chan error, 1)

	go func() {
		_, err := s.persistNode(probe)
		persistDone <- err
	}()

	select {
	case err := <-persistDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("a GC delete waiting on session admission stalled every persist")
	}

	unblock()
	wg.Wait()
	require.NoError(t, <-gcDone)
	require.NotZero(t, <-epoch, "the blocked session itself must still be admitted")

	_, ok := s.GetNodeByID(eph.ID())
	require.False(t, ok, "the ephemeral node is deleted once sessions release")
}

// TestEphemeralDeletePanicReleasesThePersistLock pins that a panicking
// lifetime delete cannot leak persistMu: the row write is scoped with a
// deferred unlock, so a driver or callback panic leaves the control plane
// writable instead of wedging every registration and persist for the life
// of the process.
func TestEphemeralDeletePanicReleasesThePersistLock(t *testing.T) {
	dbPath, s, id := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "panic-delete-target")

	require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").Register("panic_gc_delete", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			panic("boom")
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove("panic_gc_delete") })

	assert.Panics(t, func() { _, _ = s.DeleteEphemeralNode(eph.ID()) })

	live, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok, "a failed delete must leave the node in memory")
	require.True(t, live.IsEphemeral())

	persistDone := make(chan error, 1)

	view, ok := s.GetNodeByID(id)
	require.True(t, ok)

	go func() {
		_, err := s.persistNode(view)
		persistDone <- err
	}()

	select {
	case err := <-persistDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the panicking delete leaked persistMu; every write is wedged")
	}

	require.NotZero(t, s.Connect(id), "session admission must be released too")
}

// TestLogoutDeletePanicReleasesSessionAdmission pins the same panic safety on
// the logout-driven delete: the ephemeral branch takes connectMu around
// DeleteNode, and a panicking row write must not leak it — leaked, every
// Connect in the tailnet blocks for the life of the process.
func TestLogoutDeletePanicReleasesSessionAdmission(t *testing.T) {
	dbPath, s, id := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "logout-panic-target")

	require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").Register("panic_logout_delete", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			panic("boom")
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove("panic_logout_delete") })

	assert.Panics(t, func() { _, _ = s.LogoutNode(eph, new(time.Now().Add(-time.Hour))) })

	live, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok, "a failed logout delete must leave the node in memory")
	require.True(t, live.IsEphemeral())

	// Session admission must not be wedged by the leaked lock.
	connected := make(chan uint64, 1)

	go func() { connected <- s.Connect(id) }()

	select {
	case epoch := <-connected:
		require.NotZero(t, epoch)
	case <-time.After(2 * time.Second):
		t.Fatal("the panicking logout leaked connectMu; session admission is wedged")
	}
}

// TestLogoutEphemeralDeletionExcludesSessions pins that the logout-driven
// ephemeral delete excludes session admission for its whole length, as the
// GC delete does: a Connect arriving while the row is being deleted must
// either wait or find the node gone, never acquire a live epoch for a node
// the row no longer has.
func TestLogoutEphemeralDeletionExcludesSessions(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "logout-exclude-target")

	sqlEntered, sqlRelease := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(sqlRelease) })

	defer unblock()

	require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").Register("pause_logout_delete", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			close(sqlEntered) //nolint:govet // single delete in the window
			<-sqlRelease
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove("pause_logout_delete") })

	logoutDone := make(chan error, 1)

	go func() {
		_, err := s.LogoutNode(eph, new(time.Now().Add(-time.Hour)))
		logoutDone <- err
	}()

	<-sqlEntered

	epoch := make(chan uint64, 1)
	go func() { epoch <- s.Connect(eph.ID()) }()

	// While the delete is in flight, Connect must park on session
	// admission instead of acquiring the vanishing node.
	require.Eventually(t, func() bool {
		return stackContains("(*State).Connect(", "[sync.RWMutex.RLock")
	}, 5*time.Second, time.Millisecond, "Connect must wait out the delete")

	unblock()
	require.NoError(t, <-logoutDone)
	assert.Zero(t, <-epoch, "admission released after the delete must find the node gone")
	requireNodeGone(t, s, eph.ID())
}

// requireNodeGone asserts the node is absent from memory and the database.
func requireNodeGone(t *testing.T, s *State, id types.NodeID) {
	t.Helper()

	_, ok := s.GetNodeByID(id)
	require.False(t, ok, "node must be gone from memory")

	_, err := s.db.GetNodeByID(id)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound, "node must be gone from the database")
}

// TestPersistNodeToDBPreventsRaceCondition persists a view taken before the
// node left memory. persistNode re-reads memory and must refuse, so a stale
// caller cannot write a node memory no longer holds.
func TestPersistNodeToDBPreventsRaceCondition(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	updated, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostname = "renamed-before-delete"
	})
	require.True(t, ok)

	s.world.DeleteNode(nodeID)

	_, err := s.persistNode(updated)
	require.ErrorIs(t, err, ErrNodeNotInNodeStore)

	row, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.NotEqual(t, "renamed-before-delete", row.Hostname, "the stale view must not be written")
}

// TestPersistNodeToDBChecksMemoryBeforePersist persists a view of an
// ephemeral node taken before its logout deleted it. The deleted row must
// not come back.
func TestPersistNodeToDBChecksMemoryBeforePersist(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node := registerEphemeralNode(t, s, "ephemeral-node")

	stale, ok := s.world.UpdateNode(node.ID(), func(n *types.Node) { n.LastSeen = new(time.Now()) })
	require.True(t, ok)

	require.NoError(t, s.DeleteNode(stale))

	_, err := s.persistNode(stale)
	require.ErrorIs(t, err, ErrNodeNotInNodeStore)
	requireNodeGone(t, s, node.ID())
}

// TestEphemeralNodeLogoutRaceCondition races a map request against the
// logout of an ephemeral node. Persisting the map request after the logout
// would re-insert the node the logout deleted.
func TestEphemeralNodeLogoutRaceCondition(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	for range 10 {
		node := registerEphemeralNode(t, s, "ephemeral-node")

		req := tailcfg.MapRequest{
			NodeKey:   node.NodeKey(),
			Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:41641")},
			Hostinfo:  &tailcfg.Hostinfo{Hostname: "ephemeral-node"},
		}

		var (
			wg        sync.WaitGroup
			deleteErr error
		)

		start := make(chan struct{})

		wg.Go(func() {
			<-start

			// Fails when the logout won; either order is fine.
			_ = s.UpdateNodeFromMapRequest(node.ID(), req)
		})
		wg.Go(func() {
			<-start

			deleteErr = s.DeleteNode(node)
		})
		close(start)
		wg.Wait()

		require.NoError(t, deleteErr)
		requireNodeGone(t, s, node.ID())
	}
}

// TestUpdateNodeFromMapRequestEphemeralLogoutSequence delivers a map request
// that was in flight when its ephemeral node logged out. It must fail and
// leave the node deleted.
func TestUpdateNodeFromMapRequestEphemeralLogoutSequence(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node := registerEphemeralNode(t, s, "ephemeral-node")

	require.NoError(t, s.DeleteNode(node))

	err := s.UpdateNodeFromMapRequest(node.ID(), tailcfg.MapRequest{
		NodeKey:   node.NodeKey(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:41641")},
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "ephemeral-node"},
	})
	require.ErrorIs(t, err, ErrNodeNotInNodeStore)
	requireNodeGone(t, s, node.ID())
}

// TestUpdateAfterDeleteInOneBatch holds a commit open, queues a delete and
// then an update of the same node behind it, and lets both commit in one
// batch, in that order: the update must report the node gone, with no
// view of it. Results are the batch's committed state, so the other order
// reports the node gone too.
func TestUpdateAfterDeleteInOneBatch(t *testing.T) {
	const id = types.NodeID(1)

	queued := func(w *world) int {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes)
	}

	// batch runs first and then second, both queued behind a commit held
	// open, so they commit together in that order.
	batch := func(w *world, first, second func()) {
		inCommit, release := make(chan struct{}), make(chan struct{})

		go w.update(func(*nodeEdit) {
			close(inCommit)
			<-release
		})

		<-inCommit

		var wg sync.WaitGroup

		wg.Go(first)
		require.Eventually(t, func() bool { return queued(w) == 1 }, time.Second, time.Millisecond)

		wg.Go(second)
		require.Eventually(t, func() bool { return queued(w) == 2 }, time.Second, time.Millisecond)

		close(release)
		wg.Wait()
	}

	t.Run("delete then update", func(t *testing.T) {
		w := newTestWorld(t, createTestNode(id, 1, "test-user", "test-node"))

		var (
			updated types.NodeView
			ok      bool
		)

		batch(w,
			func() { w.DeleteNode(id) },
			func() { updated, ok = w.UpdateNode(id, func(n *types.Node) { n.Hostname = "late" }) },
		)

		assert.False(t, ok, "an update after the delete finds no node")
		assert.False(t, updated.Valid(), "and returns no view of it")

		_, found := w.snapshot().GetNode(id)
		assert.False(t, found, "an update never re-inserts a deleted node")
	})

	t.Run("update then delete", func(t *testing.T) {
		w := newTestWorld(t, createTestNode(id, 1, "test-user", "test-node"))

		var (
			updated types.NodeView
			ok      bool
		)

		batch(w,
			func() { updated, ok = w.UpdateNode(id, func(n *types.Node) { n.Hostname = "early" }) },
			func() { w.DeleteNode(id) },
		)

		// Results are the batch's committed state, where the node is gone.
		assert.False(t, ok)
		assert.False(t, updated.Valid())

		_, found := w.snapshot().GetNode(id)
		assert.False(t, found)
	})
}

// TestDoubleDeleteRunsTeardownOnce pins the delete's ownership rule: a second
// delete arriving for a node whose row another delete already dropped must
// not report failure, and must not run the teardown (IP frees, deleted
// callbacks) a second time — a double free could hand out an IP that was
// already reallocated. The GC completes fully before the admin API's stale
// view reaches its delete, so the sequence is deterministic.
func TestDoubleDeleteRunsTeardownOnce(t *testing.T) {
	dbPath, s, id := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "double-delete-target")

	deleted := make(chan types.NodeID, 4)

	s.OnNodeDeleted(func(id types.NodeID) { deleted <- id })

	// The admin API's view, read before any delete runs.
	stale, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok)

	// The GC delete fully wins the race: row and world node gone,
	// teardown run.
	gone, err := s.DeleteEphemeralNode(eph.ID())
	require.NoError(t, err)
	require.True(t, gone)
	require.Len(t, deleted, 1, "the winning delete runs the teardown")

	// The admin delete arrives with its stale view. The row is already
	// gone, so it reports success and must not run the teardown again.
	require.NoError(t, s.DeleteNode(stale), "an already-deleted row is success, not an error")
	require.Len(t, deleted, 1, "the teardown must run exactly once")
	require.Equal(t, eph.ID(), <-deleted)

	requireNodeGone(t, s, eph.ID())
	require.NotZero(t, s.Connect(id), "unrelated nodes are unaffected")
}

// TestDisconnectVanishedRowIsNotAnErrorLog pins the expected-race log level:
// a session tearing down inside its own node's delete window persists against
// a gone row, and the log must not read as a database fault.
func TestDisconnectVanishedRowIsNotAnErrorLog(t *testing.T) {
	dbPath, s, id := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()

	t.Cleanup(func() {
		log.Logger = previousLogger

		zerolog.SetGlobalLevel(previousLevel)
	})

	var output bytes.Buffer

	log.Logger = zerolog.New(&output)

	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	require.NotZero(t, s.Connect(id))

	// The delete's window: row gone, world node still present.
	require.NoError(t, s.db.DeleteNode(node.AsStruct()))

	require.NoError(t, s.Disconnect(id, 1))

	assert.NotContains(t, output.String(), "failed to update last seen",
		"the expected race must not read as a database fault")
	assert.Contains(t, output.String(), "node vanished before last seen persist")
}

// stripIPv6 clears a node's IPv6 address in memory and in its row, leaving
// an address backfill a family to assign while a delete is in flight.
func stripIPv6(t *testing.T, s *State, id types.NodeID) {
	t.Helper()

	_, ok := s.world.UpdateNode(id, func(n *types.Node) { n.IPv6 = nil })
	require.True(t, ok)
	require.NoError(t, s.db.DB.Model(&types.Node{}).Where("id = ?", id).Update("ipv6", nil).Error)
}

// TestDeleteFreesTheAddressesItsRecheckSaw pins the admin delete's teardown:
// the caller's view can go stale behind the row write's lock, and a backfill
// landing in between must not leave its address allocated forever.
func TestDeleteFreesTheAddressesItsRecheckSaw(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	node := registerPersistedNode(t, s, "backfill-delete-target")

	// The admin API's view, read while the node has no IPv6.
	stripIPv6(t, s, node.ID())

	stale, ok := s.GetNodeByID(node.ID())
	require.True(t, ok)
	require.False(t, stale.IPv6().Valid(), "precondition: the stale view has no IPv6")

	// A backfill assigns the node a fresh IPv6 after the view was read.
	_, err := s.BackfillNodeIPs()
	require.NoError(t, err)

	current, ok := s.GetNodeByID(node.ID())
	require.True(t, ok)
	require.True(t, current.IPv6().Valid())

	// The precondition the teardown is about to prove it frees.
	used, err := s.ipAlloc.IsUsed(current.IPv6().Get())
	require.NoError(t, err)
	require.True(t, used, "precondition: the backfilled address is in use")

	// The delete arrives with the stale view.
	require.NoError(t, s.DeleteNode(stale))

	// The teardown must free the addresses the delete's recheck saw, not
	// the stale view's: the backfilled IPv6 must be reusable.
	used, err = s.ipAlloc.IsUsed(current.IPv6().Get())
	require.NoError(t, err)
	assert.False(t, used, "the backfilled address must be freed with the node")

	used, err = s.ipAlloc.IsUsed(current.IPv4().Get())
	require.NoError(t, err)
	assert.False(t, used, "the unchanged address must be freed too")

	requireNodeGone(t, s, node.ID())
}

// TestEphemeralGCFreesTheAddressesItsRecheckSaw pins the GC delete's
// teardown: a backfill landing between the GC's lifetime decision and its
// row write must be freed with the node, not leaked until a restart.
func TestEphemeralGCFreesTheAddressesItsRecheckSaw(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "backfill-gc-target")
	stripIPv6(t, s, eph.ID())

	// Hold the GC at its session-admission gate: the phase-1 candidate view
	// was read before the backfill, and the re-check is what must save it.
	// The release is a deferred once, so a failure at any later step still
	// unblocks the parked goroutine, which drains into its buffered channels
	// and exits instead of leaking with the lock held.
	s.connectMu.RLock()

	release := sync.OnceFunc(s.connectMu.RUnlock)
	defer release()

	gcGone := make(chan bool, 1)
	gcErr := make(chan error, 1)

	go func() {
		gone, err := s.DeleteEphemeralNode(eph.ID())

		gcGone <- gone

		gcErr <- err
	}()

	require.Eventually(t, func() bool {
		return stackContains("(*State).DeleteEphemeralNode(", "[sync.RWMutex.Lock")
	}, 5*time.Second, time.Millisecond, "the GC must park on session admission")

	_, err := s.BackfillNodeIPs()
	require.NoError(t, err)

	backfilled, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok)
	require.True(t, backfilled.IPv6().Valid())

	// The precondition the teardown is about to prove it frees.
	used, err := s.ipAlloc.IsUsed(backfilled.IPv6().Get())
	require.NoError(t, err)
	require.True(t, used, "precondition: the backfilled address is in use")

	release()
	require.NoError(t, <-gcErr, "the GC delete")
	require.True(t, <-gcGone, "the GC delete wins the row")

	used, err = s.ipAlloc.IsUsed(backfilled.IPv6().Get())
	require.NoError(t, err)
	assert.False(t, used, "the teardown must free the address the re-check saw")

	requireNodeGone(t, s, eph.ID())
}

// TestDeleteRemovesWorldNodeOrphanedByADeadWinner pins the recovery from a
// delete that dropped the row and died before removing the world node: a
// later delete must complete the world removal (the node would otherwise
// orphan in peers' maps until restart) without running the teardown a second
// time.
func TestDeleteRemovesWorldNodeOrphanedByADeadWinner(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "orphan-target")

	deleted := make(chan types.NodeID, 4)

	s.OnNodeDeleted(func(id types.NodeID) { deleted <- id })

	// The state a dead winner leaves behind: row dropped, world node alive,
	// teardown never ran.
	require.NoError(t, s.db.DeleteNode(eph.AsStruct()))

	view, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok)

	// The admin delete completes the world removal.
	require.NoError(t, s.DeleteNode(view))

	_, ok = s.GetNodeByID(eph.ID())
	require.False(t, ok, "a delete arriving for a dead winner's node must remove it from memory")
	require.Empty(t, deleted, "no teardown may run: the row was not this delete's to drop")

	// The GC path completes it the same way.
	eph2 := registerEphemeralNode(t, s, "orphan-target-2")
	require.NoError(t, s.db.DeleteNode(eph2.AsStruct()))

	gone, err := s.DeleteEphemeralNode(eph2.ID())
	require.NoError(t, err)
	require.False(t, gone, "the row was already dropped")

	_, ok = s.GetNodeByID(eph2.ID())
	require.False(t, ok, "the GC must complete a dead winner's world removal")
	require.Empty(t, deleted, "still no teardown: the addresses heal at restart")
}

// TestDeleteOutcomeNeverReportsDroppedRowWithAnError pins the tri-state's
// contract: the outcome is meaningful only when the error is nil, and the
// zero value must be safe — a future caller that reads the outcome first
// must never be told it owns a teardown for a row it failed to drop.
func TestDeleteOutcomeNeverReportsDroppedRowWithAnError(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)
	_ = dbPath

	t.Cleanup(func() { _ = s.Close() })

	eph := registerEphemeralNode(t, s, "outcome-error-target")

	require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").Register("fail_delete_outcome", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			_ = tx.AddError(sql.ErrConnDone)
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove("fail_delete_outcome") })

	view, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok)

	outcome, _, err := s.deleteNodeRow(view)
	require.Error(t, err)
	assert.NotEqual(t, deleteDroppedRow, outcome,
		"a failed row write must not claim the teardown")

	outcome, _, err = s.deleteEphemeralRow(view)
	require.Error(t, err)
	assert.NotEqual(t, deleteDroppedRow, outcome,
		"a failed row write must not claim the teardown")

	// The failed deletes leave the node alive on both paths, in memory and
	// in its row: a write that errored must not have dropped the row
	// either — the transaction rolls back.
	live, ok := s.GetNodeByID(eph.ID())
	require.True(t, ok)
	require.True(t, live.IsEphemeral())

	durable, err := s.db.GetNodeByID(eph.ID())
	require.NoError(t, err, "the row must survive a failed delete")
	require.True(t, durable.IsEphemeral())
}
