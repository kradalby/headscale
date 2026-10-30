package hscontrol

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type delayedSuccessResponseWriter struct {
	header http.Header

	firstWriteDelay time.Duration

	firstWriteStarted     chan struct{}
	firstWriteStartedOnce sync.Once

	firstWriteFinished     chan struct{}
	firstWriteFinishedOnce sync.Once

	mu         sync.Mutex
	writeCount int
	body       []byte
}

// deadlineResponseWriter simulates an HTTP/2 response blocked on flow control.
// The write only returns when the handler expires its per-stream write deadline.
type deadlineResponseWriter struct {
	header http.Header

	blockWrites atomic.Bool
	writeCount  atomic.Int64

	writeStarted     chan struct{}
	writeStartedOnce sync.Once
	deadlineSet      chan struct{}
	deadlineSetOnce  sync.Once
	deadlineReturn   <-chan struct{}
}

func newDeadlineResponseWriter() *deadlineResponseWriter {
	return &deadlineResponseWriter{
		header:       make(http.Header),
		writeStarted: make(chan struct{}),
		deadlineSet:  make(chan struct{}),
	}
}

func (w *deadlineResponseWriter) Header() http.Header {
	return w.header
}

func (w *deadlineResponseWriter) WriteHeader(int) {}

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	w.writeCount.Add(1)

	if !w.blockWrites.Load() {
		return len(data), nil
	}

	w.writeStartedOnce.Do(func() { close(w.writeStarted) })
	<-w.deadlineSet

	return 0, context.DeadlineExceeded
}

func (w *deadlineResponseWriter) Flush() {}

func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		w.deadlineSetOnce.Do(func() { close(w.deadlineSet) })
	}

	if w.deadlineReturn != nil {
		<-w.deadlineReturn
	}

	return nil
}

func (w *deadlineResponseWriter) WriteStarted() <-chan struct{} {
	return w.writeStarted
}

func (w *deadlineResponseWriter) BlockWrites() {
	w.blockWrites.Store(true)
}

func (w *deadlineResponseWriter) WriteCount() int64 {
	return w.writeCount.Load()
}

func newDelayedSuccessResponseWriter(firstWriteDelay time.Duration) *delayedSuccessResponseWriter {
	return &delayedSuccessResponseWriter{
		header:             make(http.Header),
		firstWriteDelay:    firstWriteDelay,
		firstWriteStarted:  make(chan struct{}),
		firstWriteFinished: make(chan struct{}),
	}
}

func (w *delayedSuccessResponseWriter) Header() http.Header {
	return w.header
}

func (w *delayedSuccessResponseWriter) WriteHeader(int) {}

func (w *delayedSuccessResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	w.writeCount++
	writeCount := w.writeCount
	w.body = append(w.body, data...)
	w.mu.Unlock()

	if writeCount == 1 {
		// Only the first write is delayed. This simulates a transiently
		// wedged map response the session must recover from.
		w.firstWriteStartedOnce.Do(func() {
			close(w.firstWriteStarted)
		})

		timer := time.NewTimer(w.firstWriteDelay)
		defer timer.Stop()

		<-timer.C

		w.firstWriteFinishedOnce.Do(func() {
			close(w.firstWriteFinished)
		})
	}

	return len(data), nil
}

func (w *delayedSuccessResponseWriter) Flush() {}

func (w *delayedSuccessResponseWriter) FirstWriteStarted() <-chan struct{} {
	return w.firstWriteStarted
}

func (w *delayedSuccessResponseWriter) FirstWriteFinished() <-chan struct{} {
	return w.firstWriteFinished
}

func (w *delayedSuccessResponseWriter) WriteCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.writeCount
}

func (w *delayedSuccessResponseWriter) Body() string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return string(w.body)
}

// recordingResponseWriter records the status code and whether anything was
// written, so a test can tell an explicit error response apart from a handler
// that returned without writing (which net/http turns into an empty 200 the
// client reads as "unexpected EOF").
type recordingResponseWriter struct {
	mu     sync.Mutex
	header http.Header
	status int
	writes int
}

func (w *recordingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}

	return w.header
}

func (w *recordingResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.status == 0 {
		w.status = code
	}
}

func (w *recordingResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.status == 0 {
		w.status = http.StatusOK
	}

	w.writes++

	return len(data), nil
}

func (w *recordingResponseWriter) Flush() {}

func (w *recordingResponseWriter) statusCode() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.status
}

func TestNonStreamMapRequestRejectsReauthenticatedKey(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("map-reauth")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine().Public()
	initial, err := app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: key.NewNode().Public(), Hostinfo: &tailcfg.Hostinfo{Hostname: "before-reauth"},
		Expiry: time.Now().Add(time.Hour),
	}, machineKey)
	require.NoError(t, err)

	node := initial.AsStruct()
	ns := noiseServer{headscale: app, machineKey: node.MachineKey}
	req := tailcfg.MapRequest{
		NodeKey: node.NodeKey, DiscoKey: key.NewDisco().Public(), OmitPeers: true,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:4242")},
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "stale", NetInfo: &tailcfg.NetInfo{PreferredDERP: 7},
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		},
	}

	// Authenticate the request, then delay its mutation across real reauthentication.
	authenticated, err := ns.getAndValidateNode(req)
	require.NoError(t, err)

	writer := httptest.NewRecorder()
	session := app.newMapSession(t.Context(), req, writer, authenticated.AsStruct())
	registered, err := app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: key.NewNode().Public(), Hostinfo: &tailcfg.Hostinfo{Hostname: "reauthenticated"},
		Expiry: time.Now().Add(time.Hour),
	}, node.MachineKey)
	require.NoError(t, err)
	require.Equal(t, node.ID, registered.ID())

	before := app.state.Snapshot()
	durableBefore, err := app.state.DB().GetNodeByID(node.ID)
	require.NoError(t, err)
	session.serve()
	assert.Equal(t, http.StatusNotFound, writer.Code)
	assert.Equal(t, before.Rev(), app.state.Snapshot().Rev(), "rejected requests must not publish")
	live, ok := app.state.GetNodeByID(node.ID)
	require.True(t, ok)
	assert.Equal(t, registered.AsStruct(), live.AsStruct())

	durableAfter, err := app.state.DB().GetNodeByID(node.ID)
	require.NoError(t, err)
	assert.Equal(t, durableBefore, durableAfter, "rejected requests must not persist")

	// The same payload remains a valid update when authenticated with the live key.
	req.NodeKey = registered.NodeKey()
	authenticated, err = ns.getAndValidateNode(req)
	require.NoError(t, err)

	writer = httptest.NewRecorder()
	app.newMapSession(t.Context(), req, writer, authenticated.AsStruct()).serve()
	require.Equal(t, http.StatusOK, writer.Code)

	live, ok = app.state.GetNodeByID(node.ID)
	require.True(t, ok)
	assert.Equal(t, req.NodeKey, live.NodeKey())
	assert.Equal(t, req.DiscoKey, live.DiscoKey())
	assert.Equal(t, req.Hostinfo, live.Hostinfo().AsStruct())
	assert.Equal(t, req.Endpoints, live.Endpoints().AsSlice())

	durableAfter, err = app.state.DB().GetNodeByID(node.ID)
	require.NoError(t, err)
	assert.Equal(t, req.NodeKey, durableAfter.NodeKey)
	assert.Equal(t, req.DiscoKey, durableAfter.DiscoKey)
	assert.Equal(t, req.Hostinfo, durableAfter.Hostinfo)
	assert.Equal(t, types.AddrPorts(req.Endpoints), durableAfter.Endpoints)
}

// TestServeLongPollWritesErrorWhenInitialMapFails proves that when the initial
// map cannot be generated (here: the node's own GivenName is invalid, so
// WithSelfNode fails and AddNode errors), serveLongPoll writes an explicit HTTP
// error instead of returning with no body. Returning empty leaves net/http to
// send an empty 200, which the Tailscale client reports as
// "PollNetMap: ... unexpected EOF" and retries forever (issue #3346).
func TestServeLongPollWritesErrorWhenInitialMapFails(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("self-bad-name-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "self-bad-name-node")

	// Corrupt the node's stored name to empty so GetFQDN fails for itself,
	// then reload state so the bad row enters memory verbatim.
	require.NoError(t, app.state.Close())

	database, err := db.NewHeadscaleDatabase(app.cfg)
	require.NoError(t, err)
	require.NoError(t, database.DB.
		Model(&types.Node{}).
		Where("id = ?", createdNode.ID).
		Update("given_name", "").Error)
	require.NoError(t, database.Close())

	app.state, err = state.NewState(app.cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, app.state.Close())
	})

	nodeView, ok := app.state.GetNodeByID(createdNode.ID)
	require.True(t, ok)

	node := nodeView.AsStruct()

	ctx, cancel := context.WithCancel(context.Background())
	writer := &recordingResponseWriter{}
	session := app.newMapSession(ctx, tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node)

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	t.Cleanup(func() {
		// Break the post-disconnect reconnect wait so the goroutine exits.
		// A second live session lets the cleanup skip the reconnect grace.
		other := app.mapHub.Join(node.ID, func() {})

		cancel()

		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
		}

		app.mapHub.Leave(other)
	})

	assert.Eventually(t, func() bool {
		return writer.statusCode() >= http.StatusInternalServerError
	}, 2*time.Second, 10*time.Millisecond,
		"serveLongPoll must write an HTTP error response when the initial map cannot be built, not an empty 200")
}

// TestDelayedStreamDoesNotOverwriteReauthentication resumes a stream captured
// before reauthentication only after the new key and explicit update landed.
func TestDelayedStreamDoesNotOverwriteReauthentication(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("stream-reauth")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine().Public()
	oldKey, newKey := key.NewNode().Public(), key.NewNode().Public()
	register := func(nodeKey key.NodePublic) {
		t.Helper()

		_, err := app.handleRegister(t.Context(), tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  nodeKey,
			Hostinfo: &tailcfg.Hostinfo{Hostname: "stream-node"},
		}, machineKey)
		require.NoError(t, err)
	}
	register(oldKey)
	old, ok := app.state.GetNodeByNodeKey(oldKey)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	writer := newDelayedSuccessResponseWriter(0)
	stream := app.newMapSession(ctx, tailcfg.MapRequest{
		Stream:    true,
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   oldKey,
		DiscoKey:  key.NewDisco().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")},
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "old-stream-name"},
	}, writer, old.AsStruct())

	register(newKey)
	current, ok := app.state.GetNodeByNodeKey(newKey)
	require.True(t, ok)
	require.Equal(t, old.ID(), current.ID())

	route := netip.MustParsePrefix("10.55.0.0/16")
	update := tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		OmitPeers: true,
		NodeKey:   newKey,
		DiscoKey:  key.NewDisco().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:5678")},
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "updated-name", RoutableIPs: []netip.Prefix{route}},
	}
	response := httptest.NewRecorder()
	app.newMapSession(t.Context(), update, response, current.AsStruct()).serve()
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	_, err = app.state.SetApprovedRoutes(current.ID(), []netip.Prefix{route})
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		stream.serveLongPoll()
		close(done)
	}()

	t.Cleanup(func() {
		cancel()
		app.mapHub.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("stream did not stop")
		}
	})

	select {
	case <-writer.FirstWriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not send its initial map")
	}

	got, ok := app.state.GetNodeByID(current.ID())
	require.True(t, ok)
	assert.Equal(t, newKey, got.NodeKey())
	assert.Equal(t, update.DiscoKey, got.DiscoKey())
	assert.Equal(t, update.Endpoints, got.Endpoints().AsSlice())
	assert.Equal(t, update.Hostinfo, got.Hostinfo().AsStruct())
	assert.Equal(t, update.Hostinfo.Hostname, got.Hostname())
	assert.Equal(t, []netip.Prefix{route}, got.AnnouncedRoutes())
	assert.Equal(t, []netip.Prefix{route}, got.ApprovedRoutes().AsSlice())

	stored, err := app.state.DB().GetNodeByID(current.ID())
	require.NoError(t, err)
	assert.Equal(t, newKey, stored.NodeKey, "the old stream must not persist the superseded key")
}

// TestFailedReconnectDoesNotCancelEphemeralGC proves that a
// long-poll reconnect attempt which fails in [state.State.Connect] must
// not cancel a previously armed ephemeral GC timer. Cancelling at the start of
// [mapSession.serveLongPoll] left departed ephemeral nodes stuck offline with
// no deletion scheduled (https://github.com/juanfont/headscale/issues/3382).
func TestFailedReconnectDoesNotCancelEphemeralGC(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-cancel-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "eph-gc-cancel-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}, machineKey.Public())
	require.NoError(t, err)

	nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, nodeView.IsEphemeral(), "node must be ephemeral so Cancel would arm on long-poll")

	node := nodeView.AsStruct()

	// Arm a long-lived deletion timer — the state after a normal disconnect
	// has called afterServeLongPoll. A long expiry avoids racing the
	// fail-before-Connect path below.
	app.ephemeralGC.Schedule(node.ID, time.Hour)
	require.True(t, app.ephemeralGC.IsScheduled(node.ID), "test sanity: GC timer must be armed")

	// Drop the node from memory so Connect fails, while the session still
	// carries an ephemeral AuthKey (so the old Cancel-on-entry path would
	// clear the timer).
	app.state.DeleteNodeFromStoreForTest(node.ID)

	writer := &recordingResponseWriter{}
	session := app.newMapSession(context.Background(), tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node)

	session.serveLongPoll()

	assert.GreaterOrEqual(t, writer.statusCode(), http.StatusInternalServerError,
		"failed reconnect must write an HTTP error before Connect")
	assert.True(t, app.ephemeralGC.IsScheduled(node.ID),
		"failed reconnect must not cancel the ephemeral GC timer (issue #3382)")
}

// TestEphemeralGCSparesNodeMadePermanent arms an ephemeral node's timer,
// then makes the node permanent, as a re-registration with a reusable key
// does: the timer firing must not delete it, and its session ending must
// not arm a new one.
func TestEphemeralGCSparesNodeMadePermanent(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.cfg.Node.Ephemeral.InactivityTimeout = 50 * time.Millisecond
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-permanent-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "eph-gc-permanent-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}, key.NewMachine().Public())
	require.NoError(t, err)

	nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, nodeView.IsEphemeral(), "test sanity: node must be ephemeral")

	session := app.newMapSession(context.Background(), tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, &recordingResponseWriter{}, nodeView.AsStruct())

	permanent := nodeView.AsStruct()
	key := *permanent.AuthKey
	key.Ephemeral = false
	permanent.AuthKey = &key
	app.state.PutNodeInStoreForTest(*permanent)

	// The session's copy still says ephemeral; its end must not arm a timer.
	session.afterServeLongPoll()
	assert.False(t, app.ephemeralGC.IsScheduled(nodeView.ID()), "a session ending must not arm a permanent node's timer")

	// A timer armed while it was ephemeral fires, and spares it.
	app.ephemeralGC.Schedule(nodeView.ID(), app.cfg.Node.Ephemeral.InactivityTimeout)
	require.True(t, app.ephemeralGC.IsScheduled(nodeView.ID()), "test sanity: the timer is armed")

	assert.Never(t, func() bool {
		_, ok := app.state.GetNodeByID(nodeView.ID())

		return !ok
	}, time.Second, 10*time.Millisecond, "a node made permanent must survive its ephemeral timer")

	// Nothing here cancels the timer, so unscheduled means it fired.
	assert.False(t, app.ephemeralGC.IsScheduled(nodeView.ID()), "test sanity: the timer fired")
}

func TestEphemeralGCRechecksAfterRegistrationSQL(t *testing.T) {
	for _, change := range []string{"make_permanent", "reconnect"} {
		t.Run(change, func(t *testing.T) {
			app := createTestApp(t)
			app.StartEphemeralGCForTest(t)
			user := app.state.CreateUserForTest("gc-reauth")
			initial, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
			require.NoError(t, err)

			machine := key.NewMachine().Public()
			req := tailcfg.RegisterRequest{
				Auth: &tailcfg.RegisterResponseAuth{AuthKey: initial.Key}, NodeKey: key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "gc-reauth"},
			}
			node, err := app.state.HandleNodeFromPreAuthKey(req, machine)
			require.NoError(t, err)

			if change == "make_permanent" {
				permanent, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
				require.NoError(t, err)

				req.Auth = &tailcfg.RegisterResponseAuth{AuthKey: permanent.Key}
			}

			sqlEntered, sqlRelease := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(sqlRelease) })
			// A second nodes write in the window must fail the test with
			// context, not "close of closed channel".
			entered := sync.OnceFunc(func() { close(sqlEntered) })

			require.NoError(t, app.state.DB().DB.Callback().Update().Before("gorm:update").Register("pause_gc_reauth", func(tx *gorm.DB) {
				if tx.Statement.Table == "nodes" {
					entered()
					<-sqlRelease
				}
			}))
			t.Cleanup(func() { _ = app.state.DB().DB.Callback().Update().Remove("pause_gc_reauth") })

			done, finished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(finished)

				_, err := app.state.HandleNodeFromPreAuthKey(req, machine)
				done <- err
			}()

			defer func() { release(); <-finished }()

			<-sqlEntered
			app.ephemeralGC.Schedule(node.ID(), 0)
			require.Eventually(t, ephemeralGCInFlight, 5*time.Second, time.Millisecond, "GC must wait behind registration SQL")

			if change == "reconnect" {
				epoch := make(chan uint64, 1)
				go func() { epoch <- app.state.Connect(node.ID()) }()

				select {
				case connected := <-epoch:
					require.NotZero(t, connected, "registration SQL must not block session admission")
				case <-time.After(5 * time.Second):
					t.Fatal("Connect blocked behind registration SQL")
				}
			}

			release()
			require.NoError(t, <-done)
			require.Eventually(t, func() bool { return !ephemeralGCInFlight() }, 5*time.Second, time.Millisecond)

			live, ok := app.state.GetNodeByID(node.ID())
			require.True(t, ok, "GC must recheck the state published while it waited")

			durable, err := app.state.DB().GetNodeByID(node.ID())
			require.NoError(t, err)

			if change == "make_permanent" {
				assert.False(t, live.IsEphemeral())
				assert.False(t, durable.IsEphemeral())
			} else {
				assert.Equal(t, 1, live.ActiveSessions())
			}
		})
	}
}

func TestEphemeralGCExcludesConnectDuringDeletion(t *testing.T) {
	app := createTestApp(t)
	app.StartEphemeralGCForTest(t)
	user := app.state.CreateUserForTest("gc-connect")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)
	node, err := app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{AuthKey: pak.Key}, NodeKey: key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "gc-connect"},
	}, key.NewMachine().Public())
	require.NoError(t, err)

	sqlEntered, sqlRelease := make(chan struct{}), make(chan struct{})

	release := sync.OnceFunc(func() { close(sqlRelease) })
	defer release()
	// A second nodes write in the window must fail with context, not
	// "close of closed channel".
	entered := sync.OnceFunc(func() { close(sqlEntered) })

	require.NoError(t, app.state.DB().DB.Callback().Delete().Before("gorm:delete").Register("pause_gc_delete", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			entered()
			<-sqlRelease
		}
	}))
	t.Cleanup(func() { _ = app.state.DB().DB.Callback().Delete().Remove("pause_gc_delete") })
	app.ephemeralGC.Schedule(node.ID(), 0)
	<-sqlEntered

	connected := make(chan uint64, 1)
	go func() { connected <- app.state.Connect(node.ID()) }()

	var epoch uint64

	returned := false

	require.Eventually(t, func() bool {
		select {
		case epoch = <-connected:
			returned = true
			return true
		default:
			// A dump that fills the buffer is cut short and can miss the
			// target goroutine, so it grows until the dump fits.
			buf := make([]byte, 64<<10)

			n := runtime.Stack(buf, true)
			for n == len(buf) {
				buf = make([]byte, 2*len(buf))
				n = runtime.Stack(buf, true)
			}

			for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
				if strings.Contains(g, "(*State).Connect(") && strings.Contains(g, "[sync.RWMutex.RLock") {
					return true
				}
			}

			return false
		}
	}, 5*time.Second, time.Millisecond)
	release()

	if !returned {
		epoch = <-connected
	}

	assert.Zero(t, epoch, "Connect must not acquire a node being durably deleted")
	require.Eventually(t, func() bool { return !ephemeralGCInFlight() }, 5*time.Second, time.Millisecond)

	_, ok := app.state.GetNodeByID(node.ID())
	assert.False(t, ok)
}

func TestEphemeralGCDeletionFailurePreservesNode(t *testing.T) {
	app := createTestApp(t)
	app.StartEphemeralGCForTest(t)
	user := app.state.CreateUserForTest("gc-failure")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)
	node, err := app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{AuthKey: pak.Key}, NodeKey: key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "gc-failure"},
	}, key.NewMachine().Public())
	require.NoError(t, err)

	attempted := make(chan struct{})
	attempt := sync.OnceFunc(func() { close(attempted) })

	require.NoError(t, app.state.DB().DB.Callback().Delete().Before("gorm:delete").Register("fail_gc_delete", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			_ = tx.AddError(sql.ErrConnDone)

			attempt()
		}
	}))
	t.Cleanup(func() { _ = app.state.DB().DB.Callback().Delete().Remove("fail_gc_delete") })
	app.ephemeralGC.Schedule(node.ID(), 0)
	<-attempted
	require.Eventually(t, func() bool { return !ephemeralGCInFlight() }, 5*time.Second, time.Millisecond)

	live, ok := app.state.GetNodeByID(node.ID())
	require.True(t, ok)
	assert.Equal(t, node.AsStruct(), live.AsStruct())
	durable, err := app.state.DB().GetNodeByID(node.ID())
	require.NoError(t, err)
	assert.Equal(t, node.NodeKey(), durable.NodeKey)
	assert.True(t, durable.IsEphemeral())
	require.NotZero(t, app.state.Connect(node.ID()), "failed deletion must release session admission")
}

// ephemeralGCInFlight synchronizes with the real callback, including its SQL wait.
// The stack dump grows until it fits: a cut dump can miss the GC goroutine
// and turn a timing observation into a false timeout.
func ephemeralGCInFlight() bool {
	buf := make([]byte, 64<<10)

	n := runtime.Stack(buf, true)
	for n == len(buf) {
		buf = make([]byte, 2*len(buf))
		n = runtime.Stack(buf, true)
	}

	for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
		if strings.Contains(g, ".NewHeadscale.func") && strings.Contains(g, "(*State).Delete") {
			return true
		}
	}

	return false
}

// TestEphemeralGCDoesNotDeleteReconnectedNode replays, in order, the
// interleaving of two sessions from
// https://github.com/juanfont/headscale/issues/3535: the old session takes the
// node offline, a reconnect brings it back online and cancels the GC before
// the old session arms its timer. The armed timer is stale; firing it must not
// delete a node that has a live session.
func TestEphemeralGCDoesNotDeleteReconnectedNode(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.cfg.Node.Ephemeral.InactivityTimeout = 50 * time.Millisecond
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-reconnect-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "eph-gc-reconnect-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}, key.NewMachine().Public())
	require.NoError(t, err)

	nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, nodeView.IsEphemeral(), "test sanity: node must be ephemeral")

	node := nodeView.AsStruct()
	session := app.newMapSession(context.Background(), tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, &recordingResponseWriter{}, node)

	oldGen := app.state.Connect(node.ID)

	// Old session's cleanup releases the last session.
	err = app.state.Disconnect(node.ID, oldGen)
	require.NoError(t, err)

	offline, ok := app.state.GetNodeByID(node.ID)
	require.True(t, ok)
	require.False(t, offline.Online(), "test sanity: old session must take the node offline")

	// Reconnect: what serveLongPoll does at Connect.
	newGen := app.state.Connect(node.ID)
	app.ephemeralGC.Cancel(node.ID)

	// Old session's cleanup continues and arms the GC.
	session.afterServeLongPoll()

	online, ok := app.state.GetNodeByID(node.ID)
	require.True(t, ok)
	require.True(t, online.Online(), "test sanity: reconnected node must be online")

	// Watch well past the inactivity timeout, so a stale timer has fired.
	assert.Never(t, func() bool {
		_, ok := app.state.GetNodeByID(node.ID)

		return !ok
	}, 2*time.Second, 10*time.Millisecond,
		"ephemeral GC must not delete a node with a live session (issue #3535)")

	// Once the reconnected session ends, the node is idle and must still be
	// collected.
	err = app.state.Disconnect(node.ID, newGen)
	require.NoError(t, err)
	session.afterServeLongPoll()

	assert.Eventually(t, func() bool {
		_, ok := app.state.GetNodeByID(node.ID)

		return !ok
	}, 5*time.Second, 10*time.Millisecond,
		"an idle ephemeral node must still be garbage collected")
}

// generatedResponses reads headscale_mapresponse_generated_total for typ.
func generatedResponses(t *testing.T, typ string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if f.GetName() != "headscale_mapresponse_generated_total" {
			continue
		}

		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "response_type" && l.GetValue() == typ {
					return m.GetCounter().GetValue()
				}
			}
		}
	}

	return 0
}

// TestGitHubIssue3129_TransientlyBlockedWriteKeepsSessionLive tests the
// scenario reported in https://github.com/juanfont/headscale/issues/3129: a
// map write that blocks for a while must not leave a session that is alive
// but no longer receives updates.
//
// Changes committed and pings sent while the first write is blocked must
// reach the node once the write completes, on the same, still registered
// session. Two distinct pings cannot collapse into one, so both must arrive.
func TestGitHubIssue3129_TransientlyBlockedWriteKeepsSessionLive(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-stale-session-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-stale-session-node")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

	app.cfg.Tuning.BatchChangeDelay = 20 * time.Millisecond

	require.NoError(t, app.state.Close())

	reloadedState, err := state.NewState(app.cfg)
	require.NoError(t, err)

	app.state = reloadedState

	// The hub watched the state it was built with.
	app.mapHub.Watch(reloadedState)
	t.Cleanup(func() {
		require.NoError(t, app.state.Close())
	})

	nodeView, ok := app.state.GetNodeByID(createdNode.ID)
	require.True(t, ok, "expected node to be present after reload")

	node := nodeView.AsStruct()

	ctx, cancel := context.WithCancel(t.Context())
	writer := newDelayedSuccessResponseWriter(250 * time.Millisecond)
	session := app.newMapSession(ctx, tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node)

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	t.Cleanup(func() {
		// A second live session lets the cleanup skip the reconnect grace.
		other := app.mapHub.Join(node.ID, func() {})

		cancel()

		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
		}

		app.mapHub.Leave(other)
	})

	select {
	case <-writer.FirstWriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("expected initial map write to start")
	}

	for i := range 2 {
		expiry := time.Now().Add(time.Duration(i+1) * time.Hour)
		_, err := app.state.SetNodeExpiry(node.ID, &expiry)
		require.NoError(t, err)
	}

	const (
		firstPing  = "https://example.com/queued-first"
		secondPing = "https://example.com/queued-second"
	)

	pings := generatedResponses(t, "ping")

	require.True(t, app.mapHub.Ping(node.ID, &tailcfg.PingRequest{URL: firstPing}))
	require.True(t, app.mapHub.Ping(node.ID, &tailcfg.PingRequest{URL: secondPing}))

	select {
	case <-writer.FirstWriteFinished():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the blocked write to eventually complete")
	}

	assert.Eventually(t, func() bool {
		return writer.WriteCount() >= 2
	}, 2*time.Second, 20*time.Millisecond,
		"changes made during the blocked write must reach the node afterwards")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		body := writer.Body()
		assert.Contains(c, body, firstPing)
		assert.Contains(c, body, secondPing)
	}, 2*time.Second, 10*time.Millisecond, "both pings sent during the blocked write must arrive")
	// No other test in this package sends pings, so the delta is these two.
	assert.GreaterOrEqual(t, generatedResponses(t, "ping")-pings, 2.0, "pings count as generated responses, as on main")
	assert.True(t, app.mapHub.IsConnected(node.ID), "the session must stay registered")

	select {
	case <-serveDone:
		t.Fatal("a transiently blocked write must not end the session")
	default:
	}
}

// TestDeletedNodeEndsLongPoll proves that deleting a node ends its long-poll
// session, rather than leaving the goroutine streaming to a node that no longer
// exists. An orphaned session blocks server shutdown on clientStreamsOpen and
// keeps the client polling instead of re-authenticating.
//
// It also pins the teardown latency: a deleted node cannot reconnect, so the
// session must not spend the reconnect grace period waiting for one.
//
// See: https://github.com/juanfont/headscale/issues/3410
func TestDeletedNodeEndsLongPoll(t *testing.T) {
	t.Parallel()

	// A deletion while the policy fails to compile must clean up just
	// the same: the node leaves memory and the database, and its session
	// ends.
	for _, policyFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("policy_fails=%t", policyFails), func(t *testing.T) {
			t.Parallel()

			app := createTestApp(t)
			user := app.state.CreateUserForTest("poll-delete-user")
			createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-delete-node")
			require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

			// Reload so memory is populated from the database; the create
			// helpers only write to the database.
			require.NoError(t, app.state.Close())

			reloadedState, err := state.NewState(app.cfg)
			require.NoError(t, err)

			app.state = reloadedState

			// The hub watched the state it was built with.
			app.mapHub.Watch(reloadedState)
			t.Cleanup(func() {
				require.NoError(t, app.state.Close())
			})

			nodeView, ok := app.state.GetNodeByID(createdNode.ID)
			require.True(t, ok)

			node := nodeView.AsStruct()

			if policyFails {
				// The policy compiles, then a second user of the same name
				// makes its nodeAttrs target ambiguous: every compile from
				// here on fails, and the last good policy keeps serving.
				_, err = app.state.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],
					"nodeAttrs":[{"target":["poll-delete-user@"],"attr":["custom:x"]}]}`))
				require.NoError(t, err)

				dup := types.User{Name: "poll-delete-user", ProviderIdentifier: sql.NullString{String: "oidc|dup", Valid: true}}
				require.NoError(t, app.state.DB().DB.Create(&dup).Error)
				require.Error(t, app.state.UpdatePolicyManagerUsersForTest())
				require.Error(t, app.state.Snapshot().PolicyErr(), "test sanity: the policy must fail to compile")
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			writer := newDelayedSuccessResponseWriter(0)
			session := app.newMapSession(ctx, tailcfg.MapRequest{
				Stream:  true,
				Version: tailcfg.CapabilityVersion(100),
			}, writer, node)

			serveDone := make(chan struct{})

			go func() {
				session.serveLongPoll()
				close(serveDone)
			}()

			select {
			case <-writer.FirstWriteStarted():
			case <-time.After(2 * time.Second):
				t.Fatal("expected the initial map write to start")
			}

			require.NoError(t, app.state.DeleteNode(nodeView))

			_, ok = app.state.GetNodeByID(nodeView.ID())
			assert.False(t, ok, "the deleted node must leave memory")

			_, err = app.state.DB().GetNodeByID(nodeView.ID())
			require.Error(t, err, "and the database")

			// The reconnect grace period is 10s, so a generous bound here still fails
			// if teardown waits for a node that can never come back.
			select {
			case <-serveDone:
			case <-time.After(3 * time.Second):
				t.Fatal("deleting a node must promptly end its long-poll session")
			}

			streamsClosed := make(chan struct{})

			go func() {
				app.clientStreamsOpen.Wait()
				close(streamsClosed)
			}()

			select {
			case <-streamsClosed:
			case <-time.After(2 * time.Second):
				t.Fatal("an orphaned session would block server shutdown on clientStreamsOpen")
			}
		})
	}
}

func TestDeletedNodeInterruptsBlockedWrite(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-delete-blocked-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-delete-blocked-node")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())
	app.cfg.Tuning.BatchChangeDelay = 20 * time.Millisecond

	require.NoError(t, app.state.Close())

	reloadedState, err := state.NewState(app.cfg)
	require.NoError(t, err)

	app.state = reloadedState

	// The hub watched the state it was built with.
	app.mapHub.Watch(reloadedState)
	t.Cleanup(func() {
		require.NoError(t, app.state.Close())
	})

	nodeView, ok := app.state.GetNodeByID(createdNode.ID)
	require.True(t, ok)

	writer := newDeadlineResponseWriter()
	session := app.newMapSession(t.Context(), tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, nodeView.AsStruct())

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	require.Eventually(t, func() bool {
		return writer.WriteCount() >= 1 && app.mapHub.IsConnected(nodeView.ID())
	}, 2*time.Second, 10*time.Millisecond,
		"expected the initial map to be delivered")

	writer.BlockWrites()

	// Any change the node sees produces a write that now blocks.
	expiry := time.Now().Add(time.Hour)
	_, err = app.state.SetNodeExpiry(nodeView.ID(), &expiry)
	require.NoError(t, err)

	select {
	case <-writer.WriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the update write to block")
	}

	require.NoError(t, app.state.DeleteNode(nodeView))

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("deleting a node must interrupt its blocked map response write")
	}
}

// TestDeletedNodeEndsStreamCleanly deletes a node over a real HTTP/2
// stream: idle, with a write in flight the client keeps reading, and with
// a client that stopped reading. The first two must end the stream
// cleanly, not reset it; the stalled one must still end.
func TestDeletedNodeEndsStreamCleanly(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name              string
		inFlight, stalled bool
	}{
		{name: "idle"},
		{name: "write_in_flight", inFlight: true},
		{name: "client_stalled", inFlight: true, stalled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := createTestApp(t, func(cfg *types.Config) {
				cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{}
			})

			user := app.state.CreateUserForTest("poll-delete-clean-user")
			pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
			require.NoError(t, err)

			nodeKey := key.NewNode()

			_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  nodeKey.Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "poll-delete-clean-node"},
				Expiry:   time.Now().Add(24 * time.Hour),
			}, key.NewMachine().Public())
			require.NoError(t, err)

			nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
			require.True(t, ok)

			sessions := make(chan *mapSession, 1)
			served := make(chan struct{})

			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				session := app.newMapSession(r.Context(), tailcfg.MapRequest{
					Stream:  true,
					Version: tailcfg.CapabilityVersion(100),
				}, w, nodeView.AsStruct())
				sessions <- session

				session.serveLongPoll() //nolint:contextcheck // the session carries r.Context()
				close(served)
			}))
			srv.Config.Protocols = new(http.Protocols)
			srv.Config.Protocols.SetUnencryptedHTTP2(true)
			srv.Start()
			t.Cleanup(srv.Close)

			h2c := new(http.Protocols)
			h2c.SetUnencryptedHTTP2(true)
			// A small window lets a client that pauses reading block a write.
			client := &http.Client{Transport: &http.Transport{
				Protocols: h2c,
				HTTP2:     &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10},
			}}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			var size [4]byte

			_, err = io.ReadFull(resp.Body, size[:])
			require.NoError(t, err, "expected the initial map")

			session := <-sessions

			if tt.inFlight {
				// A peer joining with a Hostinfo far larger than the
				// client's window, so the blocked write carries peers.
				services := make([]tailcfg.Service, 20000)
				for i := range services {
					services[i] = tailcfg.Service{Proto: tailcfg.TCP, Port: uint16(i), Description: "a-service-name"} //nolint:gosec // small
				}

				// The test app allocates no addresses; peers need them.
				self := nodeView.AsStruct()
				self.IPv4 = new(netip.MustParseAddr("100.64.0.1"))
				app.state.PutNodeInStoreForTest(*self)

				peer := app.state.CreateRegisteredNodeForTest(user, "poll-delete-clean-peer")
				peer.Hostinfo = &tailcfg.Hostinfo{Hostname: "poll-delete-clean-peer", Services: services}
				app.state.PutNodeInStoreForTest(*peer)
				require.Contains(t, app.state.Snapshot().ListPeerIDs(nodeView.ID()), peer.ID, "test sanity: the viewer sees the peer")

				require.Eventually(t, func() bool { return session.writing.Load() != 0 }, 5*time.Second, 10*time.Millisecond,
					"test sanity: the frame must outgrow the window and block")
			}

			require.NoError(t, app.state.DeleteNode(nodeView))

			if tt.stalled {
				select {
				case <-served:
				case <-time.After(writeStallTimeout + stopWriteGrace + 3*time.Second):
					t.Fatal("a client that stopped reading must not keep a stopped session")
				}

				return
			}

			if tt.inFlight {
				// The hub forgets the node before it stops the session, so
				// the write completes only after the history is gone.
				require.Eventually(t, session.cancelChClosed.Load, 5*time.Second, 10*time.Millisecond,
					"test sanity: the deletion stopped the session")
			}

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err, "a clean stop must end the stream, not reset it")

			<-served
			assert.False(t, app.mapHub.HasPeerHistoryForTest(nodeView.ID()),
				"a write completing after its node's deletion must record no history")
		})
	}
}

// TestDeleteNodeCancelsEphemeralGC deletes a disconnected ephemeral node
// through the API while its inactivity timer is armed. The timer belongs to
// the deleted node, so the delete must disarm it rather than leave it to fire
// at a node that is no longer there.
func TestDeleteNodeCancelsEphemeralGC(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-delete-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "eph-gc-delete-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}, key.NewMachine().Public())
	require.NoError(t, err)

	node, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, node.IsEphemeral(), "test sanity: node must be ephemeral")

	// The state a disconnect leaves behind.
	app.ephemeralGC.Schedule(node.ID(), time.Hour)
	require.True(t, app.ephemeralGC.IsScheduled(node.ID()), "test sanity: GC timer must be armed")

	api := registerAPIV2(t, app)
	require.Equal(t, http.StatusOK, api.Delete("/api/v2/device/"+node.ID().String()).Code)

	assert.False(t, app.ephemeralGC.IsScheduled(node.ID()),
		"deleting a node must cancel its ephemeral GC timer")
}

// TestLongPollShutdownWaitsForCleanup catches streams counted as closed before
// their disconnect cleanup finishes, including sessions already in reconnect grace.
func TestLongPollWaitsForConcurrentDeadlineBeforeReturning(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("deadline-lifetime")
	node := app.state.CreateRegisteredNodeForTest(user, "deadline-lifetime")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())
	app.state.PutNodeInStoreForTest(*node)

	writer := newDeadlineResponseWriter()
	writer.BlockWrites()

	deadlineReturn := make(chan struct{})
	writer.deadlineReturn = deadlineReturn
	releaseDeadline := sync.OnceFunc(func() { close(deadlineReturn) })
	session := app.newMapSession(t.Context(), tailcfg.MapRequest{
		Stream: true, Version: tailcfg.CurrentCapabilityVersion,
	}, writer, node)
	serveDone := make(chan struct{})
	shutdownDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	t.Cleanup(func() {
		releaseDeadline()
		app.mapHub.Close()

		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
			t.Error("handler did not finish")
		}
	})

	select {
	case <-writer.WriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start writing")
	}

	go func() {
		app.mapHub.Close()
		close(shutdownDone)
	}()

	// The write returns while its concurrent deadline call is still in flight.
	select {
	case <-writer.deadlineSet:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not interrupt the write")
	}

	select {
	case <-serveDone:
		t.Error("handler returned while shutdown still used its response writer")
	case <-time.After(100 * time.Millisecond):
	}

	releaseDeadline()

	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestLongPollShutdownWaitsForCleanup(t *testing.T) {
	t.Parallel()

	for _, inGrace := range []bool{false, true} {
		t.Run(fmt.Sprintf("in_grace=%t", inGrace), func(t *testing.T) {
			t.Parallel()

			app := createTestApp(t)
			user := app.state.CreateUserForTest("poll-shutdown-user")
			createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-shutdown-node")
			require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

			require.NoError(t, app.state.Close())

			var err error

			app.state, err = state.NewState(app.cfg)
			require.NoError(t, err)

			// The hub watched the state it was built with.
			app.mapHub.Watch(app.state)

			node, ok := app.state.GetNodeByID(createdNode.ID)
			require.True(t, ok)

			ctx, cancel := context.WithCancel(t.Context())
			writer := newDelayedSuccessResponseWriter(0)
			session := app.newMapSession(ctx, tailcfg.MapRequest{
				Stream:  true,
				Version: tailcfg.CapabilityVersion(100),
			}, writer, node.AsStruct())

			serveDone := make(chan struct{})

			go func() {
				session.serveLongPoll()
				close(serveDone)
			}()

			t.Cleanup(func() {
				cancel()
				app.mapHub.Close()

				select {
				case <-serveDone:
				case <-time.After(15 * time.Second):
					t.Error("map session did not finish cleanup")
				}

				require.NoError(t, app.state.Close())
			})

			require.Eventually(t, func() bool {
				return writer.WriteCount() >= 1 && app.mapHub.IsConnected(node.ID())
			}, 2*time.Second, 10*time.Millisecond, "map session should connect")

			if inGrace {
				cancel()
				require.Eventually(t, func() bool {
					return !app.mapHub.IsConnected(node.ID())
				}, 2*time.Second, 10*time.Millisecond, "session should enter reconnect grace")

				pending, ok := app.state.GetNodeByID(node.ID())
				require.True(t, ok)
				require.Equal(t, 1, pending.ActiveSessions(), "reconnect grace should keep the node online")
			}

			streamsClosed := make(chan struct{})

			go func() {
				app.mapHub.Close()
				app.clientStreamsOpen.Wait()
				close(streamsClosed)
			}()

			select {
			case <-streamsClosed:
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown must interrupt reconnect grace and wait for cleanup")
			}

			disconnected, ok := app.state.GetNodeByID(node.ID())
			require.True(t, ok)
			assert.Zero(t, disconnected.ActiveSessions(), "shutdown must wait for the session to release")
			assert.False(t, disconnected.Online(), "the last session must take the node offline before shutdown returns")

			persisted, err := app.state.DB().GetNodeByID(node.ID())
			require.NoError(t, err)
			require.NotNil(t, persisted.LastSeen)
			assert.True(t, persisted.LastSeen.Equal(disconnected.LastSeen().Get()),
				"shutdown must wait for the disconnect write to finish")
		})
	}
}

// TestStalledWriteEndsSession blocks a session's first write well past the
// stall budget: the session must leave the hub and stop within it, and
// exit once the write returns. A transient block, see
// TestGitHubIssue3129_TransientlyBlockedWriteKeepsSessionLive, must not.
func TestStalledWriteEndsSession(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-stalled-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-stalled-node")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

	require.NoError(t, app.state.Close())

	reloadedState, err := state.NewState(app.cfg)
	require.NoError(t, err)

	app.state = reloadedState

	// The hub watched the state it was built with.
	app.mapHub.Watch(reloadedState)
	t.Cleanup(func() {
		require.NoError(t, app.state.Close())
	})

	nodeView, ok := app.state.GetNodeByID(createdNode.ID)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	writer := newDelayedSuccessResponseWriter(10 * time.Second)
	session := app.newMapSession(ctx, tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, nodeView.AsStruct())

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	select {
	case <-writer.FirstWriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the first map write to start")
	}

	require.Eventually(t, func() bool {
		return !app.mapHub.IsConnected(nodeView.ID()) && session.cancelChClosed.Load()
	}, 8*time.Second, 10*time.Millisecond, "a stalled session must leave the hub and stop within the budget")

	// Shutdown skips the reconnect grace a stalled node is otherwise given.
	app.mapHub.Close()

	select {
	case <-serveDone:
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled session must exit once its write returns")
	}
}

// TestWriteMapFrameReportsProgressPerChunk writes a 48 KiB frame and checks
// progress is reported once it is encoded and after each chunk of at most
// 16 KiB: the stall watchdog arms and resets on it, so neither encoding
// nor a reader slower than a chunk per stall budget is taken for a
// stopped client.
func TestWriteMapFrameReportsProgressPerChunk(t *testing.T) {
	body := make([]byte, 48<<10)
	encode := func(*tailcfg.MapResponse, bool) ([]byte, error) { return body, nil }

	w := httptest.NewRecorder()
	calls := 0

	err := writeMapFrame(w, true, &tailcfg.MapResponse{}, false, encode, func() { calls++ })
	require.NoError(t, err)

	assert.GreaterOrEqual(t, calls-1, 4, "progress per chunk, chunks of at most 16 KiB; the length prefix spills into a fourth")
	assert.Len(t, w.Body.Bytes(), reservedResponseHeaderSize+len(body))
}

// pacedResponseWriter delays every write by delay, and with block set
// holds a write until its deadline passes, as an HTTP/2 stream does when
// the client stopped reading and the server cuts the write.
type pacedResponseWriter struct {
	header http.Header
	delay  time.Duration
	block  bool

	mu       sync.Mutex
	deadline time.Time
	cut      chan struct{}
}

func newPacedResponseWriter(delay time.Duration, block bool) *pacedResponseWriter {
	return &pacedResponseWriter{header: make(http.Header), delay: delay, block: block, cut: make(chan struct{})}
}

func (w *pacedResponseWriter) Header() http.Header { return w.header }
func (w *pacedResponseWriter) WriteHeader(int)     {}
func (w *pacedResponseWriter) Flush()              {}

func (w *pacedResponseWriter) Write(data []byte) (int, error) {
	if w.block {
		<-w.cut

		return 0, os.ErrDeadlineExceeded
	}

	time.Sleep(w.delay) //nolint:forbidigo // the slow reader under test

	return len(data), nil
}

// SetWriteDeadline is what [http.ResponseController] calls to cut a write.
func (w *pacedResponseWriter) SetWriteDeadline(d time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.deadline.IsZero() {
		w.deadline = d
		time.AfterFunc(time.Until(d), func() { close(w.cut) })
	}

	return nil
}

// bigMapResponse encodes to several write chunks.
func bigMapResponse() *tailcfg.MapResponse {
	resp := &tailcfg.MapResponse{}
	for i := range 4000 {
		resp.Peers = append(resp.Peers, &tailcfg.Node{
			ID:   tailcfg.NodeID(i + 1),
			Name: fmt.Sprintf("peer-%d-%s.example.com.", i, strings.Repeat("x", 40)),
		})
	}

	return resp
}

func pollStallTestSession(t *testing.T, w http.ResponseWriter) *mapSession {
	t.Helper()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-stall-user")
	node := app.state.CreateRegisteredNodeForTest(user, "poll-stall-node")

	m := app.newMapSession(t.Context(), tailcfg.MapRequest{Stream: true, Version: tailcfg.CapabilityVersion(100)}, w, node)
	m.stallTimeout = 100 * time.Millisecond

	return m
}

// TestSlowReaderOfALargeMapIsNotStalled writes a frame of several chunks,
// each taking a good part of the stall budget: the whole write takes several
// budgets, yet every chunk moves, so the session must live.
func TestSlowReaderOfALargeMapIsNotStalled(t *testing.T) {
	m := pollStallTestSession(t, newPacedResponseWriter(40*time.Millisecond, false))

	start := time.Now()

	require.NoError(t, m.writeMap(bigMapResponse()))
	require.Greater(t, time.Since(start), 2*m.stallTimeout, "test sanity: the write outlasts the budget")
	assert.False(t, m.cancelChClosed.Load(), "a reader that keeps reading is not stalled")
}

// TestStopDuringSharedEncodingDoesNotArmWriteDeadline stops a session while
// another session encodes their shared frame: it must end without starting
// a network deadline or sending the frame once encoding finishes.
func TestStopDuringSharedEncodingDoesNotArmWriteDeadline(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-stop-encode-user")
	node := app.state.CreateRegisteredNodeForTest(user, "poll-stop-encode-node")
	node.User = user
	app.state.PutNodeInStoreForTest(*node)

	stream := mapper.NewStream(app.cfg, app.mapHub, node.ID, tailcfg.CurrentCapabilityVersion)
	_, err := stream.Initial(app.state.Snapshot())
	require.NoError(t, err)
	app.state.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}})
	responses, err := stream.Update(app.state.Snapshot())
	require.NoError(t, err)
	require.Len(t, responses, 1)

	encoding, unblock := make(chan struct{}), make(chan struct{})

	release := sync.OnceFunc(func() { close(unblock) })
	defer release()

	encoded := make(chan error, 1)

	go func() {
		_, err := app.mapHub.Encode(responses[0], false, func(msg *tailcfg.MapResponse, compress bool) ([]byte, error) {
			close(encoding)
			<-unblock

			return encodeMapResponse(msg, compress)
		})
		encoded <- err
	}()

	<-encoding

	writer := newDeadlineResponseWriter()
	session := app.newMapSession(t.Context(), tailcfg.MapRequest{Stream: true}, writer, node)

	written := make(chan error, 1)

	go func() { written <- session.writeMap(responses[0]) }()

	require.Eventually(t, func() bool { return session.writeSeq.Load() != 0 }, time.Second, time.Millisecond)
	session.stop()

	select {
	case <-writer.deadlineSet:
		t.Error("stopping during encoding must not start a network write deadline")
	default:
	}

	release()
	require.NoError(t, <-encoded)
	require.ErrorIs(t, <-written, errMapSessionStopped)
	assert.Zero(t, writer.WriteCount(), "a frame encoded after stop must not reach the writer")
}

// TestSlowEncodeIsNotAStall gives a frame a stall budget shorter than its
// encoding: encoding is the server's time, not the client's, so a reader
// taking every chunk at once must not be taken as gone.
func TestSlowEncodeIsNotAStall(t *testing.T) {
	m := pollStallTestSession(t, newPacedResponseWriter(0, false))

	// Large enough that encoding takes well over the budget's floor below.
	frame := func() *tailcfg.MapResponse {
		resp := bigMapResponse()
		for range 4 {
			resp.Peers = append(resp.Peers, resp.Peers...)
		}

		return resp
	}

	// Timed on frames of their own: encoding caches each node's JSON, so
	// timing resp itself would make its write cheaper than measured. The
	// faster of two keeps a slow first run from widening the budget.
	resp := frame()
	took := time.Duration(math.MaxInt64)

	for range 2 {
		start := time.Now()
		_, err := encodeMapResponse(frame(), false)
		require.NoError(t, err)

		took = min(took, time.Since(start))
	}

	// A third of the encoding, but never so little that a deschedule
	// between two chunks reads as a stopped client.
	m.stallTimeout = max(took/3, 20*time.Millisecond)

	require.NoError(t, m.writeMap(resp))
	assert.False(t, m.cancelChClosed.Load(), "the budget runs from the first chunk, not from encoding")
}

// TestStalledWriteIsCutByItsDeadline blocks a write until the stream cuts
// it: the stall must stop the session and set the deadline, so the write
// returns instead of holding the session open for good.
func TestStalledWriteIsCutByItsDeadline(t *testing.T) {
	m := pollStallTestSession(t, newPacedResponseWriter(0, true))

	done := make(chan error, 1)

	go func() { done <- m.writeMap(bigMapResponse()) }()

	select {
	case err := <-done:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(m.stallTimeout + stopWriteGrace + 5*time.Second):
		t.Fatal("a stalled write must be cut by its deadline")
	}

	assert.True(t, m.cancelChClosed.Load(), "the stall stops the session")
}

// TestStallTimerFiringLateEndsNothing fires a write's stall timer after the
// write returned, and again during the next write: neither may end the
// session.
func TestStallTimerFiringLateEndsNothing(t *testing.T) {
	m := pollStallTestSession(t, newPacedResponseWriter(0, false))

	require.NoError(t, m.writeMap(&tailcfg.MapResponse{KeepAlive: true}))
	m.stallWrite(m.writeSeq.Load())
	assert.False(t, m.cancelChClosed.Load(), "a timer for a finished write ends nothing")

	m.writing.Store(m.writeSeq.Add(1))
	m.stallWrite(m.writing.Load() - 1)
	m.writing.Store(0)
	assert.False(t, m.cancelChClosed.Load(), "nor does it end the next write")
}

// TestFirstMapSlotSurvivesAPanickingRender panics in more first-map renders
// than the hub has slots: each must give its slot back, or the next
// session would wait for a first map forever.
func TestFirstMapSlotSurvivesAPanickingRender(t *testing.T) {
	m := pollStallTestSession(t, newPacedResponseWriter(0, false))

	// A leaked slot makes a later wait give up instead of hanging the test.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	for range runtime.GOMAXPROCS(0) + 1 {
		func() {
			defer func() { _ = recover() }()

			// A nil stream panics once the slot is taken.
			_, _, _ = m.renderFirst(ctx.Done(), nil)
		}()
	}

	release, ok := m.h.mapHub.RenderFirst(ctx.Done(), nil)
	require.True(t, ok, "panicking renders leaked their first-map slots")
	release()
}

// TestStoppedSessionGivesUpItsFirstMapWait queues a session for a first
// map while every slot is held and stops it: it must give up the wait and
// end, not hold its place until a slot frees.
func TestStoppedSessionGivesUpItsFirstMapWait(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-firstmap-user")
	created := app.state.CreateRegisteredNodeForTest(user, "poll-firstmap-node")
	require.NoError(t, app.state.Close())

	var err error

	app.state, err = state.NewState(app.cfg)
	require.NoError(t, err)
	app.mapHub.Watch(app.state)
	t.Cleanup(func() { _ = app.state.Close() })

	for range runtime.GOMAXPROCS(0) {
		release, ok := app.mapHub.RenderFirst(t.Context().Done(), nil)
		require.True(t, ok)
		t.Cleanup(release)
	}

	nv, ok := app.state.GetNodeByID(created.ID)
	require.True(t, ok)

	session := app.newMapSession(t.Context(), tailcfg.MapRequest{Stream: true, Version: tailcfg.CapabilityVersion(100)},
		newBreakableResponseWriter(), nv.AsStruct())
	done := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(done)
	}()

	t.Cleanup(func() {
		// Closing the hub skips the reconnect grace.
		app.mapHub.Close()
		<-done
	})

	require.Eventually(t, func() bool { return app.mapHub.IsConnected(created.ID) }, 5*time.Second, 10*time.Millisecond,
		"test sanity: the session joined and waits for a first-map slot")

	session.stop()

	require.Eventually(t, func() bool { return !app.mapHub.IsConnected(created.ID) }, 2*time.Second, 10*time.Millisecond,
		"a stopped session must give up its first-map wait")
}

// TestMapFrameReportsHTTP2FlushFailure writes a small removal to an HTTP/2
// stream the client has reset, through the middleware the noise router
// wraps the writer in. The write is only buffered, so the failed flush is
// the only sign it never left: it must fail the frame, or the session
// records a removal as delivered that the client never got.
func TestMapFrameReportsHTTP2FlushFailure(t *testing.T) {
	type result struct {
		frameErr error
		proto    int
	}

	got := make(chan result, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		ww.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(ww).Flush()

		<-r.Context().Done()

		err := writeMapResponse(ww, "", true, &tailcfg.MapResponse{PeersRemoved: []tailcfg.NodeID{42}})
		got <- result{frameErr: err, proto: r.ProtoMajor}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)

	cancel()

	_ = resp.Body.Close()

	select {
	case r := <-got:
		require.Equal(t, 2, r.proto)
		require.Error(t, r.frameErr, "a removal whose flush failed must not count as written")
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never saw the stream reset")
	}
}

// breakableResponseWriter records frames until broken, then fails every
// write, as a connection that dropped does.
type breakableResponseWriter struct {
	header http.Header
	broken atomic.Bool
	// flushBroken fails only flushes, as an HTTP/2 stream does that was
	// reset after a small write was buffered.
	flushBroken atomic.Bool

	mu   sync.Mutex
	body []byte
}

func newBreakableResponseWriter() *breakableResponseWriter {
	return &breakableResponseWriter{header: make(http.Header)}
}

func (w *breakableResponseWriter) Header() http.Header { return w.header }
func (w *breakableResponseWriter) WriteHeader(int)     {}
func (w *breakableResponseWriter) Flush()              {}

func (w *breakableResponseWriter) FlushError() error {
	if w.flushBroken.Load() {
		return io.ErrClosedPipe
	}

	return nil
}

func (w *breakableResponseWriter) Write(data []byte) (int, error) {
	if w.broken.Load() {
		return 0, io.ErrClosedPipe
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.body = append(w.body, data...)

	return len(data), nil
}

// written reports whether any frame has been written.
func (w *breakableResponseWriter) written() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.body) > 0
}

// removed returns every peer the frames written so far removed.
func (w *breakableResponseWriter) removed(t *testing.T) []tailcfg.NodeID {
	t.Helper()

	w.mu.Lock()
	body := slices.Clone(w.body)
	w.mu.Unlock()

	var out []tailcfg.NodeID

	for len(body) >= reservedResponseHeaderSize {
		n := int(binary.LittleEndian.Uint32(body))
		if len(body) < reservedResponseHeaderSize+n {
			break
		}

		var resp tailcfg.MapResponse
		require.NoError(t, json.Unmarshal(body[reservedResponseHeaderSize:reservedResponseHeaderSize+n], &resp))

		out = append(out, resp.PeersRemoved...)
		body = body[reservedResponseHeaderSize+n:]
	}

	return out
}

// TestRemovalHistoryFollowsWhatWasWritten runs real sessions of a node
// whose peer is deleted. When the update removing the peer fails to write,
// or only its flush fails, the next session must announce the removal
// again; when it was written, the next session must not. Either half fails
// if the session records delivery at the wrong time. The writer is wrapped
// as the noise router's middleware wraps it.
func TestRemovalHistoryFollowsWhatWasWritten(t *testing.T) {
	for _, tt := range []struct{ name, fails string }{
		{name: "write_fails", fails: "write"},
		{name: "flush_fails", fails: "flush"},
		{name: "written"},
	} {
		writeFails, lost := tt.fails == "write", tt.fails != ""

		t.Run(tt.name, func(t *testing.T) {
			app := createTestApp(t)
			user := app.state.CreateUserForTest("poll-history-user")
			viewer := app.state.CreateRegisteredNodeForTest(user, "poll-history-viewer")
			peer := app.state.CreateRegisteredNodeForTest(user, "poll-history-peer")
			require.NoError(t, app.state.Close())

			var err error

			app.state, err = state.NewState(app.cfg)
			require.NoError(t, err)
			app.mapHub.Watch(app.state)
			t.Cleanup(func() { _ = app.state.Close() })

			serve := func(w http.ResponseWriter) (context.CancelFunc, <-chan struct{}) {
				nv, ok := app.state.GetNodeByID(viewer.ID)
				require.True(t, ok)

				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})

				go func() {
					ww := middleware.NewWrapResponseWriter(w, 2)
					app.newMapSession(ctx, tailcfg.MapRequest{Stream: true, Version: tailcfg.CapabilityVersion(100)}, ww, nv.AsStruct()).serveLongPoll()
					close(done)
				}()

				return cancel, done
			}

			first := newBreakableResponseWriter()
			cancel, done := serve(first)

			// The initial map is written before the connection breaks.
			require.Eventually(t, first.written, 5*time.Second, 10*time.Millisecond)

			pv, ok := app.state.GetNodeByID(peer.ID)
			require.True(t, ok)

			first.broken.Store(writeFails)
			first.flushBroken.Store(tt.fails == "flush")
			require.NoError(t, app.state.DeleteNode(pv))

			if !lost {
				require.Eventually(t, func() bool { return slices.Contains(first.removed(t), peer.ID.NodeID()) },
					5*time.Second, 10*time.Millisecond, "test sanity: the removal is written")
			}

			// A failed write ends the first session on its own; a good one
			// is ended here. The second starts once the first left the hub,
			// which also ends the first's reconnect grace.
			if !lost {
				cancel()
			}

			require.Eventually(t, func() bool { return !app.mapHub.IsConnected(viewer.ID) }, 5*time.Second, 10*time.Millisecond,
				"the first session must end")

			firstCancel, firstDone := cancel, done
			second := newBreakableResponseWriter()

			if writeFails {
				// The second session's first map, which announces the
				// removal, fails too: a third must announce it again.
				second.broken.Store(true)
				_, secondDone := serve(second)

				firstCancel()
				<-firstDone
				<-secondDone

				require.Eventually(t, func() bool { return !app.mapHub.IsConnected(viewer.ID) }, 5*time.Second, 10*time.Millisecond)

				third := newBreakableResponseWriter()
				cancel, done = serve(third)

				t.Cleanup(func() { app.mapHub.Close(); cancel(); <-done })

				require.Eventually(t, func() bool { return slices.Contains(third.removed(t), peer.ID.NodeID()) },
					5*time.Second, 10*time.Millisecond, "a removal that was never written must be announced again")

				return
			}

			cancel, done = serve(second)

			firstCancel()
			<-firstDone

			// Closing the hub skips the last session's reconnect grace.
			t.Cleanup(func() { app.mapHub.Close(); cancel(); <-done })
			require.Eventually(t, func() bool { return app.mapHub.IsConnected(viewer.ID) }, 5*time.Second, 10*time.Millisecond)

			if lost {
				require.Eventually(t, func() bool { return slices.Contains(second.removed(t), peer.ID.NodeID()) },
					5*time.Second, 10*time.Millisecond, "a removal whose flush failed must be announced again")

				return
			}

			assert.Never(t, func() bool { return slices.Contains(second.removed(t), peer.ID.NodeID()) },
				500*time.Millisecond, 10*time.Millisecond, "a removal that was written is not announced again")
		})
	}
}
