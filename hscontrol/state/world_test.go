package state

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestWorldDNSNoOpPublication(t *testing.T) {
	cfg := &types.Config{TailcfgDNSConfig: &tailcfg.DNSConfig{}}
	w, err := newWorld(nil, nil, nil, cfg.DNSView())
	require.NoError(t, err)

	sub := w.g.Subscribe()
	t.Cleanup(sub.Close)

	before := w.snapshot()

	for _, records := range [][]tailcfg.DNSRecord{nil, {}} {
		w.SetExtraRecords(records)
		assert.Equal(t, before.Rev(), w.snapshot().Rev())
		assert.Equal(t, before.DNSRev(), w.snapshot().DNSRev())

		select {
		case <-sub.C:
			t.Fatal("empty no-op publication woke subscribers")
		default:
		}
	}

	records := []tailcfg.DNSRecord{{Name: "Service.Example.COM", Type: "A", Value: "100.64.0.99"}}
	w.SetExtraRecords(records)
	after := w.snapshot()
	require.Greater(t, after.DNSRev(), before.DNSRev())
	assert.Equal(t, before.PolicyRev(), after.PolicyRev())
	assert.Equal(t, before.PeerPolicyRev(), after.PeerPolicyRev())
	assert.Equal(t, before.PeersRev(), after.PeersRev())

	select {
	case <-sub.C:
	default:
		t.Fatal("changed DNS publication did not wake subscribers")
	}

	records[0].Name = "service.example.com"
	w.SetExtraRecords(records)
	assert.Equal(t, after.Rev(), w.snapshot().Rev())
	assert.Equal(t, after.DNSRev(), w.snapshot().DNSRev())

	select {
	case <-sub.C:
		t.Fatal("case-normalized no-op publication woke subscribers")
	default:
	}

	records[0].Name = "changed.example.com"
	assert.Equal(t, "service.example.com", after.DNS().ExtraRecords().At(0).Name)
}

func TestWorldDNSReorderRetainsRevision(t *testing.T) {
	cfg := &types.Config{TailcfgDNSConfig: &tailcfg.DNSConfig{}}
	w, err := newWorld(nil, nil, nil, cfg.DNSView())
	require.NoError(t, err)

	sub := w.g.Subscribe()
	t.Cleanup(sub.Close)

	w.SetExtraRecords([]tailcfg.DNSRecord{
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
		{Name: "b.example.com", Type: "A", Value: "100.64.0.2"},
	})
	before := w.snapshot()

	select {
	case <-sub.C:
	default:
		t.Fatal("first publication must wake subscribers")
	}

	// The records manager republishes sets in map order; a reordered set is
	// a no-op and must retain its revision.
	w.SetExtraRecords([]tailcfg.DNSRecord{
		{Name: "b.example.com", Type: "A", Value: "100.64.0.2"},
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
	})
	after := w.snapshot()

	assert.Equal(t, before.Rev(), after.Rev())
	assert.Equal(t, before.DNSRev(), after.DNSRev())

	select {
	case <-sub.C:
		t.Fatal("reordered no-op publication woke subscribers")
	default:
	}
}

func worldNode(id types.NodeID, user *types.User, ip string) *types.Node {
	addr := netip.MustParseAddr(ip)
	uid := user.ID

	return &types.Node{
		ID:         id,
		GivenName:  "node",
		Hostname:   "node",
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		IPv4:       &addr,
		UserID:     &uid,
		User:       user,
		IsOnline:   new(true),
		Hostinfo:   &tailcfg.Hostinfo{},
	}
}

const ownUserPolicy = `{"acls":[{"action":"accept","src":["alice@"],"dst":["alice@:*"]}]}`

func testWorld(t *testing.T, nodes ...*types.Node) (*world, []types.User) {
	t.Helper()

	users := []types.User{{Name: "alice"}, {Name: "bob"}}
	users[0].ID, users[1].ID = 1, 2

	w, err := newWorld(nodes, users, []byte(ownUserPolicy), types.DNSView{})
	require.NoError(t, err)

	return w, users
}

// worldCommitCount reads the package-global counter, so the metric tests
// below compare deltas and this package's tests must stay serial (no
// t.Parallel anywhere in it).
func worldCommitCount(t *testing.T) float64 {
	t.Helper()

	return testutil.ToFloat64(worldCommits)
}

func TestWorldCommitMetric(t *testing.T) {
	before := worldCommitCount(t)
	w, users := testWorld(t,
		worldNode(1, &types.User{}, "100.64.0.1"),
		worldNode(2, &types.User{}, "100.64.0.2"),
	)
	assert.InDelta(t, before, worldCommitCount(t), 0, "initialization is not a write")

	users[0].DisplayName = "Alice"
	pol := []byte(`{"grants":[]}`)
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}}
	records := []tailcfg.DNSRecord{{Name: "example.test", Type: "A", Value: "192.0.2.1"}}
	update := func(n *types.Node) { n.Hostname += "-updated" }

	for _, tt := range []struct {
		name    string
		write   func()
		commits uint64
	}{
		{"node", func() { w.UpdateNode(1, update) }, 1},
		{"node batch", func() { w.UpdateNodes(map[types.NodeID]UpdateNodeFunc{1: update, 2: update}) }, 1},
		// A write that replaces a node with an identical copy still counts:
		// it stages an edit, and the nodes input compares nodes by identity.
		{"unchanged node", func() { w.UpdateNode(1, func(*types.Node) {}) }, 1},
		{"add node", func() { w.PutNode(*worldNode(3, &users[0], "100.64.0.3")) }, 1},
		{"delete node", func() { w.DeleteNode(3) }, 1},
		{"missing node", func() { w.DeleteNode(99) }, 0},
		{"users", func() { require.NoError(t, w.SetUsers(users)) }, 1},
		{"unchanged users", func() { require.NoError(t, w.SetUsers(slices.Clone(users))) }, 0},
		{"policy", func() {
			changed, err := w.SetPolicy(pol, (*Snapshot).PolicyErr)
			require.NoError(t, err)
			require.True(t, changed)
		}, 1},
		{"unchanged policy", func() {
			changed, err := w.SetPolicy(slices.Clone(pol), (*Snapshot).PolicyErr)
			require.NoError(t, err)
			require.False(t, changed)
		}, 0},
		{"refused policy", func() {
			changed, err := w.SetPolicy([]byte(ownUserPolicy), func(*Snapshot) error { return errPolicyInputsMoved })
			require.ErrorIs(t, err, errPolicyInputsMoved)
			require.False(t, changed)
		}, 0},
		{"DERP", func() { w.SetDERPMap(dm) }, 1},
		{"unchanged DERP", func() { w.SetDERPMap(dm.Clone()) }, 0},
		{"DNS", func() { w.SetExtraRecords(records) }, 1},
		{"unchanged DNS", func() { w.SetExtraRecords(slices.Clone(records)) }, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := worldCommitCount(t)
			rev := w.snapshot().Rev()

			tt.write()
			assert.Equal(t, rev+tt.commits, w.snapshot().Rev())
			assert.InDelta(t, before+float64(tt.commits), worldCommitCount(t), 0)

			assert.InDelta(t, float64(w.snapshot().ListNodes().Len()), testutil.ToFloat64(worldNodes), 0, "node gauge describes published nodes")
		})
	}
}

func TestWorldCommitMetricExcludesDerivationPanic(t *testing.T) {
	for _, kind := range []string{"node", "users"} {
		t.Run(kind, func(t *testing.T) {
			g := graph.New()
			w := &world{g: g}
			w.nodes = g.NewInput("nodes", graph.NewMap[types.NodeID](graph.Same[*types.Node], nil), graph.Same[*nodeMap])
			w.users = g.NewInput("users", []types.User(nil), slices.Equal[[]types.User])
			graph.NewDerived(g, "panic after staging", graph.Same[int], func(s *graph.Snapshot, _ int) int {
				s.Get(w.nodes)
				s.Get(w.users)

				if s.Rev() > 1 {
					panic("derivation failed")
				}

				return 0
			})
			_, err := g.Update(func(*graph.Tx) error { return nil })
			require.NoError(t, err)

			before := worldCommitCount(t)
			gaugeBefore := testutil.ToFloat64(worldNodes)

			// A sentinel the batch must not overwrite; restored so later
			// tests read the gauge this package's serial run left behind.
			worldNodes.Set(0)
			t.Cleanup(func() { worldNodes.Set(gaugeBefore) })

			if kind == "node" {
				_, p, _ := w.commitBatch([]*nodeWrite{{fn: func(e *nodeEdit) {
					e.Set(1, &types.Node{ID: 1})
				}}})
				require.Equal(t, "derivation failed", p)
			} else {
				require.PanicsWithValue(t, "derivation failed", func() { require.NoError(t, w.SetUsers([]types.User{{Name: "alice"}})) })
			}

			assert.EqualValues(t, 1, g.Snapshot().Rev(), "a panic publishes nothing")
			assert.Zero(t, g.Snapshot().Get(w.nodes).Len(), "a failed derivation publishes no node")
			assert.InDelta(t, before, worldCommitCount(t), 0, "staging inputs is not a commit")
			assert.Zero(t, testutil.ToFloat64(worldNodes), "a failed derivation must not change the node gauge")
		})
	}
}

// A panicking batch is retried write by write; each surviving write that
// publishes counts separately, which the commit counter's help text states.
// The test drives the real commit loop, not commitBatch alone, so a
// regression in commitWrites' retry wiring changes the count.
func TestWorldCommitMetricCountsPanicRetriesSeparately(t *testing.T) {
	g := graph.New()
	w := &world{g: g}
	w.nodes = g.NewInput("nodes", graph.NewMap[types.NodeID](graph.Same[*types.Node], nil), graph.Same[*nodeMap])
	// The derivation fails whenever node 1 is staged, so a batch containing
	// it panics and only its sibling writes survive the per-write retry.
	graph.NewDerived(g, "panic on node 1", graph.Same[int], func(s *graph.Snapshot, _ int) int {
		nodes := s.Get(w.nodes)

		if s.Rev() > 1 {
			if _, ok := nodes.Get(1); ok {
				panic("derivation failed")
			}
		}

		return 0
	})
	_, err := g.Update(func(*graph.Tx) error { return nil })
	require.NoError(t, err)

	before := worldCommitCount(t)
	gaugeBefore := testutil.ToFloat64(worldNodes)

	t.Cleanup(func() { worldNodes.Set(gaugeBefore) })

	// Hold a first commit open until both writes queue into one batch, as
	// group commit batches concurrent writers (the pattern of
	// TestWorldWritePanicFailsOnlyItsWriter).
	inCommit, release := make(chan struct{}), make(chan struct{})

	// Releasing the hold is cleanup-safe: a failed assertion must not
	// strand the held commit or the writers on their done channels, and
	// the retry loop delivers each write's panic to its own writer, where
	// the recovers below pick it up.
	var releaseOnce sync.Once

	releaseHold := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHold)

	go w.update(func(*nodeEdit) {
		close(inCommit)
		<-release
	})

	<-inCommit

	var (
		wg        sync.WaitGroup
		panicked  any
		goodPanic any
		good      *Snapshot
	)

	wg.Go(func() {
		defer func() { panicked = recover() }()

		w.update(func(e *nodeEdit) { e.Set(1, &types.Node{ID: 1}) })
	})
	wg.Go(func() {
		defer func() { goodPanic = recover() }()

		good = w.update(func(e *nodeEdit) { e.Set(2, &types.Node{ID: 2}) })
	})

	require.Eventually(t, func() bool {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes) == 2
	}, time.Second, time.Millisecond, "both writes must queue into one batch")

	releaseHold()

	// A regression that stops retrying a panicked batch blocks every
	// writer on its done channel; fail fast with a message instead of
	// hanging the package until its timeout.
	waited := make(chan struct{})

	go func() {
		wg.Wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("the individual retries did not finish; commitWrites' retry loop looks broken")
	}

	require.Nil(t, goodPanic, "the surviving write must commit, not panic")

	assert.Equal(t, "derivation failed", panicked, "the panicking write's retry re-raises it")
	require.NotNil(t, good, "the surviving write commits")

	n2, ok := good.GetNode(2)
	require.True(t, ok, "the survivor's snapshot carries its node")
	assert.Equal(t, types.NodeID(2), n2.ID())

	assert.InDelta(t, before+1, worldCommitCount(t), 0,
		"the batch attempt counts nothing and the surviving retry counts once")
	assert.InDelta(t, float64(1), testutil.ToFloat64(worldNodes), 0, "only the survivor's node is published")
}

func TestWorldPayloadWriteKeepsPolicy(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t,
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
	)

	before := w.snapshot()

	w.UpdateNode(1, func(n *types.Node) {
		n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	})

	after := w.snapshot()
	require.Greater(t, after.Rev(), before.Rev())
	assert.Equal(t, before.PolicyRev(), after.PolicyRev(), "an endpoint update must not recompile the policy")
	assert.Same(t, before.Policy(), after.Policy())
	assert.Equal(t, []types.NodeID{2}, after.ListPeerIDs(1))

	nv, _ := after.GetNode(1)
	assert.Len(t, nv.Endpoints().AsSlice(), 1, "readers see the write")
}

func TestWorldNodeJoinUpdatesPeers(t *testing.T) {
	alice, bob := &types.User{Name: "alice"}, &types.User{Name: "bob"}
	alice.ID, bob.ID = 1, 2

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"))
	before := w.snapshot()

	w.PutNode(*worldNode(2, alice, "100.64.0.2"))
	w.PutNode(*worldNode(3, bob, "100.64.0.3"))

	after := w.snapshot()
	assert.NotEqual(t, before.PolicyRev(), after.PolicyRev(), "a join recompiles the policy")
	assert.Equal(t, []types.NodeID{2}, after.ListPeerIDs(1))
	assert.Empty(t, after.ListPeerIDs(3), "bob's node is outside alice's ACL")

	// The old snapshot is untouched.
	assert.Empty(t, before.ListPeerIDs(1))
}

func TestWorldGivenNamesStayUnique(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t)

	a := w.PutNode(*worldNode(1, alice, "100.64.0.1"))
	b := w.PutNode(*worldNode(2, alice, "100.64.0.2"))

	assert.Equal(t, "node", a.GivenName())
	assert.Equal(t, "node-1", b.GivenName())

	_, err := w.SetGivenName(2, "NODE")
	require.ErrorIs(t, err, ErrGivenNameTaken)

	_, err = w.SetGivenName(2, "not a label")
	require.ErrorIs(t, err, ErrGivenNameInvalid)

	_, err = w.SetGivenName(9, "x")
	require.ErrorIs(t, err, ErrNodeNotFound)

	nv, err := w.SetGivenName(2, "laptop")
	require.NoError(t, err)
	assert.Equal(t, "laptop", nv.GivenName())
}

func TestWorldPrimaryKeepsHealthyIncumbent(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	route := netip.MustParsePrefix("10.0.0.0/24")
	router := func(id types.NodeID, ip string) *types.Node {
		n := worldNode(id, alice, ip)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}

		return n
	}

	w, _ := testWorld(t, router(1, "100.64.0.1"), router(2, "100.64.0.2"))

	primary, _ := w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(1), primary, "lowest ID wins first")

	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(false) })
	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(2), primary, "failover")

	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(true) })
	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(2), primary, "a returning router does not take the prefix back")

	w.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(1), primary, "an unhealthy primary hands over")
}

func TestWorldPrimaryRouteCutoff(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1
	route := netip.MustParsePrefix("10.0.0.0/24")

	nodes := types.Nodes{
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
		worldNode(3, alice, "100.64.0.3"),
	}
	for _, n := range nodes[:2] {
		n.Hostinfo.RoutableIPs = []netip.Prefix{route}
		n.ApprovedRoutes = []netip.Prefix{route}
	}

	w, _ := testWorld(t, nodes...)

	for _, tt := range []struct {
		name    string
		id      types.NodeID
		update  UpdateNodeFunc
		primary types.NodeID
		changed bool
	}{
		{"unrelated endpoint", 3, func(n *types.Node) {
			n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
		}, 1, false},
		{"router endpoint", 1, func(n *types.Node) {
			n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:41641")}
		}, 1, false},
		{"unhealthy backup", 2, func(n *types.Node) { n.Unhealthy = true }, 1, false},
		{"retain unhealthy incumbent", 1, func(n *types.Node) { n.Unhealthy = true }, 1, false},
		{"healthy backup takes over", 2, func(n *types.Node) { n.Unhealthy = false }, 2, true},
		{"endpoint after failover", 3, func(n *types.Node) {
			n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.3:41641")}
		}, 2, false},
		{"healthy former incumbent", 1, func(n *types.Node) { n.Unhealthy = false }, 2, false},
		{"withdraw primary approval", 2, func(n *types.Node) { n.ApprovedRoutes = nil }, 1, true},
		{"withdraw final advertisement", 1, func(n *types.Node) { n.Hostinfo.RoutableIPs = nil }, 0, true},
		{"restore advertisement", 1, func(n *types.Node) { n.Hostinfo.RoutableIPs = []netip.Prefix{route} }, 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := w.snapshot()
			previous := maps.Clone(before.PrimaryRoutes())

			w.UpdateNode(tt.id, tt.update)

			after := w.snapshot()
			if tt.changed {
				assert.Greater(t, after.PrimariesRev(), before.PrimariesRev())
			} else {
				assert.Equal(t, before.PrimariesRev(), after.PrimariesRev(), "equal elections must preserve the cutoff")
			}

			primary, ok := after.PrimaryRouteFor(route)
			assert.Equal(t, tt.primary != 0, ok)
			assert.Equal(t, tt.primary, primary)
			assert.Equal(t, previous, before.PrimaryRoutes(), "old snapshots remain immutable")
			assert.Same(t, after.nodes(), after.s.Get(w.primaries).from, "equal elections still advance their input cursor")
		})
	}
}

func TestWorldSetUsersRefreshesNodeOwner(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, users := testWorld(t, worldNode(1, alice, "100.64.0.1"))

	users[0].DisplayName = "Alice A."
	require.NoError(t, w.SetUsers(users))

	nv, _ := w.snapshot().GetNode(1)
	assert.Equal(t, "Alice A.", nv.User().DisplayName())
}

func TestWorldFailedCompileKeepsLastPolicy(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"), worldNode(2, alice, "100.64.0.2"))
	good := w.snapshot().Policy()

	// Two users named alice make the policy's "alice@" ambiguous.
	dup := []types.User{{Name: "alice"}, {Name: "alice"}}
	dup[0].ID, dup[1].ID = 1, 3
	require.Error(t, w.SetUsers(dup))

	snap := w.snapshot()
	require.Error(t, snap.PolicyErr())
	assert.Same(t, good, snap.Policy())
}

// createTestNode returns a user-owned node with keys and an IPv4 address
// unique to id.
func createTestNode(id types.NodeID, userID uint, username, hostname string) types.Node {
	ip := netip.MustParseAddr(fmt.Sprintf("100.64.%d.%d", id/256, id%256))
	user := &types.User{Name: username, DisplayName: username}
	user.ID = userID

	return types.Node{
		ID:             id,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       hostname,
		GivenName:      hostname,
		UserID:         new(userID),
		User:           user,
		RegisterMethod: "test",
		IPv4:           &ip,
		Hostinfo:       &tailcfg.Hostinfo{},
	}
}

// newTestWorld returns a world without a policy, so every node sees every
// other, holding nodes as PutNode stores them.
func newTestWorld(t *testing.T, nodes ...types.Node) *world {
	t.Helper()

	w, err := newWorld(nil, nil, nil, types.DNSView{})
	require.NoError(t, err)

	for _, n := range nodes {
		w.PutNode(n)
	}

	return w
}

// fatalfer is what *testing.T and *rapid.T share, so property tests can use
// the checks below.
type fatalfer interface {
	Helper()
	Fatalf(format string, args ...any)
}

// checkPeersMatchFullBuild compares the snapshot's derived peer map against
// a policy compiled from scratch over the same nodes and users. Divergence
// means a cutoff kept a peer map the inputs no longer produce.
func checkPeersMatchFullBuild(t fatalfer, snap *Snapshot) {
	t.Helper()

	nodes := snap.ListNodes()

	fresh, err := policy.NewPolicyManager(snap.PolicySource(), snap.Users(), nodes)
	if err != nil {
		t.Fatalf("fresh policy: %v", err)
	}

	want := fresh.BuildPeerMap(nodes)

	for _, nv := range nodes.All() {
		got := snap.ListPeerIDs(nv.ID())

		exp := slices.Sorted(slices.Values(want[nv.ID()]))
		if !slices.Equal(got, exp) {
			t.Fatalf("node %d: peers %v, full build %v", nv.ID(), got, exp)
		}
	}
}

// TestPutNodeGivenNameCollisionBumps is the reproduction for #3188: two
// nodes written with one GivenName get -1, -2, … appended instead of
// sharing it.
func TestPutNodeGivenNameCollisionBumps(t *testing.T) {
	w := newTestWorld(t)

	got1 := w.PutNode(createTestNode(1, 1, "alice", "laptop"))
	got2 := w.PutNode(createTestNode(2, 1, "alice", "laptop"))
	got3 := w.PutNode(createTestNode(3, 1, "alice", "laptop"))

	require.Equal(t, "laptop", got1.GivenName(), "first registration keeps base label")
	require.Equal(t, "laptop-1", got2.GivenName(), "second registration bumps to -1")
	require.Equal(t, "laptop-2", got3.GivenName(), "third registration bumps to -2")
}

// TestPutNodeEmptyGivenNameFallsBackToNode covers the SaaS rule that an
// empty sanitised label becomes the literal "node".
func TestPutNodeEmptyGivenNameFallsBackToNode(t *testing.T) {
	w := newTestWorld(t)

	got1 := w.PutNode(createTestNode(1, 1, "alice", ""))
	got2 := w.PutNode(createTestNode(2, 1, "alice", ""))

	require.Equal(t, "node", got1.GivenName())
	require.Equal(t, "node-1", got2.GivenName())
}

// TestPutNodeIdempotentKeepsLabel asserts re-putting a node does not bump
// its own label.
func TestPutNodeIdempotentKeepsLabel(t *testing.T) {
	w := newTestWorld(t)

	n := createTestNode(1, 1, "alice", "laptop")
	require.Equal(t, "laptop", w.PutNode(n).GivenName())
	require.Equal(t, "laptop", w.PutNode(n).GivenName(), "re-put of same node must not bump its own label")
}

// TestUpdateNodeBumpsOnCollision asserts an update that rewrites GivenName
// to a label another node holds is bumped too.
func TestUpdateNodeBumpsOnCollision(t *testing.T) {
	w := newTestWorld(t,
		createTestNode(1, 1, "alice", "laptop"),
		createTestNode(2, 1, "alice", "phone"),
	)

	view, ok := w.UpdateNode(2, func(n *types.Node) { n.GivenName = "laptop" })
	require.True(t, ok)
	require.Equal(t, "laptop-1", view.GivenName(), "UpdateNode must bump on collision")
}

// TestConcurrentPutNodeSameGivenNameAllUnique writes one GivenName from many
// goroutines; every stored label must still be unique.
func TestConcurrentPutNodeSameGivenNameAllUnique(t *testing.T) {
	const n = 20

	w := newTestWorld(t)

	var wg sync.WaitGroup

	results := make(chan string, n)
	for id := range n {
		wg.Go(func() {
			results <- w.PutNode(createTestNode(types.NodeID(id+1), 1, "alice", "laptop")).GivenName() //nolint:gosec // test ids
		})
	}

	wg.Wait()
	close(results)

	seen := make(map[string]struct{}, n)
	for label := range results {
		require.NotContains(t, seen, label, "duplicate label across concurrent PutNode")

		seen[label] = struct{}{}
	}

	for i := range n {
		want := "laptop"
		if i > 0 {
			want = fmt.Sprintf("laptop-%d", i)
		}

		assert.Contains(t, seen, want)
	}
}

func TestSetGivenName(t *testing.T) {
	w := newTestWorld(t,
		createTestNode(1, 1, "alice", "Laptop"),
		createTestNode(2, 1, "alice", "phone"),
	)

	t.Run("free label", func(t *testing.T) {
		view, err := w.SetGivenName(2, "workhorse")
		require.NoError(t, err)
		require.Equal(t, "workhorse", view.GivenName())
	})

	t.Run("own label", func(t *testing.T) {
		view, err := w.SetGivenName(2, "workhorse")
		require.NoError(t, err, "a node's own label is not a collision")
		require.Equal(t, "workhorse", view.GivenName())
	})

	// "Laptop" and "laptop" are one DNS name, so a certificate for one
	// would be valid for the other.
	t.Run("taken ignoring case", func(t *testing.T) {
		_, err := w.SetGivenName(2, "laptop")
		require.ErrorIs(t, err, ErrGivenNameTaken)

		view, _ := w.snapshot().GetNode(2)
		require.Equal(t, "workhorse", view.GivenName(), "rejected rename must not mutate state")

		got := w.PutNode(createTestNode(3, 1, "alice", "laptop"))
		require.Equal(t, "laptop-1", got.GivenName())
	})

	t.Run("invalid", func(t *testing.T) {
		for _, bad := range []string{"Joe's Mac", "has space", "-leading", "trailing-", "", "dot.in.label"} {
			_, err := w.SetGivenName(1, bad)
			require.ErrorIsf(t, err, ErrGivenNameInvalid, "label %q must reject as invalid", bad)
		}
	})

	t.Run("missing node", func(t *testing.T) {
		_, err := w.SetGivenName(999, "something")
		require.ErrorIs(t, err, ErrNodeNotFound)
	})
}

// TestWorldIndex covers the lookups every reader relies on: peers never
// include the node itself, and tagged nodes belong to no user.
func TestWorldIndex(t *testing.T) {
	tagged := createTestNode(4, 1, "user1", "tagged")
	tagged.UserID, tagged.User = nil, nil
	tagged.Tags = []string{"tag:srv"}

	snap := newTestWorld(t,
		createTestNode(1, 1, "user1", "node1"),
		createTestNode(2, 2, "user2", "node2"),
		createTestNode(3, 1, "user1", "node3"),
		tagged,
	).snapshot()

	assert.Equal(t, 4, snap.ListNodes().Len())
	assert.Equal(t, 2, snap.ListNodesByUser(1).Len())
	assert.Equal(t, 1, snap.ListNodesByUser(2).Len())
	assert.Zero(t, snap.ListNodesByUser(0).Len(), "tagged nodes are owned by no user")

	for _, nv := range snap.ListNodes().All() {
		peers := snap.ListPeerIDs(nv.ID())
		assert.Len(t, peers, 3, "node %d sees every other node", nv.ID())
		assert.NotContains(t, peers, nv.ID(), "node %d listed among its own peers", nv.ID())
	}

	assert.Zero(t, newTestWorld(t).snapshot().ListNodes().Len())
}

func TestGetNodesByMachineKeyAllUsers(t *testing.T) {
	mk := key.NewMachine().Public()

	owned1 := createTestNode(1, 1, "user1", "node1")
	owned1.MachineKey = mk
	owned2 := createTestNode(2, 2, "user2", "node2")
	owned2.MachineKey = mk
	tagged := createTestNode(3, 3, "user3", "node3")
	tagged.MachineKey = mk
	tagged.UserID, tagged.User = nil, nil
	tagged.Tags = []string{"tag:foo"}

	require.Empty(t, newTestWorld(t).snapshot().GetNodesByMachineKeyAllUsers(mk))

	all := newTestWorld(t, owned1, owned2, tagged).snapshot().GetNodesByMachineKeyAllUsers(mk)
	require.Len(t, all, 3)
	require.Equal(t, types.NodeID(1), all[types.UserID(1)].ID())
	require.Equal(t, types.NodeID(2), all[types.UserID(2)].ID())
	require.True(t, all[types.UserID(0)].IsTagged(), "tagged node is indexed under UserID(0)")
	require.Equal(t, types.NodeID(3), all[types.UserID(0)].ID())
}

// nodeKeyIndexMismatch describes where snap's NodeKey index disagrees with
// its node list, or returns "" when every listed node, and nothing else, is
// indexed.
func nodeKeyIndexMismatch(snap *Snapshot) string {
	idx := snap.index()
	if keys := idx.byNodeKey.Groups.Len(); keys != len(idx.all.get()) {
		return fmt.Sprintf("index holds %d keys, list holds %d nodes", keys, len(idx.all.get()))
	}

	for _, nv := range idx.all.get() {
		got, ok := snap.GetNodeByNodeKey(nv.NodeKey())
		if !ok {
			return fmt.Sprintf("node %d: key not indexed", nv.ID())
		}

		if got.ID() != nv.ID() {
			return fmt.Sprintf("node %d: key indexed to node %d", nv.ID(), got.ID())
		}
	}

	return ""
}

// TestWorldNodeKeyIndexMatchesNodes pins the index DERP admission reads:
// every published snapshot indexes exactly its nodes' keys, and a key
// rotated away or deleted stops resolving, also on writes the policy
// ignores.
func TestWorldNodeKeyIndexMatchesNodes(t *testing.T) {
	n1 := createTestNode(1, 1, "user1", "node1")
	n2 := createTestNode(2, 1, "user1", "node2")
	n3 := createTestNode(3, 2, "user2", "node3")
	w := newTestWorld(t, n1, n2, n3)

	// Readers load snapshots while the writes below publish them, so a torn
	// or stale index surfaces here and under -race.
	var (
		firstMismatch atomic.Pointer[string]
		stop          atomic.Bool
		readers       sync.WaitGroup
	)

	for range 4 {
		readers.Go(func() {
			for !stop.Load() {
				if msg := nodeKeyIndexMismatch(w.snapshot()); msg != "" {
					firstMismatch.CompareAndSwap(nil, &msg)
				}
			}
		})
	}

	stopReaders := func() {
		stop.Store(true)
		readers.Wait()
	}
	t.Cleanup(stopReaders)

	requireResolves := func(k key.NodePublic, want types.NodeID) {
		t.Helper()

		nv, ok := w.snapshot().GetNodeByNodeKey(k)
		require.True(t, ok, "key of node %d must resolve", want)
		require.Equal(t, want, nv.ID())
	}

	requireRefused := func(k key.NodePublic) {
		t.Helper()

		_, ok := w.snapshot().GetNodeByNodeKey(k)
		require.False(t, ok, "key must not resolve")
	}

	requireResolves(n1.NodeKey, 1)
	requireResolves(n2.NodeKey, 2)
	requireResolves(n3.NodeKey, 3)

	before := w.snapshot()

	// Repeat the rotation so the readers overlap many publishes.
	current := n1.NodeKey
	for range 50 {
		prev := current
		current = key.NewNode().Public()

		_, ok := w.UpdateNode(1, func(n *types.Node) { n.NodeKey = current })
		require.True(t, ok)

		requireRefused(prev)
		requireResolves(current, 1)
	}

	w.UpdateNode(2, func(n *types.Node) { n.Hostname = "node2-renamed" })

	nv, ok := w.snapshot().GetNodeByNodeKey(n2.NodeKey)
	require.True(t, ok)
	require.Equal(t, "node2-renamed", nv.Hostname(), "a payload write must republish the indexed view")

	require.Equal(t, before.PeersRev(), w.snapshot().PeersRev(),
		"rotation and payload writes must not rebuild the peer map")

	w.DeleteNode(3)
	requireRefused(n3.NodeKey)
	requireResolves(current, 1)
	requireResolves(n2.NodeKey, 2)

	stopReaders()

	if msg := firstMismatch.Load(); msg != nil {
		t.Fatalf("snapshot index disagreed with node list: %s", *msg)
	}

	require.Empty(t, nodeKeyIndexMismatch(w.snapshot()))
}

// TestWorldNonPolicyWritesKeepPolicy covers which node writes recompile the
// policy: only fields it reads, so routine map requests and sessions do not
// pay for a compile and a peer-map build.
func TestWorldNonPolicyWritesKeepPolicy(t *testing.T) {
	route := netip.MustParsePrefix("10.0.0.0/24")

	tests := []struct {
		name    string
		write   func(n *types.Node)
		compile bool
	}{
		{name: "last seen", write: func(n *types.Node) { n.LastSeen = new(time.Now()) }},
		{name: "node key", write: func(n *types.Node) { n.NodeKey = key.NewNode().Public() }},
		{name: "online", write: func(n *types.Node) { n.IsOnline = new(true) }},
		{name: "health", write: func(n *types.Node) { n.Unhealthy = true }},
		{name: "given name", write: func(n *types.Node) { n.GivenName = "renamed" }},
		{name: "announced only", write: func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		}},
		{name: "tags", compile: true, write: func(n *types.Node) {
			n.Tags = []string{"tag:srv"}
			n.UserID, n.User = nil, nil
		}},
		{name: "address", compile: true, write: func(n *types.Node) {
			n.IPv4 = new(netip.MustParseAddr("100.64.9.9"))
		}},
		{name: "announced and approved", compile: true, write: func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			n.ApprovedRoutes = []netip.Prefix{route}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newTestWorld(t, createTestNode(1, 1, "user1", "node1"), createTestNode(2, 1, "user1", "node2"))
			before := w.snapshot()

			_, ok := w.UpdateNode(1, tt.write)
			require.True(t, ok)

			after := w.snapshot()
			require.Greater(t, after.Rev(), before.Rev())
			assert.Equal(t, tt.compile, after.PolicyRev() != before.PolicyRev(), "policy recompiled")

			if !tt.compile {
				assert.Same(t, before.Policy(), after.Policy())
			}
		})
	}
}

func TestUpdateNodeDiff(t *testing.T) {
	node := createTestNode(1, 1, "user1", "node1")
	w := newTestWorld(t, node)

	newKey := key.NewNode().Public()
	before, after, ok := w.UpdateNodeDiff(1, func(n *types.Node) { n.NodeKey = newKey })
	require.True(t, ok)
	assert.Equal(t, node.NodeKey, before.NodeKey())
	assert.Equal(t, newKey, after.NodeKey())

	rev := w.snapshot().Rev()
	called := false

	before, after, ok = w.UpdateNodeDiff(99, func(*types.Node) { called = true })
	assert.False(t, ok)
	assert.False(t, before.Valid())
	assert.False(t, after.Valid())
	assert.False(t, called, "an update of a missing node must not run")
	assert.Equal(t, rev, w.snapshot().Rev(), "an update of a missing node must not commit")
}

func TestPrimaryRoutesForNodeSorted(t *testing.T) {
	node := createTestNode(1, 1, "user1", "router")

	prefixes := make([]netip.Prefix, 0, 8)
	for i := range 8 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
	}

	node.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: prefixes}
	node.ApprovedRoutes = prefixes
	node.IsOnline = new(true)

	snap := newTestWorld(t, node).snapshot()

	// Map iteration order varies per call; repeat to catch an unsorted result.
	for range 20 {
		require.Equal(t, prefixes, snap.PrimaryRoutesForNode(1))
	}
}

// Policy shapes for TestWorldPeersMatchFullBuild: a global ACL,
// autogroup:self, and a via grant.
const (
	policyGlobal = `{
		"groups": {"group:a": ["u1@"]},
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [
			{"action": "accept", "src": ["group:a"], "dst": ["tag:srv:*"]},
			{"action": "accept", "src": ["u2@"], "dst": ["10.33.0.0/24:*"]}
		]}`

	policyAutogroupSelf = `{
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`

	policyVia = `{
		"tagOwners": {"tag:router": ["u1@"]},
		"grants": [{"src": ["u2@"], "dst": ["10.33.0.0/24"], "ip": ["*"], "via": ["tag:router"]}]}`
)

// TestWorldPeersMatchFullBuild drives random node writes through the world
// and checks after every step that the derived peer map, including one the
// policy-nodes cutoff kept from the previous commit, matches a policy
// compiled from scratch. Divergence means the cutoff skipped a field the
// policy reads.
func TestWorldPeersMatchFullBuild(t *testing.T) {
	subnet := netip.MustParsePrefix("10.33.0.0/24")

	for _, tc := range []struct {
		name string
		pol  string
	}{
		{name: "global", pol: policyGlobal},
		{name: "autogroup-self", pol: policyAutogroupSelf},
		{name: "via", pol: policyVia},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				users := []types.User{{Name: "u1"}, {Name: "u2"}}
				users[0].ID, users[1].ID = 1, 2

				nodes := make(types.Nodes, 0, 6)

				for i := 1; i <= 6; i++ {
					u := users[i%2]
					n := createTestNode(types.NodeID(i), u.ID, u.Name, fmt.Sprintf("n%d", i))
					nodes = append(nodes, &n)
				}

				w, err := newWorld(nodes, users, []byte(tc.pol), types.DNSView{})
				if err != nil {
					rt.Fatalf("world: %v", err)
				}

				steps := rapid.IntRange(1, 20).Draw(rt, "steps")
				for range steps {
					id := types.NodeID(rapid.IntRange(1, 6).Draw(rt, "id")) //nolint:gosec // small test ids
					switch rapid.IntRange(0, 5).Draw(rt, "op") {
					case 0: // payload only
						w.UpdateNode(id, func(n *types.Node) { n.LastSeen = new(time.Now()) })
					case 1: // tag
						tag := rapid.SampledFrom([]string{"tag:srv", "tag:router"}).Draw(rt, "tag")

						w.UpdateNode(id, func(n *types.Node) {
							n.Tags = []string{tag}
							n.UserID, n.User = nil, nil
						})
					case 2: // announce + approve subnet
						w.UpdateNode(id, func(n *types.Node) {
							n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
							n.ApprovedRoutes = []netip.Prefix{subnet}
						})
					case 3: // drop routes
						w.UpdateNode(id, func(n *types.Node) { n.ApprovedRoutes = nil })
					case 4: // online flip
						w.UpdateNode(id, func(n *types.Node) { n.IsOnline = new(!n.Online()) })
					case 5: // endpoint
						w.UpdateNode(id, func(n *types.Node) {
							n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
						})
					}

					checkPeersMatchFullBuild(rt, w.snapshot())
				}
			})
		})
	}
}

// TestListPeersExcludesSelf proves a node is never returned among its own
// peers, also when the caller names it explicitly. The mapper would
// otherwise emit the recipient in its own PeersChanged, and the Tailscale
// client would merge it into its peer map next to the self node.
func TestListPeersExcludesSelf(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("peer-user")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "peer-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	allIDs := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		allIDs = append(allIDs, n.ID)
	}

	for _, self := range allIDs {
		t.Run(self.String(), func(t *testing.T) {
			for _, peer := range s.ListPeers(self).All() {
				require.NotEqual(t, self, peer.ID(), "node listed in its own peers")
			}

			named := s.ListPeers(self, allIDs...)
			require.Equal(t, len(allIDs)-1, named.Len(), "self must be dropped, every other named node kept")

			for _, peer := range named.All() {
				require.NotEqual(t, self, peer.ID(), "node listed in its own named peers")
			}

			require.Zero(t, s.ListPeers(self, self).Len(), "naming only self must yield no peers")
		})
	}
}

// TestPolicyCachesSurviveStaleView asks the newly compiled policy about a
// node through a view taken before the write that compiled it, as a caller
// holding an older view does. That answer must not be cached under the
// node's ID, or the fresh view keeps getting it.
func TestPolicyCachesSurviveStaleView(t *testing.T) {
	subnet := netip.MustParsePrefix("10.33.0.0/24")

	pol := `{
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [{"action": "accept", "src": ["u2@"], "dst": ["10.33.0.0/24:*"]}],
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}]
	}`

	tests := []struct {
		name   string
		mutate func(n *types.Node)
		// probe reports a property of node 1's policy artefact that the
		// write flips from !want to want.
		probe func(pm policy.PolicyManager, view types.NodeView) (bool, error)
		want  bool
	}{
		{
			name: "filter after route approval",
			mutate: func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
				n.ApprovedRoutes = []netip.Prefix{subnet}
			},
			probe: func(pm policy.PolicyManager, view types.NodeView) (bool, error) {
				rules, err := pm.FilterForNode(view)
				if err != nil {
					return false, err
				}

				for _, r := range rules {
					for _, d := range r.DstPorts {
						if d.IP == subnet.String() {
							return true, nil
						}
					}
				}

				return false, nil
			},
			want: true,
		},
		{
			// A tagged node is outside autogroup:self, so tagging it must
			// drop its SSH rules.
			name: "ssh after tagging",
			mutate: func(n *types.Node) {
				n.Tags = []string{"tag:srv"}
				n.UserID, n.User = nil, nil
			},
			probe: func(pm policy.PolicyManager, view types.NodeView) (bool, error) {
				sshPol, err := pm.SSHPolicy("", view)
				if err != nil {
					return false, err
				}

				return sshPol != nil && len(sshPol.Rules) > 0, nil
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := []types.User{{Name: "u1"}, {Name: "u2"}}
			users[0].ID, users[1].ID = 1, 2

			// Node 3 shares node 1's user so autogroup:self has a source
			// for node 1 once node 1 itself is tagged away.
			owners := []int{0, 1, 0}
			nodes := make(types.Nodes, 0, len(owners))

			for i, o := range owners {
				n := createTestNode(types.NodeID(i+1), users[o].ID, users[o].Name, fmt.Sprintf("n%d", i+1)) //nolint:gosec // small test ids
				nodes = append(nodes, &n)
			}

			w, err := newWorld(nodes, users, []byte(pol), types.DNSView{})
			require.NoError(t, err)

			before, ok := w.snapshot().GetNode(1)
			require.True(t, ok)

			got, err := tt.probe(w.snapshot().Policy(), before)
			require.NoError(t, err)
			require.NotEqual(t, tt.want, got, "precondition: the write must flip the probed artefact")

			after, ok := w.UpdateNode(1, tt.mutate)
			require.True(t, ok)

			pm := w.snapshot().Policy()

			_, err = tt.probe(pm, before)
			require.NoError(t, err)

			got, err = tt.probe(pm, after)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "the policy must answer for the written node")
		})
	}
}

// TestWorldGroupCommitsQueuedWrites queues writes behind a stalled commit
// and checks they land together: one more commit, so one policy compile,
// for the whole burst.
func TestWorldGroupCommitsQueuedWrites(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"))
	before := w.snapshot().Rev()

	entered, release := make(chan struct{}), make(chan struct{})

	go w.UpdateNode(1, func(*types.Node) {
		close(entered)
		<-release
	})

	<-entered

	const burst = 10

	var wg sync.WaitGroup

	for i := range burst {
		wg.Go(func() {
			w.PutNode(*worldNode(types.NodeID(i+2), alice, fmt.Sprintf("100.64.0.%d", i+2))) //nolint:gosec // small test IDs
		})
	}

	require.Eventually(t, func() bool {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes) == burst
	}, 5*time.Second, time.Millisecond)

	close(release)
	wg.Wait()

	after := w.snapshot()
	assert.Equal(t, before+2, after.Rev(), "the stalled write and the burst commit once each")
	assert.Equal(t, burst+1, after.ListNodes().Len())
	assert.Len(t, after.ListPeerIDs(1), burst)
}

// BenchmarkWorldEndpointWrite measures one endpoint update, the most common
// write: it must not recompile the policy or rebuild peers.
func BenchmarkWorldEndpointWrite(b *testing.B) {
	for _, n := range []int{500, 2000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			alice := &types.User{Name: "alice"}
			alice.ID = 1

			nodes := make(types.Nodes, n)
			for i := range nodes {
				nodes[i] = worldNode(types.NodeID(i+1), alice, netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}).String())
			}

			users := []types.User{*alice}

			w, err := newWorld(nodes, users, []byte(ownUserPolicy), types.DNSView{})
			require.NoError(b, err)

			port := uint16(0)

			b.ReportAllocs()

			for b.Loop() {
				port++

				w.UpdateNode(1, func(n *types.Node) {
					n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
				})
			}
		})
	}

	for _, count := range []int{0, 1000, 10000} {
		for _, timeout := range []time.Duration{0, 50 * time.Millisecond} {
			b.Run(fmt.Sprintf("prefixes=%d/batchTimeout=%s", count, timeout), func(b *testing.B) {
				alice := &types.User{Name: "alice"}
				alice.ID = 1

				router := worldNode(2, alice, "100.64.0.2")

				for i := range count {
					prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
					router.Hostinfo.RoutableIPs = append(router.Hostinfo.RoutableIPs, prefix)
					router.ApprovedRoutes = append(router.ApprovedRoutes, prefix)
				}

				w, err := newWorld(types.Nodes{worldNode(1, alice, "100.64.0.1"), router}, []types.User{*alice}, []byte(ownUserPolicy), types.DNSView{})
				require.NoError(b, err)

				w.batchTimeout = timeout
				require.Len(b, w.snapshot().PrimaryRoutes(), count)

				port := uint16(0)

				b.ReportAllocs()

				for b.Loop() {
					port++

					w.UpdateNode(1, func(n *types.Node) {
						n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
					})
				}
			})
		}
	}
}

// TestWorldIndexMatchesFullBuild applies random writes and checks the
// patched index, and the reused election, against building them afresh.
func TestWorldIndexMatchesFullBuild(t *testing.T) {
	alice, bob := &types.User{Name: "alice"}, &types.User{Name: "bob"}
	alice.ID, bob.ID = 1, 2

	route := netip.MustParsePrefix("10.0.0.0/24")

	nodes := make(types.Nodes, 8)
	for i := range nodes {
		nodes[i] = worldNode(types.NodeID(i+1), alice, fmt.Sprintf("100.64.0.%d", i+1))
		nodes[i].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		nodes[i].ApprovedRoutes = []netip.Prefix{route}
	}

	w, err := newWorld(nodes, []types.User{*alice, *bob}, nil, types.DNSView{})
	require.NoError(t, err)

	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test input
	prevRoutes := w.snapshot().PrimaryRoutes()

	for step := range 400 {
		id := types.NodeID(r.IntN(10) + 1) //nolint:gosec // small test IDs

		switch r.IntN(8) {
		case 0:
			w.UpdateNode(id, func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")} })
		case 1:
			w.UpdateNode(id, func(n *types.Node) { n.IsOnline = new(!n.Online()) })
		case 2:
			w.UpdateNode(id, func(n *types.Node) { n.NodeKey = key.NewNode().Public() })
		case 3:
			w.UpdateNode(id, func(n *types.Node) { n.Tags = []string{"tag:x"}; n.UserID, n.User = nil, nil })
		case 4:
			w.DeleteNode(id)
		case 5:
			w.PutNode(*worldNode(id, bob, fmt.Sprintf("100.64.1.%d", id)))
		case 6:
			w.UpdateNode(id, func(n *types.Node) { n.Unhealthy = !n.Unhealthy })
		case 7:
			w.UpdateNode(id, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
				n.ApprovedRoutes = []netip.Prefix{route}
			})
		}

		snap := w.snapshot()
		got, want := snap.index(), updateIndex(nil, snap.nodes())

		// The sorted list is built on first read; skip reading it now and
		// then so a later read patches across unread commits.
		if r.IntN(3) != 0 {
			require.Equal(t, want.all.get(), got.all.get(), "step %d", step)
		}

		require.Equal(t, groups(want.byNodeKey), groups(got.byNodeKey), "step %d", step)
		require.Equal(t, groups(want.byMachineKey), groups(got.byMachineKey), "step %d", step)
		require.Equal(t, groups(want.byUser), groups(got.byUser), "step %d", step)

		// Electing only the touched prefixes equals electing all of them.
		require.Equal(t, electPrimaryRoutes(snap.nodes(), prevRoutes), snap.PrimaryRoutes(), "step %d", step)
		prevRoutes = snap.PrimaryRoutes()

		for _, primary := range snap.PrimaryRoutes() {
			n, _ := snap.GetNode(primary)
			require.True(t, n.Online(), "step %d: offline primary %d", step, primary)
		}
	}
}

// TestWorldBatchTimeoutElectsTogether lets two HA routers come back during
// an outage, the healthy-incumbent case: they must land in one commit, so
// the election sees both and keeps the incumbent. The batch ends when both
// are queued, not on a timer, so a slow scheduler cannot split it.
func TestWorldBatchTimeoutElectsTogether(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	route := netip.MustParsePrefix("10.0.0.0/24")
	router := func(id types.NodeID, ip string) *types.Node {
		n := worldNode(id, alice, ip)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}

		return n
	}

	w, _ := testWorld(t, router(1, "100.64.0.1"), router(2, "100.64.0.2"))
	w.batchTimeout, w.batchSize = time.Hour, 1

	// Move the route to 2, then lose both: the all-unhealthy rule keeps 2.
	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(false) })
	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(true) })
	w.UpdateNodes(map[types.NodeID]UpdateNodeFunc{
		1: func(n *types.Node) { n.Unhealthy = true },
		2: func(n *types.Node) { n.Unhealthy = true },
	})

	primary, _ := w.snapshot().PrimaryRouteFor(route)
	require.Equal(t, types.NodeID(2), primary)

	w.batchTimeout, w.batchSize = time.Hour, 2
	before := w.snapshot().Rev()

	var wg sync.WaitGroup

	for _, id := range []types.NodeID{1, 2} {
		wg.Go(func() { w.UpdateNode(id, func(n *types.Node) { n.Unhealthy = false }) })
	}

	wg.Wait()

	assert.Equal(t, before+1, w.snapshot().Rev(), "both recoveries commit together")

	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(2), primary, "the incumbent keeps the route")
}

func TestWorldOutageTracksHealthWhenBatchingEnabled(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Hour} {
		t.Run(timeout.String(), func(t *testing.T) {
			alice := &types.User{Name: "alice"}
			alice.ID = 1
			route := netip.MustParsePrefix("10.0.0.0/24")
			router := func(id types.NodeID, ip string) *types.Node {
				n := worldNode(id, alice, ip)
				n.Hostinfo.RoutableIPs = []netip.Prefix{route}
				n.ApprovedRoutes = []netip.Prefix{route}

				return n
			}

			w, _ := testWorld(t, router(1, "100.64.0.1"), router(2, "100.64.0.2"))
			w.batchTimeout, w.batchSize = timeout, 1
			before := w.snapshot()

			w.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
			require.False(t, w.inOutage.Load(), "the incumbent is still healthy")
			w.UpdateNode(1, func(n *types.Node) { n.Unhealthy = true })

			after := w.snapshot()
			primary, ok := after.PrimaryRouteFor(route)
			require.True(t, ok)
			require.Equal(t, types.NodeID(1), primary, "an unhealthy incumbent keeps the route without a healthy backup")
			require.Equal(t, before.PrimariesRev(), after.PrimariesRev(), "health changed without changing the primary")
			assert.Equal(t, timeout > 0, w.inOutage.Load(), "only enabled batching needs outage tracking")

			w.UpdateNode(1, func(n *types.Node) {
				n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
			})
			assert.Equal(t, timeout > 0, w.inOutage.Load(), "an endpoint write preserves the outage")

			w.UpdateNode(1, func(n *types.Node) { n.Unhealthy = false })
			after = w.snapshot()
			primary, ok = after.PrimaryRouteFor(route)
			assert.True(t, ok)
			assert.Equal(t, types.NodeID(1), primary)
			assert.Equal(t, before.PrimariesRev(), after.PrimariesRev())
			assert.False(t, w.inOutage.Load(), "the healthy incumbent ends the outage")
		})
	}
}

// groups returns an index's groups as a native map, for comparing.
func groups[G comparable](g graph.Grouped[types.NodeID, *types.Node, G]) map[G][]types.NodeID {
	out := maps.Collect(g.Groups.All())

	return out
}

// TestWorldSetUsersUnchangedDoesNotWait pins that a refresh with the same
// users, one per registration, does not wait for a commit: every join
// would otherwise queue behind the commit in flight.
func TestWorldSetUsersUnchangedDoesNotWait(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, users := testWorld(t, worldNode(1, alice, "100.64.0.1"))

	// Hold a commit open; an unchanged refresh must not wait for it.
	inCommit, release := make(chan struct{}), make(chan struct{})

	go func() {
		_, _ = w.g.Update(func(*graph.Tx) error {
			close(inCommit)
			<-release

			return nil
		})
	}()

	<-inCommit

	defer close(release)

	done := make(chan struct{})

	go func() {
		assert.NoError(t, w.SetUsers(slices.Clone(users)))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an unchanged user refresh waited for a commit")
	}
}

// TestWorldIdleWriteCommitsAtOnce sets an hour-long batch timeout and
// checks a write outside an HA outage does not wait for it.
func TestWorldIdleWriteCommitsAtOnce(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"))
	w.batchTimeout = time.Hour

	done := make(chan struct{})

	go func() {
		w.UpdateNode(1, func(n *types.Node) { n.Hostname = "renamed" })
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a write outside an outage waited for the batch timeout")
	}
}

// TestNewWorldRejectsInvalidPolicy starts a world on policies that do not
// compile: it must return the error, not panic in a cell reading the
// policy the first compile never produced.
func TestNewWorldRejectsInvalidPolicy(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	for name, pol := range map[string]string{
		"malformed":         `{"acls": [`,
		"invalid reference": `{"acls":[{"action":"accept","src":["nobody@"],"dst":["*:*"]}],"nodeAttrs":[{"target":["group:missing"],"attr":["custom:x"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newWorld([]*types.Node{worldNode(1, alice, "100.64.0.1")}, []types.User{*alice}, []byte(pol), types.DNSView{})
			require.Error(t, err)
		})
	}
}

// TestWorldWritePanicFailsOnlyItsWriter batches a panicking write with a
// good one: the panic reaches only its own writer, the good write commits,
// and later writes still commit.
func TestWorldWritePanicFailsOnlyItsWriter(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"), worldNode(2, alice, "100.64.0.2"))

	inCommit, release := make(chan struct{}), make(chan struct{})

	go w.update(func(*nodeEdit) {
		close(inCommit)
		<-release
	})

	<-inCommit

	var (
		wg       sync.WaitGroup
		panicked any
		good     types.NodeView
	)

	wg.Go(func() {
		defer func() { panicked = recover() }()

		w.UpdateNode(1, func(*types.Node) { panic("boom") })
	})
	wg.Go(func() {
		good, _ = w.UpdateNode(2, func(n *types.Node) { n.Hostname = "good" })
	})

	require.Eventually(t, func() bool {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes) == 2
	}, time.Second, time.Millisecond, "both writes must queue into one batch")

	close(release)
	wg.Wait()

	assert.Equal(t, "boom", panicked, "the panic reaches its own writer")
	assert.Equal(t, "good", good.Hostname(), "the write batched with it commits")

	done := make(chan types.NodeView)

	go func() {
		n, _ := w.UpdateNode(1, func(n *types.Node) { n.Hostname = "after" })
		done <- n
	}()

	select {
	case n := <-done:
		assert.Equal(t, "after", n.Hostname())
	case <-time.After(5 * time.Second):
		t.Fatal("a write after a panic must still commit")
	}
}

// TestWorldConcurrentWritesDeletesAndUserRenames races node updates, joins
// and deletes, which share group commits and their hand-off, against user
// renames, which commit on their own: no snapshot may show a user's nodes
// with different revisions of the user, no write may be lost and no
// deleted node may come back.
func TestWorldConcurrentWritesDeletesAndUserRenames(t *testing.T) {
	alice, bob := &types.User{Name: "alice"}, &types.User{Name: "bob"}
	alice.ID, bob.ID = 1, 2

	const n, rounds = 40, 100

	nodes := make(types.Nodes, n)
	for i := range nodes {
		owner := alice
		if i%2 == 1 {
			owner = bob
		}

		nodes[i] = worldNode(types.NodeID(i+1), owner, fmt.Sprintf("100.64.0.%d", i+1)) //nolint:gosec // small test IDs
	}

	users := []types.User{*alice, *bob}

	w, err := newWorld(nodes, users, nil, types.DNSView{})
	require.NoError(t, err)

	deleted := func(id types.NodeID) bool { return id <= n && id%4 == 1 }

	var (
		writers sync.WaitGroup
		readers sync.WaitGroup
		stop    = make(chan struct{})
		mixed   atomic.Value
	)

	readers.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}

			snap := w.snapshot()
			seen := map[string]types.NodeID{}

			for _, nv := range snap.ListNodes().All() {
				if nv.User().ID() == alice.ID {
					seen[nv.User().DisplayName()] = nv.ID()
				}
			}

			if len(seen) > 1 {
				mixed.Store(fmt.Sprintf("rev %d: alice's nodes carry %v", snap.Rev(), seen))

				return
			}
		}
	})

	for g := range 4 {
		writers.Go(func() {
			for r := range rounds {
				id := types.NodeID(1 + (g*rounds+r)%n) //nolint:gosec // small test IDs
				w.UpdateNode(id, func(nd *types.Node) { nd.Hostname = fmt.Sprintf("h%d", r) })
			}
		})
	}

	writers.Go(func() {
		for id := types.NodeID(1); id <= n; id++ {
			if deleted(id) {
				w.DeleteNode(id)
			}
		}
	})

	writers.Go(func() {
		for i := range n / 2 {
			w.PutNode(*worldNode(types.NodeID(n+1+i), bob, fmt.Sprintf("100.64.1.%d", i+1))) //nolint:gosec // small test IDs
		}
	})

	writers.Go(func() {
		for r := range rounds {
			renamed := slices.Clone(users)
			renamed[0].DisplayName = fmt.Sprintf("Alice %d", r)
			assert.NoError(t, w.SetUsers(renamed))
		}
	})

	writers.Wait()
	close(stop)
	readers.Wait()

	if m := mixed.Load(); m != nil {
		t.Fatal(m)
	}

	w.writeMu.Lock()
	assert.False(t, w.committing, "the commit loop did not end")
	assert.Empty(t, w.writes, "writes left queued")
	w.writeMu.Unlock()

	snap := w.snapshot()
	last := fmt.Sprintf("Alice %d", rounds-1)

	for id := types.NodeID(1); id <= n+n/2; id++ {
		nv, ok := snap.GetNode(id)
		if deleted(id) {
			assert.False(t, ok, "deleted node %d is back", id)

			continue
		}

		if !assert.True(t, ok, "node %d lost", id) {
			continue
		}

		if nv.User().ID() == alice.ID {
			assert.Equal(t, last, nv.User().DisplayName(), "node %d", id)
		}
	}

	checkPeersMatchFullBuild(t, snap)
}

// TestWorldSetUsersStoresProfileChanges renames a user's display name: the
// snapshot must carry it, the policy must not recompile for it, and a
// later unchanged refresh must commit nothing. A login bumping only
// UpdatedAt rewrites none of the user's nodes.
func TestWorldSetUsersStoresProfileChanges(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, users := testWorld(t, worldNode(1, alice, "100.64.0.1"))
	policyRev := w.snapshot().PolicyRev()

	renamed := slices.Clone(users)
	renamed[0].DisplayName = "Alice A."
	require.NoError(t, w.SetUsers(renamed))

	snap := w.snapshot()
	assert.Equal(t, "Alice A.", snap.Users()[0].DisplayName, "the snapshot carries the new display name")
	assert.Equal(t, policyRev, snap.PolicyRev(), "a display name does not recompile the policy")

	node, ok := snap.GetNode(1)
	require.True(t, ok)
	assert.Equal(t, "Alice A.", node.User().DisplayName(), "the node renders the new display name")

	rev := snap.Rev()

	require.NoError(t, w.SetUsers(slices.Clone(renamed)))
	assert.Equal(t, rev, w.snapshot().Rev(), "an unchanged refresh commits nothing")

	bumped := slices.Clone(renamed)
	bumped[0].UpdatedAt = time.Now()

	require.NoError(t, w.SetUsers(bumped))

	after, ok := w.snapshot().GetNode(1)
	require.True(t, ok)
	assert.True(t, node.SameRender(after), "a timestamp-only user change leaves the node as it was")
}

// TestWorldNodeKeySharedByReregistrationResolvesToNewest registers a
// machine under a second user without rotating its node key: the key must
// resolve to the newer node, which the client now speaks for.
func TestWorldNodeKeySharedByReregistrationResolvesToNewest(t *testing.T) {
	alice, bob := &types.User{Name: "alice"}, &types.User{Name: "bob"}
	alice.ID, bob.ID = 1, 2

	old := worldNode(1, alice, "100.64.0.1")
	newer := worldNode(2, bob, "100.64.0.2")
	newer.NodeKey, newer.MachineKey = old.NodeKey, old.MachineKey

	w, _ := testWorld(t, old, newer)

	got, ok := w.snapshot().GetNodeByNodeKey(old.NodeKey)
	require.True(t, ok)
	assert.Equal(t, types.NodeID(2), got.ID())
}

// TestWorldOutageBatchesWritesQueuedDuringACommit holds a commit open
// during an outage, queues one router's recovery behind it, and sends the
// other's just after it ends: the commit that picks up the queued write
// must wait for the batch too, so both recoveries are elected together
// and the incumbent keeps the route.
func TestWorldOutageBatchesWritesQueuedDuringACommit(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	route := netip.MustParsePrefix("10.0.0.0/24")
	router := func(id types.NodeID, ip string) *types.Node {
		n := worldNode(id, alice, ip)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}

		return n
	}

	w, _ := testWorld(t, router(1, "100.64.0.1"), router(2, "100.64.0.2"))
	w.batchTimeout = 500 * time.Millisecond

	// Move the route to 2, then lose both: the all-unhealthy rule keeps 2.
	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(false) })
	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(true) })
	w.UpdateNodes(map[types.NodeID]UpdateNodeFunc{
		1: func(n *types.Node) { n.Unhealthy = true },
		2: func(n *types.Node) { n.Unhealthy = true },
	})
	require.True(t, w.inOutage.Load(), "test sanity: the prefix is in an outage")

	inCommit, release, held := make(chan struct{}), make(chan struct{}), make(chan struct{})

	go func() {
		w.update(func(*nodeEdit) {
			close(inCommit)
			<-release
		})
		close(held)
	}()

	<-inCommit

	var wg sync.WaitGroup

	recoverRouter := func(id types.NodeID) {
		wg.Go(func() { w.UpdateNode(id, func(n *types.Node) { n.Unhealthy = false }) })
	}

	queued := func() int {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes)
	}

	recoverRouter(1)
	require.Eventually(t, func() bool { return queued() == 1 }, time.Second, time.Millisecond,
		"the first recovery queues behind the held commit")

	close(release)
	<-held

	// The commit for the queued recovery waits for the batch, so the write
	// stays queued; one that commits at once would take it straight away.
	assert.Never(t, func() bool { return queued() == 0 }, 100*time.Millisecond, time.Millisecond,
		"the commit after the held one must wait for the batch during an outage")

	recoverRouter(2)
	wg.Wait()

	primary, _ := w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(2), primary, "the incumbent keeps the route")
}

// TestWorldMachineKeyIndexKeysTaggedNodesUnderZero indexes a tagged node
// that still records the user who created it: it must sit under UserID 0,
// where registration looks for tagged nodes, not under that user, where it
// would pass for the user's own node.
func TestWorldMachineKeyIndexKeysTaggedNodesUnderZero(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	tagged := worldNode(1, alice, "100.64.0.1")
	tagged.Tags = []string{"tag:server"}

	w, _ := testWorld(t, tagged)

	all := w.snapshot().GetNodesByMachineKeyAllUsers(tagged.MachineKey)
	assert.Contains(t, all, types.UserID(0))
	assert.NotContains(t, all, types.UserID(alice.ID))
}

// TestWorldWritePanicCountsOnce panics in a lone write and in a write
// batched with a good one: each commit reports one panic, and a lone
// write is not run a second time.
func TestWorldWritePanicCountsOnce(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"), worldNode(2, alice, "100.64.0.2"))

	before := float64(worldCommitPanics.Load())
	runs := 0

	func() {
		defer func() { _ = recover() }()

		w.UpdateNode(1, func(*types.Node) {
			runs++

			panic("lone")
		})
	}()

	assert.Equal(t, 1, runs, "a lone panicking write runs once")
	assert.InDelta(t, before+1, float64(worldCommitPanics.Load()), 0, "and counts one panic")

	inCommit, release := make(chan struct{}), make(chan struct{})

	go w.update(func(*nodeEdit) {
		close(inCommit)
		<-release
	})

	<-inCommit

	var wg sync.WaitGroup

	wg.Go(func() {
		defer func() { _ = recover() }()

		w.UpdateNode(1, func(*types.Node) { panic("batched") })
	})
	wg.Go(func() { w.UpdateNode(2, func(n *types.Node) { n.Hostname = "good" }) })

	require.Eventually(t, func() bool {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes) == 2
	}, time.Second, time.Millisecond)

	close(release)
	wg.Wait()

	assert.InDelta(t, before+2, float64(worldCommitPanics.Load()), 0, "the batch counts one panic, not one per retry")
}

func TestRegistrationRollbackRestoresExpiryOnlineInvariant(t *testing.T) {
	for name, reauthWith := range reauthEntryPoints {
		t.Run(name, func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)

			prefix := netip.MustParsePrefix("10.0.0.0/24")
			require.NoError(t, s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{
				NodeKey:  node.NodeKey(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname(), RoutableIPs: []netip.Prefix{prefix}},
			}))
			_, err := s.SetApprovedRoutes(id, []netip.Prefix{prefix})
			require.NoError(t, err)
			node, err = s.SetNodeExpiry(id, new(time.Now().Add(-time.Hour)))
			require.NoError(t, err)
			run := reauthWith(t, s, node)

			// Connect while the real reauth transaction is in flight, then fail it.
			// The candidate must never let this expired router become online or primary.
			require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("connect_then_fail", func(tx *gorm.DB) {
				if tx.Statement.Table != "nodes" {
					return
				}

				require.NotZero(t, s.Connect(id))
				live, found := s.GetNodeByID(id)
				require.True(t, found)
				assert.True(t, live.IsExpired())
				assert.False(t, live.Online(), "uncommitted auth must not revive the expired session")

				_, elected := s.Snapshot().PrimaryRouteFor(prefix)
				assert.False(t, elected, "uncommitted auth must not elect the expired router")

				_ = tx.AddError(errInjectedNodeUpdate)
			}))
			t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("connect_then_fail") })

			require.ErrorIs(t, run(), errInjectedNodeUpdate)
			s.ExpireExpiredNodes(time.Now().Add(-time.Minute))
			live, ok := s.GetNodeByID(id)
			require.True(t, ok)
			require.True(t, live.IsExpired())
			assert.Equal(t, 1, live.ActiveSessions(), "failed auth must keep the concurrent session")
			assert.False(t, live.Online(), "failed auth must leave the expired node offline")

			_, elected := s.Snapshot().PrimaryRouteFor(prefix)
			assert.False(t, elected, "expired router must not remain HA primary after failed auth")
		})
	}
}
