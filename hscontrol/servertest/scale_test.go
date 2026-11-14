package servertest

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

const (
	scaleDevicesPerUser     = 10
	scaleConvergenceTimeout = 2 * time.Minute
)

type scaleCase struct {
	name          string
	policy        string
	taggedService bool
	ssh           bool
	canSend       func(source, destination int) bool
}

// TestScale runs the same workloads at smoke-test and explicitly selected sizes.
// See README.md for large runs, resource constraints, and profiling commands.
func TestScale(t *testing.T) { testScale(t, false) }

// TestScaleChurn replaces every client over ten bounded rounds, then exercises
// transport reconnects and authenticated relogins separately from node churn.
func TestScaleChurn(t *testing.T) { testScale(t, true) }

func testScale(t *testing.T, churn bool) {
	t.Helper()

	nodes := 12

	if value, ok := os.LookupEnv("HEADSCALE_STRESS_NODES"); ok {
		var err error

		nodes, err = strconv.Atoi(value)
		require.NoError(t, err, "HEADSCALE_STRESS_NODES must be an integer")
		require.GreaterOrEqual(t, nodes, 2, "need at least two connected nodes")
	}

	personalVisibility := func(node, peer int) bool {
		return node/scaleDevicesPerUser == peer/scaleDevicesPerUser
	}

	cases := []scaleCase{
		{
			name: "allow_all",
			policy: `{
				"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:443"]}]
			}`,
			canSend: func(_, _ int) bool { return true },
		},
		{
			name:    "isolated",
			policy:  `{"acls": []}`,
			canSend: func(_, _ int) bool { return false },
		},
		{
			name: "personal_devices",
			policy: `{
				"grants": [{
					"src": ["autogroup:member"], "dst": ["autogroup:self"],
					"ip": ["tcp:443"]
				}]
			}`,
			canSend: personalVisibility,
		},
		{
			name: "shared_service",
			policy: `{
				"tagOwners": {"tag:service": ["scale-user-0@"]},
				"grants": [{
					"src": ["autogroup:member"], "dst": ["tag:service"],
					"ip": ["tcp:443"]
				}]
			}`,
			taggedService: true,
			canSend:       func(source, destination int) bool { return source != 0 && destination == 0 },
		},
		{
			name: "personal_ssh",
			policy: `{
				"grants": [{
					"src": ["autogroup:member"], "dst": ["autogroup:self"],
					"ip": ["tcp:22", "tcp:443"]
				}],
				"ssh": [{
					"action": "accept", "src": ["autogroup:member"],
					"dst": ["autogroup:self"], "users": ["root"]
				}]
			}`,
			ssh:     true,
			canSend: personalVisibility,
		},
	}

	if churn {
		grants := make([]string, 0, (nodes+scaleDevicesPerUser-1)/scaleDevicesPerUser)
		for i := range (nodes + scaleDevicesPerUser - 1) / scaleDevicesPerUser {
			grants = append(grants, fmt.Sprintf(`{"src":["scale-user-%d@"],"dst":["scale-user-%d@"],"ip":["tcp:443"]}`, i, i))
		}

		cases = append(cases, scaleCase{
			name:    "growing_diversity",
			policy:  `{"grants":[` + strings.Join(grants, ",") + `]}`,
			canSend: personalVisibility,
		})
	}

	t.Run(fmt.Sprintf("%d_nodes", nodes), func(t *testing.T) {
		// Run serially: each server and all its clients share this process.
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { runScale(t, nodes, tc, churn) })
		}
	})
}

// Discard client protocol chatter while keeping test failures and phase reports.
type quietScaleTB struct{ testing.TB }

func (quietScaleTB) Logf(string, ...any) {}

func runScale(t *testing.T, nodes int, tc scaleCase, churn bool) {
	t.Helper()

	var opts []ServerOption
	if _, largeRun := os.LookupEnv("HEADSCALE_STRESS_NODES"); !largeRun {
		opts = append(opts, WithNodeStoreBatchTimeout(10*time.Millisecond))
	}

	srv := NewServer(t, opts...)
	clients := make([]*TestClient, nodes)
	selfNodes := make([]tailcfg.NodeView, nodes)
	indices := make(map[tailcfg.NodeID]int, nodes)
	users := make([]*types.User, (nodes+scaleDevicesPerUser-1)/scaleDevicesPerUser)
	seenIDs := make(map[tailcfg.NodeID]bool)
	seenKeys := make(map[key.NodePublic]bool)

	t.Logf(
		"target_nodes=%d devices_per_user=%d gomaxprocs=%d gomemlimit=%q go=%s database_path=%q",
		nodes,
		scaleDevicesPerUser,
		runtime.GOMAXPROCS(0),
		os.Getenv("GOMEMLIMIT"),
		runtime.Version(),
		srv.cfg.Database.Sqlite.Path,
	)

	phase := func(name string, work func()) {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		started := time.Now()
		defer func() {
			elapsed := time.Since(started)

			runtime.ReadMemStats(&after)

			peers := 0
			live := 0

			for _, c := range clients {
				if c != nil {
					peers += len(c.Peers())
					select {
					case <-c.pollDone:
					default:
						live++
					}
				}
			}

			t.Logf(
				"phase=%s elapsed=%s allocated_bytes=%d heap_bytes=%d gc_cycles=%d goroutines=%d registered_nodes=%d live_clients=%d peer_entries=%d",
				name,
				elapsed,
				after.TotalAlloc-before.TotalAlloc,
				after.HeapAlloc,
				after.NumGC-before.NumGC,
				runtime.NumGoroutine(),
				srv.State().ListNodes().Len(),
				live,
				peers,
			)
		}()

		work()
		checkScaleStreams(t, srv, clients, indices)

		if churn {
			durable, err := srv.State().DB().ListNodes()
			require.NoError(t, err)
			require.Len(t, durable, len(indices))
			require.Equal(t, len(indices), srv.State().ListNodes().Len())

			for _, node := range durable {
				i, ok := indices[node.ID.NodeID()]
				require.True(t, ok, "unexpected durable node %d", node.ID)
				require.Equal(t, selfNodes[i].Key(), node.NodeKey)
			}
		}
	}

	// A generation attribute distinguishes fresh policy delivery from old maps.
	setPolicy := func(policy, generation string) {
		var document map[string]any
		require.NoError(t, json.Unmarshal([]byte(policy), &document))
		document["nodeAttrs"] = []any{map[string]any{
			"target": []string{"*"}, "attr": []string{generation},
		}}
		data, err := json.Marshal(document)
		require.NoError(t, err)
		_, err = srv.State().SetPolicyInDB(string(data))
		require.NoError(t, err)
		require.NoError(t, srv.State().ReloadPolicy())
	}

	waitForState := func(generation string, revoked bool, osMarker string) {
		waitForScaleState(t, tc, clients, selfNodes, indices, generation, revoked, osMarker)
	}

	registerSlots := func(slots []int, round int) {
		// Bound concurrent authentication and durable writes to 32 clients.
		for first := 0; first < len(slots); first += 32 {
			var registrations sync.WaitGroup
			for _, i := range slots[first:min(first+32, len(slots))] {
				registrations.Go(func() {
					opts := []ClientOption{WithUser(users[i/scaleDevicesPerUser]), WithoutNetmapHistory()}
					if tc.taggedService && i == 0 {
						opts = append(opts, WithTags("tag:service"))
					}
					clients[i] = NewClient(quietScaleTB{t}, srv,
						fmt.Sprintf("scale-node-%05d-%02d", i, round), opts...)
				})
			}
			registrations.Wait()
			if t.Failed() {
				t.FailNow()
			}
		}

		deadline := time.Now().Add(scaleConvergenceTimeout)
		for _, i := range slots {
			clients[i].WaitForCondition(t, "initial map", time.Until(deadline),
				func(nm *netmap.NetworkMap) bool { return nm.SelfNode.Valid() })
			nm := clients[i].Netmap()
			require.NotNil(t, nm)
			require.True(t, nm.SelfNode.Valid())
			id := nm.SelfNode.ID()
			require.False(t, seenIDs[id], "reused node ID %d", id)
			require.False(t, seenKeys[nm.NodeKey], "reused node key %s", nm.NodeKey)
			seenIDs[id], seenKeys[nm.NodeKey] = true, true
			selfNodes[i], indices[id] = nm.SelfNode, i
		}
	}

	slots := make([]int, nodes)
	for i := range slots {
		slots[i] = i
	}

	phase("enroll", func() {
		for i := range users {
			users[i] = srv.CreateUser(t, fmt.Sprintf("scale-user-%d", i))
		}

		setPolicy(tc.policy, "example.com/scale-initial")
		registerSlots(slots, 0)
		require.Equal(t, nodes, srv.State().ListNodes().Len())
		waitForState("example.com/scale-initial", false, "")
	})

	if churn {
		runScaleChurn(t, srv, tc, clients, selfNodes, indices, phase, setPolicy, waitForState, registerSlots)
		return
	}

	// One sender per user, including the shared service, changes in each burst.
	for round := range 3 {
		marker := fmt.Sprintf("scale-os-%d", round)
		phase(fmt.Sprintf("update_burst_%d", round), func() {
			updateScaleClients(t, srv, clients, marker)
			waitForState("example.com/scale-initial", false, marker)
		})
	}

	phase("revoke_policy", func() {
		setPolicy(`{"acls": []}`, "example.com/scale-revoked")
		waitForState("example.com/scale-revoked", true, "")
	})
	phase("restore_policy", func() {
		setPolicy(tc.policy, "example.com/scale-restored")
		waitForState("example.com/scale-restored", false, "scale-os-2")
	})
	phase("reconnect_burst", func() {
		var reconnects sync.WaitGroup
		for i := 0; i < nodes; i += scaleDevicesPerUser {
			reconnects.Go(func() { clients[i].Reconnect(quietScaleTB{t}) })
		}

		reconnects.Wait()

		if t.Failed() {
			t.FailNow()
		}

		waitForState("example.com/scale-restored", false, "scale-os-2")
		setPolicy(tc.policy, "example.com/scale-reconnected")
		waitForState("example.com/scale-reconnected", false, "scale-os-2")
	})
}

func waitForScaleState(
	t *testing.T,
	tc scaleCase,
	clients []*TestClient,
	selfNodes []tailcfg.NodeView,
	indices map[tailcfg.NodeID]int,
	generation string,
	revoked bool,
	osMarker string,
) {
	t.Helper()

	deadline := time.Now().Add(scaleConvergenceTimeout)

	for i, c := range clients {
		if c == nil {
			continue
		}

		wantPeers := tc.peerCount(i, selfNodes, revoked)

		c.WaitForCondition(
			t,
			fmt.Sprintf("%s: %d peers, OS=%q", generation, wantPeers, osMarker),
			time.Until(deadline),
			func(nm *netmap.NetworkMap) bool {
				if !nm.SelfNode.CapMap().Contains(nodecap.Cap(generation)) ||
					len(nm.Peers) != wantPeers {
					return false
				}

				hasSSH := nm.SSHPolicy != nil && len(nm.SSHPolicy.Rules) > 0
				if hasSSH != (tc.ssh && !revoked) {
					return false
				}

				if tc.ssh && !revoked && scaleSSHPolicyMismatch(nm.SSHPolicy, selfNodes, i) != "" {
					return false
				}

				if revoked && nm.PacketFilterRules.Len() != 0 {
					return false
				}

				// The policy's attribute can reach the node a frame ahead of
				// its filter, and peers alone may not tell the two apart.
				return tc.peersMatch(nm, i, indices, selfNodes, revoked, osMarker) &&
					scalePacketFilterMismatch(tc, nm, selfNodes, i, revoked) == ""
			},
		)
		require.Empty(t, scalePacketFilterMismatch(tc, c.Netmap(), selfNodes, i, revoked))

		if tc.ssh && !revoked {
			require.Empty(t, scaleSSHPolicyMismatch(c.Netmap().SSHPolicy, selfNodes, i))
		}
	}
}

func runScaleChurn(
	t *testing.T,
	srv *TestServer,
	tc scaleCase,
	clients []*TestClient,
	selfNodes []tailcfg.NodeView,
	indices map[tailcfg.NodeID]int,
	phase func(string, func()),
	setPolicy func(string, string),
	waitForState func(string, bool, string),
	registerSlots func([]int, int),
) {
	t.Helper()

	nodes := len(clients)

	retiredClients := make([]weak.Pointer[TestClient], 0, nodes)
	oldPolicies := make([]weak.Pointer[policyv2.PolicyManager], 0, scaleDevicesPerUser)

	generation := "example.com/scale-initial"
	revoked := false

	for round := range scaleDevicesPerUser {
		var cohort []int
		for i := round; i < nodes; i += scaleDevicesPerUser {
			cohort = append(cohort, i)
		}

		pm, ok := srv.State().Snapshot().Policy().(*policyv2.PolicyManager)
		require.True(t, ok)

		oldPolicies = append(oldPolicies, weak.Make(pm))

		phase(fmt.Sprintf("churn_%02d_remove", round), func() {
			started := time.Now()

			for first := 0; first < len(cohort); first += 32 {
				var removals sync.WaitGroup
				for _, i := range cohort[first:min(first+32, len(cohort))] {
					removals.Go(func() {
						node, ok := srv.State().GetNodeByNodeKey(selfNodes[i].Key())
						if assert.True(t, ok) {
							assert.NoError(t, srv.State().DeleteNode(node))
						}

						clients[i].cleanupOnce()
					})
				}

				removals.Wait()

				if t.Failed() {
					t.FailNow()
				}
			}

			for _, i := range cohort {
				retiredClients = append(retiredClients, weak.Make(clients[i]))
				delete(indices, selfNodes[i].ID())
				clients[i], selfNodes[i] = nil, tailcfg.NodeView{}
			}

			mutated := time.Since(started)

			waitForState(generation, revoked, "")
			t.Logf("operations=%d mutation_elapsed=%s convergence_elapsed=%s", len(cohort), mutated, time.Since(started)-mutated)
		})
		phase(fmt.Sprintf("churn_%02d_replace", round), func() {
			started := time.Now()

			var policyChange sync.WaitGroup
			// Change policy while fresh clients authenticate and establish streams.
			if round == 4 || round == 5 {
				revoked = round == 4
				generation = fmt.Sprintf("example.com/scale-churn-%d", round)

				policyChange.Go(func() {
					policy := tc.policy
					if revoked {
						policy = `{"acls":[]}`
					}

					setPolicy(policy, generation)
				})
			}

			registerSlots(cohort, round+1)
			policyChange.Wait()

			if t.Failed() {
				t.FailNow()
			}

			mutated := time.Since(started)

			waitForState(generation, revoked, "")
			t.Logf("operations=%d mutation_elapsed=%s convergence_elapsed=%s", len(cohort), mutated, time.Since(started)-mutated)
		})
	}

	for _, relogin := range []bool{false, true} {
		stormName := "reconnect_storm"
		if relogin {
			stormName = "relogin_storm"
		}

		phase(stormName, func() {
			for first := 0; first < nodes; first += 32 {
				var storm sync.WaitGroup

				for offset, c := range clients[first:min(first+32, nodes)] {
					i := first + offset

					storm.Go(func() {
						ctx, cancel := context.WithTimeout(t.Context(), scaleConvergenceTimeout)
						defer cancel()

						id, nodeKey := c.Netmap().SelfNode.ID(), c.Netmap().NodeKey
						if relogin {
							require.NoError(t, c.LogoutAndDisconnect(ctx))

							require.NoError(t, c.ReloginAndPoll(ctx))
						} else {
							hi := &tailcfg.Hostinfo{Hostname: c.Name, BackendLogID: "servertest-" + c.Name}
							require.NoError(t, c.RestartWithKey(ctx, c.authKey, hi))
						}

						c.WaitForCondition(t, "new stream map", scaleConvergenceTimeout, func(nm *netmap.NetworkMap) bool {
							_, maps := c.Stream()

							keyMatches := nm.NodeKey == nodeKey
							if relogin {
								keyMatches = nm.NodeKey != nodeKey
							}

							return maps > 0 && nm.SelfNode.ID() == id && keyMatches
						})
						selfNodes[i] = c.Netmap().SelfNode
					})
				}

				storm.Wait()

				if t.Failed() {
					t.FailNow()
				}
			}

			generation = fmt.Sprintf("example.com/scale-storm-%v", relogin)
			setPolicy(tc.policy, generation)
			waitForState(generation, false, "")
			t.Logf("operations=%d", nodes)
		})
	}

	phase("release_retired", func() {
		// Old policy objects own the snapshot's node set. A fresh Snapshot wrapper
		// alone is not a retention probe: the world constructs one on every read.
		require.Eventually(t, func() bool {
			runtime.GC()

			for _, old := range retiredClients {
				if old.Value() != nil {
					return false
				}
			}

			for _, old := range oldPolicies {
				if old.Value() != nil {
					return false
				}
			}

			return true
		}, 10*time.Second, 100*time.Millisecond, "retired clients and old compiled policies must be collectible")
		t.Logf("released_clients=%d released_policies=%d", len(retiredClients), len(oldPolicies))
	})
}

// peerCount is how many peers viewer has: the nodes it can reach or be reached
// from, and its user's other devices, which are peers under any policy.
func (tc scaleCase) peerCount(viewer int, active []tailcfg.NodeView, revoked bool) int {
	count := 0

	for j, node := range active {
		if j == viewer || !node.Valid() {
			continue
		}

		reachable := !revoked && tc.linked(viewer, j)
		if reachable || tc.sameUser(viewer, j) {
			count++
		}
	}

	return count
}

// sameUser reports whether two nodes are devices of one user. The tagged
// service belongs to no user.
func (tc scaleCase) sameUser(a, b int) bool {
	if tc.taggedService && (a == 0 || b == 0) {
		return false
	}

	return a/scaleDevicesPerUser == b/scaleDevicesPerUser
}

// linked reports whether the policy lets either node reach the other.
func (tc scaleCase) linked(a, b int) bool {
	return tc.canSend(a, b) || tc.canSend(b, a)
}

func (tc scaleCase) peersMatch(
	nm *netmap.NetworkMap,
	viewer int,
	indices map[tailcfg.NodeID]int,
	active []tailcfg.NodeView,
	revoked bool,
	osMarker string,
) bool {
	var previous tailcfg.NodeID

	for _, peer := range nm.Peers {
		j, ok := indices[peer.ID()]
		if !ok || j == viewer || peer.ID() <= previous || peer.Key() != active[j].Key() {
			return false
		}

		if (revoked || !tc.linked(viewer, j)) && !tc.sameUser(viewer, j) {
			return false
		}

		previous = peer.ID()

		online, known := peer.Online().GetOk()
		if !known || !online {
			return false
		}

		if osMarker != "" && j%scaleDevicesPerUser == 0 &&
			peer.Hostinfo().OS() != osMarker {
			return false
		}
	}

	return true
}

func updateScaleClients(
	t *testing.T,
	srv *TestServer,
	clients []*TestClient,
	marker string,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	var senders sync.WaitGroup

	for i := 0; i < len(clients); i += scaleDevicesPerUser {
		c := clients[i]

		senders.Go(func() {
			c.Direct().SetHostinfo(&tailcfg.Hostinfo{
				Hostname: c.Name, BackendLogID: "servertest-" + c.Name, OS: marker,
			})
			assert.NoError(t, c.Direct().SendUpdate(ctx), c.Name)
		})
	}

	senders.Wait()

	if t.Failed() {
		t.FailNow()
	}

	for i := 0; i < len(clients); i += scaleDevicesPerUser {
		node, ok := srv.State().GetNodeByNodeKey(clients[i].Netmap().NodeKey)
		require.True(t, ok)
		require.Equal(t, marker, node.Hostinfo().OS(), clients[i].Name)
	}
}

// scalePacketFilterMismatch names the first verdict nm's packet filter gets
// wrong, or returns "". Probe a few sources per node instead of making the test
// itself all-pairs.
func scalePacketFilterMismatch(
	tc scaleCase,
	nm *netmap.NetworkMap,
	selfNodes []tailcfg.NodeView,
	viewer int,
	revoked bool,
) string {
	var localIPs netipx.IPSetBuilder
	for _, prefix := range nm.SelfNode.Addresses().All() {
		localIPs.AddPrefix(prefix)
	}

	local, err := localIPs.IPSet()
	if err != nil {
		return err.Error()
	}

	packetFilter := filter.New(nm.PacketFilter, nil, local, nil, nil, logger.Discard)

	first := viewer / scaleDevicesPerUser * scaleDevicesPerUser
	groupSize := min(scaleDevicesPerUser, len(selfNodes)-first)

	sibling := first + (viewer-first+1)%groupSize
	for _, source := range []int{sibling, (first + scaleDevicesPerUser) % len(selfNodes), 0} {
		if !selfNodes[source].Valid() {
			continue
		}
		for family, dst := range nm.SelfNode.Addresses().All() {
			src := selfNodes[source].Addresses().At(family).Addr()

			want := filter.Drop
			if !revoked && tc.canSend(source, viewer) {
				want = filter.Accept
			}

			type verdict struct {
				name      string
				want, got filter.Response
			}

			checks := []verdict{
				{"TCP 443", want, packetFilter.CheckTCP(src, dst.Addr(), 443)},
				{"TCP 80", filter.Drop, packetFilter.CheckTCP(src, dst.Addr(), 80)},
				{"UDP 443", filter.Drop, packetFilter.Check(src, dst.Addr(), 443, ipproto.UDP)},
			}
			if tc.ssh {
				checks = append(checks, verdict{"TCP 22", want, packetFilter.CheckTCP(src, dst.Addr(), 22)})
			}

			for _, check := range checks {
				if check.got != check.want {
					return fmt.Sprintf("%d -> %d %s: got %v, want %v",
						selfNodes[source].ID(), selfNodes[viewer].ID(), check.name, check.got, check.want)
				}
			}
		}
	}

	return ""
}

func scaleSSHPolicyMismatch(policy *tailcfg.SSHPolicy, selfNodes []tailcfg.NodeView, viewer int) string {
	if policy == nil || len(policy.Rules) != 1 {
		return "expected one SSH rule"
	}
	rule := policy.Rules[0]
	if rule.Action == nil || !rule.Action.Accept || rule.Action.Reject || rule.Action.HoldAndDelegate != "" {
		return "expected SSH accept action"
	}

	if !maps.Equal(rule.SSHUsers, map[string]string{"0": "", "root": "root"}) {
		return "unexpected SSH user mapping"
	}
	wantIPs := make(map[string]bool)
	first := viewer / scaleDevicesPerUser * scaleDevicesPerUser
	for _, node := range selfNodes[first:min(first+scaleDevicesPerUser, len(selfNodes))] {
		if !node.Valid() {
			continue
		}
		for _, prefix := range node.Addresses().All() {
			wantIPs[prefix.Addr().String()] = true
		}
	}

	if len(rule.Principals) != len(wantIPs) {
		return fmt.Sprintf("got %d SSH principals, want %d", len(rule.Principals), len(wantIPs))
	}
	for _, principal := range rule.Principals {
		if principal.Any || principal.Node != "" || principal.UserLogin != "" || !wantIPs[principal.NodeIP] {
			return fmt.Sprintf("unexpected SSH principal %+v", principal)
		}
		delete(wantIPs, principal.NodeIP)
	}

	return ""
}

func checkScaleStreams(
	t *testing.T,
	srv *TestServer,
	clients []*TestClient,
	indices map[tailcfg.NodeID]int,
) {
	t.Helper()

	// A reconnected client's old session leaves the hub on its own time.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		connections := srv.App.MapHub().Connected()
		assert.Len(ct, connections, len(indices))

		for id, sessions := range connections {
			_, known := indices[id.NodeID()]
			assert.True(ct, known, "unexpected connected node %s", id)
			assert.Equal(ct, 1, sessions, "node %s", id)
		}
	}, 10*time.Second, 20*time.Millisecond, "one session per client")

	for _, c := range clients {
		if c == nil {
			continue
		}

		select {
		case <-c.pollDone:
			t.Fatalf("%s: control stream exited", c.Name)
		default:
		}

		require.NotNil(t, c.Netmap(), c.Name)
		require.Empty(t, c.History(), "scale clients must not retain netmaps")
		require.Positive(t, c.UpdateCount(), c.Name)
	}
}

func TestClientNetmapHistory(t *testing.T) {
	for _, noHistory := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%v", noHistory), func(t *testing.T) {
			c := &TestClient{
				noHistory: noHistory,
				updates:   make(chan *netmap.NetworkMap, 1),
			}
			for range 3 {
				c.UpdateFullNetmap(&netmap.NetworkMap{})
			}

			require.Equal(t, 3, c.UpdateCount())
			require.NotNil(t, c.Netmap())

			if noHistory {
				require.Empty(t, c.History())
			} else {
				require.Len(t, c.History(), 3)
			}
		})
	}
}
