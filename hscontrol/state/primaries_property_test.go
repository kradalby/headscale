package state

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/propcheck"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// nodeForRapid builds a minimal types.Node for use in property
// tests. Tests drive (IsOnline, Hostinfo.RoutableIPs, ApprovedRoutes,
// Unhealthy) via UpdateNode; the rest stays fixed.
func nodeForRapid(id types.NodeID) types.Node {
	mk := key.NewMachine()
	nk := key.NewNode()

	return types.Node{
		ID:         id,
		Hostname:   fmt.Sprintf("rapid-%d", id),
		MachineKey: mk.Public(),
		NodeKey:    nk.Public(),
		UserID:     new(uint(1)),
		User:       &types.User{Name: "rapid"},
		IsOnline:   new(false),
		Hostinfo:   &tailcfg.Hostinfo{},
	}
}

// The route domain includes overlapping networks, public subnets, exit routes,
// and host routes inside the configured node ranges. Sampling with replacement
// deliberately produces duplicate announcements and approvals.
func propertyRoutePrefixes() []netip.Prefix {
	return []netip.Prefix{
		mp("10.0.0.0/16"), mp("10.0.0.0/24"),
		mp("fd00:1::/48"), mp("fd00:1::/64"),
		mp("8.8.8.0/24"), mp("2001:4860::/48"),
		mp("0.0.0.0/0"), mp("::/0"),
		mp("100.64.0.99/32"), mp("fd7a:115c:a1e0::99/128"),
	}
}

func drawRouteNode(t *rapid.T, id uint64) propcheck.RouteNode {
	prefixes := rapid.SliceOfN(rapid.SampledFrom(propertyRoutePrefixes()), 0, 6)

	return propcheck.RouteNode{
		ID:           id,
		Online:       rapid.Bool().Draw(t, "online"),
		Expired:      rapid.Bool().Draw(t, "expired"),
		Unhealthy:    rapid.Bool().Draw(t, "unhealthy"),
		SessionStart: rapid.SampledFrom([]time.Time{{}, time.Unix(0, 0), time.Unix(1, 0), time.Unix(2, 0)}).Draw(t, "start"),
		Announced:    prefixes.Draw(t, "announced"),
		Approved:     prefixes.Draw(t, "approved"),
		Tags:         rapid.SampledFrom([][]string{nil, {"tag:a"}, {"tag:b"}, {"tag:a", "tag:b"}}).Draw(t, "tags"),
	}
}

// Deterministic records avoid unrelated key generation in shrinkable histories.
func nodeFromRouteRecord(record propcheck.RouteNode) *types.Node {
	user := &types.User{Name: "rapid"}
	user.ID = 1

	n := &types.Node{
		ID:        types.NodeID(record.ID),
		Hostname:  fmt.Sprintf("route-%d", record.ID),
		GivenName: fmt.Sprintf("route-%d", record.ID),
		UserID:    new(uint(1)), User: user,
		IPv4:     new(netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", record.ID))),
		IsOnline: new(record.Online), Unhealthy: record.Unhealthy,
		SessionStart:   record.SessionStart,
		Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: slices.Clone(record.Announced)},
		ApprovedRoutes: slices.Clone(record.Approved), Tags: slices.Clone(record.Tags),
	}
	if record.Expired {
		n.Expiry = new(time.Unix(1, 0))
	}

	return n
}

func routeRecords(snap *Snapshot) []propcheck.RouteNode {
	var records []propcheck.RouteNode

	for _, n := range snap.ListNodes().All() {
		if n.ID() > 5 {
			continue
		}

		records = append(records, propcheck.RouteNode{
			ID: uint64(n.ID()), Online: n.IsOnline().GetOr(false),
			// Generated expirations are either absent or the fixed Unix epoch.
			Expired:   !n.Expiry().GetOr(time.Time{}).IsZero(),
			Unhealthy: n.Unhealthy(), SessionStart: n.SessionStart(),
			Announced: slices.Clone(n.Hostinfo().RoutableIPs().AsSlice()),
			Approved:  slices.Clone(n.ApprovedRoutes().AsSlice()), Tags: slices.Clone(n.Tags().AsSlice()),
		})
	}

	return records
}

func propertyViaScopes(records []propcheck.RouteNode) []propcheck.ViaScope {
	var scopes []propcheck.ViaScope

	for _, tag := range []string{"tag:a", "tag:b"} {
		var ids []uint64

		for _, n := range records {
			if slices.Contains(n.Tags, tag) {
				ids = append(ids, n.ID)
			}
		}

		for _, p := range propertyRoutePrefixes() {
			if p.Bits() != 0 {
				scopes = append(scopes, propcheck.ViaScope{Key: tag, Prefix: p, Candidates: ids})
			}
		}
	}

	return scopes
}

func propertyRoutePolicy(reverse bool) []byte {
	dst := `"10.0.0.0/8","fd00::/8","8.8.8.0/24","2001:4860::/48","100.64.0.99/32","fd7a:115c:a1e0::99/128"`

	grants := []string{
		`{"src":["100.64.0.10"],"dst":[` + dst + `],"ip":["*"]}`,
		`{"src":["100.64.0.11"],"dst":[` + dst + `],"ip":["*"],"via":["tag:a"]}`,
		`{"src":["100.64.0.12"],"dst":[` + dst + `],"ip":["*"],"via":["tag:b"]}`,
	}
	if reverse {
		slices.Reverse(grants)
	}

	return []byte(`{"tagOwners":{"tag:a":["rapid@"],"tag:b":["rapid@"]},"grants":[` + strings.Join(grants, ",") + `]}`)
}

func checkRouteSnapshot(t *rapid.T, snap *Snapshot, records []propcheck.RouteNode, want propcheck.RouteResult) {
	t.Helper()

	if !reflect.DeepEqual(routeRecords(snap), records) {
		t.Fatalf("snapshot route records differ from generated inputs: got=%+v want=%+v", routeRecords(snap), records)
	}

	got := make(map[netip.Prefix]uint64)
	for p, id := range snap.PrimaryRoutes() {
		got[p] = uint64(id)
	}

	if !maps.Equal(got, want.Global) {
		t.Fatalf("global routes = %v, reference = %v; records=%+v", got, want.Global, records)
	}

	if hasOutage(snap) != (want.GlobalOutage || want.ViaOutage) {
		t.Fatalf("outage=%v, global=%v via=%v", hasOutage(snap), want.GlobalOutage, want.ViaOutage)
	}

	for viewerID := types.NodeID(10); viewerID <= 12; viewerID++ {
		viewer, _ := snap.GetNode(viewerID)

		matchers, err := snap.Policy().MatchersForNode(viewer)
		if err != nil {
			t.Fatal(err)
		}

		winners := want.Global

		switch viewerID {
		case 11:
			winners = want.Via["tag:a"]
		case 12:
			winners = want.Via["tag:b"]
		}

		for _, record := range records {
			peer, _ := snap.GetNode(types.NodeID(record.ID))

			var expected []netip.Prefix

			for prefix, id := range winners {
				// These host routes name nodes, so approval must not publish them.
				if id == record.ID && prefix != mp("100.64.0.99/32") && prefix != mp("fd7a:115c:a1e0::99/128") {
					expected = append(expected, prefix)
				}
			}

			actual := snap.RoutesForPeer(viewer, peer, matchers)
			// Public-IP grants also authorize exit selection. The reference
			// predicts subnet ownership, while exits remain per-node approvals.
			for _, p := range actual {
				if p.Bits() == 0 && (!slices.Contains(record.Announced, p) || !slices.Contains(record.Approved, p)) {
					t.Fatalf("peer %d exposes unapproved exit route %s", record.ID, p)
				}
			}

			actual = slices.DeleteFunc(actual, func(p netip.Prefix) bool { return p.Bits() == 0 })

			slices.SortFunc(expected, netip.Prefix.Compare)
			slices.SortFunc(actual, netip.Prefix.Compare)

			if !slices.Equal(actual, expected) {
				t.Fatalf("viewer %d peer %d: routes=%v, reference=%v", viewerID, record.ID, actual, expected)
			}
		}
	}
	// HA secondaries need their primary even with no matching ACL grant.
	for _, record := range records {
		viewer, _ := snap.GetNode(types.NodeID(record.ID))
		for prefix, id := range want.Global {
			if prefix.IsSingleIP() || id == record.ID || !slices.Contains(record.Announced, prefix) || !slices.Contains(record.Approved, prefix) {
				continue
			}

			peer, _ := snap.GetNode(types.NodeID(id))
			if !slices.Contains(snap.RoutesForPeer(viewer, peer, nil), prefix) {
				t.Fatalf("secondary %d cannot route %s through primary %d", record.ID, prefix, id)
			}
		}
	}
}

// TestPrimaryRoutesProperty uses the shared pure reference after every commit,
// retaining global incumbents across membership, policy and availability edits.
func TestPrimaryRoutesProperty(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")
	rapid.Check(t, func(t *rapid.T) {
		var viewers types.Nodes
		for id := uint64(10); id <= 12; id++ {
			viewers = append(viewers, nodeFromRouteRecord(propcheck.RouteNode{ID: id, Online: true}))
		}

		w, err := newWorld(viewers, []types.User{*viewers[0].User}, propertyRoutePolicy(false), types.DNSView{})
		if err != nil {
			t.Fatal(err)
		}

		cfg := &types.Config{Prefixes: types.PrefixesConfig{V4: new(mp("100.64.0.0/10")), V6: new(mp("fd7a:115c:a1e0::/48"))}}
		w.servesRoute = cfg.ServesRoute
		runs, failures := PolicyAuditRuns(), PolicyAuditFailures()

		type retained struct {
			snap    *Snapshot
			records []propcheck.RouteNode
			want    propcheck.RouteResult
		}

		var (
			history  []retained
			previous map[netip.Prefix]uint64
		)

		model := make(map[uint64]propcheck.RouteNode)
		update := func(id uint64, change func(*propcheck.RouteNode)) {
			if record, ok := model[id]; ok {
				record.Announced = slices.Clone(record.Announced)
				record.Approved = slices.Clone(record.Approved)
				record.Tags = slices.Clone(record.Tags)
				change(&record)
				model[id] = record
			}
		}
		health := func(updates map[types.NodeID]bool) {
			for id, healthy := range updates {
				update(uint64(id), func(record *propcheck.RouteNode) {
					approved := slices.ContainsFunc(record.Announced, func(prefix netip.Prefix) bool {
						return slices.Contains(record.Approved, prefix)
					})
					if healthy || record.Online && approved {
						record.Unhealthy = !healthy
					}
				})
			}
		}

		check := func() {
			snap := w.snapshot()

			records := slices.Collect(maps.Values(model))
			slices.SortFunc(records, func(a, b propcheck.RouteNode) int { return cmp.Compare(a.ID, b.ID) })
			want := propcheck.ElectRoutes(records, previous, propertyViaScopes(records))
			checkRouteSnapshot(t, snap, records, want)
			history = append(history, retained{snap, records, want})
			previous = want.Global
		}
		check()
		// Every generated history reaches a scoped outage with a healthy global
		// router, then a global outage, deletion and reinsertion. Audit assertions
		// therefore cannot pass merely because their counters stayed at zero.
		prefix := rapid.SampledFrom(propertyRoutePrefixes()[:6]).Draw(t, "shared-prefix")

		for id := uint64(1); id <= 3; id++ {
			tag := "tag:a"
			if id == 3 {
				tag = "tag:b"
			}

			record := propcheck.RouteNode{ID: id, Online: true, SessionStart: time.Unix(int64(3-id), 0), Announced: []netip.Prefix{prefix}, Approved: []netip.Prefix{prefix}, Tags: []string{tag}}
			model[id] = record
			w.PutNode(*nodeFromRouteRecord(record))
			check()
		}

		st := &State{world: w}

		health(map[types.NodeID]bool{1: false, 2: false})
		st.BatchSetNodeHealth(map[types.NodeID]bool{1: false, 2: false})
		check()

		if !history[len(history)-1].want.ViaOutage || history[len(history)-1].want.GlobalOutage {
			t.Fatal("setup did not reach a via-only outage")
		}

		health(map[types.NodeID]bool{3: false})
		st.BatchSetNodeHealth(map[types.NodeID]bool{3: false})
		check()

		if !history[len(history)-1].want.GlobalOutage {
			t.Fatal("setup did not reach a global outage")
		}

		deleted := model[1]
		delete(model, 1)
		w.DeleteNode(1)
		check()

		model[1] = deleted
		w.PutNode(*nodeFromRouteRecord(deleted))
		check()

		prefixes := rapid.SliceOfN(rapid.SampledFrom(propertyRoutePrefixes()), 0, 8)

		steps := rapid.IntRange(1, 60).Draw(t, "steps")
		for range steps {
			id := types.NodeID(rapid.Uint64Range(1, 5).Draw(t, "id"))
			switch rapid.IntRange(0, 10).Draw(t, "operation") {
			case 0:
				record := drawRouteNode(t, uint64(id))
				model[uint64(id)] = record
				n := nodeFromRouteRecord(record)
				n.SessionEpoch = rapid.Uint64Range(0, 3).Draw(t, "epoch")
				w.PutNode(*n)
			case 1:
				delete(model, uint64(id))
				w.DeleteNode(id)
			case 2:
				prefs := prefixes.Draw(t, "announced")

				update(uint64(id), func(record *propcheck.RouteNode) { record.Announced = slices.Clone(prefs) })
				w.UpdateNode(id, func(n *types.Node) { n.Hostinfo.RoutableIPs = prefs })
			case 3:
				prefs := prefixes.Draw(t, "approved")

				update(uint64(id), func(record *propcheck.RouteNode) { record.Approved = slices.Clone(prefs) })
				w.UpdateNode(id, func(n *types.Node) { n.ApprovedRoutes = prefs })
			case 4:
				r := drawRouteNode(t, uint64(id))
				epoch := rapid.Uint64Range(0, 3).Draw(t, "epoch")

				update(uint64(id), func(record *propcheck.RouteNode) {
					record.Online, record.SessionStart, record.Expired = r.Online, r.SessionStart, r.Expired
				})

				w.UpdateNode(id, func(n *types.Node) {
					n.IsOnline, n.SessionStart, n.SessionEpoch = new(r.Online), r.SessionStart, epoch

					n.Expiry = nil
					if r.Expired {
						n.Expiry = new(time.Unix(1, 0))
					}
				})
			case 5:
				updates := rapid.MapOfN(rapid.SampledFrom([]types.NodeID{1, 2, 3, 4, 5, 99}), rapid.Bool(), 0, 6).Draw(t, "health")
				health(updates)
				st.BatchSetNodeHealth(updates)
			case 6:
				tags := rapid.SampledFrom([][]string{nil, {"tag:a"}, {"tag:b"}, {"tag:a", "tag:b"}}).Draw(t, "tags")

				update(uint64(id), func(record *propcheck.RouteNode) { record.Tags = slices.Clone(tags) })
				w.UpdateNode(id, func(n *types.Node) { n.Tags = slices.Clone(tags) })
			case 7:
				update(uint64(id), func(record *propcheck.RouteNode) {
					slices.Reverse(record.Announced)
					slices.Reverse(record.Approved)
					slices.Reverse(record.Tags)
				})
				w.UpdateNode(id, func(n *types.Node) {
					slices.Reverse(n.Hostinfo.RoutableIPs)
					slices.Reverse(n.ApprovedRoutes)
					slices.Reverse(n.Tags)
				})

				_, err := w.SetPolicy(propertyRoutePolicy(rapid.Bool().Draw(t, "reverse-policy")), func(*Snapshot) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
			case 8:
				before := w.snapshot().Rev()

				applied := w.UpdateNodesIf(map[types.NodeID]UpdateNodeFunc{id: healthSetter(false)}, func(*types.Node) bool { return false })
				if applied || w.snapshot().Rev() != before {
					t.Fatal("refused health write published")
				}
			case 9:
				online, unhealthy := rapid.Bool().Draw(t, "online"), rapid.Bool().Draw(t, "unhealthy")

				updates := make(map[types.NodeID]UpdateNodeFunc)
				for i := types.NodeID(1); i <= 5; i++ {
					update(uint64(i), func(record *propcheck.RouteNode) { record.Online, record.Unhealthy = online, unhealthy })
					updates[i] = func(n *types.Node) { n.IsOnline, n.Unhealthy = new(online), unhealthy }
				}

				w.UpdateNodes(updates)
			case 10:
				prefs := prefixes.Draw(t, "both")

				update(uint64(id), func(record *propcheck.RouteNode) {
					record.Announced, record.Approved = slices.Clone(prefs), slices.Clone(prefs)
				})
				w.UpdateNode(id, func(n *types.Node) { n.Hostinfo.RoutableIPs, n.ApprovedRoutes = prefs, slices.Clone(prefs) })
			}

			check()
		}

		for _, old := range history {
			checkRouteSnapshot(t, old.snap, old.records, old.want)
		}

		if PolicyAuditRuns() <= runs || PolicyAuditFailures() != failures {
			t.Fatalf("audit runs=%d failures=%d", PolicyAuditRuns()-runs, PolicyAuditFailures()-failures)
		}
	})
}

// Election ranking is independent of input order, duplicates, epochs, and
// dangling candidate IDs. All-unavailable fallback is intentionally scoped.
func TestRouteElectionReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.SampledFrom(propertyRoutePrefixes()[:6]).Draw(t, "prefix")

		var records []propcheck.RouteNode

		stored := make(map[types.NodeID]*types.Node)

		count := rapid.Uint64Range(0, 6).Draw(t, "count")
		for id := uint64(1); id <= count; id++ {
			r := drawRouteNode(t, id)
			r.Announced, r.Approved = []netip.Prefix{prefix, prefix}, []netip.Prefix{prefix, prefix}
			records = append(records, r)
			n := nodeFromRouteRecord(r)
			n.SessionEpoch = rapid.Uint64Range(0, 3).Draw(t, "epoch")
			stored[n.ID] = n
		}

		ids := rapid.SliceOfN(rapid.Uint64Range(1, 8), 0, 10).Draw(t, "candidates")

		var (
			candidates = make([]types.NodeID, 0, len(ids))
			selected   []propcheck.RouteNode
		)

		for _, id := range ids {
			candidates = append(candidates, types.NodeID(id))
		}

		for _, n := range records {
			if slices.Contains(ids, n.ID) {
				selected = append(selected, n)
			}
		}

		previous := rapid.Uint64Range(0, 8).Draw(t, "previous")
		want := propcheck.ElectRoutes(selected, map[netip.Prefix]uint64{prefix: previous}, []propcheck.ViaScope{{Key: "scope", Prefix: prefix, Candidates: ids}})
		nodes := graph.NewMap(graph.Same[*types.Node], stored)
		global, ok := electPrimary(nodes, views.SliceOf(candidates), types.NodeID(previous))

		via, viaOK := electViaPrimary(nodes, views.SliceOf(candidates), types.NodeID(previous))
		if uint64(global) != want.Global[prefix] || ok != (want.Global[prefix] != 0) || uint64(via) != want.Via["scope"][prefix] || viaOK != (want.Via["scope"][prefix] != 0) {
			t.Fatalf("global=%d/%v via=%d/%v reference=%+v", global, ok, via, viaOK, want)
		}

		slices.Reverse(selected)
		slices.Reverse(ids)

		reordered := propcheck.ElectRoutes(selected, map[netip.Prefix]uint64{prefix: previous}, []propcheck.ViaScope{{Key: "scope", Prefix: prefix, Candidates: ids}})
		if !reflect.DeepEqual(reordered, want) {
			t.Fatal("reference depends on candidate order")
		}
	})
}

// A probe observes candidacy before queueing; withdrawal ahead of its write
// must reject the stale unhealthy result, while another router's recovery in
// that same batch must still apply. Channels fix ordering without sleeps.
func TestQueuedRouteHealthProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.SampledFrom(propertyRoutePrefixes()[:6]).Draw(t, "prefix")
		withdraw := rapid.Bool().Draw(t, "withdraw-routes")
		records := []propcheck.RouteNode{
			{ID: 1, Online: true, SessionStart: time.Unix(1, 0), Announced: []netip.Prefix{prefix}, Approved: []netip.Prefix{prefix}},
			{ID: 2, Online: true, Unhealthy: true, Announced: []netip.Prefix{prefix}, Approved: []netip.Prefix{prefix}},
		}

		w, err := newWorld(types.Nodes{nodeFromRouteRecord(records[0]), nodeFromRouteRecord(records[1])}, nil, nil, types.DNSView{})
		if err != nil {
			t.Fatal(err)
		}

		before := w.snapshot()
		initial := propcheck.ElectRoutes(records, nil, nil)
		departure := &nodeWrite{done: make(chan writeResult, 1), fn: func(e *nodeEdit) {
			n, _ := e.Get(1)

			n = n.Clone()
			if withdraw {
				n.ApprovedRoutes = nil
			} else {
				n.IsOnline = new(false)
			}

			e.Set(1, n)
		}}
		// Stage the first arrival, then let the public health API enqueue the
		// second. No leader runs until both writes are waiting in the queue.
		w.batchSize, w.batchTimeout = 2, time.Hour
		w.writes, w.committing = []*nodeWrite{departure}, true
		changed := make(chan bool, 1)

		go func() {
			st := &State{world: w}
			changed <- st.BatchSetNodeHealth(map[types.NodeID]bool{1: false, 2: true, 99: false})
		}()

		<-w.full
		w.commitWrites()

		moved := <-changed

		result := <-departure.done
		if result.panic != nil {
			t.Fatalf("queued write panicked: %v", result.panic)
		}

		if withdraw {
			records[0].Approved = nil
		} else {
			records[0].Online = false
		}

		records[1].Unhealthy = false
		want := propcheck.ElectRoutes(records, initial.Global, nil)

		after := w.snapshot()
		if !reflect.DeepEqual(routeRecords(after), records) {
			t.Fatalf("queued health gate: got %+v, want %+v", routeRecords(after), records)
		}

		if !moved || after.Rev() != before.Rev()+1 || result.snap.Rev() != after.Rev() {
			t.Fatalf("batch must publish one election: moved=%v revisions=%d/%d/%d", moved, before.Rev(), after.Rev(), result.snap.Rev())
		}

		got := make(map[netip.Prefix]uint64)
		for p, id := range after.PrimaryRoutes() {
			got[p] = uint64(id)
		}

		if !maps.Equal(got, want.Global) || hasOutage(after) != want.GlobalOutage {
			t.Fatalf("queued election=%v outage=%v, reference=%+v", got, hasOutage(after), want)
		}

		if w.outageStores.Load() == 0 || w.inOutage.Load() != want.GlobalOutage {
			t.Fatal("batch did not refresh outage state")
		}

		stores := w.outageStores.Load()
		w.storeOutage(before)

		if w.outageStores.Load() != stores || w.outageRev != after.Rev() {
			t.Fatal("an old snapshot overwrote the newer outage state")
		}

		if id, ok := before.PrimaryRouteFor(prefix); !ok || uint64(id) != initial.Global[prefix] {
			t.Fatal("queued batch changed its old snapshot")
		}
	})
}
