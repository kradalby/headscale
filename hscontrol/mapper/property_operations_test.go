package mapper

import (
	"bytes"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/internal/propcheck"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/mem"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// streamOperation contains all generated parameters before either model or
// production state changes. Drawing reads only the independent reference.
type streamOperation struct {
	kind         string
	node, before *types.Node
	policy       int
	doc          []byte
	user         types.User
	records      []tailcfg.DNSRecord
	derp         *tailcfg.DERPMap
	request      tailcfg.MapRequest
}

//nolint:gocyclo // One switch arm per generated operation keeps the input contract visible.
func (p *streamPropertySystem) drawOperation(t *rapid.T, kinds ...string) streamOperation {
	ids := slices.Sorted(maps.Keys(p.world.Nodes))
	id := rapid.SampledFrom(ids).Draw(t, "node")
	n := p.world.Nodes[id].Clone()

	operations := kinds
	if len(operations) == 0 {
		operations = []string{"endpoints", "hostinfo", "keys", "expiry", "online", "identity", "routes", "health", "policy", "generated-policy", "policy-order", "policy-duplicate", "policy-restore", "user", "dns", "derp", "noop", "revert", "request", "stale-request", "invalid-policy"}
		if len(ids) > 3 {
			operations = append(operations, "delete")
		}

		if len(ids) < 8 {
			operations = append(operations, "add")
		}
	}

	op := rapid.SampledFrom(operations).Draw(t, "operation")

	result := streamOperation{kind: op, node: n, before: n.Clone()}
	switch op {
	case "endpoints", "revert":
		n.Endpoints = nil
		for range rapid.IntRange(0, 3).Draw(t, "endpoint-count") {
			n.Endpoints = append(n.Endpoints, netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{192, 0, 2, rapid.ByteRange(1, 254).Draw(t, "endpoint-ip")}),
				rapid.Uint16().Draw(t, "endpoint-port")))
		}

	case "hostinfo":
		n.Hostinfo.OS = rapid.SampledFrom([]string{"linux", "windows", "android", ""}).Draw(t, "os")
		n.Hostinfo.Hostname = fmt.Sprintf("reported-%d", rapid.IntRange(0, 10).Draw(t, "hostname"))
		n.Hostinfo.NetInfo = &tailcfg.NetInfo{PreferredDERP: tailcfg.DERPRegionID(rapid.IntRange(0, 3).Draw(t, "home-derp"))}

		n.Hostinfo.Services = nil
		if rapid.Bool().Draw(t, "service") {
			n.Hostinfo.Services = []tailcfg.Service{{Proto: "tcp", Port: rapid.Uint16().Draw(t, "service-port")}}
		}

	case "keys":
		var raw [32]byte
		copy(raw[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "node-key"))
		raw[0] |= 1 // Registered nodes cannot have a zero node key.
		n.NodeKey = key.NodePublicFromRaw32(mem.B(raw[:]))

		var disco [32]byte
		if !rapid.Bool().Draw(t, "zero-disco") {
			copy(disco[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "disco-key"))
		}

		n.DiscoKey = key.DiscoPublicFromRaw32(mem.B(disco[:]))
	case "expiry":
		// Fixed distant dates make shrinking independent of wall time.
		n.Expiry = rapid.SampledFrom([]*time.Time{nil, new(time.Time{}), new(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)), new(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))}).Draw(t, "expiry")
		n.IsOnline = new(n.ActiveSessions > 0 && !propertyExpired(n))
	case "online":
		n.ActiveSessions = 1 - n.ActiveSessions
		n.IsOnline = new(n.ActiveSessions > 0 && !propertyExpired(n))
		n.LastSeen = new(time.Unix(1_700_000_000+rapid.Int64Range(0, 1000).Draw(t, "last-seen"), 0).UTC())
		n.SessionStart = time.Unix(1_700_000_000+int64(n.ID), 0).UTC() //nolint:gosec // IDs are in [1, 8].
	case "identity":
		user := p.world.Users[rapid.IntRange(0, 2).Draw(t, "owner")].Clone()

		n.UserID, n.User = &user.ID, user

		n.Tags = rapid.SampledFrom([]types.Strings{nil, {"tag:a"}, {"tag:b"}, {"tag:a", "tag:b"}, {"tag:srv"}, {"tag:router"}}).Draw(t, "tags")
		if len(n.Tags) > 0 && rapid.Bool().Draw(t, "clear-creator") {
			n.UserID, n.User = nil, nil
		}

	case "routes":
		routes := rapid.SampledFrom([][]netip.Prefix{
			nil,
			{netip.MustParsePrefix("10.0.0.0/24")},
			{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.1.0.0/24")},
		}).Draw(t, "routes")
		n.Hostinfo.RoutableIPs = slices.Clone(routes)

		n.ApprovedRoutes = nil
		if rapid.Bool().Draw(t, "approve") {
			n.ApprovedRoutes = slices.Clone(routes)
		}

	case "health":
		n.Unhealthy = !n.Unhealthy
	case "policy":
		result.policy = rapid.IntRange(0, len(streamPropertyPolicies)-1).Draw(t, "policy")
		result.doc = []byte(streamPropertyPolicies[result.policy])
	case "generated-policy":
		result.policy, result.doc = -1, propcheck.DrawPolicy(t)
	case "policy-order", "policy-duplicate":
		result.policy, result.doc = -1, propcheck.ReorderPolicy(t, p.policyDoc, op == "policy-duplicate")
	case "policy-restore":
		result.policy, result.doc = -1, slices.Clone(p.policies[rapid.IntRange(0, len(p.policies)-1).Draw(t, "policy-ancestor")])
	case "user":
		u := p.world.Users[rapid.IntRange(0, 2).Draw(t, "user")]

		u.DisplayName = rapid.SampledFrom([]string{"", "Renamed", "Display ☃"}).Draw(t, "display-name")
		if u.Name == fmt.Sprintf("u%d", u.ID) {
			u.Name += "-renamed"
		} else {
			u.Name = fmt.Sprintf("u%d", u.ID)
		}

		result.user = u
	case "dns":
		result.records = propcheck.DrawDNSRecords(t)
	case "derp":
		regions := make(map[tailcfg.DERPRegionID]*tailcfg.DERPRegion)

		for i := range rapid.IntRange(0, 3).Draw(t, "derp-count") {
			id := tailcfg.DERPRegionID(i + 1)
			regions[id] = &tailcfg.DERPRegion{RegionID: id, RegionName: fmt.Sprintf("region-%d", rapid.IntRange(0, 3).Draw(t, "derp-name"))}
		}

		result.derp = &tailcfg.DERPMap{Regions: regions}
	case "add":
		var absent []types.NodeID

		for id := types.NodeID(1); id <= 8; id++ {
			if p.world.Nodes[id] == nil {
				absent = append(absent, id)
			}
		}

		result.node = p.drawNode(t, rapid.SampledFrom(absent).Draw(t, "insert-id"))
	case "request", "stale-request":
		result.request = tailcfg.MapRequest{
			NodeKey: n.NodeKey, DiscoKey: n.DiscoKey,
			Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, rapid.ByteRange(1, 254).Draw(t, "request-ip")}), 41641)},
		}
		if rapid.Bool().Draw(t, "request-disco-clear") {
			result.request.DiscoKey = key.DiscoPublic{}
		}

		if op == "stale-request" {
			result.request.NodeKey = key.NodePublic{}
		}
	case "delete", "noop", "invalid-policy":
	}

	return result
}

// apply is the production adapter. Each model transition uses the generated
// values; only validated server timestamps are adopted from a response.
func (p *streamPropertySystem) apply(t *rapid.T, op streamOperation) {
	audits := state.PolicyAuditFailures()
	before := p.state.Snapshot()

	switch op.kind {
	case "policy", "generated-policy", "policy-order", "policy-duplicate", "policy-restore":
		changed, err := p.state.SetPolicy(op.doc)
		require.NoError(t, err, "generated policy: %s", op.doc)
		expectedChange := !bytes.Equal(p.policyDoc, op.doc)
		require.Equal(t, expectedChange, changed)

		wantRev := before.Rev()
		if expectedChange {
			wantRev++
		}

		require.Equal(t, wantRev, p.state.Snapshot().Rev(), "policy publication")
		p.policy, p.policyDoc = op.policy, slices.Clone(op.doc)
		p.policies = append(p.policies, slices.Clone(op.doc))
	case "invalid-policy":
		_, err := p.state.SetPolicy([]byte(`{"grants":`))
		require.Error(t, err)
		require.Equal(t, before.Rev(), p.state.Snapshot().Rev(), "refused policy published")
	case "user":
		users := slices.Clone(p.world.Users)
		users[op.user.ID-1] = op.user
		p.world.SetUsers(users)
		_, err := p.state.UpdateUser(types.UserID(op.user.ID), func(u *types.User) error { *u = op.user; return nil })
		require.NoError(t, err)
	case "dns":
		p.state.SetExtraRecords(op.records)
		p.dnsRecords = propcheck.CanonicalDNSRecords(op.records)

		wantRev := before.Rev()
		if !slices.Equal(before.DNS().ExtraRecords().AsSlice(), p.dnsRecords) {
			wantRev++
		}

		require.Equal(t, wantRev, p.state.Snapshot().Rev(), "DNS publication equivalence")
	case "derp":
		p.state.SetDERPMap(op.derp)
	case "delete":
		p.world.Delete(op.node.ID)
		p.state.DeleteNodeFromStoreForTest(op.node.ID)
		p.hub.forget(op.node.ID)
		p.history.Forget(op.node.ID)

		if session := p.sessions[op.node.ID]; session != nil {
			_, err := session.stream.Update(p.state.Snapshot())
			require.ErrorIs(t, err, ErrNodeGone)
		}

		delete(p.sessions, op.node.ID)
	case "add":
		p.create(t, op.node)
		p.open(t, op.node.ID, p.state.Snapshot(), false)
	case "stale-request":
		require.ErrorIs(t, p.state.UpdateNodeFromMapRequest(op.node.ID, op.request), state.ErrNodeKeyChanged)
		require.Equal(t, before.Rev(), p.state.Snapshot().Rev(), "refused key published")
	case "request":
		start := time.Now()

		require.NoError(t, p.state.UpdateNodeFromMapRequest(op.node.ID, op.request))

		end := time.Now()
		got, ok := p.state.Snapshot().GetNode(op.node.ID)
		require.True(t, ok)

		seen := got.LastSeen().Clone()
		require.NotNil(t, seen)
		require.False(t, seen.Before(start), "LastSeen precedes request")
		require.False(t, seen.After(end), "LastSeen follows request completion")

		n := op.before.Clone()
		// Requests in this component have one endpoint and omit Hostinfo. A
		// substantive endpoint/disco change receives the next report sequence.
		if !slices.Equal(n.Endpoints, op.request.Endpoints) || n.DiscoKey != op.request.DiscoKey {
			p.reportSeq++
			n.ReportGen = p.reportSeq
		}

		n.Endpoints, n.DiscoKey, n.LastSeen = slices.Clone(op.request.Endpoints), op.request.DiscoKey, new(*seen)
		if n.Unhealthy && len(propertyApproved(n)) == 0 {
			n.Unhealthy = false
		}

		p.world.Put(n)
		require.Equal(t, before.Rev()+1, p.state.Snapshot().Rev(), "MapRequest always publishes LastSeen")
	default:
		p.put(t, op.node)

		if op.kind == "revert" {
			p.put(t, op.before)
		}

		writes := uint64(1)
		if op.kind == "revert" {
			writes++
		}

		require.Equal(t, before.Rev()+writes, p.state.Snapshot().Rev(), "graph input publication")
	}

	p.checkWorld(t)
	p.checkHistory(t)
	require.Equal(t, audits, state.PolicyAuditFailures(), "policy audit after %s", op.kind)
	p.checkCausal(t, before, p.state.Snapshot(), op)
}

func propertyApproved(n *types.Node) []netip.Prefix {
	var routes []netip.Prefix

	for _, prefix := range n.Hostinfo.RoutableIPs {
		if slices.Contains(n.ApprovedRoutes, prefix) {
			routes = append(routes, prefix)
		}
	}

	return routes
}

// checkCausal checks one input's effect through render, diff, JSON and the
// pinned client. It runs in focused histories and after each composed write,
// independently of the aggregate's coalesced/partial delivery schedule.
func (p *streamPropertySystem) checkCausal(t *rapid.T, before, after *state.Snapshot, op streamOperation) {
	// Router removal can move another router's overlay; wider policies can
	// change other peers' visibility. Those use the composed intent checks.
	if op.kind == "delete" && (p.policy != 0 || len(propertyApproved(op.node)) != 0) {
		return
	}

	switch op.kind {
	case "endpoints", "hostinfo", "dns", "derp", "noop", "revert", "stale-request", "invalid-policy", "delete":
	default:
		return
	}

	for _, viewer := range before.ListNodes().All() {
		if _, live := after.GetNode(viewer.ID()); !live {
			continue
		}

		hub := NewHub()
		stream := NewStream(p.cfg, hub, viewer.ID(), capVer)
		initial, err := stream.Initial(before)
		require.NoError(t, err)

		expected, actual := newPropertyClient(&tailcfg.MapResponse{}), newPropertyClient(&tailcfg.MapResponse{})
		applyStreamPropertyWire(t, expected, initial)
		applyStreamPropertyWire(t, actual, initial)
		stream.Delivered()
		responses, err := stream.Update(after)
		require.NoError(t, err)
		applyStreamPropertyWire(t, actual, responses)

		freshHub := NewHub()
		full, err := NewStream(p.cfg, freshHub, viewer.ID(), capVer).Initial(after)
		freshHub.Close()
		require.NoError(t, err)

		fresh := newPropertyClient(&tailcfg.MapResponse{})
		applyStreamPropertyWire(t, fresh, full)
		actual.check(t, fresh)

		switch op.kind {
		case "endpoints":
			if peer := expected.peers[op.node.ID.NodeID()]; peer != nil {
				peer.Endpoints = slices.Clone(op.node.Endpoints)
			}

			if expected.self.ID == op.node.ID.NodeID() {
				expected.self.Endpoints = slices.Clone(op.node.Endpoints)
			}
		case "hostinfo":
			subject := actual.peers[op.node.ID.NodeID()]

			self := actual.self.ID == op.node.ID.NodeID()
			if self {
				subject = actual.self
			}

			if subject != nil {
				require.Equal(t, op.node.Hostinfo.Hostname, subject.Hostinfo.Hostname(), "reported hostname")
				require.Equal(t, wireJSON(t, op.node.Hostinfo.Services), wireJSON(t, subject.Hostinfo.Services().AsSlice()), "reported TCP services")

				if !self {
					require.Equal(t, op.node.Hostinfo.OS, subject.Hostinfo.OS(), "reported peer OS")
				}

				require.Equal(t, op.node.Hostinfo.NetInfo.PreferredDERP, subject.HomeDERP, "reported home DERP")
			}
			// Hostinfo can change platform-dependent capabilities on self; peers
			// and globals unrelated to this node must still remain unchanged.
			if expected.self.ID == op.node.ID.NodeID() {
				expected.self = actual.self
			}

			if expected.peers[op.node.ID.NodeID()] != nil {
				expected.peers[op.node.ID.NodeID()] = actual.peers[op.node.ID.NodeID()]
			}
		case "dns":
			require.True(t, slices.Equal(propcheck.CanonicalDNSRecords(op.records), actual.dns.ExtraRecords), "DNS input to canonical wire records")
			expected.dns = actual.dns
		case "derp":
			require.Equal(t, wireJSON(t, op.derp), wireJSON(t, actual.derp))
			expected.derp = actual.derp
		case "delete":
			delete(expected.peers, op.node.ID.NodeID())
			delete(expected.deltaPeers, op.node.ID.NodeID())
			// Policy-derived filters/profiles/DNS can legitimately change on removal.
			expected.filter, expected.ssh, expected.dns = actual.filter, actual.ssh, actual.dns
			expected.self, expected.profiles = actual.self, actual.profiles
		}

		actual.check(t, expected)

		quiet, err := stream.Update(after)
		require.NoError(t, err)
		require.Empty(t, quiet, "same snapshot quiet after %s", op.kind)
		hub.Close()
	}
}
