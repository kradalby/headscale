package mapper

import (
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/internal/propcheck"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

// TestRapidStreamSystem checks the entire world/policy/Route/render/diff/wire
// path. Only Route's viewers receive updates; every other active viewer must
// already equal an independent fresh stream. Rapid's default case and step
// budgets bound CI work; -rapid.checks, -rapid.steps and -rapid.seed drive campaigns.
func TestRapidStreamSystem(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")
	rapid.Check(t, func(t *rapid.T) {
		audits := state.PolicyAuditFailures()
		p := newStreamPropertySystem(t)
		last := p.state.Snapshot()
		p.check(t, last)
		t.Repeat(map[string]func(*rapid.T){"commit": func(t *rapid.T) {
			// Keep an old snapshot and its wire model across writes and
			// cache advancement; a late renderer must still read it correctly.
			old := p.state.Snapshot()
			oldWorld := p.world.Clone()
			oldNode := old.ListNodes().At(0).ID()
			oldHub := NewHub()
			oldMap, err := NewStream(p.cfg, oldHub, oldNode, capVer).r.render(old)
			require.NoError(t, err)

			oldClient := newPropertyClient(&tailcfg.MapResponse{})
			applyStreamPropertyWire(t, oldHub, oldClient, []*tailcfg.MapResponse{fullResponse(p.cfg, oldMap)})
			oldHub.Close()

			for range rapid.IntRange(1, 3).Draw(t, "coalesced-writes") {
				p.apply(t, p.drawOperation(t))

				if rapid.Bool().Draw(t, "intermediate-render") {
					id := rapid.SampledFrom(slices.Sorted(maps.Keys(p.sessions))).Draw(t, "intermediate-viewer")

					session := p.sessions[id]
					if session.down {
						p.open(t, id, p.state.Snapshot(), rapid.Bool().Draw(t, "partial-reconnect"))
					} else {
						p.update(t, id, p.state.Snapshot(), 0)
					}
				}
			}

			snap := p.state.Snapshot()
			all, wake := Route(last, snap, snap.Since(last))
			p.hub.advance(snap)

			for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
				session := p.sessions[id]
				if session.down {
					if rapid.Bool().Draw(t, "reconnect") {
						p.open(t, id, snap, rapid.Bool().Draw(t, "partial-reconnect"))
					}
				} else if _, named := wake[id]; all || named {
					p.update(t, id, snap, rapid.IntRange(0, 5).Draw(t, "delivery"))
				}
			}

			p.check(t, snap)
			propcheck.CheckWorld(t, oldWorld, old, p.probes)
			lateMap, err := NewStream(p.cfg, p.hub, oldNode, capVer).r.render(old)
			require.NoError(t, err)

			lateClient := newPropertyClient(&tailcfg.MapResponse{})
			applyStreamPropertyWire(t, p.hub, lateClient, []*tailcfg.MapResponse{fullResponse(p.cfg, lateMap)})
			lateClient.check(t, oldClient)

			last = snap
		}})

		for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
			if p.sessions[id].down {
				p.open(t, id, p.state.Snapshot(), false)
			}
		}

		p.check(t, p.state.Snapshot())
		require.Equal(t, audits, state.PolicyAuditFailures(), "incremental policy disagreed with full compile")
	})
}

// Guard the reusable replay model's two less common patch fields without
// claiming the system generator can create a node's KeySignature in State.
func TestRapidStreamModelPatchFields(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		capability := tailcfg.CapabilityVersion(rapid.IntRange(1, 200).Draw(t, "cap"))
		signature := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(t, "signature")
		client := newPropertyClient(&tailcfg.MapResponse{Peers: []*tailcfg.Node{{ID: 2}}})
		applyStreamPropertyWire(t, nil, client, []*tailcfg.MapResponse{{PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 2, Cap: capability, KeySignature: signature}}}})
		require.Equal(t, capability, client.peers[2].Cap)
		require.True(t, slices.Equal(signature, client.peers[2].KeySignature))
	})
}

// The route oracle needs no policy compiler: with two approved routers and
// exactly one healthy online router, that router must carry the subnet. Run
// both ordinary grants and via grants, then withdraw and restore approvals.
func TestRapidStreamRouteFailover(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := newStreamPropertySystem(t)
		last := p.state.Snapshot()
		route := netip.MustParsePrefix("10.0.0.0/24")

		via := ""
		if rapid.Bool().Draw(t, "via") {
			via = `,"via":["tag:a"]`
		}

		_, err := p.state.SetPolicy([]byte(`{"tagOwners":{"tag:a":["u1@"]},"grants":[{"src":["u1@"],"dst":["10.0.0.0/24"],"ip":["*"]` + via + `}]}`))
		require.NoError(t, err)

		p.policy = 3 // This property's route oracle replaces the simple-policy oracle.
		p.policyDoc = []byte(`{"tagOwners":{"tag:a":["u1@"]},"grants":[{"src":["u1@"],"dst":["10.0.0.0/24"],"ip":["*"]` + via + `}]}`)
		p.viaOnly = via != ""
		winner := rapid.SampledFrom([]types.NodeID{2, 3}).Draw(t, "healthy-router")

		for _, id := range []types.NodeID{2, 3} {
			router := p.world.Nodes[id].Clone()
			router.Tags = []string{"tag:a"}
			router.Hostinfo.RoutableIPs = []netip.Prefix{route}
			router.ApprovedRoutes = []netip.Prefix{route}
			router.ActiveSessions, router.IsOnline = 1, new(true)
			router.Unhealthy = id != winner
			router.SessionStart = time.Unix(1_700_000_000+int64(id), 0).UTC() //nolint:gosec // Router IDs are 2 and 3.
			p.put(t, router)
		}

		for phase := range 4 {
			if phase == 1 {
				winner = 5 - winner
			}

			if phase > 0 {
				for _, id := range []types.NodeID{2, 3} {
					router := p.world.Nodes[id].Clone()
					router.Unhealthy = id != winner

					router.ApprovedRoutes = []netip.Prefix{route}
					if phase == 2 {
						router.ApprovedRoutes = nil
					}

					p.put(t, router)
				}
			}

			snap := p.state.Snapshot()
			all, wake := Route(last, snap, snap.Since(last))
			p.hub.advance(snap)

			for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
				if _, named := wake[id]; all || named {
					p.update(t, id, snap, 0)
				}
			}

			p.check(t, snap)

			for _, id := range []types.NodeID{2, 3} {
				peer := p.sessions[1].client.peers[id.NodeID()]

				winners := p.routes.Global
				if p.viaOnly {
					winners = p.routes.Via["tag:a"]
				}

				want := winners[route] == uint64(id)
				require.Equal(t, want, phase != 2 && id == winner, "election oracle and directed scenario agree")

				if want {
					require.NotNil(t, peer, "healthy router must be visible")
				}

				if peer != nil {
					require.Equal(t, want, slices.Contains(peer.AllowedIPs, route), "phase %d router %d", phase, id)
					require.Equal(t, want, slices.Contains(peer.PrimaryRoutes, route), "phase %d router %d", phase, id)
				}
			}

			last = snap
		}
	})
}

// Visibility changes must revoke peers through deltas as well as full maps;
// reconnecting clients retain profiles, but never learn a hidden owner.
func TestRapidStreamVisibilityTransitions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := newStreamPropertySystem(t)

		last := p.state.Snapshot()
		for _, policy := range []int{0, 1, 0, 2} {
			p.setPolicy(t, policy)
			snap := p.state.Snapshot()
			all, wake := Route(last, snap, snap.Since(last))
			p.hub.advance(snap)

			for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
				if _, named := wake[id]; all || named {
					p.update(t, id, snap, 0)
				}
			}

			p.check(t, snap)
			id := rapid.SampledFrom(slices.Sorted(maps.Keys(p.sessions))).Draw(t, "reconnecting-viewer")
			p.open(t, id, snap, false)
			p.check(t, snap)
			last = snap
		}
	})
}

// Focused callers draw subsets of the same operations and invoke the same
// world, election, causal-delta and replay assertions as the composed driver.
func TestRapidStreamOperationContracts(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	for _, kinds := range [][]string{
		{"endpoints", "hostinfo", "dns", "derp", "noop", "revert"},
		{"request", "stale-request", "invalid-policy"},
		{"generated-policy", "policy-order", "policy-duplicate", "policy-restore"},
	} {
		t.Run(kinds[0], func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				audits := state.PolicyAuditFailures()
				p := newStreamPropertySystem(t)

				last := p.state.Snapshot()
				for range rapid.IntRange(1, 12).Draw(t, "operations") {
					p.apply(t, p.drawOperation(t, kinds...))
					snap := p.state.Snapshot()
					all, wake := Route(last, snap, snap.Since(last))
					p.hub.advance(snap)

					for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
						if _, named := wake[id]; all || named {
							p.update(t, id, snap, 0)
						}
					}

					p.check(t, snap)
					last = snap
				}

				require.Equal(t, audits, state.PolicyAuditFailures(), "incremental policy audit")
			})
		})
	}
}

func TestRapidStreamSimplePolicyEdits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := newStreamPropertySystem(t)
		kind := rapid.IntRange(0, 2).Draw(t, "simple-policy")
		p.setPolicy(t, kind)

		p.policies = []streamPropertyPolicy{{doc: slices.Clone(p.policyDoc), kind: kind}}
		for _, operation := range []string{"policy-order", "policy-duplicate", "policy-restore"} {
			op := p.drawOperation(t, operation)
			require.Equal(t, kind, op.policy, "simple intent survives %s", operation)
			p.apply(t, op)
			require.Equal(t, kind, p.policy)
		}
	})
}

// Persistent IDs identify one lifetime. Deletion never makes an ID available
// for another node, and the byte-based fixture stops allocating at 255.
func TestRapidStreamFreshNodeIDs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := newStreamPropertySystem(t)
		if len(p.world.Nodes) == 3 {
			p.apply(t, p.drawOperation(t, "add"))
		}

		for range rapid.IntRange(1, 8).Draw(t, "lifetimes") {
			removed := p.drawOperation(t, "delete")
			previousID := p.lastNodeID
			p.apply(t, removed)
			added := p.drawOperation(t, "add")
			require.Equal(t, previousID+1, added.node.ID)
			require.NotEqual(t, removed.node.ID, added.node.ID)
			p.apply(t, added)
			require.Contains(t, p.probes.IDs, removed.node.ID, "deleted IDs remain world/history probes")
			require.Contains(t, p.probes.IDs, added.node.ID)
			require.GreaterOrEqual(t, len(p.world.Nodes), 3)
			require.LessOrEqual(t, len(p.world.Nodes), 8)
		}

		if len(p.world.Nodes) == 8 {
			p.apply(t, p.drawOperation(t, "delete"))
		}

		p.lastNodeID = maxStreamPropertyNodeID - 1
		last := p.drawOperation(t, "add")
		require.Equal(t, maxStreamPropertyNodeID, last.node.ID)
		require.Equal(t, netip.MustParseAddr("100.64.0.255"), *last.node.IPv4)
		p.apply(t, last)
		// Keep room in the live fleet so the exhausted-ID guard is exercised.
		p.apply(t, p.drawOperation(t, "delete"))

		for range 20 {
			require.NotEqual(t, "add", p.drawOperation(t).kind)
		}
	})
}
