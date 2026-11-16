// Visibility, route access and via from roles over the SaaS captures: for
// every policy headscale compiles, every node of its topology, the
// role-based peers equal the compile's, route access for every viewer and
// route equals the viewer's matchers', and via steering for every pair
// equals the compile's (check E, through AuditSides); built from scratch
// and reached by joins and leaves. Where a capture holds a netmap, the
// role-based peers and AllowedIPs are compared with what SaaS sent.

package v2

import (
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
)

type sidesTally struct {
	mu sync.Mutex

	files, loads, refused, incremental int
	report                             SidesReport
	saasPeers, saasPeersExact          int
	saasPeersDiffer                    []string
	saasRoutes, saasRoutesExact        int
	saasRoutesDiffer                   []string
	steps, stepCaptures                int
}

func (g *sidesTally) add(f func(*sidesTally)) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f(g)
}

// TestGoldenSides runs the role-based visibility over every policy the
// captures hold, with each directory's own users and nodes, the user
// captures under every overlay, and the step capture replayed
// incrementally.
func TestGoldenSides(t *testing.T) {
	t.Parallel()

	tally := &sidesTally{}

	t.Cleanup(func() {
		t.Logf("capture files %d; %d policy loads audited (%d refused by headscale), %d replayed by joins and leaves",
			tally.files, tally.loads, tally.refused, tally.incremental)
		t.Logf("compared from scratch: %+v", tally.report)
		slices.Sort(tally.saasPeersDiffer)
		slices.Sort(tally.saasRoutesDiffer)
		t.Logf("against SaaS, each equal to today's: peers of %d captured nodes, %d exact; captures with a difference %d: %v",
			tally.saasPeers, tally.saasPeersExact, len(tally.saasPeersDiffer), tally.saasPeersDiffer)
		t.Logf("against SaaS, each equal to today's: AllowedIPs of %d captured peers (primary routes as captured, no via steering), %d exact; captures with a difference %d",
			tally.saasRoutes, tally.saasRoutesExact, len(tally.saasRoutesDiffer))
		t.Logf("policy-generation: %d steps audited, %d captured netmaps compared", tally.steps, tally.stepCaptures)
	})

	sources := goldenFilterSources()
	sources = append(sources, goldenFilterSource{
		dir: "policytest_results", glob: "*.hujson",
		build: func(_ *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
			users := setupSSHDataCompatUsers()

			return users, buildGrantsNodesFromCapture(users, c)
		},
	})

	for _, src := range sources {
		files, err := filepath.Glob(filepath.Join("testdata", src.dir, src.glob))
		require.NoError(t, err)
		require.NotEmpty(t, files, "no captures in %s", src.dir)

		for _, file := range files {
			t.Run(filepath.Join(src.dir, filepath.Base(file)), func(t *testing.T) {
				t.Parallel()

				c, err := testcapture.Read(file)
				require.NoError(t, err)

				tally.add(func(g *sidesTally) { g.files++ })

				policy := []byte(c.Input.FullPolicy)

				if src.dir != "users_results" {
					users, nodes := src.build(t, c)
					goldenSides(t, tally, c.TestID, policy, users, nodes, c)

					return
				}

				for _, o := range userTokenOverlays {
					name := o.name
					if name == "" {
						name = "capture"
					}

					t.Run(name, func(t *testing.T) {
						users, nodes, _ := userTokenUsersAndNodes(t, c, o)

						var captured *testcapture.Capture
						if o.name == "" {
							captured = c
						}

						goldenSides(t, tally, c.TestID, policy, users, nodes, captured)
					})
				}
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		goldenSidesSequence(t, tally, "policy-generation")
	})
}

func goldenSides(t *testing.T, tally *sidesTally, id string, src []byte, users types.Users, nodes types.Nodes, c *testcapture.Capture) {
	t.Helper()

	pm, err := NewPolicyManager(src, users, nodes.ViewSlice())
	if err != nil {
		tally.add(func(g *sidesTally) { g.refused++ })

		return
	}

	m := newSideModel(t, pm, users, nodes)

	rep, err := m.audit()
	require.NoError(t, err, "from scratch")

	tally.add(func(g *sidesTally) {
		g.loads++
		g.report.Add(rep)
	})

	if c != nil && !c.Error && c.Input.APIResponseCode == 200 {
		goldenSidesAgainstSaaS(t, tally, id, m, c)
	}

	// The same tailnet reached incrementally: every node joining an empty
	// one in one commit, then every other node leaving.
	sel := m.t.sel
	us := NewUserSets(nil, sel, users)
	empty := graph.NewMap[types.NodeID, *types.Node](graph.Same[*types.Node], nil)

	inc := &sideModel{users: users, t: m.t, nodes: empty}
	inc.roles = Roles{}.Update(us, empty, nil)
	inc.posts = Postings{}.Update(inc.roles)
	inc.appr = SubnetApprovals{}.Update(empty)
	inc.sides = UpdateSides(Sides{}, m.t, inc.roles, inc.posts, inc.appr, empty)
	inc.peers = RolePeers(nil, inc.sides)
	inc.via = UpdateViaPlans(ViaPlans{}, inc.sides)

	step := func(next *NodeMap, listed types.Nodes, what string) {
		inc.nodes, inc.list = next, listed
		inc.roles = inc.roles.Update(us, next, nil)
		inc.posts = inc.posts.Update(inc.roles)
		inc.appr = inc.appr.Update(next)
		inc.sides = UpdateSides(inc.sides, m.t, inc.roles, inc.posts, inc.appr, next)
		inc.peers = RolePeers(inc.peers, inc.sides)
		inc.via = UpdateViaPlans(inc.via, inc.sides)

		// From the first compile, so the document's parse, which the
		// templates describe, carries over.
		inc.pm, err = NewPolicyManagerFrom(m.pm, src, users, listed.ViewSlice())
		require.NoError(t, err)

		_, err := inc.audit()
		require.NoError(t, err, what)
	}

	e := empty.Edit()
	for _, n := range nodes {
		e.Set(n.ID, n)
	}

	joined := e.Done()
	step(joined, nodes, "after every node joined")

	e = joined.Edit()

	var kept types.Nodes

	for i, n := range nodes {
		if i%2 == 1 {
			e.Delete(n.ID)
		} else {
			kept = append(kept, n)
		}
	}

	step(e.Done(), kept, "after every other node left")

	tally.add(func(g *sidesTally) { g.incremental++ })
}

// goldenSidesAgainstSaaS compares, for every captured netmap, the
// role-based peers and each peer's AllowedIPs with today's — the pair scan,
// and the routes [types.NodeView.CanAccessRoute] keeps with the viewer's
// matchers, as TestRoutesCompatPeerAllowedIPs computes them — which must be
// equal, and counts where both differ from what SaaS sent.
func goldenSidesAgainstSaaS(t *testing.T, tally *sidesTally, id string, m *sideModel, c *testcapture.Capture) {
	t.Helper()

	names := map[types.NodeID]string{}
	for _, n := range m.list {
		names[n.ID] = n.GivenName
	}

	today := m.pm.BuildPeerMap(m.list.ViewSlice())

	for _, alias := range slices.Sorted(maps.Keys(c.Captures)) {
		capture := c.Captures[alias]
		if capture.Netmap == nil {
			continue
		}

		viewer := findNodeByGivenName(m.list, alias)
		require.NotNilf(t, viewer, "%s: node %s not built", id, alias)

		var want, got, was []string

		for _, p := range capture.Netmap.Peers {
			name, _, _ := strings.Cut(p.Name(), ".")
			if findNodeByGivenName(m.list, name) != nil {
				want = append(want, name)
			}
		}

		for _, p := range m.peers.Peers(viewer.ID) {
			got = append(got, names[p])
		}

		for _, p := range today[viewer.ID] {
			was = append(was, names[p])
		}

		slices.Sort(want)
		slices.Sort(got)
		slices.Sort(was)
		require.Equal(t, was, got, "%s/%s: peers differ from today's", id, alias)

		same := slices.Equal(want, got)

		tally.add(func(g *sidesTally) {
			g.saasPeers++
			if same {
				g.saasPeersExact++
			} else if !slices.Contains(g.saasPeersDiffer, id) {
				g.saasPeersDiffer = append(g.saasPeersDiffer, id)
			}
		})

		matchers, err := m.pm.MatchersForNode(viewer.View())
		require.NoError(t, err)

		for _, nmPeer := range capture.Netmap.Peers {
			name, _, _ := strings.Cut(nmPeer.Name(), ".")

			peer := findNodeByGivenName(m.list, name)
			if peer == nil {
				continue
			}

			routes := slices.Concat(nmPeer.PrimaryRoutes().AsSlice(), peer.ExitRoutes())

			var kept []netip.Prefix

			for _, r := range routes {
				if viewer.View().CanAccessRoute(matchers, r) {
					kept = append(kept, r)
				}
			}

			gotIPs := slices.Concat(peer.View().Prefixes(), m.sides.RouteAccess(viewer.ID, routes))
			wasIPs := slices.Concat(peer.View().Prefixes(), kept)

			slices.SortFunc(gotIPs, netip.Prefix.Compare)
			slices.SortFunc(wasIPs, netip.Prefix.Compare)
			require.Equal(t, wasIPs, gotIPs, "%s/%s/%s: AllowedIPs differ from today's", id, alias, name)

			wantIPs := nmPeer.AllowedIPs().AsSlice()
			slices.SortFunc(wantIPs, netip.Prefix.Compare)

			same := slices.Equal(wantIPs, gotIPs)

			tally.add(func(g *sidesTally) {
				g.saasRoutes++
				if same {
					g.saasRoutesExact++
				} else if !slices.Contains(g.saasRoutesDiffer, id) {
					g.saasRoutesDiffer = append(g.saasRoutesDiffer, id)
				}
			})
		}
	}
}

// goldenSidesSequence replays a step capture as the world runs it: one
// compile, templates, roles, postings, sides, classes and via plan carried
// from step to step, the role-based answers audited at every step.
func goldenSidesSequence(t *testing.T, tally *sidesTally, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)

	users := setupGrantsCompatUsers()
	ids := map[string]types.NodeID{}

	var (
		m      = &sideModel{users: users, nodes: graph.NewMap[types.NodeID, *types.Node](graph.Same[*types.Node], nil)}
		sel    *Selectors
		us     *UserSets
		policy []byte
	)

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if _, ok := ids[a.Node]; a.Kind == "join" && !ok {
				ids[a.Node] = types.NodeID(len(ids) + 1) //nolint:gosec // a handful of nodes
			}
		}

		listed, _ := sequenceNodes(t, users, step, ids)

		if pushed := stepPolicy(t, step); pushed != nil {
			policy = pushed
		}

		e := m.nodes.Edit()
		seen := map[types.NodeID]bool{}

		for _, n := range listed {
			seen[n.ID] = true
			e.Set(n.ID, n)
		}

		for nid := range m.nodes.All() {
			if !seen[nid] {
				e.Delete(nid)
			}
		}

		m.nodes, m.list = e.Done(), listed

		m.pm, err = NewPolicyManagerFrom(m.pm, policy, users, nodeViews(m.nodes))
		require.NoError(t, err, step.Name)

		sel = SelectorsFor(sel, m.pm)
		m.t = BuildTemplates(m.t, sel)
		us = NewUserSets(us, sel, users)
		m.roles = m.roles.Update(us, m.nodes, nil)
		m.posts = m.posts.Update(m.roles)
		m.appr = m.appr.Update(m.nodes)
		m.sides = UpdateSides(m.sides, m.t, m.roles, m.posts, m.appr, m.nodes)
		m.peers = RolePeers(m.peers, m.sides)
		m.via = UpdateViaPlans(m.via, m.sides)

		_, err := m.audit()
		require.NoError(t, err, step.Name)

		for _, alias := range slices.Sorted(maps.Keys(step.Captures)) {
			capture := step.Captures[alias]
			if capture.Netmap == nil {
				continue
			}

			key := strings.Join([]string{id, step.Name, alias}, "/")
			if notCompared(policySequenceNotCompared, key+"/filter") {
				continue
			}

			node := findGrantsNode(listed, alias)
			require.NotNil(t, node)

			var want, got []string

			for _, p := range capture.Netmap.Peers {
				name, _, _ := strings.Cut(p.Name(), ".")
				if findGrantsNode(listed, name) != nil {
					want = append(want, name)
				}
			}

			for _, p := range m.peers.Peers(node.ID) {
				for _, n := range listed {
					if n.ID == p {
						got = append(got, n.GivenName)
					}
				}
			}

			slices.Sort(want)
			slices.Sort(got)
			require.Equal(t, want, got, "%s: peers differ from SaaS", key)

			tally.add(func(g *sidesTally) { g.stepCaptures++ })
		}

		tally.add(func(g *sidesTally) { g.steps++ })
	}
}
