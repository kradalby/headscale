package servertest_test

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

// TestConcurrentMapRequestDERPReachesObservers supplements the state's six SQL
// ordering rows with actual long-poll consumers and an overlapping reconnect.
func TestConcurrentMapRequestDERPReachesObservers(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		for _, tt := range []struct {
			name        string
			first, last tailcfg.DERPRegionID
		}{
			{name: "newer region", first: 2, last: 3},
			{name: "newer clear", first: 2, last: 0},
			{name: "superseded clear", first: 0, last: 3},
		} {
			t.Run(fmt.Sprintf("%s rotate=%t", tt.name, rotate), func(t *testing.T) {
				srv := servertest.NewServer(t)
				user := srv.CreateUser(t, "derp-owner")
				endpoint := netip.MustParseAddrPort("203.0.113.9:41641")
				subject := servertest.NewClient(t, srv, "derp-subject", servertest.WithUser(user),
					servertest.WithHostinfo(&tailcfg.Hostinfo{BackendLogID: "servertest-derp-subject", Hostname: "derp-subject", NetInfo: &tailcfg.NetInfo{PreferredDERP: 1}}),
					servertest.WithEndpoints(tailcfg.Endpoint{Addr: endpoint, Type: tailcfg.EndpointExplicitConf}))
				stable := servertest.NewClient(t, srv, "stable-observer", servertest.WithUser(user))
				reconnected := servertest.NewClient(t, srv, "reconnected-observer", servertest.WithUser(user))
				subjectID := findNodeID(t, srv, subject.Name)
				reconnectedID := findNodeID(t, srv, reconnected.Name)
				node, ok := srv.State().GetNodeByID(subjectID)
				require.True(t, ok)

				disco := node.DiscoKey()
				if rotate {
					disco = key.NewDisco().Public()
				}

				peerIs := func(nm *netmap.NetworkMap, region tailcfg.DERPRegionID, wantDisco key.DiscoPublic) bool {
					peer, missing := peerByID(nm, subjectID.NodeID())
					return missing == "" && peer.HomeDERP() == region && peer.DiscoKey() == wantDisco && slices.Equal(peer.Endpoints().AsSlice(), []netip.AddrPort{endpoint})
				}
				for _, observer := range []*servertest.TestClient{stable, reconnected} {
					observer.WaitForCondition(t, "initial DERP paths", 5*time.Second, func(nm *netmap.NetworkMap) bool {
						return peerIs(nm, 1, node.DiscoKey())
					})
				}

				sqlEntered, sqlRelease := make(chan struct{}), make(chan struct{})
				releaseSQL := sync.OnceFunc(func() { close(sqlRelease) })

				var held atomic.Bool

				gdb := srv.State().DB().DB
				require.NoError(t, gdb.Callback().Update().Before("gorm:update").Register("hold_derp_write", func(tx *gorm.DB) {
					candidate, matches := tx.Statement.Dest.(*types.Node)
					if tx.Statement.Table == "nodes" && matches && candidate.ID == subjectID && held.CompareAndSwap(false, true) {
						close(sqlEntered)
						<-sqlRelease
					}
				}))

				var reports sync.WaitGroup

				t.Cleanup(func() {
					releaseSQL()
					reports.Wait()

					_ = gdb.Callback().Update().Remove("hold_derp_write")
				})

				streamEntered, streamRelease := make(chan struct{}), make(chan struct{})
				releaseStream := sync.OnceFunc(func() { close(streamRelease) })
				t.Cleanup(releaseStream)

				var reconnectArmed atomic.Bool

				srv.App.SetBeforeMapRequestForTest(t, func(id types.NodeID, req tailcfg.MapRequest) {
					if id == reconnectedID && req.Stream && reconnectArmed.CompareAndSwap(true, false) {
						close(streamEntered)
						<-streamRelease
					}
				})

				errs := make(chan error, 2)

				for i, region := range []tailcfg.DERPRegionID{tt.first, tt.last} {
					req := tailcfg.MapRequest{
						NodeKey: node.NodeKey(), DiscoKey: disco, Endpoints: []netip.AddrPort{endpoint},
						Hostinfo: &tailcfg.Hostinfo{Hostname: subject.Name, NetInfo: &tailcfg.NetInfo{PreferredDERP: region}},
					}

					reports.Go(func() { errs <- srv.State().UpdateNodeFromMapRequest(subjectID, req) })
					require.EventuallyWithT(t, func(c *assert.CollectT) {
						current, exists := srv.State().GetNodeByID(subjectID)
						if assert.True(c, exists) {
							assert.Equal(c, region, current.Hostinfo().NetInfo().PreferredDERP())
						}
					}, 5*time.Second, time.Millisecond, "each report must publish before SQL is released")
					stable.WaitForCondition(t, "published DERP before SQL", 5*time.Second, func(nm *netmap.NetworkMap) bool {
						return peerIs(nm, region, disco)
					})

					if i == 0 {
						select {
						case <-sqlEntered:
						case <-time.After(5 * time.Second):
							t.Fatal("first report did not reach the held SQL write")
						}

						reconnectArmed.Store(true)
						require.NoError(t, reconnected.RestartPoll(t.Context()))

						select {
						case <-streamEntered:
						case <-time.After(5 * time.Second):
							t.Fatal("reconnecting observer did not reach the held map request")
						}
					}
				}

				select {
				case err := <-errs:
					t.Fatalf("a report completed while its SQL write remained held: %v", err)
				default:
				}

				releaseStream()
				reconnected.WaitForCondition(t, "reconnect sees latest unpublished-to-SQL report", 5*time.Second, func(nm *netmap.NetworkMap) bool {
					return peerIs(nm, tt.last, disco)
				})
				releaseSQL()
				reports.Wait()

				for range 2 {
					require.NoError(t, <-errs)
				}

				current, ok := srv.State().GetNodeByID(subjectID)
				require.True(t, ok)
				assert.Equal(t, tt.last, current.Hostinfo().NetInfo().PreferredDERP())
				assert.Equal(t, disco, current.DiscoKey())
				assert.Equal(t, []netip.AddrPort{endpoint}, current.Endpoints().AsSlice())

				durable, err := srv.State().DB().GetNodeByID(subjectID)
				require.NoError(t, err)
				assert.Equal(t, tt.last, durable.Hostinfo.NetInfo.PreferredDERP)
				assert.Equal(t, disco, durable.DiscoKey)
				assert.Equal(t, []netip.AddrPort{endpoint}, []netip.AddrPort(durable.Endpoints))

				// A different real edit supplies a transport barrier. No identical
				// DERP report is sent to repair a stale stream or durable row.
				renamed, err := srv.State().RenameNode(subjectID, "after-derp")
				require.NoError(t, err)
				wantName, err := renamed.GetFQDN(srv.State().Snapshot().DNS().BaseDomain())
				require.NoError(t, err)

				for _, observer := range []*servertest.TestClient{stable, reconnected} {
					observer.WaitForCondition(t, "rename after both SQL completions", 5*time.Second, func(nm *netmap.NetworkMap) bool {
						peer, missing := peerByID(nm, subjectID.NodeID())
						return missing == "" && peer.Name() == wantName && peerIs(nm, tt.last, disco)
					})

					latestSeen := false

					for _, nm := range observer.History() {
						if peerIs(nm, tt.last, disco) {
							latestSeen = true
						}

						if latestSeen {
							require.True(t, peerIs(nm, tt.last, disco), "a later frame must not restore superseded paths")
						}
					}

					require.True(t, latestSeen)

					freshHub := mapper.NewHub()
					fresh, err := mapper.NewStream(srv.State().DebugConfig(), freshHub, findNodeID(t, srv, observer.Name), tailcfg.CurrentCapabilityVersion).Initial(srv.State().Snapshot())
					freshHub.Close()
					require.NoError(t, err)

					index := slices.IndexFunc(fresh[0].Peers, func(peer *tailcfg.Node) bool { return peer.ID == subjectID.NodeID() })
					require.GreaterOrEqual(t, index, 0)
					peer := fresh[0].Peers[index]
					assert.Equal(t, tt.last, peer.HomeDERP)
					assert.Equal(t, disco, peer.DiscoKey)
					assert.Equal(t, []netip.AddrPort{endpoint}, peer.Endpoints)
				}
			})
		}
	}
}

// TestRoutes verifies that route advertisements and approvals
// propagate correctly through the control plane to all peers.
//
//nolint:gocyclo // table-driven test driver with many independent subtests
func TestRoutes(t *testing.T) {
	t.Parallel()

	t.Run("node_addresses_in_allowed_ips", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Each peer's AllowedIPs should contain the peer's addresses.
		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)

			for _, peer := range nm.Peers {
				addrs := make(map[netip.Prefix]bool)
				for i := range peer.Addresses().Len() {
					addrs[peer.Addresses().At(i)] = true
				}

				for i := range peer.AllowedIPs().Len() {
					aip := peer.AllowedIPs().At(i)
					if addrs[aip] {
						delete(addrs, aip)
					}
				}

				assert.Empty(t, addrs,
					"client %s: peer %d AllowedIPs should contain all of Addresses",
					c.Name, peer.ID())
			}
		}
	})

	t.Run("advertised_routes_in_hostinfo", func(t *testing.T) {
		t.Parallel()
		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "advroute-user")
		route := netip.MustParsePrefix("192.168.1.0/24")
		advertiser := servertest.NewClient(t, srv, "advroute-node1", servertest.WithUser(user))
		observer := servertest.NewClient(t, srv, "advroute-node2", servertest.WithUser(user))
		advertiser.WaitForPeers(t, 1, 10*time.Second)
		advertiseRoutes(t, advertiser, []netip.Prefix{route})
		node, ok := srv.State().GetNodeByID(findNodeID(t, srv, advertiser.Name))
		require.True(t, ok)
		assert.Equal(t, []netip.Prefix{route}, node.AnnouncedRoutes())
		advertiser.WaitForCondition(t, "own announcement in Hostinfo", 10*time.Second, func(nm *netmap.NetworkMap) bool {
			return nm.SelfNode.Hostinfo().Valid() && slices.Contains(nm.SelfNode.Hostinfo().RoutableIPs().AsSlice(), route)
		})
		peer, ok := peerByHostname(observer.Netmap(), advertiser.Name)
		require.True(t, ok)
		assert.Empty(t, peer.Hostinfo().RoutableIPs().AsSlice(), "upstream trims peer Hostinfo route advertisements")
		assert.NotContains(t, peer.AllowedIPs().AsSlice(), route, "an unapproved announcement must not authorize a route")
	})

	t.Run("route_advertise_and_approve", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "fullrt-user")

		route := netip.MustParsePrefix("10.0.0.0/24")

		c1 := servertest.NewClient(t, srv, "fullrt-advertiser",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "fullrt-observer",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Step 1: Advertise the route by updating [tailcfg.Hostinfo].
		c1.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-fullrt-advertiser",
			Hostname:     "fullrt-advertiser",
			RoutableIPs:  []netip.Prefix{route},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// The server stores the announcement before it answers.
		require.NoError(t, c1.Direct().SendUpdate(ctx))

		// Step 2: Approve the route on the server.
		nodeID := findNodeID(t, srv, "fullrt-advertiser")

		_, err := srv.State().SetApprovedRoutes(
			nodeID, []netip.Prefix{route})
		require.NoError(t, err)

		// Step 3: Observer should see the route in AllowedIPs.
		c2.WaitForCondition(t, "approved route in AllowedIPs",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "fullrt-advertiser" {
						for i := range p.AllowedIPs().Len() {
							if p.AllowedIPs().At(i) == route {
								return true
							}
						}
					}
				}

				return false
			})
	})

	t.Run("allowed_ips_superset_of_addresses", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)

			for _, peer := range nm.Peers {
				allowedSet := make(map[netip.Prefix]bool)
				for i := range peer.AllowedIPs().Len() {
					allowedSet[peer.AllowedIPs().At(i)] = true
				}

				for i := range peer.Addresses().Len() {
					addr := peer.Addresses().At(i)
					assert.True(t, allowedSet[addr],
						"client %s: peer %d Address %v should be in AllowedIPs",
						c.Name, peer.ID(), addr)
				}
			}
		}
	})

	t.Run("addresses_are_in_cgnat_range", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		cgnat := netip.MustParsePrefix("100.64.0.0/10")
		ula := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)
			require.True(t, nm.SelfNode.Valid())

			for i := range nm.SelfNode.Addresses().Len() {
				addr := nm.SelfNode.Addresses().At(i)
				inCGNAT := cgnat.Contains(addr.Addr())
				inULA := ula.Contains(addr.Addr())
				assert.True(t, inCGNAT || inULA,
					"client %s: address %v should be in CGNAT or ULA range",
					c.Name, addr)
			}
		}
	})

	// Reproduces the HA secondary recovery race:
	// HA tracking loses the secondary subnet router after all routers serving
	// the route have been offline simultaneously and one of them returns.
	//
	// Two assertions split the failure surface:
	//   R1 — server-side primary route state restores after reconnect.
	//   R2 — observer's [netmap.NetworkMap] shows the reconnected router online with
	//        the route in its primary set.
	// If R1 fails the bug is in [state.State.Connect] / the primary election; if
	// R1 passes and R2 fails the bug is in change broadcast / [mapper.Hub].
	//
	// Caveat: [TestClient.Reconnect] re-registers via [controlclient.Direct.TryLogin] in addition
	// to starting a new poll session. Production reconnects after a brief
	// network outage may bypass re-registration. If this test passes on
	// main, fall back to the integration variant noted in the plan
	// (TestHASubnetRouterFailover with all routers offline simultaneously).
	t.Run("ha_secondary_recovers_after_all_offline", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "ha3203-user")

		route := netip.MustParsePrefix("10.0.0.0/24")

		r1 := servertest.NewClient(t, srv, "ha3203-router1",
			servertest.WithUser(user))
		r2 := servertest.NewClient(t, srv, "ha3203-router2",
			servertest.WithUser(user))
		obs := servertest.NewClient(t, srv, "ha3203-observer",
			servertest.WithUser(user))

		obs.WaitForPeers(t, 2, 10*time.Second)

		// Both routers advertise the same route via their [tailcfg.Hostinfo].
		advertise := func(c *servertest.TestClient, name string) {
			t.Helper()
			c.Direct().SetHostinfo(&tailcfg.Hostinfo{
				BackendLogID: "servertest-" + name,
				Hostname:     name,
				RoutableIPs:  []netip.Prefix{route},
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_ = c.Direct().SendUpdate(ctx)
		}
		advertise(r1, "ha3203-router1")
		advertise(r2, "ha3203-router2")

		// Approve the route on both routers explicitly. Auto-approvers
		// would also work but introduce a policy dependency the harness
		// does not currently set up here.
		approve := func(name string) {
			t.Helper()
			id := findNodeID(t, srv, name)

			_, err := srv.State().SetApprovedRoutes(id, []netip.Prefix{route})
			require.NoError(t, err)
		}
		approve("ha3203-router1")
		approve("ha3203-router2")

		// Sanity: r1 starts as primary (lower NodeID by registration order).
		r1ID := findNodeID(t, srv, "ha3203-router1")
		r2ID := findNodeID(t, srv, "ha3203-router2")

		hasRoute := func(id types.NodeID) bool {
			return slices.Contains(srv.State().GetNodePrimaryRoutes(id), route)
		}

		assert.Eventually(t, func() bool { return hasRoute(r1ID) },
			10*time.Second, 100*time.Millisecond,
			"r1 should be primary initially")

		// 1. Take r1 offline. After the 15s grace period, r2 should take over.
		r1.Disconnect(t)
		assert.Eventually(t, func() bool { return hasRoute(r2ID) && !hasRoute(r1ID) },
			20*time.Second, 200*time.Millisecond,
			"r2 should take over as primary after r1 offline")

		// 2. Take r2 offline. With both routers gone, r2 keeps the route.
		r2.Disconnect(t)
		assert.Eventually(t, func() bool {
			nv, ok := srv.State().GetNodeByID(r2ID)

			return ok && !nv.IsOnline().Get() && hasRoute(r2ID) && !hasRoute(r1ID)
		}, 20*time.Second, 200*time.Millisecond,
			"the last primary keeps the route while both routers are offline")

		// 3. Reconnect r2 (cable plugged back in).
		r2.Reconnect(t)

		// [tailcfg.Hostinfo] is part of the [controlclient.Direct] state; the [TestClient.Reconnect]
		// helper re-registers via [controlclient.Direct.TryLogin] which carries the same [tailcfg.Hostinfo]
		// that was set above. Push it again to be sure the announced route
		// is registered in the new session.
		advertise(r2, "ha3203-router2")

		// R1: server-side state must restore r2 as primary.
		assert.Eventually(t, func() bool { return hasRoute(r2ID) },
			15*time.Second, 200*time.Millisecond,
			"R1: r2 should be re-registered as primary after reconnect — issue #3203")

		// R2: observer must see r2 online with the route in its primary set.
		obs.WaitForCondition(t, "R2: observer sees r2 online with primary route",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if !hi.Valid() || hi.Hostname() != "ha3203-router2" {
						continue
					}

					online, known := p.Online().GetOk()
					if !known || !online {
						return false
					}

					for i := range p.PrimaryRoutes().Len() {
						if p.PrimaryRoutes().At(i) == route {
							return true
						}
					}
				}

				return false
			})
	})
}

// [findNodeID] is defined in issues_test.go.

// routeOverlapCompatTests lists captures whose routers announce addresses
// and prefixes of the tailnet's own range, approved by the policy's
// autoApprovers (t1–t3), an admin key (t4) or a devices:routes token (t5).
var routeOverlapCompatTests = []string{
	"routes-t1-auto-v4-default",
	"routes-t2-auto-v6-default",
	"routes-t3-auto-narrow-keys",
	"routes-t4-admin",
	"routes-t5-oauth-routes-scope",
}

// routeOverlapSkipReasons lists checks where headscale differs from SaaS,
// keyed <test_id>/<node>/<check>. A listed check that matches fails, so a fix
// must delete its entry.
var routeOverlapSkipReasons = map[string]string{}

// routeOverlapNotCompared lists, by key prefix, checks left out: SaaS's
// answer there is in doubt, so it is no reference.
var routeOverlapNotCompared = []string{
	"routes-t1-auto-v4-default/ovl-r-ctrl/peers",
	"routes-t1-auto-v4-default/ovl-r-host4/peers",
	"routes-t1-auto-v4-default/ovl-r-host6/peers",
	"routes-t1-auto-v4-default/ovl-r-mapped/peers",
	"routes-t1-auto-v4-default/ovl-r-narrow/peers",
	"routes-t1-auto-v4-default/ovl-r-via/peers",
	"routes-t1-auto-v4-default/ovl-r-wide-in/peers",
	"routes-t2-auto-v6-default/ovl-r-ctrl/peers",
	"routes-t2-auto-v6-default/ovl-r-host4/peers",
	"routes-t2-auto-v6-default/ovl-r-host6/peers",
	"routes-t2-auto-v6-default/ovl-r-mapped/peers",
	"routes-t2-auto-v6-default/ovl-r-narrow/peers",
	"routes-t2-auto-v6-default/ovl-r-via/peers",
	"routes-t3-auto-narrow-keys/ovl-r-ctrl/peer-routes",
	"routes-t3-auto-narrow-keys/ovl-r-ctrl/peers",
	"routes-t3-auto-narrow-keys/ovl-r-host4/peers",
	"routes-t3-auto-narrow-keys/ovl-r-host6/peers",
	"routes-t3-auto-narrow-keys/ovl-r-mapped/peer-routes",
	"routes-t3-auto-narrow-keys/ovl-r-mapped/peers",
	"routes-t3-auto-narrow-keys/ovl-r-narrow/peer-routes",
	"routes-t3-auto-narrow-keys/ovl-r-narrow/peers",
	"routes-t3-auto-narrow-keys/ovl-r-via/peer-routes",
	"routes-t3-auto-narrow-keys/ovl-r-via/peers",
	"routes-t4-admin/ovl-r-ctrl/peer-routes",
	"routes-t4-admin/ovl-r-ctrl/peers",
	"routes-t4-admin/ovl-r-host4/peers",
	"routes-t4-admin/ovl-r-host6/peers",
	"routes-t4-admin/ovl-r-mapped/peer-routes",
	"routes-t4-admin/ovl-r-mapped/peers",
	"routes-t4-admin/ovl-r-narrow/peer-routes",
	"routes-t4-admin/ovl-r-narrow/peers",
	"routes-t4-admin/ovl-r-via/peer-routes",
	"routes-t4-admin/ovl-r-via/peers",
	"routes-t5-oauth-routes-scope/ovl-r-ctrl/peer-routes",
	"routes-t5-oauth-routes-scope/ovl-r-ctrl/peers",
	"routes-t5-oauth-routes-scope/ovl-r-host4/peers",
	"routes-t5-oauth-routes-scope/ovl-r-host6/peers",
	"routes-t5-oauth-routes-scope/ovl-r-mapped/peer-routes",
	"routes-t5-oauth-routes-scope/ovl-r-mapped/peers",
	"routes-t5-oauth-routes-scope/ovl-r-narrow/peer-routes",
	"routes-t5-oauth-routes-scope/ovl-r-narrow/peers",
	"routes-t5-oauth-routes-scope/ovl-r-via/peer-routes",
	"routes-t5-oauth-routes-scope/ovl-r-via/peers",
}

// TestRoutesTailnetOverlapCompat replays routers whose routes overlap the
// tailnet's addresses and compares approvals, served routes, peers and
// filters with SaaS. Headscale must hand out SaaS's addresses, so a route
// naming a node's address names the same node here and AllowedIPs compare
// literally.
//
// Test data source: ../policy/v2/testdata/routes_results/, shared with
// TestRoutesCompat* in policy/v2.
func TestRoutesTailnetOverlapCompat(t *testing.T) {
	t.Parallel()

	for _, id := range routeOverlapCompatTests {
		t.Run(id, func(t *testing.T) {
			t.Parallel()

			c, err := testcapture.Read(filepath.Join(
				"..", "policy", "v2", "testdata", "routes_results", id+".hujson",
			))
			require.NoError(t, err)

			srv, clients := startCaptureClients(t, c, routesSetByAPI(c))
			names := slices.Sorted(maps.Keys(clients))

			for _, name := range names {
				want, got := c.Captures[name].Netmap.SelfNode, clients[name].Netmap().SelfNode
				require.Equalf(t, prefixList(want.Addresses()), prefixList(got.Addresses()),
					"%s: addresses differ from SaaS, so routes would name other nodes", name)
			}

			saasAddrs := saasAddrsByNode(c, clients)

			// Each node's checks read only its own netmap and node, so the
			// holds run at once.
			var wg sync.WaitGroup

			for _, name := range names {
				wg.Go(func() {
					t.Run(name, func(t *testing.T) {
						key := id + "/" + name + "/"
						want := c.Captures[name].Netmap
						topo := c.Topology.Nodes[name]
						nodeID := findNodeID(t, srv, name)

						// Approvals and routes reach clients in batches; retry
						// the comparisons until they hold.
						requireNetmapHolds(t, func(t require.TestingT) {
							nm := clients[name].Netmap()

							if len(topo.RoutableIPs) > 0 {
								node, ok := srv.State().GetNodeByID(nodeID)
								require.True(t, ok)

								overlapCheck(t, key+"approved",
									sortedStrings(topo.ApprovedRoutes),
									sortedStrings(util.PrefixesToString(node.ApprovedRoutes().AsSlice())))
							}

							wantPeers, gotPeers := peerRoutes(want, clients), peerRoutes(nm, clients)
							overlapCheck(t, key+"peers",
								strings.Join(slices.Sorted(maps.Keys(wantPeers)), "\n"),
								strings.Join(slices.Sorted(maps.Keys(gotPeers)), "\n"))

							// Peers on one side only are the peers check's; here
							// only what both sides show is compared.
							var wantRoutes, gotRoutes []string

							for peer, routes := range wantPeers {
								if got, ok := gotPeers[peer]; ok {
									wantRoutes = append(wantRoutes, peer+": "+routes)
									gotRoutes = append(gotRoutes, peer+": "+got)
								}
							}

							overlapCheck(t, key+"peer-routes",
								strings.Join(slices.Sorted(slices.Values(wantRoutes)), "\n"),
								strings.Join(slices.Sorted(slices.Values(gotRoutes)), "\n"))

							comparePacketFilter(t, nm, c.Captures[name], clients, saasAddrs,
								key+"packet-filter", routeOverlapSkipReasons)

							overlapCheck(t, key+"self-primary",
								prefixList(want.SelfNode.PrimaryRoutes()), prefixList(nm.SelfNode.PrimaryRoutes()))
							overlapCheck(t, key+"self-allowed",
								selfAllowed(want.SelfNode), selfAllowed(nm.SelfNode))
						})
					})
				})
			}

			wg.Wait()
		})
	}
}

// routesSetByAPI reports whether the capture's routes were approved through
// the routes API rather than by the policy.
func routesSetByAPI(c *testcapture.Capture) bool {
	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if a.Kind == "api" && a.Method == http.MethodPost &&
				strings.HasSuffix(a.Path, "/routes") && a.Status == http.StatusOK {
				return true
			}
		}
	}

	return false
}

// overlapCheck compares one rendering of a check, honouring
// routeOverlapSkipReasons: a listed check must keep differing.
func overlapCheck(t require.TestingT, key, want, got string) {
	if notCompared(routeOverlapNotCompared, key) {
		return
	}

	reason, listed := routeOverlapSkipReasons[key]

	switch {
	case listed && want == got:
		t.Errorf("matches SaaS; delete routeOverlapSkipReasons[%q] (%s)", key, reason)
	case !listed:
		assert.Equalf(t, want, got, "%s", key)
	}
}

// notCompared reports whether key falls under one of prefixes.
func notCompared(prefixes []string, key string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool {
		return strings.HasPrefix(key, p)
	})
}

// peerRoutes maps each peer in clients to its AllowedIPs and PrimaryRoutes.
func peerRoutes(
	nm *netmap.NetworkMap,
	clients map[string]*servertest.TestClient,
) map[string]string {
	out := map[string]string{}

	for _, p := range nm.Peers {
		name := extractHostname(p.Name())
		if hi := p.Hostinfo(); hi.Valid() && hi.Hostname() != "" {
			name = hi.Hostname()
		}

		if _, ok := clients[name]; ok {
			out[name] = "allowed " + prefixList(p.AllowedIPs()) + " primary " + prefixList(p.PrimaryRoutes())
		}
	}

	return out
}

// selfAllowed is the node's AllowedIPs without its own addresses.
func selfAllowed(self tailcfg.NodeView) string {
	var out []netip.Prefix

	for _, pfx := range self.AllowedIPs().All() {
		if !views.SliceContains(self.Addresses(), pfx) {
			out = append(out, pfx)
		}
	}

	return prefixList(views.SliceOf(out))
}

func prefixList(pfxs views.Slice[netip.Prefix]) string {
	return sortedStrings(util.PrefixesToString(pfxs.AsSlice()))
}

func sortedStrings(s []string) string {
	return fmt.Sprint(slices.Sorted(slices.Values(s)))
}

// TestRoutesNodeRangeSingleNotServed checks that a router's approved single
// addresses inside the node ranges, in either spelling, reach no viewer
// through a plain grant or a via grant. They stay approved and in the
// router's own AllowedIPs, never in its PrimaryRoutes, and its wider route
// is still served.
func TestRoutesNodeRangeSingleNotServed(t *testing.T) {
	t.Parallel()

	subnet := netip.MustParsePrefix("10.9.0.0/24")
	singles := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.50/32"),
		netip.MustParsePrefix("fd7a:115c:a1e0::50/128"),
		netip.MustParsePrefix("::ffff:100.64.0.50/128"),
	}
	routes := append([]netip.Prefix{subnet}, singles...)

	for name, grant := range map[string]string{
		"plain": `{"src": ["tag:client"], "dst": ["*"], "ip": ["*"]}`,
		"via": `{"src": ["tag:client"], "ip": ["*"], "via": ["tag:router"],
			"dst": ["10.9.0.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "::ffff:0:0/96"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := servertest.NewServer(t)
			user := srv.CreateUser(t, "routes-user")

			changed, err := srv.State().SetPolicy([]byte(`{
				"tagOwners": {"tag:client": ["routes-user@"], "tag:router": ["routes-user@"]},
				"grants": [
					{"src": ["tag:client"], "dst": ["tag:router"], "ip": ["*"]},
					{"src": ["tag:router"], "dst": ["*"], "ip": ["*"]},
					` + grant + `
				]
			}`))
			require.NoError(t, err)

			if changed {
				err := srv.State().ReloadPolicy()
				require.NoError(t, err)
			}

			router := servertest.NewClient(t, srv, "router",
				servertest.WithUser(user), servertest.WithTags("tag:router"),
				servertest.WithHostinfo(&tailcfg.Hostinfo{
					BackendLogID: "servertest-router", Hostname: "router", RoutableIPs: routes,
				}))
			viewer := servertest.NewClient(t, srv, "viewer",
				servertest.WithUser(user), servertest.WithTags("tag:client"))

			viewer.WaitForPeers(t, 1, 15*time.Second)

			routerID := findNodeID(t, srv, "router")
			_, err = srv.State().SetApprovedRoutes(routerID, routes)
			require.NoError(t, err)

			viewer.WaitForCondition(t, "viewer is served the subnet", 15*time.Second,
				func(nm *netmap.NetworkMap) bool {
					p, ok := viewer.PeerByName("router")

					return ok && views.SliceContains(p.PrimaryRoutes(), subnet)
				})
			router.WaitForCondition(t, "router serves its subnet", 15*time.Second,
				func(nm *netmap.NetworkMap) bool {
					return views.SliceContains(nm.SelfNode.PrimaryRoutes(), subnet)
				})

			peer, _ := viewer.PeerByName("router")
			self := router.Netmap().SelfNode

			for _, single := range singles {
				assert.Falsef(t, views.SliceContains(peer.AllowedIPs(), single),
					"%s served in AllowedIPs", single)
				assert.Falsef(t, views.SliceContains(peer.PrimaryRoutes(), single),
					"%s served in PrimaryRoutes", single)
				assert.Truef(t, views.SliceContains(self.AllowedIPs(), single),
					"%s missing from the router's own AllowedIPs", single)
				assert.Falsef(t, views.SliceContains(self.PrimaryRoutes(), single),
					"%s in the router's own PrimaryRoutes", single)
			}

			node, ok := srv.State().GetNodeByID(routerID)
			require.True(t, ok)
			assert.ElementsMatch(t, routes, node.ApprovedRoutes().AsSlice())
		})
	}
}

// TestRoutesViaAppOnlyGrantFollowsPolicy checks that a via grant carrying
// only app capabilities moves the router's route in a viewer's AllowedIPs
// both ways. Such a grant compiles to no filter rule, so a recompile that
// adds or removes it leaves the filter unchanged; the route must still
// follow it, as a fresh map would.
func TestRoutesViaAppOnlyGrantFollowsPolicy(t *testing.T) {
	t.Parallel()

	subnet := netip.MustParsePrefix("10.9.0.0/24")

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "routes-user")

	setPolicy := func(viaApp bool) {
		t.Helper()

		grants := `{"src": ["tag:client"], "dst": ["tag:router"], "ip": ["*"]},
			{"src": ["tag:router"], "dst": ["*"], "ip": ["*"]}`
		if viaApp {
			grants += `, {"src": ["tag:client"], "dst": ["10.9.0.0/24"], "via": ["tag:router"],
				"app": {"example.com/cap/routes": [{}]}}`
		}

		changed, err := srv.State().SetPolicy([]byte(`{
			"tagOwners": {"tag:client": ["routes-user@"], "tag:router": ["routes-user@"]},
			"grants": [` + grants + `]
		}`))
		require.NoError(t, err)
		require.True(t, changed)
		require.NoError(t, srv.State().ReloadPolicy())
	}

	setPolicy(true)

	servertest.NewClient(t, srv, "router",
		servertest.WithUser(user), servertest.WithTags("tag:router"),
		servertest.WithHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-router", Hostname: "router", RoutableIPs: []netip.Prefix{subnet},
		}))
	viewer := servertest.NewClient(t, srv, "viewer",
		servertest.WithUser(user), servertest.WithTags("tag:client"))

	viewer.WaitForPeers(t, 1, 15*time.Second)

	routerID := findNodeID(t, srv, "router")
	_, err := srv.State().SetApprovedRoutes(routerID, []netip.Prefix{subnet})
	require.NoError(t, err)

	served := func(*netmap.NetworkMap) bool {
		p, ok := viewer.PeerByName("router")

		return ok && views.SliceContains(p.AllowedIPs(), subnet)
	}

	viewer.WaitForCondition(t, "app-only via grant serves the subnet", 15*time.Second, served)

	setPolicy(false)
	viewer.WaitForCondition(t, "removing the grant withdraws the subnet", 15*time.Second,
		func(nm *netmap.NetworkMap) bool { return !served(nm) })

	setPolicy(true)
	viewer.WaitForCondition(t, "restoring the grant serves the subnet again", 15*time.Second, served)
}

// TestAutoClientDelayedStreamKeepsLiteUpdate runs tailscaled's own control
// client against a stream request the network delays: the client restarts
// its stream, the request is held at the server, and meanwhile the client
// reports new routes in the lite update it sends by itself. The held
// stream then arrives carrying the Hostinfo from before the change. Streams
// are read-only (capver 68), so the node keeps the lite update's routes; a
// server applying stream payloads would roll them back.
func TestAutoClientDelayedStreamKeepsLiteUpdate(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "auto-router")
	route := netip.MustParsePrefix("10.77.0.0/16")

	var (
		holdNext          atomic.Bool
		held, release     = make(chan struct{}), make(chan struct{})
		liteUpdates       atomic.Int32
		streamsWithRoutes atomic.Int32
	)

	srv.App.SetBeforeMapRequestForTest(t, func(_ types.NodeID, req tailcfg.MapRequest) {
		if !req.Stream && req.OmitPeers {
			liteUpdates.Add(1)
		}

		if req.Stream && req.Hostinfo != nil && slices.Contains(req.Hostinfo.RoutableIPs, route) {
			streamsWithRoutes.Add(1)
		}

		if req.Stream && holdNext.CompareAndSwap(true, false) {
			close(held)
			<-release
		}
	})

	var netmaps atomic.Int32

	hi := &tailcfg.Hostinfo{BackendLogID: "servertest-auto-router", Hostname: "auto-router"}
	auto := servertest.NewAutoClient(t, srv, user, hi.Clone(), netmapCounter(func() { netmaps.Add(1) }))

	node := func() (types.NodeView, bool) {
		for _, nv := range srv.State().ListNodes().All() {
			if nv.Hostname() == "auto-router" {
				return nv, true
			}
		}

		return types.NodeView{}, false
	}
	online := func() bool {
		nv, ok := node()
		return ok && nv.IsOnline().Valid() && nv.IsOnline().Get()
	}

	require.Eventually(t, online, 10*time.Second, 10*time.Millisecond, "the client registers and streams")

	// Restart the stream and hold its request: it carries the Hostinfo
	// without the route.
	holdNext.Store(true)
	auto.SetPaused(true)
	auto.SetPaused(false)

	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("the client did not restart its stream")
	}

	before := liteUpdates.Load()
	withRoute := hi.Clone()
	withRoute.RoutableIPs = []netip.Prefix{route}
	auto.SetHostinfo(withRoute)

	require.Eventually(t, func() bool {
		nv, ok := node()
		return ok && slices.Contains(nv.AnnouncedRoutes(), route)
	}, 10*time.Second, 10*time.Millisecond, "the client's lite update reports the route")
	require.Greater(t, liteUpdates.Load(), before, "the route came in a lite update the client sent itself")

	// The held stream's first map is sent after its session connected, so
	// once the client has it, whatever the stream changed has landed.
	maps := netmaps.Load()

	close(release)
	require.Eventually(t, func() bool { return netmaps.Load() > maps }, 10*time.Second, 10*time.Millisecond,
		"the held stream delivers its map")

	nv, _ := node()
	assert.Contains(t, nv.AnnouncedRoutes(), route, "the stale stream rolled back the lite update")
	assert.Zero(t, streamsWithRoutes.Load(), "test sanity: only the lite update carried the route before release")
}

// netmapCounter is a [controlclient.Observer] calling seen for each
// network map the client receives.
type netmapCounter func()

func (seen netmapCounter) SetControlClientStatus(_ controlclient.Client, st controlclient.Status) {
	if st.NetMap != nil {
		seen()
	}
}

// TestStreamOnlyRouterStateConvergesOnLiteUpdate reconnects an HA router
// whose new routes, disco key and endpoints reach the server only through
// its streaming request and tailscaled's follow-up lite update, which race.
// Streams are read-only (capver 68), so the lite update alone must elect
// primaries and converge peers to what a fresh session sees.
func TestStreamOnlyRouterStateConvergesOnLiteUpdate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		streamFirst   bool
		primaryOnline bool
	}{
		{"stream_first/primary_online", true, true},
		{"lite_first/primary_online", false, true},
		{"stream_first/all_offline", true, false},
		{"lite_first/all_offline", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := servertest.NewServer(t)
			user := srv.CreateUser(t, "stream-only-user")
			route := netip.MustParsePrefix("10.77.0.0/24")

			r1 := servertest.NewClient(t, srv, "so-router1", servertest.WithUser(user))
			r2 := servertest.NewClient(t, srv, "so-router2", servertest.WithUser(user))
			obs := servertest.NewClient(t, srv, "so-observer", servertest.WithUser(user))
			obs.WaitForPeers(t, 2, 10*time.Second)

			advertiseRoutes(t, r1, []netip.Prefix{route})

			r1ID := findNodeID(t, srv, r1.Name)
			r2ID := findNodeID(t, srv, r2.Name)

			for _, id := range []types.NodeID{r1ID, r2ID} {
				_, err := srv.State().SetApprovedRoutes(id, []netip.Prefix{route})
				require.NoError(t, err)
			}

			primary := func(id types.NodeID) bool {
				return slices.Contains(srv.State().GetNodePrimaryRoutes(id), route)
			}
			online := func(id types.NodeID) bool {
				nv, ok := srv.State().GetNodeByID(id)
				if !ok {
					return false
				}

				on, known := nv.IsOnline().GetOk()

				return known && on
			}

			require.Eventually(t, func() bool { return primary(r1ID) }, 10*time.Second, 50*time.Millisecond)

			r2.Disconnect(t)

			if !tc.primaryOnline {
				r1.Disconnect(t)
			}

			require.Eventually(t, func() bool { return !online(r2ID) && online(r1ID) == tc.primaryOnline },
				20*time.Second, 100*time.Millisecond)

			// What tailscaled learns while its stream is down: Auto records
			// it in Direct and queues a lite update.
			disco := key.NewDisco().Public()
			endpoint := netip.MustParseAddrPort("192.0.2.77:41641")

			r2.Direct().SetHostinfo(&tailcfg.Hostinfo{
				BackendLogID: "servertest-" + r2.Name,
				Hostname:     r2.Name,
				RoutableIPs:  []netip.Prefix{route},
			})
			r2.Direct().SetDiscoPublicKey(disco)
			r2.Direct().SetEndpoints([]tailcfg.Endpoint{{Addr: endpoint, Type: tailcfg.EndpointExplicitConf}})

			liteUpdate := func() {
				t.Helper()

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				require.NoError(t, r2.Direct().SendUpdate(ctx))
			}
			restartStream := func() {
				t.Helper()

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				before := r2.UpdateCount()

				require.NoError(t, r2.RestartPoll(ctx))
				require.Eventually(t, func() bool { return online(r2ID) && r2.UpdateCount() > before },
					5*time.Second, 10*time.Millisecond, "r2's new stream connects and gets its initial map")
			}

			if tc.streamFirst {
				restartStream()

				nv, ok := srv.State().GetNodeByID(r2ID)
				require.True(t, ok)
				t.Logf("PROBE before lite: announced=%v newDisco=%v endpoints=%v primary(r1)=%v primary(r2)=%v",
					nv.AnnouncedRoutes(), nv.DiscoKey() == disco, nv.Endpoints().AsSlice(), primary(r1ID), primary(r2ID))

				liteUpdate()
			} else {
				liteUpdate()
				restartStream()
			}

			// The lite update's own write decides the election: no wait.
			nv, ok := srv.State().GetNodeByID(r2ID)
			require.True(t, ok)
			assert.Equal(t, []netip.Prefix{route}, nv.AnnouncedRoutes())
			assert.Equal(t, disco, nv.DiscoKey())
			assert.Equal(t, []netip.AddrPort{endpoint}, nv.Endpoints().AsSlice())
			assert.Equal(t, tc.primaryOnline, primary(r1ID), "HA keeps an online primary")
			assert.Equal(t, !tc.primaryOnline, primary(r2ID), "r2 is elected when no other router is online")

			obs.WaitForCondition(t, "observer sees r2's lite update", 5*time.Second,
				func(nm *netmap.NetworkMap) bool {
					p, ok := peerByHostname(nm, r2.Name)

					return ok && p.DiscoKey() == disco &&
						p.Hostinfo().RoutableIPs().Len() == 0 &&
						slices.Contains(p.Endpoints().AsSlice(), endpoint)
				})

			if tc.primaryOnline {
				// r2 must be eligible for failover without another update.
				r1.Disconnect(t)
				require.Eventually(t, func() bool { return primary(r2ID) && !primary(r1ID) },
					20*time.Second, 100*time.Millisecond, "r2 takes over from r1")
			}

			obs.WaitForCondition(t, "observer sees r2 as primary", 5*time.Second,
				func(nm *netmap.NetworkMap) bool {
					p, ok := peerByHostname(nm, r2.Name)

					return ok && slices.Contains(p.PrimaryRoutes().AsSlice(), route) &&
						slices.Contains(p.AllowedIPs().AsSlice(), route)
				})

			fresh := servertest.NewClient(t, srv, "so-fresh", servertest.WithUser(user))
			fresh.WaitForPeers(t, 3, 10*time.Second)

			want, ok := peerByHostname(fresh.Netmap(), r2.Name)
			require.True(t, ok)

			obs.WaitForCondition(t, "observer's r2 matches a fresh session's", 5*time.Second,
				func(nm *netmap.NetworkMap) bool {
					got, ok := peerByHostname(nm, r2.Name)

					return ok && peerStateEqual(got, want)
				})
		})
	}
}

// peerStateEqual compares the parts of a peer a reconnecting router reports
// or the server derives from its report.
func peerStateEqual(a, b tailcfg.NodeView) bool {
	return a.DiscoKey() == b.DiscoKey() &&
		slices.Equal(a.Endpoints().AsSlice(), b.Endpoints().AsSlice()) &&
		slices.Equal(a.AllowedIPs().AsSlice(), b.AllowedIPs().AsSlice()) &&
		slices.Equal(a.PrimaryRoutes().AsSlice(), b.PrimaryRoutes().AsSlice()) &&
		slices.Equal(a.Hostinfo().RoutableIPs().AsSlice(), b.Hostinfo().RoutableIPs().AsSlice()) &&
		a.Online().Get() == b.Online().Get()
}
