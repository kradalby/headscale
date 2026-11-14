package mapper

import (
	stdcmp "cmp"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/dns"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/views"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func TestExitNodeFilteredSet(t *testing.T) {
	tests := []struct {
		name       string
		magicDNS   bool
		baseDomain string
		want       []string
	}{
		{name: "magicdns", magicDNS: true, baseDomain: "Tail.Example.com", want: []string{".tail.example.com"}},
		{name: "no magicdns", magicDNS: false, baseDomain: "tail.example.com"},
		{name: "no base domain", magicDNS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateDNSConfig(
				(&types.Config{
					DNSConfig: types.DNSConfig{MagicDNS: tt.magicDNS, BaseDomain: tt.baseDomain},
				}).DNSView(),
				(&types.Node{}).View(),
				nil,
			)

			assert.Equal(t, tt.want, got.ExitNodeFilteredSet)
		})
	}
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{},
				Domains: []string{
					"foobar.headscale.net",
				},
				Proxied:             true,
				ExitNodeFilteredSet: []string{".foobar.headscale.net"},
			},
		},
		{
			// Only MagicDNS answers for the base domain.
			magicDNS: false,
			want:     &tailcfg.DNSConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("with-magicdns-%v", tt.magicDNS), func(t *testing.T) {
			mach := func(hostname, username string, userid uint) *types.Node {
				return &types.Node{
					Hostname: hostname,
					UserID:   new(userid),
					User: &types.User{
						Name: username,
					},
				}
			}

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)

			got := generateDNSConfig(
				(&types.Config{
					DNSConfig: types.DNSConfig{MagicDNS: tt.magicDNS, BaseDomain: "foobar.headscale.net"},
				}).DNSView(),
				nodeInShared1.View(),
				nil,
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNextDNSCapMapRendering(t *testing.T) {
	t.Parallel()

	mkConfig := func(addrs ...string) types.DNSView {
		return (&types.Config{
			DNSConfig: types.DNSConfig{OverrideLocalDNS: true, Nameservers: types.Nameservers{Global: addrs}},
		}).DNSView()
	}

	mkNode := func() types.NodeView {
		return (&types.Node{
			ID:       1,
			Hostname: "node1",
			IPv4:     iap("100.64.0.1"),
			Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
		}).View()
	}

	// resolverAddr extracts the first resolver's address with a
	// bounds check. Without it, a regression that drops the
	// resolver list would nil-panic instead of failing cleanly.
	resolverAddr := func(t *testing.T, got *tailcfg.DNSConfig) string {
		t.Helper()

		if got == nil {
			t.Fatalf("generateDNSConfig returned nil")
		}

		if len(got.Resolvers) == 0 {
			t.Fatalf("generateDNSConfig returned no Resolvers")
		}

		return got.Resolvers[0].Addr
	}

	t.Run("no_capmap_metadata_appended", func(t *testing.T) {
		t.Parallel()

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/abc"),
			mkNode(),
			nil,
		)

		want := "https://dns.nextdns.io/abc?device_id=1&device_ip=100.64.0.1&device_model=linux&device_name=node1"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("profile_overrides_global", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:override": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/global"),
			mkNode(),
			capMap,
		)

		want := "https://dns.nextdns.io/override?device_id=1&device_ip=100.64.0.1&device_model=linux&device_name=node1"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("no_device_info_skips_metadata", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:abc":            []tailcfg.RawMessage{},
			"nextdns:no-device-info": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/global"),
			mkNode(),
			capMap,
		)

		want := "https://dns.nextdns.io/abc"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("non_nextdns_resolver_untouched", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:abc": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.example.org/dns-query"),
			mkNode(),
			capMap,
		)

		want := "https://dns.example.org/dns-query"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("non-nextdns resolver was rewritten: %q", addr)
		}
	})
}

// nextDNSResolverSkipReasons lists checks where headscale's DoH address
// differs from SaaS, keyed <test_id>/<check>.
var nextDNSResolverSkipReasons = map[string]string{}

// TestNextDNSResolverCompat compares the NextDNS DoH address every node gets
// with what SaaS sent: the global profile, a per-node profile, and a
// malformed one, which SaaS skips. The captured self CapMap stands in for
// the policy, so only the resolver rewrite is compared.
//
// Test data source: ../policy/v2/testdata/nodeattrs_results/, shared with
// TestNodeAttrsCompat, which compares the same captures' CapMaps.
func TestNextDNSResolverCompat(t *testing.T) {
	t.Parallel()

	for _, id := range []string{
		"nodeattrs-nextdns-d10-resolver-default",
		"nodeattrs-nextdns-d11-resolver-profile",
		"nodeattrs-nextdns-d13-resolver-malformed",
	} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()

			c, err := testcapture.Read(filepath.Join(
				"..", "policy", "v2", "testdata", "nodeattrs_results", id+".hujson",
			))
			require.NoError(t, err)

			cfg := &types.Config{DNSConfig: types.DNSConfig{
				OverrideLocalDNS: true,
				Nameservers:      types.Nameservers{Global: c.Input.Tailnet.DNS.Nameservers},
			}}

			// Mismatches by check, one entry per node.
			diffs := map[string][]string{}

			for i, name := range slices.Sorted(maps.Keys(c.Captures)) {
				self := c.Captures[name].Netmap.SelfNode
				topo := c.Topology.Nodes[name]

				// The capture fleet runs tailscaled on Linux; the self
				// Hostinfo SaaS echoes back leaves the OS out.
				node := &types.Node{
					ID:       types.NodeID(i + 1), //nolint:gosec
					Hostname: topo.Hostname,
					IPv4:     iap(topo.IPv4),
					IPv6:     iap(topo.IPv6),
					Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
				}

				capMap := tailcfg.NodeCapMap{}
				for k, v := range self.CapMap().All() {
					capMap[k] = v.AsSlice()
				}

				got := generateDNSConfig(cfg.DNSView(), node.View(), capMap)
				want := c.Captures[name].Netmap.DNS.Resolvers

				wantAddr, wantQuery, wantID := splitDoHAddrs(t, want, self.StableID())
				gotAddr, gotQuery, gotID := splitDoHAddrs(t, got.Resolvers, node.ID.StableID())

				for check, diff := range map[string]string{
					"path":      cmp.Diff(wantAddr, gotAddr),
					"query":     cmp.Diff(wantQuery, gotQuery),
					"device_id": cmp.Diff(wantID, gotID),
				} {
					if diff != "" {
						diffs[check] = append(diffs[check], name+" (-tailscale +headscale):\n"+diff)
					}
				}
			}

			for _, check := range []string{"path", "query", "device_id"} {
				t.Run(check, func(t *testing.T) {
					key := id + "/" + check
					reason, listed := nextDNSResolverSkipReasons[key]

					switch {
					case listed && len(diffs[check]) == 0:
						t.Errorf("matches SaaS; delete the skip entry %q (%s)", key, reason)
					case listed:
						t.Skip(reason)
					case len(diffs[check]) > 0:
						t.Error(strings.Join(diffs[check], "\n"))
					}
				})
			}
		})
	}
}

// splitDoHAddrs returns each resolver's address without its query, the query
// without device_id, and device_id, read as "self" when it is selfID.
func splitDoHAddrs(
	t *testing.T,
	rs []*dnstype.Resolver,
	selfID tailcfg.StableNodeID,
) ([]string, []url.Values, []string) {
	t.Helper()

	addrs := make([]string, 0, len(rs))
	queries := make([]url.Values, 0, len(rs))
	ids := make([]string, 0, len(rs))

	for _, r := range rs {
		u, err := url.Parse(r.Addr)
		require.NoError(t, err)

		q := u.Query()

		id := q.Get("device_id")
		if id == string(selfID) {
			id = "self"
		}

		q.Del("device_id")

		u.RawQuery = ""

		addrs, queries, ids = append(addrs, u.String()), append(queries, q), append(ids, id)
	}

	return addrs, queries, ids
}

func TestFullMapResponseSurvivesPeerWithInvalidData(t *testing.T) {
	// Each expiry is in range in its own zone and out of range in UTC.
	west := time.FixedZone("", -(23*60+59)*60)
	east := time.FixedZone("", (23*60+59)*60)

	for _, tt := range []struct {
		name   string
		column string
		value  any
	}{
		{"empty given name", "given_name", ""},
		{
			"over-long fqdn", "given_name",
			strings.Repeat("a", types.MaxHostnameLength+1),
		},
		{
			"expiry after year 9999", "expiry",
			time.Date(9999, time.December, 31, 23, 59, 59, 0, west),
		},
		{
			"expiry before year 0", "expiry",
			time.Date(0, time.January, 1, 0, 0, 0, 0, east),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			p4 := netip.MustParsePrefix("100.64.0.0/10")
			p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
			cfg := &types.Config{
				Database: types.DatabaseConfig{
					Type:   types.DatabaseSqlite,
					Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
				},

				Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
				DERP: types.DERPConfig{
					DERPMap: &tailcfg.DERPMap{
						Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
					},
				}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
			}

			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			user := database.CreateUserForTest("u1")
			n1 := database.CreateRegisteredNodeForTest(user, "n1")     // viewer, valid
			bad := database.CreateRegisteredNodeForTest(user, "bad")   // peer, bad data
			good := database.CreateRegisteredNodeForTest(user, "good") // peer, valid control

			// Simulate a legacy/corrupt row that v29 loads verbatim.
			require.NoError(t, database.DB.
				Model(&types.Node{}).
				Where("id = ?", bad.ID).
				Update(tt.column, tt.value).Error)
			require.NoError(t, database.Close())

			s, err := state.NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			// Allow-all so n1 sees both peers; the bad one must still be dropped.
			_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
			require.NoError(t, err)

			resps, err := NewStream(cfg, NewHub(), n1.ID, capVer).Initial(s.Snapshot())
			require.NoError(t, err,
				"n1's map must build despite a peer with invalid data")

			resp := resps[0]
			require.NotNil(t, resp.Node, "n1 must receive its own self node")

			_, err = json.Marshal(resp)
			require.NoError(t, err,
				"n1's map must encode despite a peer with invalid data")

			peers := map[tailcfg.NodeID]bool{}
			for _, p := range resp.Peers {
				peers[p.ID] = true
			}

			assert.False(t, peers[bad.ID.NodeID()],
				"the peer with invalid data must be dropped")
			assert.True(t, peers[good.ID.NodeID()], "valid peers must remain in the map")
		})
	}
}

// TestGenerateDNSConfigNilHostinfoNoPanic proves generateDNSConfig does not
// panic when a node's Hostinfo is nil (e.g. a legacy DB row with a NULL
// host_info column). addNextDNSMetadata dereferenced node.Hostinfo().OS()
// without the .Valid() guard its siblings (RequestTags, TailNode) apply, so
// building such a node's map crashed the server whenever a NextDNS resolver
// was configured.
func TestGenerateDNSConfigNilHostinfoNoPanic(t *testing.T) {
	node := (&types.Node{
		Hostname: "legacy-node",
		IPv4:     iap("100.64.0.1"),
		// Hostinfo intentionally nil, as a legacy NULL host_info row loads.
	}).View()

	cfg := &types.Config{DNSConfig: types.DNSConfig{
		OverrideLocalDNS: true,
		Nameservers:      types.Nameservers{Global: []string{"https://dns.nextdns.io/abc"}},
	}}

	require.NotPanics(t, func() {
		generateDNSConfig(cfg.DNSView(), node, nil)
	}, "generateDNSConfig must not panic when a node has nil Hostinfo")
}

// policyShapes covers the paths that decide which peers the mapper sends: a
// global filter with matchers, a per-node (autogroup:self) filter, a policy
// that leaves every node with zero matchers, and no rules at all. The
// zero-matcher shape is the interesting one: it must hide every peer, not
// fall open to "no matchers => all visible".
var policyShapes = []struct {
	name   string
	policy string
}{
	{
		name:   "allow all",
		policy: `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	},
	{name: "user isolation", policy: ownUserOnly},
	{
		name:   "autogroup self",
		policy: `{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
	},
	{
		name:   "no rules",
		policy: `{"acls":[]}`,
	},
	{
		name:   "empty policy",
		policy: `{}`,
	},
}

// assertSelfNotAPeer fails when a [tailcfg.MapResponse] addressed to nodeID
// mentions nodeID in any peer-carrying field.
//
// The Tailscale client merges [tailcfg.MapResponse.PeersChanged] straight into
// its peer map (controlclient updatePeersStateFromResponse) and keeps the self
// node in a separate field, so a node present in its own peer list is rendered
// twice by clients that concatenate peers with self.
func assertSelfNotAPeer(t *testing.T, nodeID types.NodeID, resp *tailcfg.MapResponse, what string) {
	t.Helper()

	if resp == nil {
		return
	}

	self := nodeID.NodeID()

	for _, p := range resp.Peers {
		assert.NotEqualf(t, self, p.ID, "%s: node %d listed in its own Peers", what, nodeID)
	}

	for _, p := range resp.PeersChanged {
		assert.NotEqualf(t, self, p.ID, "%s: node %d listed in its own PeersChanged", what, nodeID)
	}

	for _, p := range resp.PeersChangedPatch {
		assert.NotEqualf(t, self, p.NodeID, "%s: node %d patched in its own PeersChangedPatch", what, nodeID)
	}

	for _, id := range resp.PeersRemoved {
		assert.NotEqualf(t, self, id, "%s: node %d listed in its own PeersRemoved", what, nodeID)
	}
}

// TestMapResponseNeverContainsSelfAsPeer streams every node's map through
// connects, renames, expiry and policy changes under each policy shape, and
// asserts the recipient is never present in its own peer fields.
func TestMapResponseNeverContainsSelfAsPeer(t *testing.T) {
	for _, tt := range policyShapes {
		t.Run(tt.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, tt.policy)

			streams := make(map[types.NodeID]*Stream)

			for _, id := range ids {
				streams[id] = NewStream(cfg, NewHub(), id, capVer)
				resps, err := streams[id].Initial(s.Snapshot())
				require.NoError(t, err)

				for _, r := range resps {
					assertSelfNotAPeer(t, id, r, "initial")
				}
			}

			churn := []func(){
				func() { _ = s.Connect(ids[0]) },
				func() { _ = s.Connect(ids[2]) },
				func() { _, _ = s.RenameNode(ids[1], "renamed") },
				func() {
					expiry := time.Now().Add(-time.Minute)
					_, _ = s.SetNodeExpiry(ids[0], &expiry)
				},
				func() { _, _ = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)) },
			}

			for i, step := range churn {
				step()

				for id, st := range streams {
					resps, err := st.Update(s.Snapshot())
					require.NoError(t, err)

					for _, r := range resps {
						assertSelfNotAPeer(t, id, r, fmt.Sprintf("churn step %d", i))
					}
				}
			}
		})
	}
}

// TestBackfillNodeIPsReachesBackfilledNode proves the node that receives a
// backfilled address learns it too. Peers pick it up from the policy
// refresh, but that refresh carries no self node, so the node itself kept
// serving its old addresses until an unrelated self update.
func TestBackfillNodeIPsReachesBackfilledNode(t *testing.T) {
	tmp := t.TempDir()
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},

		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("u1")
	nodes := database.CreateRegisteredNodesForTest(user, 2, "bf")
	target := nodes[0].ID
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", target).Update("ipv6", nil).Error)
	// Backfill copies the stored Hostinfo, which a registered client always has.
	require.NoError(t, database.DB.Model(&types.Node{}).Where("1 = 1").Update("host_info", "{}").Error)
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	st := NewStream(cfg, NewHub(), target, capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)

	backfilled, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, backfilled)

	stored, ok := s.GetNodeByID(target)
	require.True(t, ok)
	require.True(t, stored.IPv6().Valid(), "backfill must assign an IPv6 address")

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	var self *tailcfg.Node

	for _, resp := range resps {
		if resp.Node != nil {
			self = resp.Node
		}
	}

	require.NotNil(t, self, "the backfilled node must receive its own node")
	assert.Contains(t, self.Addresses, netip.PrefixFrom(stored.IPv6().Get(), 128))
}

var errInjectedExpiry = errors.New("injected expiry failure")

// TestFailedExpiryOfPrimaryAnnouncesBackup expires the primary of an HA
// route while the database write fails. The NodeStore already moved the
// route to the backup, so the change returned with the error must still
// tell a client about the new primary, as the successful path does;
// otherwise the client drops the old primary's route with no replacement.
func TestFailedExpiryOfPrimaryAnnouncesBackup(t *testing.T) {
	tmp := t.TempDir()
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},

		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}

	route := netip.MustParsePrefix("10.77.0.0/24")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("u1")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "ha")

	for _, n := range nodes[:2] {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
		require.NoError(t, database.DB.Save(n).Error)
	}

	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	primary, backup, client := nodes[0].ID, nodes[1].ID, nodes[2].ID
	for _, id := range []types.NodeID{primary, backup, client} {
		s.Connect(id)
	}

	require.Equal(t, []netip.Prefix{route}, s.GetNodePrimaryRoutes(primary))

	st := NewStream(cfg, NewHub(), client, capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)

	require.NoError(t, s.DB().DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedExpiry)
			}
		}))
	t.Cleanup(func() { _ = s.DB().DB.Callback().Update().Remove("fail_node_update") })

	past := time.Now().Add(-time.Hour)
	_, err = s.SetNodeExpiry(primary, &past)
	require.ErrorIs(t, err, errInjectedExpiry)
	require.Equal(t, []netip.Prefix{route}, s.GetNodePrimaryRoutes(backup),
		"the NodeStore moved the route to the backup")

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	var backupRoutes []netip.Prefix

	for _, resp := range resps {
		for _, p := range append(resp.Peers, resp.PeersChanged...) {
			if p.ID == backup.NodeID() {
				backupRoutes = p.PrimaryRoutes
			}
		}
	}

	assert.Contains(t, backupRoutes, route, "the client must learn the backup is primary")
}

// TestGenerateMapResponseDebugOnlyOnFullMaps pins where [tailcfg.Debug] rides:
// on every full map (the initial map and FullUpdate renders), so a client that
// connects or reconnects is told to stop log uploads, and on nothing else. The
// renders run through [Stream], the path every session uses.
func TestGenerateMapResponseDebugOnlyOnFullMaps(t *testing.T) {
	for _, logTail := range []bool{false, true} {
		t.Run(fmt.Sprintf("logtail=%t", logTail), func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")
			cfg.LogTail.Enabled = logTail

			var want *tailcfg.Debug
			if !logTail {
				want = &tailcfg.Debug{DisableLogTail: true}
			}

			st := NewStream(cfg, NewHub(), ids[0], capVer)
			initial, err := st.Initial(s.Snapshot())
			require.NoError(t, err)
			assert.Equal(t, want, initial[0].Debug, "every full map carries it")

			changes := []func(){
				func() { _ = s.Connect(ids[2]) },
				func() { _, _ = s.RenameNode(ids[0], "n1-renamed") },
				func() { _, _ = s.SetPolicy([]byte(ownUserOnly)) },
				func() {
					s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}})
				},
			}

			for i, c := range changes {
				c()

				resps, err := st.Update(s.Snapshot())
				require.NoError(t, err)
				require.NotEmpty(t, resps, "change %d reaches n1", i)

				for _, r := range resps {
					assert.Nil(t, r.Debug, "change %d: only full maps carry it", i)
				}
			}
		})
	}
}

// TestCertDomains pins the name sent in DNSConfig.CertDomains: the
// client only runs `tailscale cert` for a name it finds there exactly,
// compared against its own MagicDNS name without the trailing dot.

func TestCertDomains(t *testing.T) {
	enabled := types.DNSConfig{Certificates: types.CertificatesConfig{Enabled: true}}

	acmeDNS, err := dns.NewProvider("acmedns", map[string]any{"config": map[string]any{
		"laptop.ts.example.com": map[string]any{
			"username":   "user",
			"password":   "pass",
			"subdomain":  "reg",
			"server_url": "https://auth.acme-dns.io",
		},
	}}, func(string) (any, bool) { return nil, false },
		func(_, v string) (string, error) { return v, nil })
	require.NoError(t, err)

	tests := []struct {
		name       string
		node       *types.Node
		dns        types.DNSConfig
		provider   dns.Provider
		baseDomain string
		want       []string
	}{
		{
			name:     "own acme-dns registration",
			node:     &types.Node{GivenName: "laptop"},
			dns:      enabled,
			provider: acmeDNS,
			want:     []string{"laptop.ts.example.com"},
		},
		{
			// Without a registration of its own, the node's challenge would
			// be answered from a record another name's challenge shares.
			name:     "no acme-dns registration of its own",
			node:     &types.Node{GivenName: "desktop"},
			dns:      enabled,
			provider: acmeDNS,
		},
		{
			name: "user owned",
			node: &types.Node{GivenName: "laptop", UserID: new(uint(1))},
			dns:  enabled,
			want: []string{"laptop.ts.example.com"},
		},
		{
			name: "tagged",
			node: &types.Node{GivenName: "server", Tags: []string{"tag:server"}},
			dns:  enabled,
			want: []string{"server.ts.example.com"},
		},
		{
			name: "disabled",
			node: &types.Node{GivenName: "laptop"},
		},
		{
			// The operator gave this name, in another case, to a service; a
			// node naming itself grafana must not get a certificate for it.
			name: "extra record name",
			node: &types.Node{GivenName: "grafana"},
			dns:  enabled,
		},
		{
			// A wildcard order for *.svc shares its challenge record with
			// svc, so svc must not get one covering grafana.svc.
			name: "extra record below name",
			node: &types.Node{GivenName: "svc"},
			dns:  enabled,
		},
		{
			name: "label suffix of extra record",
			node: &types.Node{GivenName: "fana"},
			dns:  enabled,
			want: []string{"fana.ts.example.com"},
		},
		{
			// Renames are lowercased now; an older mixed-case name could
			// share its challenge record with another node's name.
			name: "mixed case name",
			node: &types.Node{GivenName: "Laptop"},
			dns:  enabled,
		},
		{
			name:       "challenge name too long",
			node:       &types.Node{GivenName: strings.Repeat("a", 63)},
			dns:        enabled,
			baseDomain: strings.Repeat("b.", 87) + "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseDomain := tt.baseDomain
			if baseDomain == "" {
				baseDomain = "ts.example.com"
			}

			dnsCfg := tt.dns
			dnsCfg.MagicDNS = true
			dnsCfg.BaseDomain = baseDomain
			dnsCfg.ExtraRecords = []tailcfg.DNSRecord{
				{Name: "Grafana.ts.example.com", Type: "A", Value: "100.64.0.3"},
				{Name: "grafana.svc.ts.example.com.", Type: "A", Value: "100.64.0.4"},
			}

			cfg := &types.Config{DNSConfig: dnsCfg}
			cfg.StartDNS(tt.provider)

			got := generateDNSConfig(cfg.DNSView(), tt.node.View(), nil)
			assert.Equal(t, tt.want, got.CertDomains)
			assert.Nil(t, cfg.CloneTailcfgDNSConfig().CertDomains, "global DNS config must stay untouched")
		})
	}
}

// profileUserOriginal freezes the user profile helpers from 1096abfc8.
// This package cannot call the test-only originals in types.
type profileUserOriginal types.User

func (u *profileUserOriginal) StringID() string {
	if u == nil {
		return ""
	}

	return strconv.FormatUint(uint64(u.ID), 10)
}

func (u *profileUserOriginal) Username() string {
	return stdcmp.Or(
		u.Email,
		u.Name,
		u.ProviderIdentifier.String,
		u.StringID(),
	)
}

func (u *profileUserOriginal) Display() string {
	return stdcmp.Or(u.DisplayName, u.Username())
}

func (u *profileUserOriginal) TailscaleUserProfile() tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:            tailcfg.UserID(u.ID), //nolint:gosec // UserID is bounded
		LoginName:     u.Username(),
		DisplayName:   u.Display(),
		ProfilePicURL: u.ProfilePicURL,
	}
}

// userProfileOriginal reads the view without cloning or calling changed helpers.
func userProfileOriginal(view *types.UserView) tailcfg.UserProfile {
	u := profileUserOriginal{
		Model:              view.Model(),
		Name:               view.Name(),
		Email:              view.Email(),
		DisplayName:        view.DisplayName(),
		ProviderIdentifier: view.ProviderIdentifier(),
		ProfilePicURL:      view.ProfilePicURL(),
	}

	return u.TailscaleUserProfile()
}

// generateUserProfilesOriginal freezes 1096abfc8, including its profile helpers.
func generateUserProfilesOriginal(
	node types.NodeView,
	peers views.Slice[types.NodeView],
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.UserView)

	user := node.Owner()
	if !user.Valid() {
		log.Error().
			EmbedObject(node).
			Msg("node has no valid owner, skipping user profile generation")

		return nil
	}

	userMap[user.Model().ID] = &user

	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		if !peerUser.Valid() {
			continue
		}

		userMap[peerUser.Model().ID] = &peerUser
	}

	var profiles []tailcfg.UserProfile

	for _, id := range slices.Sorted(maps.Keys(userMap)) {
		profiles = append(profiles, userProfileOriginal(userMap[id]))
	}

	return profiles
}

// generateUserProfilesPointerMap freezes the map work but uses current name helpers,
// so map-only benchmarks do not include the frozen profile's view adapter.
func generateUserProfilesPointerMap(
	node types.NodeView,
	peers views.Slice[types.NodeView],
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.UserView)

	user := node.Owner()
	if !user.Valid() {
		log.Error().
			EmbedObject(node).
			Msg("node has no valid owner, skipping user profile generation")

		return nil
	}

	userMap[user.Model().ID] = &user

	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		if !peerUser.Valid() {
			continue
		}

		userMap[peerUser.Model().ID] = &peerUser
	}

	var profiles []tailcfg.UserProfile

	for _, id := range slices.Sorted(maps.Keys(userMap)) {
		profiles = append(profiles, userMap[id].TailscaleUserProfile())
	}

	return profiles
}

func checkUserProfilesOriginal(
	t *testing.T,
	node types.NodeView,
	peers views.Slice[types.NodeView],
) {
	t.Helper()

	want := generateUserProfilesOriginal(node, peers)
	require.Equal(t, want, profilesForFixture(node, peers))
	require.Equal(t, want, generateUserProfilesPointerMap(node, peers))
}

func TestGenerateUserProfilesMatchesOriginal(t *testing.T) {
	first := &types.User{
		ID: 7, Name: "first", DisplayName: "First",
		Email: "first@example.com", ProfilePicURL: "https://example.com/first",
	}
	last := &types.User{
		ID: 7, Name: "last", DisplayName: "Last",
		Email: "last@example.com", ProfilePicURL: "https://example.com/last",
	}
	other := &types.User{ID: 100}
	node := (&types.Node{ID: 1, UserID: new(first.ID), User: first}).View()
	duplicate := (&types.Node{ID: 2, UserID: new(last.ID), User: last}).View()
	peer := (&types.Node{ID: 3, UserID: new(other.ID), User: other}).View()
	orphan := (&types.Node{ID: 4}).View()
	missingUser := (&types.Node{ID: 5, UserID: new(first.ID)}).View()
	tagged := (&types.Node{ID: 6, Tags: []string{"tag:server"}}).View()
	taggedCreator := (&types.Node{
		ID: 7, Tags: []string{"tag:server"}, UserID: new(first.ID), User: first,
	}).View()
	zeroUser := (&types.Node{ID: 8, User: &types.User{}}).View()

	for _, tt := range []struct {
		name  string
		node  types.NodeView
		peers []types.NodeView
	}{
		{name: "nil_peers", node: node},
		{name: "empty_peers", node: node, peers: []types.NodeView{}},
		{name: "unowned_requester", node: orphan, peers: []types.NodeView{peer}},
		{name: "missing_requester_user", node: missingUser, peers: []types.NodeView{peer}},
		{name: "invalid_peer_after_unowned_requester", node: orphan, peers: []types.NodeView{{}}},
		{name: "invalid_owner_peers", node: node, peers: []types.NodeView{orphan, missingUser}},
		{name: "same_owner", node: node, peers: []types.NodeView{node, node, node}},
		{name: "last_peer_wins", node: node, peers: []types.NodeView{peer, node, duplicate}},
		{name: "reverse_duplicate_order", node: node, peers: []types.NodeView{duplicate, peer, node}},
		{name: "zero_id_and_no_user_id", node: zeroUser, peers: []types.NodeView{peer, node}},
		{name: "tagged_requester", node: tagged},
		{name: "tagged_requester_with_creator", node: taggedCreator},
		{name: "tagged_peers", node: node, peers: []types.NodeView{tagged, taggedCreator}},
		{
			name: "mixed_unsorted_owners", node: node,
			peers: []types.NodeView{taggedCreator, peer, orphan, zeroUser, tagged, duplicate},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkUserProfilesOriginal(t, tt.node, views.SliceOf(tt.peers))
		})
	}

	require.Equal(t, []tailcfg.UserProfile{
		{
			ID:            7,
			LoginName:     last.Email,
			DisplayName:   last.DisplayName,
			ProfilePicURL: last.ProfilePicURL,
		},
		{ID: 100, LoginName: "100", DisplayName: "100"},
	}, profilesForFixture(node, views.SliceOf([]types.NodeView{peer, node, duplicate})))
	require.Equal(t, []tailcfg.UserProfile{
		{
			ID:          types.TaggedDevicesUserID,
			LoginName:   "tagged-devices",
			DisplayName: "Tagged Devices",
		},
	}, profilesForFixture(taggedCreator, views.SliceOf([]types.NodeView{tagged})))
	require.Nil(t, profilesForFixture(orphan, views.SliceOf([]types.NodeView{peer})))

	for _, tt := range []struct {
		name  string
		node  types.NodeView
		peers []types.NodeView
	}{
		{name: "invalid_requester"},
		{name: "invalid_peer", node: node, peers: []types.NodeView{{}}},
		{name: "invalid_peer_after_valid", node: node, peers: []types.NodeView{peer, {}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			peers := views.SliceOf(tt.peers)

			require.Panics(t, func() { generateUserProfilesOriginal(tt.node, peers) })
			require.Panics(t, func() { profilesForFixture(tt.node, peers) })
			require.Panics(t, func() { generateUserProfilesPointerMap(tt.node, peers) })
			require.Panics(t, func() { profilesForFixture(tt.node, peers) })
		})
	}
}

func TestGenerateUserProfilesFallbacksMatchOriginal(t *testing.T) {
	for _, id := range []uint{0, 99, 100, 101, ^uint(0)} {
		for mask := range 32 {
			t.Run(fmt.Sprintf("ID=%d/fields=%02d", id, mask), func(t *testing.T) {
				u := &types.User{
					ID:                 id,
					ProfilePicURL:      "https://example.com/avatar",
					ProviderIdentifier: sql.NullString{Valid: mask&8 != 0},
				}

				if mask&1 != 0 {
					u.Email = "email@example.com"
				}

				if mask&2 != 0 {
					u.Name = "username"
				}

				if mask&4 != 0 {
					u.ProviderIdentifier.String = "https://issuer.example.com/subject"
				}

				if mask&16 != 0 {
					u.DisplayName = "Display Name"
				}

				node := (&types.Node{User: u}).View()
				checkUserProfilesOriginal(t, node, views.Slice[types.NodeView]{})

				tagged := (&types.Node{Tags: []string{"tag:server"}}).View()
				checkUserProfilesOriginal(
					t,
					tagged,
					views.SliceOf([]types.NodeView{node}),
				)
			})
		}
	}
}

func userProfilesFixture(
	peerCount, ownerCount int,
	names string,
) (types.NodeView, views.Slice[types.NodeView]) {
	users := make([]types.User, ownerCount)
	for i := range users {
		users[i].ID = uint(i + 1000)
		if names == "named" {
			users[i].Name = fmt.Sprintf("user-%d", i)
			users[i].Email = fmt.Sprintf("user-%d@example.com", i)
			users[i].DisplayName = fmt.Sprintf("User %d", i)
		}

		users[i].ProfilePicURL = "https://example.com/avatar"
	}

	peers := make([]types.NodeView, peerCount)
	for i := range peers {
		u := &users[i%ownerCount]
		peers[i] = (&types.Node{UserID: new(u.ID), User: u}).View()
	}

	return (&types.Node{UserID: new(users[0].ID), User: &users[0]}).View(), views.SliceOf(
		peers,
	)
}

func TestGenerateUserProfilesTailnetsMatchOriginal(t *testing.T) {
	for _, peerCount := range []int{8, 128, 1024, 8192} {
		for _, ownerCount := range []int{1, peerCount} {
			for _, names := range []string{"named", "numeric"} {
				t.Run(
					fmt.Sprintf("peers=%d/owners=%d/%s", peerCount, ownerCount, names),
					func(t *testing.T) {
						node, peers := userProfilesFixture(peerCount, ownerCount, names)
						checkUserProfilesOriginal(t, node, peers)
					},
				)
			}
		}
	}
}

func BenchmarkGenerateUserProfiles(b *testing.B) {
	for _, peerCount := range []int{8, 128, 1024, 8192} {
		for _, ownerCount := range []int{1, peerCount} {
			for _, names := range []string{"named", "numeric"} {
				b.Run(
					fmt.Sprintf("peers=%d/owners=%d/%s", peerCount, ownerCount, names),
					func(b *testing.B) {
						node, peers := userProfilesFixture(peerCount, ownerCount, names)
						require.Equal(
							b,
							generateUserProfilesOriginal(node, peers),
							profilesForFixture(node, peers),
						)
						require.Equal(
							b,
							generateUserProfilesPointerMap(node, peers),
							profilesForFixture(node, peers),
						)

						b.Run("frozen-original", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = generateUserProfilesOriginal(node, peers)
							}
						})
						b.Run("current", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = profilesForFixture(node, peers)
							}
						})
						b.Run("pointer-map", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = generateUserProfilesPointerMap(node, peers)
							}
						})
						b.Run("value-map", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = profilesForFixture(node, peers)
							}
						})
					},
				)
			}
		}
	}
}

// profilesForFixture exercises the graph's owner collector independently of
// node rendering, retaining legacy profile fallback and duplicate-owner cases.
func profilesForFixture(self types.NodeView, peers views.Slice[types.NodeView]) []tailcfg.UserProfile {
	owner := self.Owner()
	if !owner.Valid() {
		return nil
	}

	edit := newClassOwners().edit()
	edit.set(0, owner)

	for i, peer := range peers.All() {
		edit.set(tailcfg.NodeID(i+1), peer.Owner())
	}

	owners := edit.done()

	var out []tailcfg.UserProfile

	ids := profileIDs(owners.profiles)
	//nolint:gosec // Preserve unsigned ordering for the reference fixture's deliberately wrapped user IDs.
	slices.SortFunc(ids, func(a, b tailcfg.UserID) int { return stdcmp.Compare(uint64(a), uint64(b)) })

	for _, id := range ids {
		p, _ := owners.profiles.Get(id)
		out = append(out, p)
	}

	return out
}

// These rows retain the upstream builder event matrix through real snapshot
// edits; full refreshes are new streams, and live streams send wire deltas.
func TestGenerateMapResponseDebugEventMatrix(t *testing.T) {
	for _, logTail := range []bool{false, true} {
		for _, event := range []string{"full_update", "full_self", "user_removed", "self_update", "self_node_added", "policy_change", "derp_map", "dns_config", "peer_added", "peer_online"} {
			t.Run(fmt.Sprintf("logtail=%t/%s", logTail, event), func(t *testing.T) {
				cfg, s, ids := streamTestState(t, "", func(c *types.Config) { c.LogTail.Enabled = logTail })

				h := NewHub()
				defer h.Close()

				st := NewStream(cfg, h, ids[0], capVer)
				_, err := st.Initial(s.Snapshot())
				require.NoError(t, err)

				full := event == "full_update" || event == "full_self" || event == "user_removed"
				switch event {
				case "user_removed":
					owner := mustNode(t, s, ids[2]).User().ID()
					require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))
					require.NoError(t, s.DeleteUser(types.UserID(owner)))
				case "self_update", "self_node_added":
					_, err = s.RenameNode(ids[0], "self-event")
					require.NoError(t, err)
				case "policy_change":
					_, err = s.SetPolicy([]byte(ownUserOnly))
					require.NoError(t, err)
				case "derp_map":
					s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}})
				case "dns_config":
					s.SetExtraRecords([]tailcfg.DNSRecord{{Name: "service.headscale.test", Type: "A", Value: "100.64.0.99"}})
				case "peer_added":
					u := s.CreateUserForTest("new-owner")
					n := s.CreateRegisteredNodeForTest(u, "new-peer")
					n.User = u
					s.PutNodeInStoreForTest(*n)
				case "peer_online":
					s.Connect(ids[1])
				}

				var out []*tailcfg.MapResponse
				if full {
					out, err = NewStream(cfg, h, ids[0], capVer).Initial(s.Snapshot())
				} else {
					out, err = st.Update(s.Snapshot())
				}

				require.NoError(t, err)
				require.NotEmpty(t, out, "real event must reach the stream")

				for _, resp := range out {
					if full && resp.Node != nil && !logTail {
						require.Equal(t, &tailcfg.Debug{DisableLogTail: true}, resp.Debug)
					} else {
						require.Nil(t, resp.Debug)
					}
				}
			})
		}
	}
}

func TestMapResponseNeverContainsSelfAsPeerEventMatrix(t *testing.T) {
	for _, shape := range policyShapes {
		t.Run(shape.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, shape.policy)

			var streams []*Stream

			for _, id := range ids {
				st := NewStream(cfg, NewHub(), id, capVer)
				out, err := st.Initial(s.Snapshot())
				require.NoError(t, err)

				for _, resp := range out {
					assertSelfNotAPeer(t, id, resp, "full self/full update")
				}

				streams = append(streams, st)
			}

			generations := map[types.NodeID]uint64{}

			for _, event := range []string{"self added", "self online", "self offline", "reconnect", "all peers changed", "policy change"} {
				t.Run(event, func(t *testing.T) {
					for _, id := range ids {
						switch event {
						case "self added":
							_, err := s.RenameNode(id, fmt.Sprintf("renamed-%d", id))
							require.NoError(t, err)
						case "self online", "reconnect":
							generations[id] = s.Connect(id)
						case "self offline":
							require.NoError(t, s.Disconnect(id, generations[id]))
						case "all peers changed":
							n := mustNode(t, s, id).AsStruct()
							n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}
							s.PutNodeInStoreForTest(*n)
						}
					}

					if event == "policy change" {
						_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
						require.NoError(t, err)
					}

					for i, st := range streams {
						out, err := st.Update(s.Snapshot())
						require.NoError(t, err)

						for _, resp := range out {
							assertSelfNotAPeer(t, ids[i], resp, event)
						}
					}
				})
			}
		})
	}
}

func TestBuildFromChangeFiltersPeerPatchesByVisibility(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	s.Connect(ids[2])
	s.Connect(ids[1])
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.False(t, mentions(out, ids[2]))
	require.True(t, mentions(out, ids[1]), "visible sibling online patch survives filtering")
}

func TestBuildFromChangeFiltersUserProfilesByVisibility(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	hiddenUser := mustNode(t, s, ids[2]).User()
	for _, p := range initial[0].UserProfiles {
		require.NotEqual(t, hiddenUser.TailscaleUserProfile().ID, p.ID)
	}

	_, err = s.RenameUser(types.UserID(hiddenUser.ID()), "hidden-renamed")
	require.NoError(t, err)
	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["u1@"],"dst":["u1@:80"]},{"action":"accept","src":["hidden-renamed@"],"dst":["hidden-renamed@:*"]}]}`))
	require.NoError(t, err)
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, out, "policy effects still reach viewer while the changed user's node stays hidden")

	filters := false

	for _, resp := range out {
		if resp.PacketFilters != nil {
			filters = true
		}

		require.False(t, mentions([]*tailcfg.MapResponse{resp}, ids[2]))

		for _, p := range resp.UserProfiles {
			require.NotEqual(t, hiddenUser.TailscaleUserProfile().ID, p.ID)
		}
	}

	require.True(t, filters)
}

func TestBuildFromChangeVisibilityMatchesFullMap(t *testing.T) {
	for _, shape := range policyShapes {
		t.Run(shape.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, shape.policy)
			st := NewStream(cfg, NewHub(), ids[0], capVer)
			full, err := st.Initial(s.Snapshot())
			require.NoError(t, err)

			visible := peerSet(full[0])

			want := map[tailcfg.NodeID]bool{ids[1].NodeID(): true}
			if shape.name == "allow all" || shape.name == "empty policy" {
				want[ids[2].NodeID()] = true
			}

			require.Equal(t, want, visible, "full-map visibility must match independent policy expectations")

			for _, id := range ids[1:] {
				s.Connect(id)
			}

			out, err := st.Update(s.Snapshot())
			require.NoError(t, err)

			for _, id := range ids[1:] {
				require.Equal(t, visible[id.NodeID()], mentions(out, id), "online patches use full-map visibility")
			}

			for _, id := range ids[1:] {
				_, err := s.RenameNode(id, fmt.Sprintf("renamed-%d", id))
				require.NoError(t, err)
			}

			out, err = st.Update(s.Snapshot())
			require.NoError(t, err)

			for _, id := range ids[1:] {
				require.Equal(t, visible[id.NodeID()], mentions(out, id), "whole-peer updates use full-map visibility")
			}

			for _, resp := range out {
				for _, profile := range resp.UserProfiles {
					if profile.ID == mustNode(t, s, ids[2]).TailscaleUserID() {
						require.True(t, visible[ids[2].NodeID()])
					}
				}
			}

			_, err = s.SetPolicy([]byte(`{}`))
			require.NoError(t, err)
			out, err = st.Update(s.Snapshot())
			require.NoError(t, err)

			if !visible[ids[2].NodeID()] {
				require.True(t, mentions(out, ids[2]), "newly visible cross-user peer must be added")

				profileFound := false

				for _, resp := range out {
					for _, profile := range resp.UserProfiles {
						if profile.ID == mustNode(t, s, ids[2]).TailscaleUserID() {
							profileFound = true
						}
					}
				}

				require.True(t, profileFound, "new cross-user peer must carry its owner's profile")
			}

			owner := mustNode(t, s, ids[2]).User()
			_, err = s.RenameUser(types.UserID(owner.ID()), "positive-profile-control")
			require.NoError(t, err)
			out, err = st.Update(s.Snapshot())
			require.NoError(t, err)

			profileFound := false

			for _, resp := range out {
				for _, profile := range resp.UserProfiles {
					if profile.ID == owner.TailscaleUserProfile().ID {
						require.Equal(t, "positive-profile-control", profile.LoginName)

						profileFound = true
					}
				}
			}

			require.True(t, profileFound, "visible owner's changed profile must be delivered")
		})
	}
}

func TestBuildTailPeersCapMapsReference(t *testing.T) {
	for _, attrs := range []struct{ name, policy string }{
		{"empty", `[]`},
		{"partial", `[{"target":["100.64.0.2"],"attr":["disable-ipv4","suggest-exit-node"]}]`},
		{"all", `[{"target":["*"],"attr":["disable-ipv4","suggest-exit-node"]}]`},
	} {
		t.Run(attrs.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"nodeAttrs":`+attrs.policy+`}`)
			route := netip.MustParsePrefix("10.0.0.0/24")
			node := mustNode(t, s, ids[1]).AsStruct()
			node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			node.ApprovedRoutes = []netip.Prefix{route}
			s.PutNodeInStoreForTest(*node)
			s.Connect(ids[1])
			snap := s.Snapshot()
			viewer, _ := snap.GetNode(ids[0])
			caps := snap.Policy().NodeCapMaps()
			before, err := json.Marshal(caps)
			require.NoError(t, err)
			out, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(snap)
			require.NoError(t, err)
			matchers, err := snap.Policy().MatchersForNode(viewer)
			require.NoError(t, err)

			_, disable4 := caps[viewer.ID()][types.NodeAttrDisableIPv4]

			var want []*tailcfg.Node

			for _, peerID := range snap.ListPeerIDs(viewer.ID()) {
				peer, _ := snap.GetNode(peerID)
				tn, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return snap.RoutesForPeer(viewer, peer, matchers) }, cfg, snap.DNS(), caps[peerID])
				require.NoError(t, err)

				tn.CapMap = policyv2.PeerCapMap(peer, caps[peerID])
				tn.Hostinfo = types.PeerHostinfo(tn.Hostinfo)

				if disable4 {
					identity4 := func(p netip.Prefix) bool { return p.Addr().Is4() && slices.Contains(tn.Addresses, p) }
					tn.AllowedIPs = slices.DeleteFunc(tn.AllowedIPs, identity4)
					tn.Addresses = slices.DeleteFunc(tn.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() })
				}

				want = append(want, tn)
			}

			slices.SortFunc(want, func(a, b *tailcfg.Node) int { return stdcmp.Compare(a.ID, b.ID) })
			require.Equal(t, want, out[0].Peers, "shared graph peer renders match independent direct TailNode rendering")
			wire, err := Marshal(out[0])
			require.NoError(t, err)

			var decoded tailcfg.MapResponse
			require.NoError(t, json.Unmarshal(wire, &decoded))

			for _, peer := range decoded.Peers {
				if peer.CapMap != nil {
					peer.CapMap["caller-only"] = nil
					delete(peer.CapMap, nodecap.SuggestExitNode)
				}
			}

			after, err := json.Marshal(snap.Policy().NodeCapMaps())
			require.NoError(t, err)
			require.Equal(t, before, after)

			again, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(snap)
			require.NoError(t, err)
			require.Equal(t, want, again[0].Peers)
		})
	}
}

func TestInvalidPeerExpiryUpdateKeepsValidPeerUpdates(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	bad := mustNode(t, s, ids[1]).AsStruct()
	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	bad.Expiry = new(latest.Add(time.Second))
	s.PutNodeInStoreForTest(*bad)
	good := mustNode(t, s, ids[2]).AsStruct()
	good.Expiry = &latest
	good.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.3:1234")}
	s.PutNodeInStoreForTest(*good)
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, out)
	require.True(t, mentions(out, ids[2]), "valid peer's update must survive a corrupt sibling expiry")

	removed := false

	for _, resp := range out {
		encoded, err := Marshal(resp)
		require.NoError(t, err)

		var decoded tailcfg.MapResponse
		require.NoError(t, json.Unmarshal(encoded, &decoded))

		if slices.Contains(decoded.PeersRemoved, ids[1].NodeID()) {
			removed = true
		}

		for _, p := range append(decoded.Peers, decoded.PeersChanged...) {
			require.NotEqual(t, ids[1].NodeID(), p.ID)
		}

		for _, p := range decoded.PeersChangedPatch {
			require.NotEqual(t, ids[1].NodeID(), p.NodeID)
		}
	}

	require.True(t, removed, "previously visible corrupt peer must leave client state")

	valid, ok := st.sent.peer(ids[2].NodeID())
	require.True(t, ok)
	require.Equal(t, latest, valid.KeyExpiry)
	require.Equal(t, []netip.AddrPort(good.Endpoints), valid.Endpoints)
}
