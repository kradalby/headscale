package mapper

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
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
				Proxied: true,
			},
		},
		{
			magicDNS: false,
			want: &tailcfg.DNSConfig{
				Domains: []string{"foobar.headscale.net"},
				Proxied: false,
			},
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

			baseDomain := "foobar.headscale.net"

			dnsConfigOrig := tailcfg.DNSConfig{
				Routes:  make(map[string][]*dnstype.Resolver),
				Domains: []string{baseDomain},
				Proxied: tt.magicDNS,
			}

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)

			got := generateDNSConfig(
				(&types.Config{
					TailcfgDNSConfig: &dnsConfigOrig,
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
		resolvers := make([]*dnstype.Resolver, len(addrs))
		for i, a := range addrs {
			resolvers[i] = &dnstype.Resolver{Addr: a}
		}

		return (&types.Config{
			TailcfgDNSConfig: &tailcfg.DNSConfig{
				Resolvers: resolvers,
			},
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

		want := "https://dns.nextdns.io/abc?device_ip=100.64.0.1&device_model=linux&device_name=node1"
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

		want := "https://dns.nextdns.io/override?device_ip=100.64.0.1&device_model=linux&device_name=node1"
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

// TestFullMapResponseSurvivesPeerWithInvalidData proves a single node with
// stored data that cannot be sent must not break map generation for its peers.
//
// A node whose stored GivenName is empty (ErrNodeHasNoGivenName) or yields an
// FQDN longer than MaxHostnameLength (ErrHostnameTooLong) makes GetFQDN, and
// therefore TailNode, return an error. Rendering used to abort the entire
// peer list on the first such error, so the map failed for every node that
// could see the bad peer; on the initial-connection path that
// surfaced as "PollNetMap: ... unexpected EOF" and the "Unable to connect to
// the Tailscale coordination server" health warning. A legacy DB row loads
// verbatim (NewState reads db.ListNodes() without re-sanitising names), so
// the bad peer persists across restart. The build for an unaffected viewer
// must succeed: the bad peer is dropped, valid peers and self survive.
//
// A key expiry outside the years [0,9999] in UTC is the same class, caught
// later: TailNode sends it in UTC and json.Marshal refuses it.
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
				PrefixV4:     &p4,
				PrefixV6:     &p6,
				IPAllocation: types.IPAllocationStrategySequential,
				BaseDomain:   "headscale.test",
				Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
				DERP: types.DERPConfig{
					DERPMap: &tailcfg.DERPMap{
						Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
					},
				},
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

	cfg := &types.Config{
		TailcfgDNSConfig: &tailcfg.DNSConfig{
			Resolvers: []*dnstype.Resolver{{Addr: "https://dns.nextdns.io/abc"}},
		},
	}

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
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
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
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
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
	}}, func(string) (any, bool) { return nil, false })
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

			cfg := &types.Config{
				BaseDomain:   baseDomain,
				DNSConfig:    tt.dns,
				DNSChallenge: types.DNSChallengeConfig{Provider: tt.provider},
				TailcfgDNSConfig: &tailcfg.DNSConfig{
					Proxied: true,
					ExtraRecords: []tailcfg.DNSRecord{
						{Name: "Grafana.ts.example.com", Type: "A", Value: "100.64.0.3"},
						{Name: "grafana.svc.ts.example.com.", Type: "A", Value: "100.64.0.4"},
					},
				},
			}

			got := generateDNSConfig(cfg.DNSView(), tt.node.View(), nil)
			assert.Equal(t, tt.want, got.CertDomains)
			assert.Nil(t, cfg.TailcfgDNSConfig.CertDomains, "global DNS config must stay untouched")
		})
	}
}
