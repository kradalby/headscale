package state

import (
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestDebugNodeStore(t *testing.T) {
	tests := []struct {
		name     string
		nodes    []types.Node
		contains []string
	}{
		{
			name: "empty",
			contains: []string{
				"=== Node State Debug Information ===",
				"Total Nodes: 0",
				"Users with Nodes: 0",
			},
		},
		{
			name: "with data",
			nodes: []types.Node{
				createTestNode(1, 1, "user1", "node1"),
				createTestNode(2, 2, "user2", "node2"),
			},
			contains: []string{
				"Total Nodes: 2",
				"Users with Nodes: 2",
				"Peer Relationships:",
				"Node 1 (node1): 1 peers",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{world: newTestWorld(t, tt.nodes...)}

			debugStr := s.DebugNodeStore()

			for _, expected := range tt.contains {
				assert.Contains(t, debugStr, expected,
					"Debug string should contain: %s\nActual debug:\n%s", expected, debugStr)
			}
		})
	}
}

func TestDebugRegistrationCache(t *testing.T) {
	s := &State{
		authCacheMaxEntries: defaultRegisterCacheMaxEntries,
		authCacheExpiration: time.Minute,
		authCache: expirable.NewLRU[types.AuthID, *types.AuthRequest](
			defaultRegisterCacheMaxEntries, nil, time.Minute),
	}
	t.Cleanup(s.authCache.Close)
	require.NoError(t, s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest()))

	info := s.DebugRegistrationCache()

	assert.Equal(t, "expirable-lru", info["type"])
	assert.Equal(t, time.Minute.String(), info["expiration"])
	assert.Equal(t, defaultRegisterCacheMaxEntries, info["max_entries"])
	assert.Equal(t, 1, info["current_len"])

	for _, tt := range []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{name: "configured", set: 20 * time.Minute, want: 20 * time.Minute},
		{name: "zero is the default", set: 0, want: 15 * time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := persistTestConfig(t.TempDir() + "/headscale.db")
			cfg.Tuning.RegisterCacheExpiration = tt.set
			state, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, state.Close()) })
			assert.Equal(t, tt.want.String(), state.DebugRegistrationCache()["expiration"])

			cfg.Tuning.RegisterCacheExpiration = time.Hour

			assert.Equal(t, tt.want.String(), state.DebugRegistrationCache()["expiration"], "diagnostics report the captured cache TTL")
		})
	}
}

func TestDebugConfigExtraRecordsSnapshot(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.DNSConfig.MagicDNS = false
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	records := []tailcfg.DNSRecord{{Name: "service.example.com", Type: "A", Value: "100.64.0.99"}}
	s.SetExtraRecords(records)
	before := s.DebugConfig()
	s.SetExtraRecords(nil)

	assert.Equal(t, records, before.TailcfgDNSConfig().ExtraRecords)
	assert.Empty(t, s.DebugConfig().TailcfgDNSConfig().ExtraRecords)
}

// The startup config dump serves the frozen DNS view, so it must carry the
// MagicDNS reverse routes the served maps carry.
func TestDebugConfigReverseRoutes(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.DNSConfig.MagicDNS = true
	customV4 := netip.MustParsePrefix("10.0.0.0/8")
	customV6 := netip.MustParsePrefix("fd00::/48")
	cfg.Prefixes.V4 = &customV4
	cfg.Prefixes.V6 = &customV6
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	out := s.DebugConfig()
	require.NotNil(t, out.TailcfgDNSConfig())

	for _, zone := range []string{"10.in-addr.arpa", "0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"} {
		resolvers, ok := out.TailcfgDNSConfig().Routes[zone]
		assert.True(t, ok, zone)
		assert.NotNil(t, resolvers, zone)
		assert.Empty(t, resolvers, zone)
	}
}

func TestDebugConfigDNSOwnsStartupSettings(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.DNSConfig.BaseDomain = "headscale.test"
	cfg.DNSConfig = types.DNSConfig{
		BaseDomain:       "headscale.test",
		Certificates:     types.CertificatesConfig{Enabled: true},
		ExtraRecordsPath: "original.json",
		Nameservers: types.Nameservers{
			Global: []string{"1.1.1.1"},
			Split:  map[string][]string{"split.test": {"1.0.0.1"}},
		},
		SearchDomains: []string{"search.test"},
	}
	cfg.DNSConfig.MagicDNS = true
	cfg.DNSConfig.ExtraRecords = []tailcfg.DNSRecord{{Name: "svc.example.com", Value: "100.64.0.9"}}
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	cfg.DNSConfig.BaseDomain = "changed.test"
	cfg.DNSConfig.BaseDomain = "changed.test"
	cfg.DNSConfig.Certificates.Enabled = false
	cfg.DNSConfig.ExtraRecordsPath = "changed.json"
	cfg.DNSConfig.Nameservers.Global[0] = "9.9.9.9"
	cfg.DNSConfig.Nameservers.Split["split.test"][0] = "9.9.9.10"
	cfg.DNSConfig.SearchDomains[0] = "changed.test"
	cfg.TailcfgDNSConfig().Domains[0] = "changed.test"

	check := func() *types.Config {
		out := s.DebugConfig()
		assert.Equal(t, "headscale.test", out.DNSConfig.BaseDomain)
		assert.Equal(t, "headscale.test", out.DNSConfig.BaseDomain)
		assert.True(t, out.DNSConfig.Certificates.Enabled)
		assert.Equal(t, "original.json", out.DNSConfig.ExtraRecordsPath)
		assert.Equal(t, []string{"1.1.1.1"}, out.DNSConfig.Nameservers.Global)
		assert.Equal(t, []string{"1.0.0.1"}, out.DNSConfig.Nameservers.Split["split.test"])
		assert.Equal(t, []string{"search.test"}, out.DNSConfig.SearchDomains)
		assert.Equal(t, []string{"headscale.test", "search.test"}, out.TailcfgDNSConfig().Domains)
		assert.Equal(t, []tailcfg.DNSRecord{{Name: "svc.example.com", Value: "100.64.0.9"}}, out.DNSConfig.ExtraRecords)
		assert.Equal(t, []tailcfg.DNSRecord{{Name: "svc.example.com", Value: "100.64.0.9"}}, out.TailcfgDNSConfig().ExtraRecords)

		return out
	}
	out := check()
	out.DNSConfig.Nameservers.Global[0] = "8.8.8.8"
	out.DNSConfig.Nameservers.Split["split.test"][0] = "8.8.4.4"
	out.DNSConfig.SearchDomains[0] = "output.test"
	out.TailcfgDNSConfig().Domains[0] = "output.test"
	out.DNSConfig.ExtraRecords[0].Value = "9.9.9.9"
	out.TailcfgDNSConfig().ExtraRecords[0].Value = "9.9.9.9"

	check()
}
