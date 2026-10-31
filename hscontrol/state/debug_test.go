package state

import (
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
		authCache: expirable.NewLRU[types.AuthID, *types.AuthRequest](
			defaultRegisterCacheMaxEntries, nil, time.Minute),
	}
	s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest())

	info := s.DebugRegistrationCache()

	assert.Equal(t, "expirable-lru", info["type"])
	assert.Equal(t, defaultRegisterCacheMaxEntries, info["max_entries"])
	assert.Equal(t, 1, info["current_len"])
}

func TestDebugConfigExtraRecordsSnapshot(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{}
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	records := []tailcfg.DNSRecord{{Name: "service.example.com", Type: "A", Value: "100.64.0.99"}}
	s.SetExtraRecords(records)
	before := s.DebugConfig()
	s.SetExtraRecords(nil)

	assert.Equal(t, records, before.TailcfgDNSConfig.ExtraRecords)
	assert.Empty(t, s.DebugConfig().TailcfgDNSConfig.ExtraRecords)
}

// The startup config dump serves the frozen DNS view, so it must carry the
// MagicDNS reverse routes the served maps carry.
func TestDebugConfigReverseRoutes(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{Proxied: true}
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	out := s.DebugConfig()
	require.NotNil(t, out.TailcfgDNSConfig)

	for _, zone := range []string{"64.100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"} {
		resolvers, ok := out.TailcfgDNSConfig.Routes[zone]
		assert.True(t, ok, zone)
		assert.NotNil(t, resolvers, zone)
		assert.Empty(t, resolvers, zone)
	}
}

func TestDebugConfigDNSOwnsStartupSettings(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.BaseDomain = "headscale.test"
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
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{
		Domains:      []string{"headscale.test"},
		ExtraRecords: []tailcfg.DNSRecord{{Name: "svc.example.com", Value: "100.64.0.9"}},
	}
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	cfg.BaseDomain = "changed.test"
	cfg.DNSConfig.BaseDomain = "changed.test"
	cfg.DNSConfig.Certificates.Enabled = false
	cfg.DNSConfig.ExtraRecordsPath = "changed.json"
	cfg.DNSConfig.Nameservers.Global[0] = "9.9.9.9"
	cfg.DNSConfig.Nameservers.Split["split.test"][0] = "9.9.9.10"
	cfg.DNSConfig.SearchDomains[0] = "changed.test"
	cfg.TailcfgDNSConfig.Domains[0] = "changed.test"

	check := func() *types.Config {
		out := s.DebugConfig()
		assert.Equal(t, "headscale.test", out.BaseDomain)
		assert.Equal(t, "headscale.test", out.DNSConfig.BaseDomain)
		assert.True(t, out.DNSConfig.Certificates.Enabled)
		assert.Equal(t, "original.json", out.DNSConfig.ExtraRecordsPath)
		assert.Equal(t, []string{"1.1.1.1"}, out.DNSConfig.Nameservers.Global)
		assert.Equal(t, []string{"1.0.0.1"}, out.DNSConfig.Nameservers.Split["split.test"])
		assert.Equal(t, []string{"search.test"}, out.DNSConfig.SearchDomains)
		assert.Equal(t, []string{"headscale.test"}, out.TailcfgDNSConfig.Domains)
		assert.Equal(t, []tailcfg.DNSRecord{{Name: "svc.example.com", Value: "100.64.0.9"}}, out.DNSConfig.ExtraRecords)
		assert.Equal(t, []tailcfg.DNSRecord{{Name: "svc.example.com", Value: "100.64.0.9"}}, out.TailcfgDNSConfig.ExtraRecords)

		return out
	}
	out := check()
	out.DNSConfig.Nameservers.Global[0] = "8.8.8.8"
	out.DNSConfig.Nameservers.Split["split.test"][0] = "8.8.4.4"
	out.DNSConfig.SearchDomains[0] = "output.test"
	out.TailcfgDNSConfig.Domains[0] = "output.test"
	out.DNSConfig.ExtraRecords[0].Value = "9.9.9.9"
	out.TailcfgDNSConfig.ExtraRecords[0].Value = "9.9.9.9"

	check()
}
