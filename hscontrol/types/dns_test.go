package types

import (
	"encoding/json"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestDNSViewFromConfigIsCanonical pins that the boot view orders extra
// records as a publication of the same set does, so the first publish of
// a reordered set keeps the revision instead of waking every session.
func TestDNSViewFromConfigIsCanonical(t *testing.T) {
	records := []tailcfg.DNSRecord{
		{Name: "B.example.com", Type: "A", Value: "100.64.0.2"},
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
	}

	cfg := &Config{DNSConfig: DNSConfig{ExtraRecords: slices.Clone(records)}}
	boot := cfg.DNSView()
	assert.Equal(t, []tailcfg.DNSRecord{
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
		{Name: "b.example.com", Type: "A", Value: "100.64.0.2"},
	}, boot.ExtraRecords().AsSlice(), "snapshot records are lowercase and sorted in exact ascending order")

	slices.Reverse(records)
	assert.True(t, boot.Equal(boot.WithExtraRecords(records)),
		"a reordered publication of the boot records must be a no-op")
}

func TestDNSViewOwnsNestedChallengeMetadata(t *testing.T) {
	cfg := &Config{DNSConfig: DNSConfig{Challenge: DNSChallengeConfig{
		Resolvers: []string{"9.9.9.9:53"},
		ProviderSettings: map[string]any{
			"name": "acmedns", "secret": "private",
			"config": map[string]any{"node.example.com": map[string]any{"token": "original", "ports": []any{int64(53), map[string]any{"transport": "udp"}}}},
			"typed":  []map[string]string{{"token": "typed-original"}},
		},
	}}}
	view := cfg.DNSView()
	mutate := func(d *DNSConfig) {
		d.Challenge.Resolvers[0] = "changed"

		settings, ok := d.Challenge.ProviderSettings["config"].(map[string]any)
		if !assert.True(t, ok) {
			return
		}

		records, ok := settings["node.example.com"].(map[string]any)
		if !assert.True(t, ok) {
			return
		}

		records["token"] = "changed"

		ports, ok := records["ports"].([]any)
		if !assert.True(t, ok) {
			return
		}

		transport, ok := ports[1].(map[string]any)
		if !assert.True(t, ok) {
			return
		}

		transport["transport"] = "changed"

		typed, ok := d.Challenge.ProviderSettings["typed"].([]map[string]string)
		if !assert.True(t, ok) {
			return
		}

		typed[0]["token"] = "changed"
	}
	want := view.DebugConfig()

	mutate(&cfg.DNSConfig)
	assert.Equal(t, want, view.DebugConfig(), "the original builder cannot mutate snapshot diagnostic metadata")
	debug := view.DebugConfig()
	mutate(&debug)
	assert.Equal(t, want, view.DebugConfig(), "a returned debug copy cannot mutate snapshot metadata")
	// Debug consumers retain concrete numeric types and credential redaction.
	settings, ok := view.DebugConfig().Challenge.ProviderSettings["config"].(map[string]any)
	require.True(t, ok)
	record, ok := settings["node.example.com"].(map[string]any)
	require.True(t, ok)
	ports, ok := record["ports"].([]any)
	require.True(t, ok)
	assert.IsType(t, int64(0), ports[0])

	encoded, err := json.Marshal(Config{DNSConfig: view.DebugConfig()})
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "private")
	assert.NotContains(t, string(encoded), "original")

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				debugCopy := view.DebugConfig()
				mutate(&debugCopy)
				assert.Equal(t, want, view.DebugConfig())
			}
		})
	}

	wg.Wait()
}
