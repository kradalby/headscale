package types

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
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

	cfg := &Config{TailcfgDNSConfig: &tailcfg.DNSConfig{ExtraRecords: slices.Clone(records)}}
	boot := cfg.DNSView()

	slices.Reverse(records)
	assert.True(t, boot.Equal(boot.WithExtraRecords(records)),
		"a reordered publication of the boot records must be a no-op")
}
