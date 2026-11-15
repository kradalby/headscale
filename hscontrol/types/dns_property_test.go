package types_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/internal/propcheck"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

func TestDNSRecordsReference(t *testing.T) {
	records := []tailcfg.DNSRecord{
		{Name: "B.example.com", Type: "A", Value: "100.64.0.2"},
		{Name: "a.example.com", Type: "AAAA", Value: "fd7a:115c:a1e0::1"},
		{Name: "A.example.com", Type: "A", Value: "100.64.0.2"},
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
		{Name: "A.example.com", Type: "A", Value: "100.64.0.1"},
		{Name: "a.example.com.", Type: "A", Value: "100.64.0.1"},
	}
	before := slices.Clone(records)
	want := []tailcfg.DNSRecord{
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
		{Name: "a.example.com", Type: "A", Value: "100.64.0.1"},
		{Name: "a.example.com", Type: "A", Value: "100.64.0.2"},
		{Name: "a.example.com", Type: "AAAA", Value: "fd7a:115c:a1e0::1"},
		{Name: "a.example.com.", Type: "A", Value: "100.64.0.1"},
		{Name: "b.example.com", Type: "A", Value: "100.64.0.2"},
	}
	got := propcheck.CanonicalDNSRecords(records)
	require.Equal(t, want, got)
	require.Equal(t, before, records)

	got[0].Name = "changed.invalid"

	require.Equal(t, before, records)
	require.Nil(t, propcheck.CanonicalDNSRecords(nil))
	require.Nil(t, propcheck.CanonicalDNSRecords([]tailcfg.DNSRecord{}))
}

func TestDNSViewPropertyZero(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var zero types.DNSView

		records := propcheck.DrawDNSRecords(t)
		view := zero.WithExtraRecords(records)
		require.True(t, slices.Equal(propcheck.CanonicalDNSRecords(records), view.ExtraRecords().AsSlice()))
		require.Nil(t, view.AsStruct())
		require.Equal(t, types.DNSConfig{}, view.DebugConfig())
		require.Empty(t, view.BaseDomain())
		require.Empty(t, view.ExtraRecordsPath())
		require.False(t, view.CertificatesEnabled())
		require.Empty(t, zero.ExtraRecords().AsSlice())
		require.True(t, zero.Equal(view.WithExtraRecords(nil)))
		require.True(t, zero.Equal(view.WithExtraRecords([]tailcfg.DNSRecord{})))
	})
}

func TestDNSViewPropertyRevisions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		initial := propcheck.DrawDNSRecords(t)
		cfg := &types.Config{DNSConfig: types.DNSConfig{ExtraRecords: slices.Clone(initial)}}
		view := cfg.DNSView()
		model := propcheck.CanonicalDNSRecords(initial)

		var (
			history []types.DNSView
			models  [][]tailcfg.DNSRecord
		)

		publish := func(records []tailcfg.DNSRecord) {
			t.Helper()

			before := slices.Clone(records)
			want := propcheck.CanonicalDNSRecords(records)
			next := view.WithExtraRecords(records)
			require.Equal(t, before, records, "publication must not sort or lowercase caller storage")
			require.Equal(t, slices.Equal(model, want), view.Equal(next), "equality must reflect record changes")
			require.Equal(t, view.Equal(next), next.Equal(view), "equality is symmetric")
			history = append(history, view)
			models = append(models, model)
			view, model = next, want

			if len(records) != 0 {
				records[0] = tailcfg.DNSRecord{Name: "mutated.invalid", Type: "A", Value: "192.0.2.1"}
			}
		}

		check := func(t *rapid.T) {
			require.True(t, slices.Equal(model, view.ExtraRecords().AsSlice()), "current records differ from reference")
			require.True(t, slices.Equal(model, view.AsStruct().ExtraRecords), "wire revision differs")
			require.True(t, slices.Equal(model, view.DebugConfig().ExtraRecords), "debug revision differs")

			for i, old := range history {
				require.True(t, slices.Equal(models[i], old.ExtraRecords().AsSlice()), "retained revision %d changed", i)
				require.True(t, slices.Equal(models[i], old.AsStruct().ExtraRecords), "retained wire revision %d changed", i)
				require.True(t, slices.Equal(models[i], old.DebugConfig().ExtraRecords), "retained debug revision %d changed", i)
			}
		}
		check(t)
		t.Repeat(map[string]func(*rapid.T){
			"":            check,
			"replace":     func(t *rapid.T) { publish(propcheck.DrawDNSRecords(t)) },
			"clear nil":   func(_ *rapid.T) { publish(nil) },
			"clear empty": func(_ *rapid.T) { publish([]tailcfg.DNSRecord{}) },
			"equivalent": func(t *rapid.T) {
				records := rapid.Permutation(model).Draw(t, "reordered records")
				for i := range records {
					records[i].Name = strings.ToUpper(records[i].Name)
				}

				publish(records)
			},
			"revert": func(t *rapid.T) {
				if len(models) == 0 {
					t.Skip("no retained revision")
				}

				index := rapid.IntRange(0, len(models)-1).Draw(t, "revision")
				publish(slices.Clone(models[index]))
				require.True(t, view.Equal(history[index]), "reverting must recover equality with retained revision")
			},
			"mutate outputs": func(_ *rapid.T) {
				for _, records := range [][]tailcfg.DNSRecord{view.ExtraRecords().AsSlice(), view.AsStruct().ExtraRecords, view.DebugConfig().ExtraRecords} {
					if len(records) != 0 {
						records[0].Value = "192.0.2.99"
					}
				}
			},
		})
	})
}

func TestDNSViewPropertyOwnership(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		records := propcheck.DrawDNSRecords(t)
		magic := rapid.Bool().Draw(t, "MagicDNS")
		override := rapid.Bool().Draw(t, "override resolvers")
		resolver := rapid.SampledFrom([]string{"1.1.1.1", "2001:db8::53", "https://dns.example.com/dns-query"}).Draw(t, "resolver")
		secret := rapid.StringMatching(`[a-z]{1,16}`).Draw(t, "provider secret")
		empty := rapid.Bool().Draw(t, "empty metadata")
		nilEmpty := rapid.Bool().Draw(t, "nil empty slices")
		build := func() *types.Config {
			cfg := &types.Config{DNSConfig: types.DNSConfig{
				MagicDNS: magic, BaseDomain: "example.com", OverrideLocalDNS: override,
				SearchDomains: []string{"search.example.com"}, ExtraRecords: slices.Clone(records),
				Nameservers: types.Nameservers{Global: []string{resolver}, Split: map[string][]string{
					"split.example.com": {resolver}, "local.example.com": nil, "empty.example.com": {},
				}},
				Challenge: types.DNSChallengeConfig{
					Resolvers: []string{"9.9.9.9:53"},
					ProviderSettings: map[string]any{"name": "acmedns", "config": map[string]any{
						"node.example.com": map[string]any{"username": "user", "password": secret, "subdomain": "reg", "server_url": "https://auth.example.com"},
					}},
				},
			}}
			if empty {
				cfg.DNSConfig.SearchDomains = []string{}
				cfg.DNSConfig.Nameservers = types.Nameservers{Global: []string{}, Split: map[string][]string{}}

				cfg.DNSConfig.Challenge = types.DNSChallengeConfig{Resolvers: []string{}, ProviderSettings: map[string]any{}}
				if nilEmpty {
					cfg.DNSConfig.SearchDomains = nil
					cfg.DNSConfig.Nameservers = types.Nameservers{}
					cfg.DNSConfig.Challenge = types.DNSChallengeConfig{}
				}
			}

			return cfg
		}

		cfg, expected := build(), build()
		if rapid.Bool().Draw(t, "started builder") {
			cfg.StartDNS(nil)
		}

		view := cfg.DNSView()
		wantDebug := expected.DNSConfig
		wantDebug.ExtraRecords = view.ExtraRecords().AsSlice()
		require.True(t, slices.Equal(propcheck.CanonicalDNSRecords(records), wantDebug.ExtraRecords))
		require.Equal(t, wantDebug, view.DebugConfig(), "metadata preserves configured values and shapes")
		frozenWire := view.AsStruct()
		wireJSON, err := json.Marshal(frozenWire)
		require.NoError(t, err)
		require.Equal(t, magic, frozenWire.Proxied)

		domains := slices.Clone(expected.DNSConfig.SearchDomains)
		if magic {
			domains = append([]string{"example.com"}, domains...)
		}

		require.True(t, slices.Equal(domains, frozenWire.Domains))

		if !empty {
			require.Equal(t, resolver, frozenWire.Routes["split.example.com"][0].Addr)

			resolvers := frozenWire.FallbackResolvers
			if override {
				resolvers = frozenWire.Resolvers
			}

			require.Len(t, resolvers, 1)
			require.Equal(t, resolver, resolvers[0].Addr)

			for _, domain := range []string{"local.example.com", "empty.example.com"} {
				require.Contains(t, frozenWire.Routes, domain)
				require.NotNil(t, frozenWire.Routes[domain], "local resolution requires non-nil empty route")
				require.Empty(t, frozenWire.Routes[domain])
			}
		}

		mutate := func(d *types.DNSConfig) {
			d.BaseDomain = "changed.invalid"

			d.MagicDNS = !d.MagicDNS
			for _, values := range [][]string{d.SearchDomains, d.Nameservers.Global, d.Challenge.Resolvers} {
				if len(values) != 0 {
					values[0] = "changed.invalid"
				}
			}

			for domain, values := range d.Nameservers.Split {
				if len(values) != 0 {
					values[0] = "192.0.2.1"
				}

				delete(d.Nameservers.Split, domain)
			}

			if !empty {
				registrations, ok := d.Challenge.ProviderSettings["config"].(map[string]any)
				require.True(t, ok)
				registration, ok := registrations["node.example.com"].(map[string]any)
				require.True(t, ok)

				registration["password"] = "changed"

				delete(registrations, "node.example.com")
				delete(d.Challenge.ProviderSettings, "config")
			}

			if len(d.ExtraRecords) != 0 {
				d.ExtraRecords[0].Name = "changed.invalid"
			}
		}
		mutate(&cfg.DNSConfig)
		cfg.SetExtraRecords([]tailcfg.DNSRecord{{Name: "changed.invalid", Type: "A", Value: "192.0.2.1"}})

		debug := view.DebugConfig()
		mutate(&debug)

		wire := view.AsStruct()

		wire.Proxied = !wire.Proxied
		for i := range wire.Domains {
			wire.Domains[i] = "changed.invalid"
		}

		for _, resolvers := range wire.Routes {
			for _, r := range resolvers {
				r.Addr = "192.0.2.1"
			}
		}

		clear(wire.Routes)

		for _, r := range append(wire.Resolvers, wire.FallbackResolvers...) {
			r.Addr = "192.0.2.2"
		}

		if len(wire.ExtraRecords) != 0 {
			wire.ExtraRecords[0].Value = "192.0.2.3"
		}

		require.Equal(t, "example.com", view.BaseDomain())
		require.Equal(t, wantDebug, view.DebugConfig(), "builder/debug mutation escaped into view")
		afterJSON, err := json.Marshal(view.AsStruct())
		require.NoError(t, err)
		require.JSONEq(t, string(wireJSON), string(afterJSON), "builder/wire mutation escaped into view")
	})
}

func TestDNSViewPropertyCertificateBoundaries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		label := rapid.StringMatching(`[a-z][a-z0-9]{0,15}`).Draw(t, "node label")
		base := "example.com"
		name := label + "." + base
		cfg := &types.Config{DNSConfig: types.DNSConfig{MagicDNS: true, BaseDomain: base, Certificates: types.CertificatesConfig{Enabled: true}}}
		view := cfg.DNSView()
		node := (&types.Node{GivenName: label}).View()

		for _, tc := range []struct {
			record  string
			allowed bool
		}{
			{name, false},
			{"child." + name, false},
			{"deep.child." + name, false},
			{"x" + name, true},
			{name + ".other", true},
			{base, true},
			{"sibling." + base, true},
		} {
			record := tc.record
			if rapid.Bool().Draw(t, "uppercase service") {
				record = strings.ToUpper(record)
			}

			if rapid.Bool().Draw(t, "rooted service") {
				record += "."
			}

			next := view.WithExtraRecords([]tailcfg.DNSRecord{{Name: record, Type: "A", Value: "100.64.0.1"}})
			got, allowed := node.CertDomain(next)
			require.Equal(t, tc.allowed, allowed, "service %q against node %q", record, name)

			if allowed {
				require.Equal(t, name, got)
			} else {
				require.Empty(t, got)
			}
		}

		got, allowed := node.CertDomain(view)
		require.True(t, allowed, "retained view must remain eligible")
		require.Equal(t, name, got)

		_, allowed = (&types.Node{GivenName: strings.ToUpper(label)}).View().CertDomain(view)
		require.False(t, allowed, "legacy mixed-case names must not share lowercase challenges")
		_, allowed = (types.NodeView{}).CertDomain(view)
		require.False(t, allowed)
		_, allowed = (&types.Node{}).View().CertDomain(view)
		require.False(t, allowed)

		cfg.DNSConfig.Certificates.Enabled = false
		_, allowed = node.CertDomain(cfg.DNSView())
		require.False(t, allowed)
		_, allowed = node.CertDomain(view)
		require.True(t, allowed, "builder changes must not disable certificates in retained view")

		// The TXT owner adds 16 bytes to the certificate name; all
		// component labels remain within DNS's 63-byte limit at both edges.
		for _, length := range []int{236, 237, 238} {
			cfg.DNSConfig.BaseDomain = strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + "." + strings.Repeat("e", length-len(label)-193)
			cfg.DNSConfig.Certificates.Enabled = true
			got, allowed = node.CertDomain(cfg.DNSView())
			require.Equal(t, length <= 237, allowed, "challenge owner for %d-byte name", length)

			if allowed {
				require.Len(t, got, length)
			}
		}
	})
}
