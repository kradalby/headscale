package types

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// drawDNSRecords draws A and AAAA records from a small pool of names and
// addresses, so sets repeat records and give one name several values,
// with nil, empty, mixed-case and rooted forms.
func drawDNSRecords(t *rapid.T) []tailcfg.DNSRecord {
	if rapid.Bool().Draw(t, "nil records") {
		return nil
	}

	records := make([]tailcfg.DNSRecord, rapid.IntRange(0, 8).Draw(t, "records"))
	for i := range records {
		name := rapid.SampledFrom([]string{"node", "service", "child.node", strings.Repeat("a", 63)}).Draw(t, "label") + ".example.com"
		if rapid.Bool().Draw(t, "uppercase") {
			name = strings.ToUpper(name)
		}

		if rapid.Bool().Draw(t, "rooted") {
			name += "."
		}

		address := rapid.IntRange(1, 4).Draw(t, "address")

		records[i] = tailcfg.DNSRecord{Name: name, Type: "A", Value: fmt.Sprintf("100.64.0.%d", address)}
		if rapid.Bool().Draw(t, "AAAA") {
			records[i].Type = "AAAA"
			records[i].Value = fmt.Sprintf("fd7a:115c:a1e0::%d", address)
		}
	}

	return records
}

// canonicalRecords is the set a publication of records stands for: names
// lowercased, rooted names kept apart (only certificate matching ignores
// the dot), duplicates kept, sorted by name, type and value, nil when
// empty, in storage of its own.
func canonicalRecords(records []tailcfg.DNSRecord) []tailcfg.DNSRecord {
	if len(records) == 0 {
		return nil
	}

	keys := make([]string, 0, len(records))
	for _, r := range records {
		keys = append(keys, strings.Join([]string{strings.ToLower(r.Name), r.Type, r.Value}, "\x00"))
	}

	slices.Sort(keys)

	out := make([]tailcfg.DNSRecord, 0, len(keys))
	for _, k := range keys {
		f := strings.Split(k, "\x00")
		out = append(out, tailcfg.DNSRecord{Name: f[0], Type: f[1], Value: f[2]})
	}

	return out
}

// TestDNSViewRevisionsFollowTheirRecords publishes drawn record sets as the
// records manager does and holds every revision, current and retained, in
// all three forms (records, wire, debug), to the canonical set it was
// published with. A publication of an equivalent set must keep the
// revision, or every session wakes for nothing; the caller's slice is
// neither normalised in place nor kept.
func TestDNSViewRevisionsFollowTheirRecords(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		initial := drawDNSRecords(t)
		cfg := &Config{DNSConfig: DNSConfig{ExtraRecords: slices.Clone(initial)}}
		view := cfg.DNSView()
		want := canonicalRecords(initial)

		var (
			history []DNSView
			wants   [][]tailcfg.DNSRecord
		)

		publish := func(records []tailcfg.DNSRecord) {
			t.Helper()

			before := slices.Clone(records)
			next := view.WithExtraRecords(records)
			nextWant := canonicalRecords(records)
			require.Equal(t, before, records, "a publication rewrote the caller's records")
			require.Equal(t, slices.Equal(want, nextWant), view.Equal(next), "a revision's equality is its records'")
			require.Equal(t, view.Equal(next), next.Equal(view), "equality is symmetric")

			history, wants = append(history, view), append(wants, want)
			view, want = next, nextWant

			if len(records) != 0 {
				records[0] = tailcfg.DNSRecord{Name: "changed.invalid", Type: "A", Value: "192.0.2.1"}
			}
		}

		check := func(*rapid.T) {
			for i, v := range append(slices.Clone(history), view) {
				w := want
				if i < len(history) {
					w = wants[i]
				}

				require.True(t, slices.Equal(w, v.ExtraRecords().AsSlice()), "revision %d: records", i)
				require.True(t, slices.Equal(w, v.AsStruct().ExtraRecords), "revision %d: wire", i)
				require.True(t, slices.Equal(w, v.DebugConfig().ExtraRecords), "revision %d: debug", i)
			}
		}

		check(t)
		t.Repeat(map[string]func(*rapid.T){
			"":            check,
			"replace":     func(t *rapid.T) { publish(drawDNSRecords(t)) },
			"clear nil":   func(*rapid.T) { publish(nil) },
			"clear empty": func(*rapid.T) { publish([]tailcfg.DNSRecord{}) },
			"equivalent": func(t *rapid.T) {
				records := rapid.Permutation(want).Draw(t, "reordered")
				for i := range records {
					if rapid.Bool().Draw(t, "uppercase") {
						records[i].Name = strings.ToUpper(records[i].Name)
					}
				}

				publish(records)
			},
			"revert": func(t *rapid.T) {
				if len(wants) == 0 {
					t.Skip("no earlier revision")
				}

				i := rapid.IntRange(0, len(wants)-1).Draw(t, "revision")
				publish(slices.Clone(wants[i]))
				require.True(t, view.Equal(history[i]), "republishing an earlier set must equal its revision")
			},
			"change outputs": func(*rapid.T) {
				for _, records := range [][]tailcfg.DNSRecord{view.ExtraRecords().AsSlice(), view.AsStruct().ExtraRecords, view.DebugConfig().ExtraRecords} {
					if len(records) != 0 {
						records[0].Value = "192.0.2.99"
					}
				}
			},
		})
	})
}

// TestDNSViewOwnsItsSettings builds views from drawn configurations, then
// changes the builder, the debug copy and the wire copy every way a
// caller can, and holds the view to what it was built from: a revision
// shared by every session must not move under them.
func TestDNSViewOwnsItsSettings(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		records := drawDNSRecords(t)
		magic := rapid.Bool().Draw(t, "MagicDNS")
		override := rapid.Bool().Draw(t, "override resolvers")
		resolver := rapid.SampledFrom([]string{"1.1.1.1", "2001:db8::53", "https://dns.example.com/dns-query"}).Draw(t, "resolver")
		secret := rapid.StringMatching(`[a-z]{1,16}`).Draw(t, "provider secret")
		empty := rapid.Bool().Draw(t, "empty settings")
		nilEmpty := rapid.Bool().Draw(t, "nil empty settings")
		build := func() *Config {
			cfg := &Config{DNSConfig: DNSConfig{
				MagicDNS: magic, BaseDomain: "example.com", OverrideLocalDNS: override,
				SearchDomains: []string{"search.example.com"}, ExtraRecords: slices.Clone(records),
				Nameservers: Nameservers{Global: []string{resolver}, Split: map[string][]string{
					"split.example.com": {resolver}, "local.example.com": nil, "empty.example.com": {},
				}},
				Challenge: DNSChallengeConfig{
					Resolvers: []string{"9.9.9.9:53"},
					ProviderSettings: map[string]any{"name": "acmedns", "config": map[string]any{
						"node.example.com": map[string]any{"username": "user", "password": secret, "subdomain": "reg", "server_url": "https://auth.example.com"},
					}},
				},
			}}
			if empty {
				cfg.DNSConfig.SearchDomains = []string{}
				cfg.DNSConfig.Nameservers = Nameservers{Global: []string{}, Split: map[string][]string{}}

				cfg.DNSConfig.Challenge = DNSChallengeConfig{Resolvers: []string{}, ProviderSettings: map[string]any{}}
				if nilEmpty {
					cfg.DNSConfig.SearchDomains = nil
					cfg.DNSConfig.Nameservers = Nameservers{}
					cfg.DNSConfig.Challenge = DNSChallengeConfig{}
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
		require.True(t, slices.Equal(canonicalRecords(records), wantDebug.ExtraRecords))
		require.Equal(t, wantDebug, view.DebugConfig(), "debug settings keep their configured values and shapes")

		wire := view.AsStruct()
		wireJSON, err := json.Marshal(wire)
		require.NoError(t, err)
		require.Equal(t, magic, wire.Proxied)

		domains := slices.Clone(expected.DNSConfig.SearchDomains)
		if magic {
			domains = append([]string{"example.com"}, domains...)
		}

		require.True(t, slices.Equal(domains, wire.Domains))

		if !empty {
			require.Equal(t, resolver, wire.Routes["split.example.com"][0].Addr)

			resolvers := wire.FallbackResolvers
			if override {
				resolvers = wire.Resolvers
			}

			require.Len(t, resolvers, 1)
			require.Equal(t, resolver, resolvers[0].Addr)

			for _, domain := range []string{"local.example.com", "empty.example.com"} {
				require.Contains(t, wire.Routes, domain)
				require.NotNil(t, wire.Routes[domain], "a split zone without resolvers resolves locally: an empty route, not nil")
				require.Empty(t, wire.Routes[domain])
			}
		}

		change := func(d *DNSConfig) {
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
		change(&cfg.DNSConfig)
		cfg.SetExtraRecords([]tailcfg.DNSRecord{{Name: "changed.invalid", Type: "A", Value: "192.0.2.1"}})

		debug := view.DebugConfig()
		change(&debug)

		copied := view.AsStruct()

		copied.Proxied = !copied.Proxied
		for i := range copied.Domains {
			copied.Domains[i] = "changed.invalid"
		}

		for _, resolvers := range copied.Routes {
			for _, r := range resolvers {
				r.Addr = "192.0.2.1"
			}
		}

		clear(copied.Routes)

		for _, r := range append(copied.Resolvers, copied.FallbackResolvers...) {
			r.Addr = "192.0.2.2"
		}

		if len(copied.ExtraRecords) != 0 {
			copied.ExtraRecords[0].Value = "192.0.2.3"
		}

		require.Equal(t, "example.com", view.BaseDomain())
		require.Equal(t, wantDebug, view.DebugConfig(), "a change to the builder or a debug copy reached the view")
		afterJSON, err := json.Marshal(view.AsStruct())
		require.NoError(t, err)
		require.JSONEq(t, string(wireJSON), string(afterJSON), "a change to the builder or a wire copy reached the view")
	})
}

// TestCertDomainAvoidsServiceNames draws node names against extra records
// at, below, beside and above them, in any case and rooted or not: a node
// gets no certificate for a name an operator gave a service, or one below
// it, and keeps it for every other. A retained view keeps its eligibility,
// and the challenge owner's length limit holds at both edges.
func TestCertDomainAvoidsServiceNames(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		label := rapid.StringMatching(`[a-z][a-z0-9]{0,15}`).Draw(t, "node label")
		base := "example.com"
		name := label + "." + base
		cfg := &Config{DNSConfig: DNSConfig{MagicDNS: true, BaseDomain: base, Certificates: CertificatesConfig{Enabled: true}}}
		view := cfg.DNSView()
		node := (&Node{GivenName: label}).View()

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

			got, allowed := node.CertDomain(view.WithExtraRecords([]tailcfg.DNSRecord{{Name: record, Type: "A", Value: "100.64.0.1"}}))
			require.Equal(t, tc.allowed, allowed, "service %q against node %q", record, name)

			if allowed {
				require.Equal(t, name, got)
			} else {
				require.Empty(t, got)
			}
		}

		got, allowed := node.CertDomain(view)
		require.True(t, allowed, "a retained view keeps its eligibility")
		require.Equal(t, name, got)

		_, allowed = (&Node{GivenName: strings.ToUpper(label)}).View().CertDomain(view)
		require.False(t, allowed, "a mixed-case legacy name shares its challenge record with the lowercase one")
		_, allowed = (NodeView{}).CertDomain(view)
		require.False(t, allowed)
		_, allowed = (&Node{}).View().CertDomain(view)
		require.False(t, allowed)

		cfg.DNSConfig.Certificates.Enabled = false
		_, allowed = node.CertDomain(cfg.DNSView())
		require.False(t, allowed)
		_, allowed = node.CertDomain(view)
		require.True(t, allowed, "a builder change must not reach a retained view")

		// The challenge owner adds 16 bytes; every label stays within 63.
		for _, length := range []int{236, 237, 238} {
			cfg.DNSConfig.BaseDomain = strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + "." + strings.Repeat("e", length-len(label)-193)
			cfg.DNSConfig.Certificates.Enabled = true
			got, allowed = node.CertDomain(cfg.DNSView())
			require.Equal(t, length <= 237, allowed, "challenge owner for a %d-byte name", length)

			if allowed {
				require.Len(t, got, length)
			}
		}
	})
}
