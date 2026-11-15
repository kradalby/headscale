package propcheck

import (
	"encoding/json"
	"slices"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// DrawPolicy draws every field through Rapid, so failures shrink policy
// rules and history, rather than merely shrinking a seed for another generator.
//
//nolint:goconst // Repeated aliases keep the generated policy schema readable.
func DrawPolicy(t *rapid.T) []byte {
	aliases := []string{
		"*", "u1@", "u2@", "group:a", "tag:srv", "tag:router",
		"autogroup:member", "autogroup:tagged", "lan", "100.64.0.1", "fd7a:115c:a1e0::2",
	}
	pick := func(pool []string) []string {
		return rapid.SliceOfN(rapid.SampledFrom(pool), 1, 3).Draw(t, "aliases")
	}
	pol := map[string]any{
		"groups":        map[string][]string{"group:a": pick([]string{"u1@", "u2@", "u3@"})},
		"tagOwners":     map[string][]string{"tag:srv": {"u1@"}, "tag:router": {"u2@"}},
		"hosts":         map[string]string{"lan": rapid.SampledFrom([]string{"10.0.0.0/24", "2001:db8::/64"}).Draw(t, "host")},
		"autoApprovers": map[string]any{"routes": map[string][]string{"10.0.0.0/24": {"tag:router"}}},
	}
	grants, acls := []any{}, []any{}

	for range rapid.IntRange(0, 5).Draw(t, "rules") {
		src := pick(aliases)

		dst := pick(append(slices.Clone(aliases), "autogroup:self", "autogroup:internet"))
		if slices.Contains(dst, "autogroup:self") {
			src = pick([]string{"u1@", "u2@", "group:a", "autogroup:member"})
		}

		switch rapid.IntRange(0, 3).Draw(t, "rule kind") {
		case 0:
			// IPv6 literals need bracket syntax in ACL destinations; grants cover them.
			dst = pick([]string{"*", "u1@", "group:a", "tag:srv", "autogroup:self", "lan"})
			if slices.Contains(dst, "autogroup:self") {
				src = pick([]string{"u1@", "u2@", "group:a", "autogroup:member"})
			}

			for i := range dst {
				dst[i] += ":" + rapid.SampledFrom([]string{"*", "22", "80,443"}).Draw(t, "ports")
			}

			acls = append(acls, map[string]any{"action": "accept", "src": src, "dst": dst})
		case 1:
			grants = append(grants, map[string]any{
				"src": src, "dst": dst,
				"ip": pick([]string{"*", "tcp:443", "udp:53", "icmp:*"}),
			})
		case 2:
			for i := range dst {
				if dst[i] == "autogroup:internet" {
					dst[i] = "8.8.8.0/24"
				}
			}

			grants = append(grants, map[string]any{
				"src": src, "dst": dst,
				"app": map[string]any{"example.com/cap/test": []any{map[string]any{"role": rapid.SampledFrom([]string{"read", "write"}).Draw(t, "role")}}},
			})
		case 3:
			grants = append(grants, map[string]any{
				"src": src, "dst": []string{"lan"},
				"via": []string{"tag:router"}, "ip": []string{"tcp:443"},
			})
		}
	}

	pol["grants"], pol["acls"] = grants, acls
	if rapid.Bool().Draw(t, "default allow") && len(grants)+len(acls) == 0 {
		delete(pol, "grants")
		delete(pol, "acls")
	}

	ssh := make([]any, 0, 2)

	for range rapid.IntRange(0, 2).Draw(t, "ssh rules") {
		action := rapid.SampledFrom([]string{"accept", "check"}).Draw(t, "ssh action")

		dst := []string{"autogroup:self"}
		if action == "accept" {
			dst = pick([]string{"autogroup:self", "tag:srv", "tag:router"})
		}

		ssh = append(ssh, map[string]any{
			"action": action, "src": pick([]string{"u1@", "group:a", "autogroup:member"}),
			"dst": dst, "users": pick([]string{"root", "autogroup:nonroot"}),
		})
	}

	pol["ssh"] = ssh
	pol["nodeAttrs"] = []any{map[string]any{"target": pick(aliases), "attr": pick([]string{"foo", "bar", "randomize-client-port"})}}
	pol["randomizeClientPort"] = rapid.Bool().Draw(t, "randomize port")
	if dm := DrawDERPMap(t, true); dm != nil {
		pol["derpMap"] = dm
	}

	return policyJSON(t, pol)
}

// ReorderPolicy reverses rule order and optionally duplicates one rule.
// Duplicate app grants intentionally retain their multiplicity.
func ReorderPolicy(t require.TestingT, doc []byte, duplicate bool) []byte {
	var pol map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &pol))

	for _, key := range []string{"grants", "acls"} {
		var rules []json.RawMessage
		if b, ok := pol[key]; ok {
			require.NoError(t, json.Unmarshal(b, &rules))
			slices.Reverse(rules)

			if duplicate && len(rules) > 0 {
				rules = append(rules, rules[0])
			}

			pol[key] = policyJSON(t, rules)
		}
	}

	return policyJSON(t, pol)
}

func policyJSON(t require.TestingT, v any) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)

	return b
}
