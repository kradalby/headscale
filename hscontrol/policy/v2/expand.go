package v2

import (
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// capSourcePrefix marks a [tailcfg.FilterRule.SrcIPs] entry the client
// matches by the source node's CapMap instead of by address.
const capSourcePrefix = "cap:"

// capHolders returns the addresses of the nodes holding a capability. The
// client looks caps up by a node's own addresses only, so holders give no
// routes.
type capHolders func(nodecap.Cap) []netip.Addr

// expandCapSources writes rules in IP form: every cap source becomes the
// addresses of its holders, written as the compile writes the sources of an
// identity alias (each address on its own, the list sorted as text without
// repeats, danger-all alone). A rule whose sources come to nothing is
// dropped, as the compile drops one. Rules are then merged as the compile
// merges them: by class, sources and protocols, at the first rule with the
// key. Without cap sources, rules come back unchanged.
//
// classes holds each rule's merge class, nil when every rule is regular.
// The wire rule does not say which rules the compile keeps apart: a via
// rule merges only with via rules through the same tags, so its class
// names them.
func expandCapSources(rules []tailcfg.FilterRule, classes []string, holders capHolders) []tailcfg.FilterRule {
	if !slices.ContainsFunc(rules, hasCapSource) {
		return rules
	}

	var (
		out  = make([]tailcfg.FilterRule, 0, len(rules))
		keys = make([]string, 0, len(rules))
	)

	for i, rule := range rules {
		if hasCapSource(rule) {
			rule.SrcIPs = expandSources(rule.SrcIPs, holders)
			if len(rule.SrcIPs) == 0 {
				continue
			}
		}

		var class string
		if classes != nil {
			class = classes[i]
		}

		out = append(out, rule)
		keys = append(keys, class+"|"+filterRuleKey(rule))
	}

	return mergeKeyedRules(out, keys)
}

// hasCapSource reports whether rule names a source by capability.
func hasCapSource(rule tailcfg.FilterRule) bool {
	return slices.ContainsFunc(rule.SrcIPs, func(src string) bool {
		return strings.HasPrefix(src, capSourcePrefix)
	})
}

// expandSources replaces each cap source with its holders' addresses; see
// [buildSrcIPStrings] for the form.
func expandSources(srcs []string, holders capHolders) []string {
	out := make([]string, 0, len(srcs))

	for _, src := range srcs {
		capName, ok := strings.CutPrefix(src, capSourcePrefix)
		if !ok {
			out = append(out, src)

			continue
		}

		for _, addr := range holders(nodecap.Cap(capName)) {
			out = append(out, addr.String())
		}
	}

	if len(out) == 0 {
		return nil
	}

	if slices.Contains(out, "*") {
		return []string{"*"}
	}

	slices.Sort(out)

	return slices.Compact(out)
}
