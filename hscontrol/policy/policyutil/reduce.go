package policyutil

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

// ReduceFilterRules takes a node and a set of global filter rules and removes all rules
// and destinations that are not relevant to that particular node.
//
// IMPORTANT: This function is designed for global filters only. Per-node filters
// (from autogroup:self policies) are already node-specific and should not be passed
// to this function. Use [policy.PolicyManager.FilterForNode] instead, which handles
// both cases.
func ReduceFilterRules(node types.NodeView, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	// One node: parse as we go rather than build an index to read once.
	return reduceRules(node, rules, func(i, j int) parsedDst {
		return parseDst(rules[i].DstPorts[j].IP)
	})
}

// Reducer reduces one set of filter rules for many nodes. It parses every
// destination once: every node reduces every rule on every policy compile,
// and parsing the same strings for each node was most of that work. Tag and
// user destinations expand to one address per node, so it also indexes
// single-address destinations: a node without routes looks its addresses
// up instead of scanning every destination.
type Reducer struct {
	rules []tailcfg.FilterRule
	dsts  [][]parsedDst // per rule, per DstPorts entry

	// byAddr holds the single-address destinations, wide the rest that can
	// reach a node through its addresses ("*", ranges, prefixes), and caps
	// the CapGrant rules; all in rule then entry order.
	byAddr map[netip.Addr][]dstRef
	wide   []dstRef
	caps   []int
}

// dstRef names DstPorts entry dst of rule rule.
type dstRef struct{ rule, dst int }

// parsedDst is a DstPorts entry's IP as a range. "*" spans both families,
// so it is the one form that is not a range; unparseable entries match
// nothing (fail closed).
type parsedDst struct {
	any, valid bool
	r          netipx.IPRange
}

// NewReducer parses rules for [Reducer.Reduce]. rules must not change
// afterwards.
func NewReducer(rules []tailcfg.FilterRule) *Reducer {
	red := &Reducer{
		rules:  rules,
		dsts:   make([][]parsedDst, len(rules)),
		byAddr: make(map[netip.Addr][]dstRef),
	}

	for i, rule := range rules {
		if len(rule.CapGrant) > 0 {
			red.caps = append(red.caps, i)

			continue
		}

		dsts := make([]parsedDst, len(rule.DstPorts))
		for j, dest := range rule.DstPorts {
			ref := dstRef{rule: i, dst: j}

			d := parseDst(dest.IP)
			dsts[j] = d

			switch {
			case !d.valid:
			case !d.any && d.r.From() == d.r.To():
				red.byAddr[d.r.From()] = append(red.byAddr[d.r.From()], ref)
			default:
				red.wide = append(red.wide, ref)
			}
		}

		red.dsts[i] = dsts
	}

	return red
}

// Reduce returns the rules and destinations relevant to node.
func (red *Reducer) Reduce(node types.NodeView) []tailcfg.FilterRule {
	nodeIPs := node.IPs()
	subnetRoutes := node.SubnetRoutes()
	exitRoutes := node.ExitRoutes()

	// A route can overlap any destination, so routers scan them all.
	if len(subnetRoutes) > 0 || len(exitRoutes) > 0 {
		return red.reduceAll(node)
	}

	var refs []dstRef

	for _, ip := range nodeIPs {
		refs = append(refs, red.byAddr[ip]...)
	}

	for _, ref := range red.wide {
		if red.dsts[ref.rule][ref.dst].reaches(nodeIPs, nil, nil) {
			refs = append(refs, ref)
		}
	}

	for _, rule := range red.caps {
		refs = append(refs, dstRef{rule: rule, dst: -1})
	}

	slices.SortFunc(refs, func(a, b dstRef) int {
		if a.rule != b.rule {
			return a.rule - b.rule
		}

		return a.dst - b.dst
	})
	refs = slices.Compact(refs)

	ret := []tailcfg.FilterRule{}

	for i := 0; i < len(refs); {
		ruleIdx := refs[i].rule
		rule := red.rules[ruleIdx]

		// Handle CapGrant rules separately — they use CapGrant[].Dsts
		// instead of DstPorts for destination matching.
		if refs[i].dst < 0 {
			if reduced := reduceCapGrantRule(node, rule); reduced != nil {
				ret = append(ret, *reduced)
			}

			i++

			continue
		}

		var dests []tailcfg.NetPortRange
		for ; i < len(refs) && refs[i].rule == ruleIdx; i++ {
			dests = append(dests, rule.DstPorts[refs[i].dst])
		}

		// Struct-copy preserves any unknown future FilterRule fields.
		out := rule
		out.DstPorts = dests
		ret = append(ret, out)
	}

	return ret
}

// reduceAll reduces by checking every destination, for a node whose routes
// may overlap any of them.
func (red *Reducer) reduceAll(node types.NodeView) []tailcfg.FilterRule {
	return reduceRules(node, red.rules, func(i, j int) parsedDst { return red.dsts[i][j] })
}

// reduceRules keeps the rules and destinations that reach node, reading
// each destination through dst.
func reduceRules(node types.NodeView, rules []tailcfg.FilterRule, dst func(rule, entry int) parsedDst) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}
	nodeIPs := node.IPs()
	subnetRoutes := node.SubnetRoutes()
	exitRoutes := node.ExitRoutes()

	for i, rule := range rules {
		// Handle CapGrant rules separately — they use CapGrant[].Dsts
		// instead of DstPorts for destination matching.
		if len(rule.CapGrant) > 0 {
			if reduced := reduceCapGrantRule(node, rule); reduced != nil {
				ret = append(ret, *reduced)
			}

			continue
		}

		var dests []tailcfg.NetPortRange

		for j, dest := range rule.DstPorts {
			if dst(i, j).reaches(nodeIPs, subnetRoutes, exitRoutes) {
				dests = append(dests, dest)
			}
		}

		if len(dests) > 0 {
			// Struct-copy preserves any unknown future FilterRule fields.
			out := rule
			out.DstPorts = dests
			ret = append(ret, out)
		}
	}

	return ret
}

// parseDst parses a DstPorts entry's IP.
func parseDst(ip string) parsedDst {
	if ip == "*" {
		return parsedDst{any: true, valid: true}
	}

	r, err := util.ParseIPRange(ip)

	return parsedDst{r: r, valid: err == nil}
}

// reaches reports whether the destination targets the node: one of its
// addresses, or a route it serves.
func (d parsedDst) reaches(nodeIPs []netip.Addr, subnetRoutes, exitRoutes []netip.Prefix) bool {
	if !d.valid {
		return false
	}

	if d.any {
		return len(nodeIPs) > 0 || len(subnetRoutes) > 0 || len(exitRoutes) > 0
	}

	overlaps := func(p netip.Prefix) bool { return d.r.Overlaps(netipx.RangeOfPrefix(p)) }

	// [types.NodeView.SubnetRoutes] holds only approved, non-exit routes:
	// Tailscale SaaS generates no rules for advertised-but-unapproved
	// routes. Approved exit routes count like subnet routes. They contain
	// every destination, so SaaS sends an exit node every rule, not only
	// internet ones.
	return slices.ContainsFunc(nodeIPs, d.r.Contains) ||
		slices.ContainsFunc(subnetRoutes, overlaps) ||
		slices.ContainsFunc(exitRoutes, overlaps)
}

// reduceCapGrantRule filters a [tailcfg.CapGrant] rule to only include
// [tailcfg.CapGrant] entries whose Dsts match the given node's IPs. When a
// broad prefix (e.g. 100.64.0.0/10 from dst:*) contains a node's IP, it is
// narrowed to the node's specific /32 or /128 prefix. Returns nil if
// no [tailcfg.CapGrant] entries are relevant to this node.
func reduceCapGrantRule(
	node types.NodeView,
	rule tailcfg.FilterRule,
) *tailcfg.FilterRule {
	var capGrants []tailcfg.CapGrant

	nodeIPs := node.IPs()
	subnetRoutes := node.SubnetRoutes()

	for _, cg := range rule.CapGrant {
		// Collect the node's IPs that fall within any of this
		// CapGrant's Dsts. Broad prefixes are narrowed to specific
		// /32 and /128 entries for the node.
		var matchingDsts []netip.Prefix

		for _, dst := range cg.Dsts {
			if dst.IsSingleIP() {
				// Already a specific IP — keep it if it matches
				// any of the node's IPs.
				if slices.Contains(nodeIPs, dst.Addr()) {
					matchingDsts = append(matchingDsts, dst)
				}
			} else {
				// Broad prefix — narrow to node's specific IPs.
				for _, ip := range nodeIPs {
					if dst.Contains(ip) {
						matchingDsts = append(matchingDsts, netip.PrefixFrom(ip, ip.BitLen()))
					}
				}
			}
		}

		// Asymmetric on purpose: the IP-match loop above narrows broad
		// prefixes to node-specific /32 or /128 so peers receive only
		// the minimum routing surface. The route-match loop below
		// preserves the original prefix so the subnet-serving node
		// receives the full CapGrant scope. [types.NodeView.SubnetRoutes]
		// excludes both unapproved and exit routes, matching Tailscale
		// SaaS behavior.
		for _, dst := range cg.Dsts {
			for _, subnetRoute := range subnetRoutes {
				if dst.Overlaps(subnetRoute) {
					// For route overlaps, keep the original prefix.
					matchingDsts = append(matchingDsts, dst)
				}
			}
		}

		if len(matchingDsts) > 0 {
			// A Dst can be appended twice when a broad prefix both
			// contains a node IP and overlaps one of its approved
			// subnet routes. Sort + Compact dedups; [netip.Prefix] is
			// comparable so Compact works with ==.
			slices.SortFunc(matchingDsts, netip.Prefix.Compare)
			matchingDsts = slices.Compact(matchingDsts)

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   matchingDsts,
				CapMap: cg.CapMap,
			})
		}
	}

	if len(capGrants) == 0 {
		return nil
	}

	return &tailcfg.FilterRule{
		SrcIPs:   rule.SrcIPs,
		CapGrant: capGrants,
	}
}
