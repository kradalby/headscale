// Oracles over the SaaS captures, on headscale's IP-form output:
//
//   - probes: every captured node's SaaS filter and headscale's filter for
//     it behave alike in the node's own client (check B), whether or not
//     they are written alike;
//   - expander: the captured filters survive [expandCapSources], as they
//     are and with their node sources turned into caps stamped on the
//     captured netmap (check A on cap-free input);
//   - merge order: whether reducing each rule to the node before merging
//     would give the filter headscale gives today, which merges first.
//
// Nodes come from the builders of the compat tests that own each
// directory, so a capture means here what it means there.

package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netmap"
)

// goldenFilterSource is a directory of single-shot captures whose nodes
// carry packet filters, with the compat test's way of building its nodes.
type goldenFilterSource struct {
	dir, glob string
	build     func(*testing.T, *testcapture.Capture) (types.Users, types.Nodes)
}

func goldenFilterSources() []goldenFilterSource {
	grants := func(_ *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
		users := setupGrantsCompatUsers()

		return users, buildGrantsNodesFromCapture(users, c)
	}
	routes := func(t *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
		t.Helper()

		return buildRoutesUsersAndNodes(t, c.Topology)
	}
	ssh := func(_ *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
		users := setupSSHDataCompatUsers()

		return users, buildGrantsNodesFromCapture(users, c)
	}
	nodeAttrs := func(t *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
		t.Helper()

		users := nodeAttrsCompatUsers()

		return users, buildNodeAttrsNodesFromCapture(t, users, c)
	}
	userTokens := func(t *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
		t.Helper()

		users, nodes, _ := userTokenUsersAndNodes(t, c, userTokenOverlay{})

		return users, nodes
	}

	return []goldenFilterSource{
		{dir: "acl_results", glob: "acl-*.hujson", build: buildACLUsersAndNodes},
		{dir: "grant_results", glob: "*-*.hujson", build: grants},
		{dir: "routes_results", glob: "routes-*.hujson", build: routes},
		{dir: "ssh_results", glob: "ssh-*.hujson", build: ssh},
		{dir: filepath.Join("ssh_results", "forwarding"), glob: "ssh-*.hujson", build: ssh},
		{dir: "nodeattrs_results", glob: "*.hujson", build: nodeAttrs},
		{dir: "users_results", glob: "*.hujson", build: userTokens},
		{dir: "dns_results", glob: "*.hujson", build: grants},
		{dir: "sshtest_results", glob: "*.hujson", build: grants},
	}
}

// goldenProbeDivergences lists, keyed <test_id>[/<step>]/<node>/<candidate>,
// captured filters headscale's client would enforce differently. Each entry
// needs maintainer sign-off; a listed filter that is enforced alike fails,
// so a fix must delete its entry.
var goldenProbeDivergences = map[string]string{
	"users-short-name/server/manager": shortUsername,

	"policy-generation/G7/rt-b/manager":     sequenceUnsettled,
	"policy-generation/G7/rt-plain/manager": sequenceUnsettled,
	"policy-generation/G7/srv/manager":      sequenceUnsettled,
}

const sequenceUnsettled = "SEQUENCE_UNSETTLED: SaaS still admits the device deleted just before the capture; policySequenceNotCompared leaves these filters out"

// goldenTally collects what the oracles saw across captures.
type goldenTally struct {
	mu sync.Mutex

	files, refusedBySaaS, pairs      int
	exact, textual, semantic, probes int

	// compiledDiffers counts nodes whose per-node compile, which some
	// compat tests also compare, differs from the manager's filter.
	compiledDiffers int

	textualKeys, semanticReports, headscaleRefusals []string

	mutations, mutationsCaught, mutationsRedundant int
	mutationsMissed                                []string

	roundTrips, rulesCapped int
	expandFailures          []string
	outOfOrder              []string

	mergeSame, mergeDiffers                []string
	globalMatches, perNodeMatches, mirrors int
	mirrorFailures                         []string
	pinsGlobal, pinsPerNode                []string
}

func (g *goldenTally) add(f func(*goldenTally)) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f(g)
}

func (g *goldenTally) report(t *testing.T) {
	t.Helper()

	list := func(name string, items []string) {
		slices.Sort(items)
		t.Logf("%s (%d):", name, len(items))

		for _, it := range items {
			t.Logf("  %s", it)
		}
	}

	t.Logf("capture files %d, refused by SaaS %d, refused by headscale %d", g.files, g.refusedBySaaS, len(g.headscaleRefusals))
	t.Logf("probes: %d node filters, %d written alike, %d written differently but enforced alike, %d enforced differently; %d probes run",
		g.pairs, g.exact, g.textual, g.semantic, g.probes)
	t.Logf("probes: per-node compile differs from the manager's filter on %d nodes", g.compiledDiffers)
	list("headscale refuses", g.headscaleRefusals)
	list("written differently, enforced alike", g.textualKeys)
	list("enforced differently", g.semanticReports)
	t.Logf("mutations: %d seeded into captured filters, %d told apart by the probes, %d allowed by another rule already",
		g.mutations, g.mutationsCaught, g.mutationsRedundant)
	list("mutations neither told apart nor allowed already", g.mutationsMissed)
	t.Logf("expander: %d SaaS rules had node sources turned into caps; headscale's filters come back byte for byte; %d SaaS filters come back as the compat tests compare",
		g.rulesCapped, g.roundTrips)
	list("expander failures", g.expandFailures)
	list("round trip matches only up to the order within a rule's lists", g.outOfOrder)
	t.Logf("merge order: mirror of today's pipeline reproduced %d filters", g.mirrors)
	list("mirror failures", g.mirrorFailures)
	t.Logf("merge order: per-node merge equals today's filter on %d nodes, differs on %d", len(g.mergeSame), len(g.mergeDiffers))
	t.Logf("merge order: against SaaS in rule order, today's global merge matches %d, per-node merge matches %d",
		g.globalMatches, g.perNodeMatches)
	list("per-node merge differs from today", g.mergeDiffers)
	list("pins the global merge (today matches SaaS, per-node does not)", g.pinsGlobal)
	list("pins the per-node merge (per-node matches SaaS, today does not)", g.pinsPerNode)
}

// TestGoldenOracles runs the probe, expander and merge-order oracles over
// every captured node that carries a packet filter.
func TestGoldenOracles(t *testing.T) {
	t.Parallel()

	tally := &goldenTally{}

	t.Cleanup(func() { tally.report(t) })

	for _, src := range goldenFilterSources() {
		files, err := filepath.Glob(filepath.Join("testdata", src.dir, src.glob))
		require.NoError(t, err)
		require.NotEmpty(t, files, "no captures in %s", src.dir)

		for _, file := range files {
			t.Run(filepath.Join(src.dir, filepath.Base(file)), func(t *testing.T) {
				t.Parallel()

				c, err := testcapture.Read(file)
				require.NoError(t, err)

				tally.add(func(g *goldenTally) { g.files++ })

				if c.Error || c.Input.APIResponseCode != 200 {
					tally.add(func(g *goldenTally) { g.refusedBySaaS++ })

					return
				}

				users, nodes := src.build(t, c)

				policy := []byte(c.Input.FullPolicy)

				pm, err := NewPolicyManager(policy, users, nodes.ViewSlice())
				if err != nil {
					tally.add(func(g *goldenTally) {
						g.headscaleRefusals = append(g.headscaleRefusals, c.TestID+": "+err.Error())
					})

					return
				}

				pol, err := unmarshalPolicy(policy)
				require.NoError(t, err)

				for _, alias := range slices.Sorted(maps.Keys(c.Captures)) {
					capture := c.Captures[alias]
					if capture.Netmap == nil {
						continue
					}

					node := findNodeByGivenName(nodes, alias)
					require.NotNilf(t, node, "%s: node %s not built", c.TestID, alias)

					t.Run(alias, func(t *testing.T) {
						goldenNodeOracles(t, tally, c.TestID+"/"+alias, goldenNode{
							pm: pm, pol: pol, users: users, nodes: nodes, node: node,
							want: capture.PacketFilterRules, netmap: capture.Netmap,
							compiled: pol.ACLs != nil || pol.Grants != nil,
						})
					})
				}
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		goldenSequenceOracles(t, tally, "policy-generation")
	})
}

// goldenNode is one captured node and headscale's view of it.
type goldenNode struct {
	pm     *PolicyManager
	pol    *Policy
	users  types.Users
	nodes  types.Nodes
	node   *types.Node
	want   []tailcfg.FilterRule
	netmap *netmap.NetworkMap

	// compiled is set where the per-node compile applies: a policy with
	// neither acls nor grants gets its allow-all from the manager only.
	compiled bool
}

func goldenNodeOracles(t *testing.T, tally *goldenTally, key string, gn goldenNode) {
	t.Helper()

	got, err := gn.pm.FilterForNode(gn.node.View())
	require.NoError(t, err)

	view := policymodel.ViewFromNetmap(gn.netmap)

	t.Run("probes", func(t *testing.T) {
		goldenProbe(t, tally, key+"/manager", gn.want, got, view)

		if !gn.compiled {
			return
		}

		compiled := policyutil.ReduceFilterRules(gn.node.View(), gn.pol.compileFilterRulesForNode(gn.users, gn.node.View(), gn.nodes.ViewSlice()))
		if cmp.Diff(got, compiled, inOrderOpts...) != "" {
			tally.add(func(g *goldenTally) { g.compiledDiffers++ })
			goldenProbe(t, tally, key+"/compiled", gn.want, compiled, view)
		}
	})

	t.Run("mutations", func(t *testing.T) {
		goldenMutations(t, tally, key, gn.want, view)
	})

	t.Run("expander", func(t *testing.T) {
		goldenExpand(t, tally, key, gn.want, got, gn.netmap)
	})

	t.Run("merge-order", func(t *testing.T) {
		goldenMergeOrder(tally, key, gn, got)
	})
}

func goldenProbe(t *testing.T, tally *goldenTally, key string, want, got []tailcfg.FilterRule, view policymodel.ClientView) {
	t.Helper()

	exact := cmp.Diff(want, got, append(cmpOptions(), cmpopts.EquateEmpty())...) == ""
	rep := policymodel.Compare(want, got, view)

	tally.add(func(g *goldenTally) {
		g.pairs++
		g.probes += rep.Probes

		switch {
		case !rep.Equivalent():
			g.semantic++
			g.semanticReports = append(g.semanticReports, key+": "+rep.String())
		case exact:
			g.exact++
		default:
			g.textual++
			g.textualKeys = append(g.textualKeys, key)
		}
	})

	reason, listed := goldenProbeDivergences[key]

	switch {
	case listed && rep.Equivalent():
		t.Errorf("enforced alike; delete the divergence entry %q (%s)", key, reason)
	case listed:
		t.Skip(reason)
	case !rep.Equivalent():
		t.Errorf("SaaS and headscale filters are enforced differently (reference SaaS, candidate headscale): %s", rep)
	}
}

// goldenMutations seeds two mistakes into a captured filter, a dropped
// source and a port range one wider, and requires the probes to tell the
// result from the capture unless another rule already allows what the
// mutation changes, which a plain reading of the rules decides.
func goldenMutations(t *testing.T, tally *goldenTally, key string, want []tailcfg.FilterRule, view policymodel.ClientView) {
	t.Helper()

	try := func(what string, mutated []tailcfg.FilterRule, redundant func() bool) {
		caught := !policymodel.Compare(want, mutated, view).Equivalent()
		explained := !caught && redundant()

		tally.add(func(g *goldenTally) {
			g.mutations++

			switch {
			case caught:
				g.mutationsCaught++
			case explained:
				g.mutationsRedundant++
			default:
				g.mutationsMissed = append(g.mutationsMissed, key+": "+what)
			}
		})

		if !caught && !explained {
			t.Errorf("probes do not see %s, and no other rule allows it", what)
		}
	}

	for i, r := range want {
		if len(r.CapGrant) > 0 || len(r.SrcIPs) < 2 {
			continue
		}

		mutated := slices.Clone(want)
		dropped := r.SrcIPs[len(r.SrcIPs)-1]
		mutated[i].SrcIPs = slices.Clip(r.SrcIPs[:len(r.SrcIPs)-1])
		try(fmt.Sprintf("rule %d without source %s", i, dropped), mutated, func() bool {
			return droppedSourceAllowed(mutated, i, dropped, view.LocalNets)
		})

		break
	}

	for i, r := range want {
		j := slices.IndexFunc(r.DstPorts, func(d tailcfg.NetPortRange) bool { return d.Ports.Last < 65535 })
		if j < 0 {
			continue
		}

		mutated := slices.Clone(want)
		mutated[i].DstPorts = slices.Clone(r.DstPorts)
		mutated[i].DstPorts[j].Ports.Last++
		try(fmt.Sprintf("rule %d destination %s ports to %d", i, r.DstPorts[j].IP, mutated[i].DstPorts[j].Ports.Last), mutated, func() bool {
			return widenedPortAllowed(want, i, j, view.LocalNets)
		})

		break
	}
}

// droppedSourceAllowed reports whether rules, rule i without dropped,
// still allow dropped everything rule i allowed it: each destination it
// can reach on the receiver is held, with its ports and protocols, by a
// rule whose sources hold dropped.
func droppedSourceAllowed(rules []tailcfg.FilterRule, i int, dropped string, localNets *netipx.IPSet) bool {
	src := entrySet(dropped)

	for _, d := range rules[i].DstPorts {
		dst := intersectSets(entrySet(d.IP), localNets, sameFamilies(src))
		if len(dst.Ranges()) > 0 && !allowedBy(rules, -1, -1, src, ruleProtos(rules[i]), dst, d.Ports) {
			return false
		}
	}

	return true
}

// widenedPortAllowed reports whether some other rule entry already allows
// rule i's sources and port protocols the port its entry j gains.
func widenedPortAllowed(rules []tailcfg.FilterRule, i, j int, localNets *netipx.IPSet) bool {
	d := rules[i].DstPorts[j]
	if d.Ports.First == 0 && d.Ports.Last+1 == 65535 {
		// All ports opens the client's path for other protocols.
		return false
	}

	var protos []int

	for _, p := range ruleProtos(rules[i]) {
		if p == int(ipproto.TCP) || p == int(ipproto.UDP) || p == int(ipproto.SCTP) {
			protos = append(protos, p)
		}
	}

	var srcs netipx.IPSetBuilder
	for _, s := range rules[i].SrcIPs {
		srcs.AddSet(entrySet(s))
	}

	srcSet, _ := srcs.IPSet()

	dst := intersectSets(entrySet(d.IP), localNets, sameFamilies(srcSet))
	if len(protos) == 0 || len(dst.Ranges()) == 0 {
		return true
	}

	port := d.Ports.Last + 1

	return allowedBy(rules, i, j, srcSet, protos, dst, tailcfg.PortRange{First: port, Last: port})
}

// allowedBy reports whether one entry of rules, other than rule i's entry
// j, allows every source in srcs to every destination in dst on every
// port in ports for every protocol in protos.
func allowedBy(rules []tailcfg.FilterRule, i, j int, srcs *netipx.IPSet, protos []int, dst *netipx.IPSet, ports tailcfg.PortRange) bool {
	for ri, r := range rules {
		if len(r.CapGrant) > 0 || !protosCover(ruleProtos(r), protos) {
			continue
		}

		var b netipx.IPSetBuilder
		for _, s := range r.SrcIPs {
			b.AddSet(entrySet(s))
		}

		rs, _ := b.IPSet()
		if !setCovers(rs, srcs) {
			continue
		}

		for ei, e := range r.DstPorts {
			if ri == i && ei == j {
				continue
			}

			if e.Ports.First <= ports.First && e.Ports.Last >= ports.Last && setCovers(entrySet(e.IP), dst) {
				return true
			}
		}
	}

	return false
}

// entrySet is a SrcIPs or DstPorts entry as addresses; a cap holds none.
func entrySet(entry string) *netipx.IPSet {
	s, err := util.ParseIPSet(entry, nil)
	if err != nil {
		return &netipx.IPSet{}
	}

	return s
}

func intersectSets(sets ...*netipx.IPSet) *netipx.IPSet {
	var b netipx.IPSetBuilder

	b.AddSet(sets[0])

	for _, s := range sets[1:] {
		b.Intersect(s)
	}

	out, _ := b.IPSet()

	return out
}

// sameFamilies is every address of the families s has addresses in.
func sameFamilies(s *netipx.IPSet) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, r := range s.Ranges() {
		if r.From().Is4() {
			b.AddPrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		} else {
			b.AddPrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))
		}
	}

	out, _ := b.IPSet()

	return out
}

func setCovers(outer, inner *netipx.IPSet) bool {
	for _, r := range inner.Ranges() {
		if !outer.ContainsRange(r) {
			return false
		}
	}

	return true
}

// ruleProtos is the protocols a rule allows, the client's defaults when
// it names none.
func ruleProtos(r tailcfg.FilterRule) []int {
	if len(r.IPProto) > 0 {
		return r.IPProto
	}

	return []int{int(ipproto.TCP), int(ipproto.UDP), int(ipproto.ICMPv4), int(ipproto.ICMPv6)}
}

func protosCover(outer, inner []int) bool {
	for _, p := range inner {
		if !slices.Contains(outer, p) {
			return false
		}
	}

	return true
}

// goldenExpand checks the expander on a captured filter and on
// headscale's: unchanged as they are, and back to them after their node
// sources become caps. Each rule gets its own cap, stamped on the netmap
// nodes whose every address the rule names, so holders come from the
// netmap as the client finds them. Headscale's filter must come back
// byte for byte; SaaS's as the compat tests compare it, since SaaS does
// not order a rule's sources as text.
func goldenExpand(t *testing.T, tally *goldenTally, key string, want, today []tailcfg.FilterRule, nm *netmap.NetworkMap) {
	t.Helper()

	roundTrip := func(rules []tailcfg.FilterRule) ([]tailcfg.FilterRule, []tailcfg.FilterRule) {
		if got := expandCapSources(rules, nil, func(nodecap.Cap) []netip.Addr { return nil }); !slices.EqualFunc(got, rules, filterRulesEqual) {
			tally.add(func(g *goldenTally) { g.expandFailures = append(g.expandFailures, key+": cap-free filter changed") })
			t.Errorf("cap-free filter changed:\n%s", cmp.Diff(rules, got, inOrderOpts...))
		}

		capped, self, peers := capifyRules(rules, nm)

		return capped, expandCapSources(capped, keptApart(rules), policymodel.NewNetmapCaps(self, peers).Holders)
	}

	if _, got := roundTrip(today); !cmp.Equal(today, got, inOrderOpts...) {
		tally.add(func(g *goldenTally) {
			g.expandFailures = append(g.expandFailures, key+": headscale round trip differs")
		})
		t.Errorf("cap round trip of headscale's filter differs (-headscale +expanded):\n%s", cmp.Diff(today, got, inOrderOpts...))
	}

	capped, got := roundTrip(want)

	n := 0

	for _, r := range capped {
		if hasCapSource(r) {
			n++
		}
	}

	tally.add(func(g *goldenTally) { g.rulesCapped += n })

	if diff := cmp.Diff(want, got, append(cmpOptions(), cmpopts.EquateEmpty())...); diff != "" {
		tally.add(func(g *goldenTally) { g.expandFailures = append(g.expandFailures, key+": SaaS round trip differs") })
		t.Errorf("cap round trip of SaaS's filter differs (-capture +expanded):\n%s", diff)

		return
	}

	inOrder := cmp.Diff(want, got, inOrderOpts...)

	tally.add(func(g *goldenTally) {
		g.roundTrips++

		if inOrder != "" {
			g.outOfOrder = append(g.outOfOrder, key+":\n"+inOrder)
		}
	})
}

// keptApart gives each rule that shares its merge key with another rule
// a class of its own: the capture's control plane merges every rule with
// a key it shares, so rules it left apart were in different classes.
func keptApart(rules []tailcfg.FilterRule) []string {
	count := map[string]int{}

	for _, r := range rules {
		if len(r.CapGrant) == 0 {
			count[filterRuleKey(r)]++
		}
	}

	classes := make([]string, len(rules))

	for i, r := range rules {
		if len(r.CapGrant) == 0 && count[filterRuleKey(r)] > 1 {
			classes[i] = strconv.Itoa(i)
		}
	}

	return classes
}

// inOrderOpts compare filters as written, every list in order.
var inOrderOpts = []cmp.Option{cmpopts.EquateEmpty(), cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{})}

func filterRulesEqual(a, b tailcfg.FilterRule) bool {
	return cmp.Equal(a, b, inOrderOpts...)
}

// capifyRules replaces, per rule, the addresses of every netmap node the
// rule names in full with one cap held by those nodes, and returns the
// netmap's nodes stamped with the caps.
func capifyRules(rules []tailcfg.FilterRule, nm *netmap.NetworkMap) ([]tailcfg.FilterRule, tailcfg.NodeView, []tailcfg.NodeView) {
	all := make([]*tailcfg.Node, 0, 1+len(nm.Peers))

	all = append(all, nm.SelfNode.AsStruct())
	for _, p := range nm.Peers {
		all = append(all, p.AsStruct())
	}

	out := make([]tailcfg.FilterRule, len(rules))

	for i, rule := range rules {
		out[i] = rule

		c := nodecap.Cap(fmt.Sprintf("test.invalid/cap/rule-%d", i))
		srcs := map[string]bool{}

		for _, s := range rule.SrcIPs {
			srcs[s] = true
		}

		taken := map[string]bool{}

		for _, n := range all {
			var addrs []string

			for _, p := range n.Addresses {
				if p.IsSingleIP() {
					addrs = append(addrs, p.Addr().String())
				}
			}

			if len(addrs) == 0 || !allIn(addrs, srcs) {
				continue
			}

			for _, a := range addrs {
				taken[a] = true
			}

			if n.CapMap == nil {
				n.CapMap = tailcfg.NodeCapMap{}
			}

			n.CapMap[c] = nil
		}

		if len(taken) == 0 {
			continue
		}

		srcIPs := []string{capSourcePrefix + string(c)}

		for _, s := range rule.SrcIPs {
			if !taken[s] {
				srcIPs = append(srcIPs, s)
			}
		}

		out[i].SrcIPs = srcIPs
	}

	peers := make([]tailcfg.NodeView, 0, len(all)-1)
	for _, n := range all[1:] {
		peers = append(peers, n.View())
	}

	return out, all[0].View(), peers
}

func allIn(items []string, set map[string]bool) bool {
	for _, it := range items {
		if !set[it] {
			return false
		}
	}

	return true
}

// goldenMergeOrder asks whether reducing each rule to the node and then
// merging gives today's filter, which merges across all nodes first. A
// mirror of today's per-node pipeline, built from the same pieces, must
// reproduce today's filter first, or the comparison says nothing.
func goldenMergeOrder(tally *goldenTally, key string, gn goldenNode, today []tailcfg.FilterRule) {
	node, want := gn.node, gn.want

	var rules []tailcfg.FilterRule

	var keys []string

	if gn.compiled {
		rules, keys = unmergedRulesForNode(gn.pm, node.View())
	} else {
		// The manager's allow-all default, compiled as it compiles it.
		for _, cg := range allowAllPolicy().compileGrants(gn.users, gn.nodes.ViewSlice()) {
			rules = append(rules, cg.rules...)
			keys = append(keys, cg.ruleKeys...)
		}
	}

	mirror := policyutil.ReduceFilterRules(node.View(), mergeKeyedRules(rules, keys))
	if cmp.Diff(today, mirror, inOrderOpts...) != "" {
		tally.add(func(g *goldenTally) { g.mirrorFailures = append(g.mirrorFailures, key) })

		return
	}

	var (
		reduced     []tailcfg.FilterRule
		reducedKeys []string
	)

	for i, rule := range rules {
		if r := policyutil.ReduceFilterRules(node.View(), []tailcfg.FilterRule{rule}); len(r) == 1 {
			reduced = append(reduced, r[0])
			reducedKeys = append(reducedKeys, keys[i])
		}
	}

	perNode := mergeKeyedRules(reduced, reducedKeys)

	opts := append(cmpOptions(), cmpopts.EquateEmpty())
	sameAsToday := cmp.Equal(today, perNode, inOrderOpts...)

	alike := sameAsToday || policymodel.Compare(want, perNode, policymodel.ViewFromNetmap(gn.netmap)).Equivalent()
	globalOK := cmp.Diff(want, today, opts...) == ""
	perNodeOK := cmp.Diff(want, perNode, opts...) == ""

	tally.add(func(g *goldenTally) {
		g.mirrors++

		if sameAsToday {
			g.mergeSame = append(g.mergeSame, key)
		} else {
			g.mergeDiffers = append(g.mergeDiffers, fmt.Sprintf("%s, enforced as SaaS's: %t (-today +per-node):\n%s",
				key, alike, cmp.Diff(today, perNode, inOrderOpts...)))
		}

		if globalOK {
			g.globalMatches++
		}

		if perNodeOK {
			g.perNodeMatches++
		}

		if globalOK && !perNodeOK {
			g.pinsGlobal = append(g.pinsGlobal, key)
		}

		if perNodeOK && !globalOK {
			g.pinsPerNode = append(g.pinsPerNode, key)
		}
	})
}

// unmergedRulesForNode is [PolicyManager.unreducedRules] before its merge:
// every rule that reaches node's filter, in policy order, with its key.
func unmergedRulesForNode(pm *PolicyManager, node types.NodeView) ([]tailcfg.FilterRule, []string) {
	var (
		rules []tailcfg.FilterRule
		keys  []string
	)

	for i := range pm.addresses().compiledGrants {
		cg := &pm.addresses().compiledGrants[i]
		rules = append(rules, cg.rules...)
		keys = append(keys, cg.ruleKeys...)

		own := pm.grantRulesFor(i, node)
		if cg.self != nil && node.IsExitNode() {
			own = nil
			for _, uid := range slices.Sorted(maps.Keys(pm.userNodeIdx)) {
				own = append(own, pm.selfFor(i, uid).rules...)
			}
		}

		rules = append(rules, own...)

		for _, rule := range own {
			if cg.via != nil {
				keys = append(keys, viaRuleKey(cg, rule))
			} else {
				keys = append(keys, filterRuleKey(rule))
			}
		}
	}

	return rules, keys
}

// goldenSequenceOracles replays a step capture as
// [runPolicySequenceCompat] does and runs the oracles at every step.
func goldenSequenceOracles(t *testing.T, tally *goldenTally, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)

	users := setupGrantsCompatUsers()
	ids := map[string]types.NodeID{}

	var (
		pm     *PolicyManager
		policy []byte
	)

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if _, ok := ids[a.Node]; a.Kind == "join" && !ok {
				ids[a.Node] = types.NodeID(len(ids) + 1) //nolint:gosec // a handful of nodes
			}
		}

		nodes, _ := sequenceNodes(t, users, step, ids)
		pushed := stepPolicy(t, step)

		if pm == nil {
			policy = pushed
			pm, err = NewPolicyManager(policy, users, nodes.ViewSlice())
			require.NoError(t, err)
		} else {
			_, err = replaceNodes(&pm, nodes.ViewSlice())
			require.NoError(t, err)

			if pushed != nil {
				policy = pushed
				_, err = replacePolicy(&pm, policy)
				require.NoError(t, err)
			}
		}

		pol, err := unmarshalPolicy(policy)
		require.NoError(t, err)

		for _, alias := range slices.Sorted(maps.Keys(step.Captures)) {
			capture := step.Captures[alias]
			if capture.Netmap == nil {
				continue
			}

			node := findGrantsNode(nodes, alias)
			require.NotNil(t, node)

			key := strings.Join([]string{id, step.Name, alias}, "/")

			t.Run(step.Name+"/"+alias, func(t *testing.T) {
				goldenNodeOracles(t, tally, key, goldenNode{
					pm: pm, pol: pol, users: users, nodes: nodes, node: node,
					want: capture.PacketFilterRules, netmap: capture.Netmap,
					compiled: pol.ACLs != nil || pol.Grants != nil,
				})
			})
		}
	}
}
