// Capability-source encoding: the worked examples as headscale writes
// them, the fallback table's completeness, and the oracle every cap-form
// check goes through: a receiver's filter in capability form, enforced by
// the client against the netmap headscale renders for it, must answer
// every probe as its address-form filter does.

package v2

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// officialHostinfo is what a current Tailscale client reports of itself,
// as far as [officialClient] reads.
func officialHostinfo(hi *tailcfg.Hostinfo) *tailcfg.Hostinfo {
	if hi == nil {
		hi = &tailcfg.Hostinfo{}
	}

	hi.GoVersion, hi.IPNVersion = "go1.27.3", "1.94.1-t0123456789ab-g0123456789ab"

	return hi
}

// asOfficial gives every node an official client's Hostinfo.
func asOfficial(nodes types.Nodes) {
	for _, n := range nodes {
		n.Hostinfo = officialHostinfo(n.Hostinfo)
	}
}

// capReceivers is every node's facts, with their policy caps.
func capReceivers(nodes *NodeMap, caps map[types.NodeID]tailcfg.NodeCapMap) Receivers {
	return Receivers{}.Update(nodes, graph.NewMap(func(a, b tailcfg.NodeCapMap) bool { return a.Equal(b) }, caps))
}

// capModel is a side model with filters in both modes and the netmap each
// node is rendered.
type capModel struct {
	*sideModel

	caps      map[types.NodeID]tailcfg.NodeCapMap
	receivers Receivers
	// ip and cap are the filters in address and capability mode.
	ip, cap *Filters
}

func newCapModel(t *testing.T, m *sideModel) *capModel {
	t.Helper()

	cm := &capModel{sideModel: m, caps: m.pm.NodeCapMaps()}
	cm.receivers = capReceivers(m.nodes, cm.caps)
	cm.ip = NewFilters(m.t, m.posts, m.appr, m.list.ViewSlice())
	cm.cap = NewFiltersFor(CapabilitySources, m.t, m.posts, m.appr, m.list.ViewSlice())

	return cm
}

// stamped returns node id as it is rendered, to itself or a peer: its
// addresses, and its CapMap with the stamps it holds.
func (cm *capModel) stamped(id types.NodeID, self bool) *tailcfg.Node {
	n, ok := cm.nodes.Get(id)
	if !ok {
		return nil
	}

	rs, _ := cm.roles.Of(id)

	tn := &tailcfg.Node{ID: tailcfg.NodeID(id), Name: n.GivenName, Addresses: n.Prefixes()} //nolint:gosec // test IDs are small

	// What the world's render caps hold, and what the mapper sends a peer
	// of them.
	caps := WithStamps(cm.caps[id], cm.t.StampsOf(rs))
	tn.CapMap = PeerCapMap(n.View(), caps, true)

	if self {
		tn.CapMap = caps

		hi := &tailcfg.Hostinfo{}
		if n.Hostinfo != nil {
			hi.RoutableIPs = n.Hostinfo.RoutableIPs
			hi.AppConnector = n.Hostinfo.AppConnector
		}

		tn.Hostinfo = hi.View()
	}

	return tn
}

// netmapOf is the netmap node id is rendered in capability mode: itself and
// its peers, stamped.
func (cm *capModel) netmapOf(id types.NodeID) *netmap.NetworkMap {
	nm := &netmap.NetworkMap{SelfNode: cm.stamped(id, true).View()}

	for _, p := range cm.peers.Peers(id) {
		if p != id {
			nm.Peers = append(nm.Peers, cm.stamped(p, false).View())
		}
	}

	return nm
}

// capProbe is what holding one node's capability form to its address form
// found.
type capProbe struct {
	report probeReport
	// crossFamilyICMP counts the verdicts on packets whose ICMP protocol
	// is the other family's, which capability form refuses where address
	// form accepts: decided as malformed, failing closed.
	crossFamilyICMP int
	// other holds every other difference.
	other []string
}

func (p capProbe) equivalent() bool { return len(p.other) == 0 }

// probeCapForm holds cap, a node's filter in capability form, to ip, its
// address form, through the client's filter over the netmap nm it is
// rendered: local nets from its own node, caps from every node.
func probeCapForm(ip, capForm []tailcfg.FilterRule, nm *netmap.NetworkMap) capProbe {
	view := clientViewFromNetmap(nm)

	var out capProbe

	out.report = probeFilters(ip, capForm, view)

	for _, p := range out.report.parse {
		out.other = append(out.other, "unparseable "+p)
	}

	for _, d := range out.report.verdicts {
		crossed := d.probe.proto == ipproto.ICMPv4 && d.probe.src.Is6() || d.probe.proto == ipproto.ICMPv6 && d.probe.src.Is4()
		if crossed && d.ref == filter.Accept && d.cand == filter.Drop {
			out.crossFamilyICMP++

			continue
		}

		out.other = append(out.other, fmt.Sprintf("%s: address form %v, capability form %v", d.probe, d.ref, d.cand))
	}

	for _, d := range out.report.caps {
		out.other = append(out.other, fmt.Sprintf("caps %s -> %s: address form %s, capability form %s",
			d.src, d.dst, peerCapsString(d.ref), peerCapsString(d.cand)))
	}

	return out
}

// requireCapEquivalent holds node id's capability form to its address
// form, and to the expander fed by holders read off its netmap.
func (cm *capModel) requireCapEquivalent(t *testing.T, id types.NodeID, where ...any) capProbe {
	t.Helper()

	ip, err := cm.ip.ForNode(id, ReceiverFacts{})
	require.NoError(t, err)

	capForm, err := cm.cap.ForNode(id, cm.receivers.Of(id))
	require.NoError(t, err)

	nm := cm.netmapOf(id)

	p := probeCapForm(ip, capForm, nm)
	if !p.equivalent() {
		t.Fatalf("%v: node %d enforces its capability form otherwise than its address form:\n  %s\naddress form    %v\ncapability form %v\nnetmap:\n%s",
			where, id, strings.Join(p.other, "\n  "), ip, capForm, describeNetmap(nm))
	}

	return p
}

func describeNetmap(nm *netmap.NetworkMap) string {
	var b strings.Builder

	for _, n := range append([]tailcfg.NodeView{nm.SelfNode}, nm.Peers...) {
		fmt.Fprintf(&b, "  %d %v caps=%v\n", n.ID(), n.Addresses().AsSlice(), slices.Sorted(maps.Keys(n.CapMap().AsMap())))
	}

	return b.String()
}

// exampleModel is the worked-example tailnet with official clients.
func exampleModel(t *testing.T, policy string) *capModel {
	t.Helper()

	users, nodes := exampleTailnet()
	asOfficial(nodes)

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	return newCapModel(t, newSideModel(t, pm, users, nodes))
}

func (cm *capModel) byName(t *testing.T, name string) types.NodeID {
	t.Helper()

	n := findNodeByGivenName(cm.list, name)
	require.NotNilf(t, n, "no node %q", name)

	return n.ID
}

// TestCapFormWorkedExamples pins the wire form of the design's worked
// examples, and holds each to its address form through the client.
func TestCapFormWorkedExamples(t *testing.T) {
	t.Parallel()

	tcp := func(port uint16) []tailcfg.NetPortRange { return web1Dsts(port, port) }
	src := func(c string) string { return capSourcePrefix + c }

	tests := []struct {
		name, policy, receiver string
		want                   []tailcfg.FilterRule
	}{
		{
			name:     "eligible rule, mixed sources, an empty group, self",
			policy:   examplePolicy,
			receiver: "web1",
			want: []tailcfg.FilterRule{
				capRule(tcp(443), []int{6}, src(capGroupEng)),
				capRule(tcp(80), []int{6}, "192.168.1.0/24", src(capGroupEng)),
				capRule(tcp(8080), []int{6}, src(capMember)),
				capRule(tcp(9000), []int{6}, src(capEmpty)),
			},
		},
		{
			name:     "autogroup:self by the owner's capability",
			policy:   examplePolicy,
			receiver: "alice-laptop",
			want: []tailcfg.FilterRule{capRule([]tailcfg.NetPortRange{
				{IP: "100.64.0.1", Ports: tailcfg.PortRangeAny},
				{IP: "fd7a:115c:a1e0::1", Ports: tailcfg.PortRangeAny},
			}, nil, src(capOwner1))},
		},
		{
			name:     "a router announcing routes is sent addresses",
			policy:   `{"groups": {"group:eng": ["alice@example.com", "bob@example.com"]}, "grants": [{"src": ["group:eng"], "dst": ["10.0.0.0/24"], "ip": ["*"]}]}`,
			receiver: "r1",
			want: []tailcfg.FilterRule{{
				SrcIPs:   engSrcIPs,
				DstPorts: []tailcfg.NetPortRange{{IP: "10.0.0.0/24", Ports: tailcfg.PortRangeAny}},
			}},
		},
		{
			name: "an app capability rule is sent addresses, the port rule beside it capabilities",
			policy: `{"tagOwners": {"tag:web": ["alice@example.com"]}, "grants": [
				{"src": ["autogroup:member"], "dst": ["tag:web"], "ip": ["tcp:443"], "app": {"example.com/cap/admin": [{"role": "ops"}]}}]}`,
			receiver: "web1",
			want: []tailcfg.FilterRule{
				capRule(tcp(443), []int{6}, src(capMember)),
				{SrcIPs: engSrcIPs, CapGrant: []tailcfg.CapGrant{{
					Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32"), netip.MustParsePrefix("fd7a:115c:a1e0::a/128")},
					CapMap: tailcfg.PeerCapMap{capAppAdmin: {`{"role": "ops"}`}},
				}}},
			},
		},
		{
			name:     "a protocol without ports is sent addresses",
			policy:   `{"tagOwners": {"tag:web": ["alice@example.com"], "tag:db": ["alice@example.com"]}, "grants": [{"src": ["tag:web"], "dst": ["tag:db"], "ip": ["gre:*"]}]}`,
			receiver: "db1",
			want: []tailcfg.FilterRule{{
				SrcIPs: []string{"100.64.0.10", "fd7a:115c:a1e0::a"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "100.64.0.20", Ports: tailcfg.PortRangeAny},
					{IP: "fd7a:115c:a1e0::14", Ports: tailcfg.PortRangeAny},
				},
				IPProto: []int{ProtocolGRE},
			}},
		},
		{
			name:     "* stays literal",
			policy:   `{"tagOwners": {"tag:web": ["alice@example.com"]}, "grants": [{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:443"]}]}`,
			receiver: "web1",
			want: []tailcfg.FilterRule{capRule(tcp(443), []int{6},
				"10.0.0.0/24", "100.115.94.0-100.127.255.255", "100.64.0.0-100.115.91.255", "fd7a:115c:a1e0::/48")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cm := exampleModel(t, tc.policy)
			id := cm.byName(t, tc.receiver)

			got, err := cm.cap.ForNode(id, cm.receivers.Of(id))
			require.NoError(t, err)

			if diff := cmp.Diff(tc.want, got, inOrderOpts...); diff != "" {
				t.Errorf("capability form (-want +got):\n%s", diff)
			}

			cm.requireCapEquivalent(t, id, tc.name)
		})
	}
}

// TestCapFormEveryExampleNodeEquivalent holds every node of the worked
// example to its address form under the example policy.
func TestCapFormEveryExampleNodeEquivalent(t *testing.T) {
	t.Parallel()

	cm := exampleModel(t, examplePolicy)
	for _, n := range cm.list {
		cm.requireCapEquivalent(t, n.ID)
	}
}

var (
	_ = os.ReadFile
	_ = regexp.MustCompile
	_ = ast.Inspect
	_ = parser.ParseFile
	_ = token.NewFileSet
	_ = nodecap.Cap("")
	_ = views.Slice[int]{}
)

// capReach counts what the capability checks reached, so a run that never
// met a shape fails instead of passing vacuously.
type capReach map[string]int

// reach cuts node id's capability form again with its decisions logged,
// and counts what it met.
func (cm *capModel) reach(t *testing.T, id types.NodeID, p capProbe, reach capReach) {
	t.Helper()

	x, err := cm.cap.expansion()
	require.NoError(t, err)

	n, ok := cm.cap.node(id)
	require.True(t, ok)

	var log formLog

	rules := x.cutFor(n, CapabilitySources, cm.receivers.Of(id), &log)
	requireNoStrayAddresses(t, rules, log)

	reach["receivers"]++
	reach["receivers: "+log.layout.String()]++
	reach["cross-family ICMP refused"] += p.crossFamilyICMP

	if f := cm.receivers.Of(id); f.AppConnector {
		reach["app connectors"]++
	}

	if n.IsExitNode() {
		reach["exit nodes"]++
	}

	if n.IsSubnetRouter() {
		reach["subnet routers"]++
	}

	for i, rule := range rules {
		if log.layout != reasonNone {
			continue
		}

		if hasCapSource(rule) {
			reach["rules with capabilities"]++
		}

		if slices.ContainsFunc(rule.SrcIPs, func(s string) bool { return strings.Contains(s, "/owner:") }) {
			reach["owner capabilities"]++
		}

		for _, why := range log.rules[i] {
			reach["rules: "+why.String()]++
		}
	}
}

// require fails for every shape the capability checks must reach.
func (r capReach) require(t *testing.T) {
	t.Helper()

	want := []string{
		"receivers: capability", "receivers: client", "receivers: local-nets",
		"rules with capabilities", "owner capabilities",
		"rules: cap-grant", "rules: literal", "rules: shared-address",
		"cross-family ICMP refused", "rules: portless", "app connectors", "exit nodes", "subnet routers",
	}

	for _, k := range want {
		if r[k] == 0 {
			t.Errorf("shape %q not reached: %v", k, r)
		}
	}
}

// requireNoStrayAddresses fails when a rule cut in capability form carries
// a source as addresses that no decision of [sourceForm]'s covers: every
// rule with a source other than a capability must have been decided so.
func requireNoStrayAddresses(t *testing.T, rules []tailcfg.FilterRule, log formLog) {
	t.Helper()

	if log.layout != reasonNone {
		return
	}

	require.Len(t, log.rules, len(rules), "a decision per rule cut")

	for i, rule := range rules {
		stray := slices.ContainsFunc(rule.SrcIPs, func(s string) bool { return !strings.HasPrefix(s, capSourcePrefix) })
		if stray && len(log.rules[i]) == 0 {
			t.Fatalf("rule %v carries address sources no fallback decided", rule)
		}

		if !stray && len(rule.SrcIPs) > 0 && len(log.rules[i]) > 0 && len(rule.CapGrant) == 0 {
			t.Fatalf("rule %v is recorded as sending addresses for %v, and sends none", rule, log.rules[i])
		}
	}
}

// goldenCapTally collects what the cap-form golden checks saw.
type goldenCapTally struct {
	mu sync.Mutex

	files, loads, filters, saasCompared, probes, crossFamily int
	// forms counts captured filters by form: fully capability, partly,
	// or fully address with the reason.
	forms   map[string]int
	reasons map[string]int
	listed  []string
	stamped int
}

func (g *goldenCapTally) add(f func(*goldenCapTally)) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f(g)
}

// TestGoldenCapForm runs checks A and B on capability form over every
// capture: each captured node's filter cut in capability form, with the
// netmap headscale renders it (its peers and itself, stamped), must
//
//   - (A) expand, through the expander fed by holders the client's own
//     HasCap reads off that netmap, to the hosted service's captured
//     filter as a rule multiset, and to headscale's address form;
//   - (B) answer every probe through the client's real packet filter, with
//     its capability lookup over that netmap, as the captured filter and
//     headscale's address form do, but for cross-family ICMP, which
//     capability form refuses (decided: malformed, fails closed).
func TestGoldenCapForm(t *testing.T) {
	t.Parallel()

	tally := &goldenCapTally{forms: map[string]int{}, reasons: map[string]int{}}

	t.Cleanup(func() {
		t.Logf("capture files %d, policy loads %d, captured filters %d (%d against SaaS, %d probes, %d cross-family ICMP refusals), %d stamps on rendered nodes",
			tally.files, tally.loads, tally.filters, tally.saasCompared, tally.probes, tally.crossFamily, tally.stamped)
		t.Logf("filters by form: %v", tally.forms)
		t.Logf("rules sent addresses in otherwise capability-form filters, by reason: %v", tally.reasons)
		slices.Sort(tally.listed)
		t.Logf("listed divergences from SaaS, held to headscale's address form only: %v", tally.listed)
	})

	for _, src := range goldenFilterSources() {
		files, err := filepath.Glob(filepath.Join("testdata", src.dir, src.glob))
		require.NoError(t, err)

		for _, file := range files {
			t.Run(filepath.Join(src.dir, filepath.Base(file)), func(t *testing.T) {
				t.Parallel()

				c, err := testcapture.Read(file)
				require.NoError(t, err)

				tally.add(func(g *goldenCapTally) { g.files++ })

				if c.Error || c.Input.APIResponseCode != 200 {
					return
				}

				users, nodes := src.build(t, c)
				asOfficial(nodes)

				pm, err := NewPolicyManager([]byte(c.Input.FullPolicy), users, nodes.ViewSlice())
				if err != nil {
					return
				}

				cm := newCapModel(t, newSideModel(t, pm, users, nodes))

				tally.add(func(g *goldenCapTally) { g.loads++ })

				for _, alias := range slices.Sorted(maps.Keys(c.Captures)) {
					capture := c.Captures[alias]
					if capture.Netmap == nil {
						continue
					}

					node := findNodeByGivenName(nodes, alias)
					require.NotNilf(t, node, "%s: node %s not built", c.TestID, alias)

					goldenCapNode(t, tally, cm, c.TestID+"/"+alias+"/manager", node.ID, capture.PacketFilterRules)
				}
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		goldenCapSequence(t, tally, "policy-generation")
	})
}

// capCheck is checks A and B on one node's capability form: what each
// found, for a caller to require or to count.
type capCheck struct {
	ip, capForm []tailcfg.FilterRule
	nm          *netmap.NetworkMap
	log         formLog
	// sameAsIP and sameAsSaaS hold check A's differences; own and saas
	// check B's.
	diffIP, diffSaaS string
	own, saas        capProbe
}

func (c capCheck) failures() []string {
	var out []string

	if c.diffIP != "" {
		out = append(out, "A against address form:\n"+c.diffIP)
	}

	if c.diffSaaS != "" {
		out = append(out, "A against SaaS:\n"+c.diffSaaS)
	}

	for _, p := range []struct {
		what string
		p    capProbe
	}{{"B against address form", c.own}, {"B against SaaS", c.saas}} {
		if !p.p.equivalent() {
			out = append(out, p.what+":\n  "+strings.Join(p.p.other, "\n  "))
		}
	}

	return out
}

// checkCapForm runs checks A and B on node id: against its address form
// and, when saas is not nil, against the hosted service's filter.
func (cm *capModel) checkCapForm(t *testing.T, id types.NodeID, saas []tailcfg.FilterRule) capCheck {
	t.Helper()

	var c capCheck

	var err error

	c.ip, err = cm.ip.ForNode(id, ReceiverFacts{})
	require.NoError(t, err)

	c.capForm, err = cm.cap.ForNode(id, cm.receivers.Of(id))
	require.NoError(t, err)

	c.nm = cm.netmapOf(id)
	nc := newNetmapCaps(c.nm.SelfNode, c.nm.Peers)

	x, err := cm.cap.expansion()
	require.NoError(t, err)

	n, _ := cm.cap.node(id)

	rules := x.cutFor(n, CapabilitySources, cm.receivers.Of(id), &c.log)
	requireNoStrayAddresses(t, rules, c.log)
	require.Equal(t, c.capForm, rules, "the served cut is the logged one")

	if c.log.layout != reasonNone {
		// Sent as address mode writes it, which the compat tests and A′
		// hold to SaaS.
		if !reflect.DeepEqual(c.ip, c.capForm) {
			c.diffIP = fmt.Sprintf("sent addresses for %s, yet unlike address form:\naddress %v\nsent    %v", c.log.layout, c.ip, c.capForm)
		}
	} else {
		// A: back to addresses through the netmap's holders, merged as
		// the compile merges: capability form keeps each grant's rules
		// apart. No via rule is cut in capability form, so no merge
		// class is needed.
		expanded := expandFilter(capFilter{rules: c.capForm}, nc.holders, reasonAddressMode)
		c.diffIP = cmp.Diff(ruleMultiset(c.ip), ruleMultiset(expanded))

		if saas != nil {
			c.diffSaaS = cmp.Diff(ruleMultiset(saas), ruleMultiset(expanded))
		}
	}

	// B: through the client.
	c.own = probeCapForm(c.ip, c.capForm, c.nm)
	if saas != nil {
		c.saas = probeCapForm(saas, c.capForm, c.nm)
	}

	return c
}

// form names how a checked filter was sent.
func (c capCheck) form() (string, map[string]bool) {
	reasons := map[string]bool{}

	switch {
	case len(c.capForm) == 0:
		return "empty", reasons
	case c.log.layout != reasonNone:
		return "address: " + c.log.layout.String(), reasons
	}

	for _, rs := range c.log.rules {
		for _, r := range rs {
			reasons[r.String()] = true
		}
	}

	with := strings.Join(slices.Sorted(maps.Keys(reasons)), "+")

	switch {
	case slices.ContainsFunc(c.capForm, hasCapSource) && len(reasons) == 0:
		return "capability", reasons
	case slices.ContainsFunc(c.capForm, hasCapSource):
		return "capability, addresses for " + with, reasons
	default:
		return "no capability source, addresses for " + with, reasons
	}
}

// goldenCapSequence runs [goldenCapNode] over every step of a step capture,
// compiling each step's tailnet afresh.
func goldenCapSequence(t *testing.T, tally *goldenCapTally, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)

	users := setupGrantsCompatUsers()
	ids := map[string]types.NodeID{}

	var policy []byte

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if _, ok := ids[a.Node]; a.Kind == "join" && !ok {
				ids[a.Node] = types.NodeID(len(ids) + 1) //nolint:gosec // a handful of nodes
			}
		}

		nodes, _ := sequenceNodes(t, users, step, ids)
		if pushed := stepPolicy(t, step); pushed != nil {
			policy = pushed
		}

		slices.SortFunc(nodes, func(a, b *types.Node) int {
			switch {
			case a.ID < b.ID:
				return -1
			case a.ID > b.ID:
				return 1
			}

			return 0
		})
		asOfficial(nodes)

		pm, err := NewPolicyManager(policy, users, nodes.ViewSlice())
		require.NoError(t, err)

		cm := newCapModel(t, newSideModel(t, pm, users, nodes))

		for _, alias := range slices.Sorted(maps.Keys(step.Captures)) {
			capture := step.Captures[alias]
			if capture.Netmap == nil {
				continue
			}

			node := findGrantsNode(nodes, alias)
			require.NotNil(t, node)

			key := strings.Join([]string{id, step.Name, alias, "manager"}, "/")
			goldenCapNode(t, tally, cm, key, node.ID, capture.PacketFilterRules)
		}
	}
}

func goldenCapNode(t *testing.T, tally *goldenCapTally, cm *capModel, key string, id types.NodeID, saas []tailcfg.FilterRule) {
	t.Helper()

	_, listed := goldenProbeDivergences[key]
	if listed {
		saas = nil
	}

	c := cm.checkCapForm(t, id, saas)
	for _, f := range c.failures() {
		t.Errorf("%s: %s\ncapability form %v", key, f, c.capForm)
	}

	form, reasons := c.form()

	stamps := 0
	for _, p := range append([]tailcfg.NodeView{c.nm.SelfNode}, c.nm.Peers...) {
		stamps += p.CapMap().Len()
	}

	tally.add(func(g *goldenCapTally) {
		g.filters++
		g.probes += c.own.report.probes + c.saas.report.probes
		g.crossFamily += c.own.crossFamilyICMP
		g.forms[form]++
		g.stamped += stamps

		if !listed {
			g.saasCompared++
		} else {
			g.listed = append(g.listed, key)
		}

		for r := range reasons {
			g.reasons[r]++
		}
	})
}

// TestFallbackReasonsComplete holds every reason to its row, its TODO and
// its canary, so the TODOs in fallback.go are the complete list of what
// closes as the client improves: a permanent reason has none, a client
// one has exactly one, naming the canary its row names, which exists.
func TestFallbackReasonsComplete(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("fallback.go")
	require.NoError(t, err)

	todo := regexp.MustCompile(`TODO\(capsrc/([a-z-]+)\): lift when (.+); canary (.+)`)
	todos := map[string][]string{}

	for _, m := range todo.FindAllStringSubmatch(string(src), -1) {
		todos[m[1]] = append(todos[m[1]], m[2]+"|"+m[3])
	}

	tests := testFuncs(t)
	labels := map[string]bool{}

	require.Equal(t, "capability", reasonNone.String())

	for r := reasonNone + 1; r < numReasons; r++ {
		d := reasonDocs[r]

		require.Regexpf(t, `^[a-z][a-z-]*$`, d.label, "reason %d has a metric label", r)
		require.Falsef(t, labels[d.label], "label %q is unique", d.label)
		labels[d.label] = true

		require.NotEmptyf(t, d.scope, "%s has a scope", d.label)
		require.NotEmptyf(t, d.lift, "%s says when it lifts", d.label)

		switch d.kind {
		case kindNone:
			t.Fatalf("%s has no kind", d.label)
		case kindPermanent:
			require.Truef(t, strings.HasPrefix(d.lift, "never"), "permanent %s never lifts", d.label)
			require.Emptyf(t, todos[d.label], "permanent %s carries no TODO", d.label)
		case kindClient:
			require.NotEmptyf(t, d.canary, "%s names its canary", d.label)
			require.Equalf(t, []string{d.lift + "|" + d.canary}, todos[d.label],
				"%s carries one TODO, with its row's lift condition and canary", d.label)

			require.Truef(t, tests[d.canary], "%s's canary %s is a test here or in integration", d.label, d.canary)
		}

		delete(todos, d.label)
	}

	require.Empty(t, todos, "every capsrc TODO in fallback.go is a reason's")
	require.Equal(t, slices.Sorted(maps.Keys(labels)), slices.Sorted(slices.Values(FallbackReasons())), "metric labels")
}

// testFuncs returns the names of the package's test functions and of the
// integration tests, where a canary needing a client headscale cannot run
// in-process lives.
func testFuncs(t *testing.T) map[string]bool {
	t.Helper()

	files, err := filepath.Glob("*_test.go")
	require.NoError(t, err)

	integration, err := filepath.Glob("../../../integration/*_test.go")
	require.NoError(t, err)
	require.NotEmpty(t, integration, "the integration tests are found")

	files = append(files, integration...)

	out := map[string]bool{}
	fset := token.NewFileSet()

	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		require.NoError(t, err)

		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
				out[fn.Name.Name] = true
			}
		}
	}

	return out
}

// TestOnlyFallbackDecidesForm fails when code outside fallback.go names a
// reason a source goes as addresses, or switches one off: only the
// decision functions there choose. Outside, a cut compares what they
// return with reasonNone, and the address-mode expander, which writes
// everything as addresses, names reasonAddressMode. Every cut in capability
// form is also checked for address sources no decision covers, over the
// goldens and the random topologies ([requireNoStrayAddresses]).
func TestOnlyFallbackDecidesForm(t *testing.T) {
	t.Parallel()

	reasons := map[string]bool{"fallbacksOff": true, "applies": true}
	for r := reasonNone + 1; r < numReasons; r++ {
		reasons[reasonConst(r)] = true
	}

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	fset := token.NewFileSet()

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "fallback.go" {
			continue
		}

		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		require.NoError(t, err)

		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}

			ast.Inspect(fn, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || !reasons[id.Name] {
					return true
				}

				if id.Name == "reasonAddressMode" && slices.Contains([]string{"expandCapSources", "FilterForNode", "AuditFilters"}, fn.Name.Name) {
					return true
				}

				t.Errorf("%s: %s names %s; only fallback.go decides why a source goes as addresses", fset.Position(id.Pos()), fn.Name.Name, id.Name)

				return true
			})
		}
	}
}

// reasonConst is the identifier of reason r, as fallback.go declares it.
func reasonConst(r ipReason) string {
	return map[ipReason]string{
		reasonAddressMode: "reasonAddressMode", reasonClient: "reasonClient", reasonLocalNets: "reasonLocalNets",
		reasonCapGrant: "reasonCapGrant", reasonPortless: "reasonPortless", reasonLiteral: "reasonLiteral",
		reasonSharedAddress: "reasonSharedAddress",
	}[r]
}

// sensitivityFixture is a tailnet where switching one fallback off must
// make the client enforce a node's capability form otherwise than its
// address form.
type sensitivityFixture struct {
	policy   string
	receiver string
	// tweak edits the tailnet before it compiles.
	tweak func(types.Nodes)
	// lookup, when set, replaces the client's capability lookup: a client
	// that looks nothing up has none.
	noLookup bool
}

var sensitivityFixtures = map[ipReason]sensitivityFixture{
	reasonClient: {
		policy:   `{"tagOwners": {"tag:web": ["alice@example.com"]}, "grants": [{"src": ["autogroup:member"], "dst": ["tag:web"], "ip": ["tcp:443"]}]}`,
		receiver: "web1",
		tweak:    func(n types.Nodes) { n[2].Hostinfo = &tailcfg.Hostinfo{App: "tailscale-rs"} },
		noLookup: true,
	},
	reasonLocalNets: {
		policy:   `{"groups": {"group:eng": ["alice@example.com"]}, "grants": [{"src": ["group:eng"], "dst": ["10.0.0.5"], "ip": ["tcp:22"]}]}`,
		receiver: "r1",
	},
	reasonCapGrant: {
		policy: `{"tagOwners": {"tag:web": ["alice@example.com"]}, "grants": [
			{"src": ["autogroup:member"], "dst": ["tag:web"], "app": {"example.com/cap/admin": [{"role": "ops"}]}}]}`,
		receiver: "web1",
	},
	reasonPortless: {
		policy:   `{"tagOwners": {"tag:web": ["alice@example.com"], "tag:db": ["alice@example.com"]}, "grants": [{"src": ["tag:web"], "dst": ["tag:db"], "ip": ["gre:*"]}]}`,
		receiver: "db1",
	},
	reasonLiteral: {
		policy:   `{"tagOwners": {"tag:web": ["alice@example.com"]}, "grants": [{"src": ["100.64.0.0/24"], "dst": ["tag:web"], "ip": ["tcp:443"]}]}`,
		receiver: "web1",
	},
	reasonSharedAddress: {
		// db1, outside group:eng, holds alice's IPv4 address; the client
		// asks the node it indexed last, db1.
		policy: `{"groups": {"group:eng": ["alice@example.com"]}, "tagOwners": {"tag:web": ["alice@example.com"], "tag:db": ["alice@example.com"]},
			"grants": [{"src": ["group:eng"], "dst": ["tag:web", "tag:db"], "ip": ["tcp:443"]}]}`,
		receiver: "web1",
		tweak:    func(n types.Nodes) { n[3].IPv4 = new(netip.MustParseAddr("100.64.0.1")) },
	},
}

// fixtureModel is the worked example with f applied.
func (f sensitivityFixture) model(t *testing.T) *capModel {
	t.Helper()

	users, nodes := exampleTailnet()
	asOfficial(nodes)
	nodes[3].Tags = []string{"tag:db"}

	if f.tweak != nil {
		f.tweak(nodes)
	}

	pm, err := NewPolicyManager([]byte(f.policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	return newCapModel(t, newSideModel(t, pm, users, nodes))
}

// probe holds the receiver's capability form to its address form.
func (f sensitivityFixture) probe(t *testing.T) capProbe {
	t.Helper()

	cm := f.model(t)
	id := cm.byName(t, f.receiver)

	ip, err := cm.ip.ForNode(id, ReceiverFacts{})
	require.NoError(t, err)

	capForm, err := cm.cap.ForNode(id, cm.receivers.Of(id))
	require.NoError(t, err)

	nm := cm.netmapOf(id)
	if !f.noLookup {
		return probeCapForm(ip, capForm, nm)
	}

	view := clientViewFromNetmap(nm)
	view.hasCap = nil

	rep := probeFilters(ip, capForm, view)

	var p capProbe

	p.report = rep
	if !rep.equivalent() {
		p.other = append(p.other, rep.String())
	}

	return p
}

// TestFallbackSensitivity switches each fallback off in turn and requires
// check B to notice on its fixture; with
// HEADSCALE_FALLBACK_SENSITIVITY_GOLDENS set it also counts the captured
// filters checks A and B then tell apart. A fallback whose removal nothing
// notices is unneeded or untested. Not parallel: it switches fallbacks off
// for the package.
func TestFallbackSensitivity(t *testing.T) { //nolint:paralleltest // switches fallbacks off for the package
	for r, f := range sensitivityFixtures {
		require.Truef(t, f.probe(t).equivalent(), "%s: the fixture is enforced alike with every fallback on", r)
	}

	// The goldens take minutes, one pass per reason.
	goldens := os.Getenv("HEADSCALE_FALLBACK_SENSITIVITY_GOLDENS") != ""

	for r := reasonClient; r < numReasons; r++ {
		f, ok := sensitivityFixtures[r]
		require.Truef(t, ok, "%s has a sensitivity fixture", r)

		t.Run(r.String(), func(t *testing.T) {
			fallbacksOff[r] = true

			t.Cleanup(func() { fallbacksOff[r] = false })

			p := f.probe(t)
			require.Falsef(t, p.equivalent(), "with %s off, its fixture is still enforced alike", r)
			t.Logf("fixture: %d of %d probes and %d capability lookups differ", len(p.report.verdicts), p.report.probes, len(p.report.caps))

			if goldens {
				t.Logf("goldens: %s", sensitivityOnGoldens(t))
			}
		})
	}
}

// sensitivityOnGoldens counts the captured filters check B or A tells
// apart from address form.
func sensitivityOnGoldens(t *testing.T) string {
	t.Helper()

	var filters, differ int

	for _, src := range goldenFilterSources() {
		files, err := filepath.Glob(filepath.Join("testdata", src.dir, src.glob))
		require.NoError(t, err)

		for _, file := range files {
			c, err := testcapture.Read(file)
			require.NoError(t, err)

			if c.Error || c.Input.APIResponseCode != 200 {
				continue
			}

			users, nodes := src.build(t, c)
			asOfficial(nodes)

			pm, err := NewPolicyManager([]byte(c.Input.FullPolicy), users, nodes.ViewSlice())
			if err != nil {
				continue
			}

			cm := newCapModel(t, newSideModel(t, pm, users, nodes))

			for alias, capture := range c.Captures {
				if capture.Netmap == nil {
					continue
				}

				node := findNodeByGivenName(nodes, alias)
				require.NotNil(t, node)

				filters++

				if len(cm.checkCapForm(t, node.ID, nil).failures()) > 0 {
					differ++
				}
			}
		}
	}

	return fmt.Sprintf("%d of %d captured filters told apart from address form", differ, filters)
}

// TestSourceCapNamespaceReserved pins that nothing a policy author writes
// lands in the namespace of source capabilities: nodeAttrs cannot grant
// one and app grants cannot name one, with or without the scheme; and
// that a capability in it reaching a CapMap otherwise is dropped there.
func TestSourceCapNamespaceReserved(t *testing.T) {
	t.Parallel()

	users, nodes := exampleTailnet()

	for _, tc := range []struct{ name, policy string }{
		{"nodeAttrs", `{"nodeAttrs": [{"target": ["*"], "attr": ["https://headscale.net/cap/src/group:eng"]}]}`},
		{"app", `{"grants": [{"src": ["*"], "dst": ["*"], "app": {"headscale.net/cap/src/group:eng": [{}]}}]}`},
		{"app with scheme", `{"grants": [{"src": ["*"], "dst": ["*"], "app": {"https://headscale.net/cap/src/owner:1": [{}]}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewPolicyManager([]byte(tc.policy), users, nodes.ViewSlice())
			require.ErrorIs(t, err, ErrCapReserved)
		})
	}

	caps := tailcfg.NodeCapMap{"https://headscale.net/cap/src/group:eng": nil, nodecap.SSH: nil}
	got := WithStamps(caps, Stamps{selectorCapPrefix + "tag:web"})
	require.Equal(t, tailcfg.NodeCapMap{nodecap.SSH: nil, selectorCapPrefix + "tag:web": nil}, got)

	plain := tailcfg.NodeCapMap{nodecap.SSH: nil}
	require.Equal(t, fmt.Sprintf("%p", plain), fmt.Sprintf("%p", WithStamps(plain, nil)), "nothing to add or drop keeps the map")
}

// TestStampNotionsUnderSharedAddresses works out what "holds a selector"
// must mean for the client's lookup to agree with address form, with the
// probe harness. db1, outside group:eng, holds alice's IPv4 address and
// an IPv6 address of its own; web1 receives group:eng's rule.
//
//   - Stamped by membership, sent capabilities: the client asks db1, which
//     it indexed last, about the shared address and refuses alice there:
//     narrower than address form.
//   - Stamped as the sides count holding, a member's address included: db1
//     is admitted from its own IPv6 address too: wider than address form.
//   - Stamped by membership, the selector sent as addresses wherever a
//     node outside holds a member's address (reasonSharedAddress): alike.
//
// With no address shared, membership is exact: every address of a member
// is a source, and no address of a non-member is.
func TestStampNotionsUnderSharedAddresses(t *testing.T) { //nolint:paralleltest // switches a fallback off
	f := sensitivityFixtures[reasonSharedAddress]
	db1v6 := netip.MustParseAddr("fd7a:115c:a1e0::14")

	t.Run("membership, address form where shared", func(t *testing.T) {
		require.True(t, f.probe(t).equivalent())
	})

	fallbacksOff[reasonSharedAddress] = true

	defer func() { fallbacksOff[reasonSharedAddress] = false }()

	t.Run("membership", func(t *testing.T) {
		p := f.probe(t)
		require.False(t, p.equivalent())

		for _, d := range p.report.verdicts {
			require.Equalf(t, canaryAlice, d.probe.src, "only the shared address differs: %v", d.probe)
			require.Equal(t, filter.Accept, d.ref)
			require.Equal(t, filter.Drop, d.cand, "narrower, never wider")
		}
	})

	t.Run("holding a member's address", func(t *testing.T) {
		cm := f.model(t)
		id := cm.byName(t, f.receiver)

		ip, err := cm.ip.ForNode(id, ReceiverFacts{})
		require.NoError(t, err)

		capForm, err := cm.cap.ForNode(id, cm.receivers.Of(id))
		require.NoError(t, err)

		nm := cm.netmapOf(id)
		for i, p := range nm.Peers {
			if p.Name() == "db1" {
				n := p.AsStruct()
				n.CapMap = tailcfg.NodeCapMap{capGroupEng: nil}
				nm.Peers[i] = n.View()
			}
		}

		p := probeCapForm(ip, capForm, nm)
		require.True(t, slices.ContainsFunc(p.report.verdicts, func(d verdictDiff) bool {
			return d.probe.src == db1v6 && d.ref == filter.Drop && d.cand == filter.Accept
		}), "db1 admitted from its own address: %s", p.report)
	})
}

// TestFallbackCensus pins what the census counts on the worked example:
// the router sent addresses for its routes, the others capabilities; the
// rule with a host source counted as literal, the others as capability.
func TestFallbackCensus(t *testing.T) {
	t.Parallel()

	cm := exampleModel(t, examplePolicy)

	c, err := cm.cap.Census(cm.receivers)
	require.NoError(t, err)

	receivers, rules := c.Labelled()
	require.Equal(t, 1, receivers["local-nets"], "r1 announces a route")
	require.Equal(t, 4, receivers["capability"])
	require.Equal(t, 1, rules["literal"], "office is a host")
	require.Equal(t, 3+2, rules["capability"], "three port grants, the self grant once per owner")

	c, err = cm.ip.Census(cm.receivers)
	require.NoError(t, err)
	require.Equal(t, FallbackCensus{}, c, "address mode counts nothing")
}

// TestAgreesWithAddressFormCatchesMissingStamp pins the runtime audit's
// check: capability form expanded through the holders must say what
// address form says, so a member left unstamped, or a non-member stamped,
// is reported, and an address listed twice is not.
func TestAgreesWithAddressFormCatchesMissingStamp(t *testing.T) {
	t.Parallel()

	cm := exampleModel(t, examplePolicy)
	id := cm.byName(t, "web1")

	ip, err := cm.ip.ForNode(id, ReceiverFacts{})
	require.NoError(t, err)

	capForm, err := cm.cap.ForNode(id, cm.receivers.Of(id))
	require.NoError(t, err)

	nm := cm.netmapOf(id)
	nc := newNetmapCaps(nm.SelfNode, nm.Peers)
	require.NoError(t, AgreesWithAddressForm(capForm, ip, nc.holders))

	// Two nodes holding one address: address form lists it once per node.
	twice := slices.Clone(ip)
	i := slices.IndexFunc(twice, func(r tailcfg.FilterRule) bool { return len(r.SrcIPs) > 0 && len(r.DstPorts) > 0 })
	require.GreaterOrEqual(t, i, 0, "test sanity: web1 receives address rules")
	twice[i].SrcIPs = append(slices.Clone(twice[i].SrcIPs), twice[i].SrcIPs[0])
	twice[i].DstPorts = append(slices.Clone(twice[i].DstPorts), twice[i].DstPorts[0])
	require.NoError(t, AgreesWithAddressForm(capForm, twice, nc.holders), "an address listed twice")

	withoutBob := func(c nodecap.Cap) []netip.Addr {
		return slices.DeleteFunc(nc.holders(c), func(a netip.Addr) bool { return a == canaryBob || a.String() == "fd7a:115c:a1e0::2" })
	}
	require.ErrorIs(t, AgreesWithAddressForm(capForm, ip, withoutBob), errCapForm, "bob unstamped")

	withDB := func(c nodecap.Cap) []netip.Addr {
		return append(nc.holders(c), netip.MustParseAddr("100.64.0.20"))
	}
	require.ErrorIs(t, AgreesWithAddressForm(capForm, ip, withDB), errCapForm, "db1 stamped")
}

// TestReceiverFormFollowsFacts pins each fact that sends a receiver's whole
// filter as addresses, from the node it is read off: every way a client is
// told apart from Tailscale's, and every way its local nets exceed its own
// addresses, an exit node's default routes among them.
func TestReceiverFormFollowsFacts(t *testing.T) {
	t.Parallel()

	official := func(tweak func(*tailcfg.Hostinfo)) *tailcfg.Hostinfo {
		hi := officialHostinfo(nil)
		if tweak != nil {
			tweak(hi)
		}

		return hi
	}

	for _, tt := range []struct {
		name string
		hi   *tailcfg.Hostinfo
		caps tailcfg.NodeCapMap
		want ipReason
	}{
		{"official client", official(nil), nil, reasonNone},
		{"no hostinfo", nil, nil, reasonClient},
		{"tailscale-rs by name", official(func(hi *tailcfg.Hostinfo) { hi.App = "tailscale-rs (tsrs-1)" }), nil, reasonClient},
		{"no Go version", official(func(hi *tailcfg.Hostinfo) { hi.GoVersion = "" }), nil, reasonClient},
		{"a crate's version", official(func(hi *tailcfg.Hostinfo) { hi.IPNVersion = "0.6.1" }), nil, reasonClient},
		{"a release headscale no longer serves", official(func(hi *tailcfg.Hostinfo) { hi.IPNVersion = "1.10.0" }), nil, reasonClient},
		{"announcing a subnet", official(func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")} }), nil, reasonLocalNets},
		{"an exit node", official(func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = tsaddr.ExitRoutes() }), nil, reasonLocalNets},
		{"an app connector", official(func(hi *tailcfg.Hostinfo) { hi.AppConnector.Set(true) }), nil, reasonLocalNets},
		{"a service host", official(nil), tailcfg.NodeCapMap{nodecap.ServiceHost: nil}, reasonLocalNets},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			n := &types.Node{ID: 1, Hostinfo: tt.hi}

			facts := ReceiverFactsOf(n.View(), tt.caps)
			require.Equal(t, tt.want, receiverForm(CapabilitySources, facts), "facts %+v", facts)
			require.Equal(t, reasonAddressMode, receiverForm(AddressSources, facts))
		})
	}
}
