// Sensitivity of the probe harness: each mistake a cap rewrite could make
// is seeded into a hand-built filter and must show as a divergence from the
// IP-form reference, while a correct rewrite must not. The fixtures follow
// the worked examples of the cap-source design.

package v2

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// Illustrative cap names; the namespace is not settled.
const (
	capGroupEng = "https://headscale.net/cap/src/group:eng"
	capTagWeb   = "https://headscale.net/cap/src/tag:web"
	capOwner1   = "https://headscale.net/cap/src/owner:1"
	capMember   = "https://headscale.net/cap/src/autogroup:member"
	capAlice    = "https://headscale.net/cap/src/user:alice@"
	capEmpty    = "https://headscale.net/cap/src/group:empty"
	capAppAdmin = "example.com/cap/admin"
)

// exampleNodes is the worked-example tailnet: alice and bob are in
// group:eng, web1 and db1 are tagged servers, r1 announces 10.0.0.0/24.
func exampleNodes() []*tailcfg.Node {
	node := func(id tailcfg.NodeID, name, v4, v6 string, caps ...string) *tailcfg.Node {
		n := &tailcfg.Node{
			ID:        id,
			Name:      name,
			Addresses: []netip.Prefix{netip.MustParsePrefix(v4 + "/32"), netip.MustParsePrefix(v6 + "/128")},
			Hostinfo:  (&tailcfg.Hostinfo{}).View(),
		}

		for _, c := range caps {
			if n.CapMap == nil {
				n.CapMap = tailcfg.NodeCapMap{}
			}

			n.CapMap[nodecap.Cap(c)] = nil
		}

		return n
	}

	r1 := node(5, "r1", "100.64.0.30", "fd7a:115c:a1e0::1e")
	r1.Hostinfo = (&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}).View()
	r1.AllowedIPs = append(slices.Clone(r1.Addresses), netip.MustParsePrefix("10.0.0.0/24"))
	r1.PrimaryRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	return []*tailcfg.Node{
		node(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", capGroupEng, capOwner1, capMember, capAlice),
		node(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", capGroupEng, capMember),
		node(3, "web1", "100.64.0.10", "fd7a:115c:a1e0::a", capTagWeb),
		node(4, "db1", "100.64.0.20", "fd7a:115c:a1e0::14"),
		r1,
	}
}

// exampleView is what receiver sees of nodes: local nets from its own
// node, caps from every node.
func exampleView(t *testing.T, nodes []*tailcfg.Node, receiver string) (clientView, netmapCaps) {
	t.Helper()

	var (
		self  tailcfg.NodeView
		peers []tailcfg.NodeView
	)

	for _, n := range nodes {
		if n.Name == receiver {
			self = n.View()

			continue
		}

		peers = append(peers, n.View())
	}

	if !self.Valid() {
		t.Fatalf("no node %q", receiver)
	}

	nc := newNetmapCaps(self, peers)

	var selfAddrs []netip.Addr
	for _, p := range self.Addresses().All() {
		selfAddrs = append(selfAddrs, p.Addr())
	}

	return clientView{
		self:      selfAddrs,
		localNets: clientLocalNets(self.Addresses().AsSlice(), self.Hostinfo().RoutableIPs().AsSlice(), false, nil),
		known:     nc.addrs(),
		hasCap:    nc.hasCap,
	}, nc
}

func withoutCap(nodes []*tailcfg.Node, name string, c string) []*tailcfg.Node {
	for _, n := range nodes {
		if n.Name == name {
			delete(n.CapMap, nodecap.Cap(c))
		}
	}

	return nodes
}

var (
	engSrcIPs = []string{"100.64.0.1", "100.64.0.2", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2"}
	web1Dsts  = func(first, last uint16) []tailcfg.NetPortRange {
		return []tailcfg.NetPortRange{
			{IP: "100.64.0.10", Ports: tailcfg.PortRange{First: first, Last: last}},
			{IP: "fd7a:115c:a1e0::a", Ports: tailcfg.PortRange{First: first, Last: last}},
		}
	}
)

// sensitivityCase is a cap or IP rewrite of an IP-form reference for one
// receiver. diverges says whether the client must tell them apart; kind,
// when set, is the only shape a divergence may take.
type sensitivityCase struct {
	name     string
	receiver string
	nodes    []*tailcfg.Node
	ref      []tailcfg.FilterRule
	cand     []tailcfg.FilterRule
	diverges bool
	kind     func(probeReport) string
}

func sensitivityCases() []sensitivityCase {
	example1 := []tailcfg.FilterRule{{SrcIPs: engSrcIPs, DstPorts: web1Dsts(443, 443), IPProto: []int{6}}}
	example1Cap := []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capGroupEng}, DstPorts: web1Dsts(443, 443), IPProto: []int{6}}}

	routerDst := []tailcfg.NetPortRange{{IP: "10.0.0.5", Ports: tailcfg.PortRange{First: 22, Last: 22}}}

	db1All := []tailcfg.NetPortRange{
		{IP: "100.64.0.20", Ports: tailcfg.PortRangeAny},
		{IP: "fd7a:115c:a1e0::14", Ports: tailcfg.PortRangeAny},
	}

	adminGrant := []tailcfg.CapGrant{{
		Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32"), netip.MustParsePrefix("fd7a:115c:a1e0::a/128")},
		CapMap: tailcfg.PeerCapMap{capAppAdmin: {`{"role":"ops"}`}},
	}}

	aliceAll := []tailcfg.NetPortRange{
		{IP: "100.64.0.1", Ports: tailcfg.PortRangeAny},
		{IP: "fd7a:115c:a1e0::1", Ports: tailcfg.PortRangeAny},
	}

	return []sensitivityCase{
		{
			// An ICMP probe takes any cap hit as leave to reach every
			// local destination, routes included.
			name:     "cap-on-subnet-router",
			receiver: "r1",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: engSrcIPs, DstPorts: routerDst, IPProto: []int{6}}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capGroupEng}, DstPorts: routerDst, IPProto: []int{6}}},
			diverges: true,
			kind:     onlyVerdicts(ipproto.ICMPv4, filter.Drop, filter.Accept),
		},
		{
			name:     "cap-on-portless-protocol",
			receiver: "db1",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.10", "fd7a:115c:a1e0::a"}, DstPorts: db1All, IPProto: []int{47}}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capTagWeb}, DstPorts: db1All, IPProto: []int{47}}},
			diverges: true,
			kind:     onlyVerdicts(ipproto.GRE, filter.Accept, filter.Drop),
		},
		{
			name:     "cap-on-capgrant",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: engSrcIPs, CapGrant: adminGrant}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capGroupEng}, CapGrant: adminGrant}},
			diverges: true,
			kind:     onlyCaps,
		},
		{
			name:     "dropped-source",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      example1,
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2"}, DstPorts: web1Dsts(443, 443), IPProto: []int{6}}},
			diverges: true,
		},
		{
			name:     "missing-cap-stamp",
			receiver: "web1",
			nodes:    withoutCap(exampleNodes(), "bob-laptop", capGroupEng),
			ref:      example1,
			cand:     example1Cap,
			diverges: true,
		},
		{
			name:     "port-range-widened",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      example1,
			cand:     []tailcfg.FilterRule{{SrcIPs: engSrcIPs, DstPorts: web1Dsts(443, 444), IPProto: []int{6}}},
			diverges: true,
			kind:     onlyVerdicts(ipproto.TCP, filter.Drop, filter.Accept),
		},
		{
			name:     "cap-rewrite-plain-receiver",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      example1,
			cand:     example1Cap,
		},
		{
			name:     "cap-rewrite-default-protocols",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: engSrcIPs, DstPorts: web1Dsts(80, 80)}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capGroupEng}, DstPorts: web1Dsts(80, 80)}},
		},
		{
			name:     "cap-rewrite-mixed-sources",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: append([]string{"192.168.1.0/24"}, engSrcIPs...), DstPorts: web1Dsts(80, 80), IPProto: []int{6}}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{"192.168.1.0/24", capSourcePrefix + capGroupEng}, DstPorts: web1Dsts(80, 80), IPProto: []int{6}}},
		},
		{
			// Default protocols name both ICMPs. An ICMP protocol number
			// in the other family's packet takes the client's path for
			// other protocols, which reads no caps: on an all-ports
			// destination the cap form refuses what the IP form accepts.
			name:     "cap-rewrite-autogroup-self",
			receiver: "alice-laptop",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, DstPorts: aliceAll}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capOwner1}, DstPorts: aliceAll}},
			diverges: true,
			kind:     onlyCrossFamilyICMP,
		},
		{
			name:     "cap-rewrite-autogroup-self-tcp",
			receiver: "alice-laptop",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, DstPorts: aliceAll, IPProto: []int{6}}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capOwner1}, DstPorts: aliceAll, IPProto: []int{6}}},
		},
		{
			name:     "cap-rewrite-sctp-udp",
			receiver: "web1",
			nodes:    exampleNodes(),
			ref:      []tailcfg.FilterRule{{SrcIPs: engSrcIPs, DstPorts: web1Dsts(5000, 5010), IPProto: []int{17, 132}}},
			cand:     []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + capGroupEng}, DstPorts: web1Dsts(5000, 5010), IPProto: []int{17, 132}}},
		},
	}
}

// onlyVerdicts requires every divergence to be a proto probe the
// reference answers ref and the candidate cand.
func onlyVerdicts(proto ipproto.Proto, ref, cand filter.Response) func(probeReport) string {
	return func(rep probeReport) string {
		if len(rep.caps) > 0 || len(rep.verdicts) == 0 {
			return "want verdict divergences only"
		}

		for _, d := range rep.verdicts {
			if d.probe.proto != proto || d.ref != ref || d.cand != cand {
				return "unexpected divergence " + d.probe.String()
			}
		}

		return ""
	}
}

// onlyCrossFamilyICMP requires every divergence to be an ICMP protocol
// number carried in the other family's packet, refused by the candidate
// only.
func onlyCrossFamilyICMP(rep probeReport) string {
	if len(rep.caps) > 0 || len(rep.verdicts) == 0 {
		return "want verdict divergences only"
	}

	for _, d := range rep.verdicts {
		cross := (d.probe.proto == ipproto.ICMPv6 && d.probe.src.Is4()) || (d.probe.proto == ipproto.ICMPv4 && d.probe.src.Is6())
		if !cross || d.ref != filter.Accept || d.cand != filter.Drop {
			return "unexpected divergence " + d.probe.String()
		}
	}

	return ""
}

func onlyCaps(rep probeReport) string {
	if len(rep.verdicts) > 0 || len(rep.caps) == 0 {
		return "want capability divergences only"
	}

	return ""
}

// TestProbeSensitivity seeds the mistakes a cap rewrite could make. A case
// that stops diverging means the model of the client the fallbacks rest
// on is wrong; the fixture must not be bent until it diverges again.
func TestProbeSensitivity(t *testing.T) {
	t.Parallel()

	for _, tc := range sensitivityCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			view, _ := exampleView(t, tc.nodes, tc.receiver)
			rep := probeFilters(tc.ref, tc.cand, view)

			t.Log(rep)

			if rep.equivalent() == tc.diverges {
				t.Fatalf("diverges = %t, want %t: %s", !rep.equivalent(), tc.diverges, rep)
			}

			if tc.kind != nil {
				if msg := tc.kind(rep); msg != "" {
					t.Fatalf("%s: %s", msg, rep)
				}
			}
		})
	}
}

// TestProbeClassesMatchExhaustive checks that probing one point per class
// finds a divergence exactly where probing every point does.
func TestProbeClassesMatchExhaustive(t *testing.T) {
	t.Parallel()

	for _, tc := range sensitivityCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			view, _ := exampleView(t, tc.nodes, tc.receiver)
			classes := probeFiltersWith(tc.ref, tc.cand, view, false)
			every := probeFiltersWith(tc.ref, tc.cand, view, true)

			if classes.equivalent() != every.equivalent() {
				t.Fatalf("classes: %s\nexhaustive: %s", classes, every)
			}

			if every.probes < classes.probes {
				t.Fatalf("exhaustive ran %d probes, classes %d", every.probes, classes.probes)
			}
		})
	}
}

// TestProbePacketsDecode checks the harness's packets reach the client
// as the probe says: protocol, addresses, port and a SYN for TCP.
func TestProbePacketsDecode(t *testing.T) {
	t.Parallel()

	for _, src := range []string{"100.64.0.1", "fd7a:115c:a1e0::1"} {
		dst := "100.64.0.10"
		if netip.MustParseAddr(src).Is6() {
			dst = "fd7a:115c:a1e0::a"
		}

		for _, proto := range []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.SCTP, ipproto.ICMPv4, ipproto.ICMPv6, ipproto.GRE, ipproto.IGMP} {
			p := probe{proto: proto, src: netip.MustParseAddr(src), dst: netip.MustParseAddr(dst), port: 443}
			q := probePacket(p)

			if q.IPProto != proto || q.Src.Addr() != p.src || q.Dst.Addr() != p.dst {
				t.Errorf("%s decodes as %v %s -> %s", p, q.IPProto, q.Src, q.Dst)
			}

			if probeHasPorts(proto) && q.Dst.Port() != p.port {
				t.Errorf("%s decodes with port %d", p, q.Dst.Port())
			}

			if proto == ipproto.TCP && !q.IsTCPSyn() {
				t.Errorf("%s is not a SYN", p)
			}

			if (proto == ipproto.ICMPv4 && p.src.Is4()) || (proto == ipproto.ICMPv6 && p.src.Is6()) {
				if !q.IsEchoRequest() {
					t.Errorf("%s is not an echo request", p)
				}
			}
		}
	}
}
