// Client canaries: each pins one behaviour of the pinned Tailscale client
// that a cap-source fallback rests on. A canary failing after a tailscale
// bump means the client changed, and names the fallback that can then be
// reconsidered; it goes only once every supported client has the change.
//
// The chunk merge of the control client (PacketFilter as "base", "*": nil
// clearing, chunks joined in key order), which named filter chunks rest
// on, is pinned with the control client's map session in servertest:
// TestCanaryClientChunkMerge.

package v2

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"go4.org/netipx"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

var (
	canaryAlice  = netip.MustParseAddr("100.64.0.1")
	canaryBob    = netip.MustParseAddr("100.64.0.2")
	canaryRouter = netip.MustParseAddr("100.64.0.30")
	canaryCap    = nodecap.Cap(capGroupEng)
)

// canaryFilter builds rules as the client does, with alice holding
// canaryCap.
func canaryFilter(t *testing.T, rules []tailcfg.FilterRule, localNets ...string) *filter.Filter {
	t.Helper()

	ms, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		t.Fatalf("rules do not parse: %v", err)
	}

	var b netipx.IPSetBuilder

	for _, p := range localNets {
		b.AddPrefix(netip.MustParsePrefix(p))
	}

	local, _ := b.IPSet()

	hasCap := func(src netip.Addr, c nodecap.Cap) bool {
		return src == canaryAlice && c == canaryCap
	}

	return filter.New(ms, hasCap, local, nil, nil, logger.Discard)
}

func runIn(f *filter.Filter, proto ipproto.Proto, src, dst netip.Addr, port uint16) filter.Response {
	return f.RunIn(policymodel.Probe{Proto: proto, Src: src, Dst: dst, Port: port}.Packet(), 0)
}

// TestCanaryICMPIgnoresDstsForCaps pins that an ICMP echo is accepted on
// any cap hit in its family, whatever the matching rule's destinations: a
// receiver whose local nets exceed its own addresses would answer pings to
// all of them. Fallback: reasonLocalNets.
func TestCanaryICMPIgnoresDstsForCaps(t *testing.T) {
	t.Parallel()

	dsts := []tailcfg.NetPortRange{{IP: "10.0.0.5", Ports: tailcfg.PortRange{First: 22, Last: 22}}}
	local := []string{"100.64.0.30/32", "10.0.0.0/24"}
	other := netip.MustParseAddr("10.0.0.7")

	ipForm := canaryFilter(t, []tailcfg.FilterRule{{SrcIPs: []string{canaryAlice.String()}, DstPorts: dsts, IPProto: []int{6}}}, local...)
	if got := runIn(ipForm, ipproto.ICMPv4, canaryAlice, other, 0); got != filter.Drop {
		t.Fatalf("setup: an address source pings %s: %v, want Drop", other, got)
	}

	capForm := canaryFilter(t, []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + string(canaryCap)}, DstPorts: dsts, IPProto: []int{6}}}, local...)
	for _, dst := range []netip.Addr{other, canaryRouter} {
		if got := runIn(capForm, ipproto.ICMPv4, canaryAlice, dst, 0); got != filter.Accept {
			t.Errorf("a cap source pinging %s outside the rule's destinations: %v; the client now checks "+
				"destinations for caps on ICMP, so fallback reasonLocalNets can be reconsidered", dst, got)
		}
	}
}

// TestCanaryCapsWithValuesIgnoresSrcCaps pins that app capabilities follow
// address sources only, and that a capability's values come in rule order.
// Fallback: reasonCapGrant, and app-cap rules kept in one chunk in policy
// order.
func TestCanaryCapsWithValuesIgnoresSrcCaps(t *testing.T) {
	t.Parallel()

	web1 := netip.MustParseAddr("100.64.0.10")
	grant := func(value string) []tailcfg.CapGrant {
		return []tailcfg.CapGrant{{
			Dsts:   []netip.Prefix{netip.PrefixFrom(web1, 32)},
			CapMap: tailcfg.PeerCapMap{capAppAdmin: {tailcfg.RawMessage(value)}},
		}}
	}

	t.Run("cap-only-source", func(t *testing.T) {
		t.Parallel()

		f := canaryFilter(t, []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + string(canaryCap)}, CapGrant: grant(`"a"`)}})
		if got := f.CapsWithValues(canaryAlice, web1); len(got) != 0 {
			t.Errorf("a cap holder gets %v from a cap-sourced grant; the client now honours caps for app "+
				"capabilities, so fallback reasonCapGrant can be reconsidered", got)
		}
	})

	t.Run("cap-beside-address", func(t *testing.T) {
		t.Parallel()

		f := canaryFilter(t, []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + string(canaryCap), canaryBob.String()}, CapGrant: grant(`"a"`)}})

		if got := f.CapsWithValues(canaryBob, web1); !got.HasCapability(capAppAdmin) {
			t.Fatalf("setup: an address source gets %v, want %s", got, capAppAdmin)
		}

		if got := f.CapsWithValues(canaryAlice, web1); len(got) != 0 {
			t.Errorf("a cap holder gets %v beside an address source; the client now honours caps for app "+
				"capabilities, so fallback reasonCapGrant can be reconsidered", got)
		}
	})

	t.Run("rule-order", func(t *testing.T) {
		t.Parallel()

		src := []string{canaryBob.String()}

		for _, order := range [][2]string{{`"a"`, `"b"`}, {`"b"`, `"a"`}} {
			f := canaryFilter(t, []tailcfg.FilterRule{
				{SrcIPs: src, CapGrant: grant(order[0])},
				{SrcIPs: src, CapGrant: grant(order[1])},
			})

			got := f.CapsWithValues(canaryBob, web1)[capAppAdmin]
			want := []tailcfg.RawMessage{tailcfg.RawMessage(order[0]), tailcfg.RawMessage(order[1])}

			if !slices.Equal(got, want) {
				t.Errorf("values %v, want %v in rule order; app-cap rules need not keep policy order in one chunk any more", got, want)
			}
		}
	})
}

// TestCanaryPortlessIgnoresSrcCaps pins that the client's path for
// protocols without ports matches address sources only. It also takes an
// ICMP protocol number carried in the other family's packet, so a cap
// rule with an all-ports destination refuses those where the IP form
// accepts them. Fallback: reasonPortless.
func TestCanaryPortlessIgnoresSrcCaps(t *testing.T) {
	t.Parallel()

	self := netip.MustParseAddr("100.64.0.20")
	all := []tailcfg.NetPortRange{{IP: self.String(), Ports: tailcfg.PortRangeAny}}

	tests := []struct {
		name  string
		proto []int
		probe ipproto.Proto
	}{
		{name: "gre", proto: []int{int(ipproto.GRE)}, probe: ipproto.GRE},
		{name: "icmpv6-in-ipv4", probe: ipproto.ICMPv6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ipForm := canaryFilter(t, []tailcfg.FilterRule{{SrcIPs: []string{canaryAlice.String()}, DstPorts: all, IPProto: tc.proto}}, "100.64.0.20/32")
			if got := runIn(ipForm, tc.probe, canaryAlice, self, 0); got != filter.Accept {
				t.Fatalf("setup: an address source sends %v: %v, want Accept", tc.probe, got)
			}

			capForm := canaryFilter(t, []tailcfg.FilterRule{{SrcIPs: []string{capSourcePrefix + string(canaryCap)}, DstPorts: all, IPProto: tc.proto}}, "100.64.0.20/32")
			if got := runIn(capForm, tc.probe, canaryAlice, self, 0); got != filter.Drop {
				t.Errorf("a cap holder sends %v: %v; the client now honours caps for protocols without "+
					"ports, so fallback reasonPortless can be reconsidered", tc.probe, got)
			}
		})
	}
}

// canaryBackend is a client running nm with prefs, through the client's
// own netmap and prefs paths; it returns the packet filter it installs.
func canaryBackend(t *testing.T, nm *netmap.NetworkMap, prefs *ipn.Prefs) *filter.Filter {
	t.Helper()

	return canaryLocalBackend(t, nm, prefs).ForTest().GetFilter()
}

// canaryLocalBackend is a client backend holding nm under prefs, for a
// canary that goes on to apply deltas.
func canaryLocalBackend(t *testing.T, nm *netmap.NetworkMap, prefs *ipn.Prefs) *ipnlocal.LocalBackend {
	t.Helper()

	b := ipnlocaltest.NewBackend(t)
	b.ForTest().InitExtensions()

	err := b.ForTest().SetPersist(&persist.Persist{PrivateNodeKey: key.NewNode()})
	if err != nil {
		t.Fatal(err)
	}

	b.ForTest().ApplyNetMap(nm)
	b.ForTest().SetPrefs(prefs)

	if b.ForTest().GetFilter() == nil {
		t.Fatal("client installed no filter")
	}

	return b
}

// canaryNetmap is self's netmap: its peers and its filter rules.
func canaryNetmap(t *testing.T, self *tailcfg.Node, peers []*tailcfg.Node, rules []tailcfg.FilterRule) *netmap.NetworkMap {
	t.Helper()

	ms, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		t.Fatalf("rules do not parse: %v", err)
	}

	// The client refuses nodes without keys.
	for _, n := range append([]*tailcfg.Node{self}, peers...) {
		n.Key = key.NewNode().Public()
		n.DiscoKey = key.NewDisco().Public()
	}

	nm := &netmap.NetworkMap{
		SelfNode:          self.View(),
		PacketFilter:      ms,
		PacketFilterRules: views.SliceOf(rules),
	}

	for _, p := range peers {
		nm.Peers = append(nm.Peers, p.View())
	}

	return nm
}

// TestCanaryCapLookupOwnAddressesOnly pins that the client finds a
// source's caps through the node owning the address, among nodes' own
// addresses only: traffic a router forwards from its subnet does not
// carry the router's caps. Fallback: reasonLiteral, which sends an address
// a route reaches as an address; an identity selector names nodes' own
// addresses only.
func TestCanaryCapLookupOwnAddressesOnly(t *testing.T) {
	t.Parallel()

	// alice and the router r1 hold the cap, bob does not.
	nodes := exampleNodes()
	nodes[0].CapMap = tailcfg.NodeCapMap{canaryCap: nil}
	nodes[1].CapMap = nil
	nodes[4].CapMap = tailcfg.NodeCapMap{canaryCap: nil}

	rules := []tailcfg.FilterRule{{
		SrcIPs:   []string{capSourcePrefix + string(canaryCap)},
		DstPorts: web1Dsts(22, 22),
		IPProto:  []int{6},
	}}

	f := canaryBackend(t, canaryNetmap(t, nodes[2], []*tailcfg.Node{nodes[0], nodes[1], nodes[4]}, rules), &ipn.Prefs{WantRunning: true})
	web1 := netip.MustParseAddr("100.64.0.10")

	for _, src := range []netip.Addr{canaryRouter, canaryAlice} {
		if got := runIn(f, ipproto.TCP, src, web1, 22); got != filter.Accept {
			t.Fatalf("setup: cap holder %s connects: %v, want Accept", src, got)
		}
	}

	if got := runIn(f, ipproto.TCP, canaryBob, web1, 22); got != filter.Drop {
		t.Fatalf("setup: %s without the cap connects: %v, want Drop", canaryBob, got)
	}

	routed := netip.MustParseAddr("10.0.0.9")
	if got := runIn(f, ipproto.TCP, routed, web1, 22); got != filter.Drop {
		t.Errorf("%s behind the cap-holding router connects: %v; the client now resolves caps for routed "+
			"addresses, so the routes a * source adds could be sent as the router's capability", routed, got)
	}
}

// TestCanaryLocalNetsFromAnnouncedRoutes pins how the client builds its
// local nets, the destinations it handles at all, against the harness's
// [policymodel.LocalNets]: its own addresses, every route it advertises whether
// approved or not, 0.0.0.0 and :: as an app connector, and service IPs.
// The local-nets guard of reasonLocalNets keys on these; a mismatch means
// either the client or the harness model moved. The model keeps the host
// LANs a client cuts from a default route, so it holds at least what the
// client holds, and filters it finds alike are alike on the client.
func TestCanaryLocalNetsFromAnnouncedRoutes(t *testing.T) {
	t.Parallel()

	svc := []netip.Addr{netip.MustParseAddr("100.100.10.1"), netip.MustParseAddr("fd7a:115c:a1e0::a0a:1")}

	svcMap, err := json.Marshal(tailcfg.ServiceIPMappings{"svc:web": svc})
	if err != nil {
		t.Fatal(err)
	}

	lans := hostLANs()

	tests := []struct {
		name       string
		advertised []string
		approved   []string
		connector  bool
		services   bool
	}{
		{name: "own-addresses"},
		{name: "subnet-route", advertised: []string{"10.0.0.0/24", "fd00:10::/64"}},
		{name: "approved-not-advertised", approved: []string{"10.0.0.0/24", "fd00:10::/64"}},
		{name: "exit-routes", advertised: []string{"0.0.0.0/0", "::/0"}},
		{name: "app-connector", connector: true},
		{name: "service-ips", services: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nodes := exampleNodes()
			self := nodes[2]

			var advertised []netip.Prefix
			for _, p := range tc.advertised {
				advertised = append(advertised, netip.MustParsePrefix(p))
			}

			// Control's approval reaches the client as its own primary
			// routes; local nets do not read them.
			for _, p := range tc.approved {
				self.PrimaryRoutes = append(self.PrimaryRoutes, netip.MustParsePrefix(p))
			}

			self.AllowedIPs = append(slices.Clone(self.Addresses), self.PrimaryRoutes...)

			var serviceIPs []netip.Addr

			if tc.services {
				self.CapMap = tailcfg.NodeCapMap{nodecap.ServiceHost: {tailcfg.RawMessage(svcMap)}}
				serviceIPs = svc
			}

			// Every source may reach every port of every destination, so
			// the client accepts exactly what it takes for local.
			rules := []tailcfg.FilterRule{{SrcIPs: []string{"*"}, DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}}}}

			client := canaryBackend(t, canaryNetmap(t, self, nodes[:2], rules), &ipn.Prefs{
				WantRunning:     true,
				AdvertiseRoutes: advertised,
				AppConnector:    ipn.AppConnectorPrefs{Advertise: tc.connector},
			})

			local := policymodel.LocalNets(self.Addresses, advertised, tc.connector, serviceIPs)
			ms, _ := filter.MatchesFromFilterRules(rules)
			model := filter.New(ms, nil, local, nil, nil, logger.Discard)

			points := slices.Concat(svc, []netip.Addr{
				netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("fd7a:115c:a1e0::a"),
				netip.IPv4Unspecified(), netip.IPv6Unspecified(),
				netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860::8888"),
				netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("fd00:10::9"),
				netip.MustParseAddr("100.64.0.11"), netip.MustParseAddr("fd7a:115c:a1e0::b"),
			})
			for _, p := range local.Prefixes() {
				points = append(points, policymodel.PrefixEdges(p)...)
			}

			for _, dst := range points {
				if !dst.IsValid() {
					continue
				}

				src := canaryAlice
				if dst.Is6() {
					src = netip.MustParseAddr("fd7a:115c:a1e0::1")
				}

				got, want := runIn(client, ipproto.TCP, src, dst, 443), runIn(model, ipproto.TCP, src, dst, 443)

				switch {
				case got == want:
				case got == filter.Drop && lans.Contains(dst) && slices.ContainsFunc(advertised, func(p netip.Prefix) bool { return p.Bits() == 0 }):
					// The client also cuts this host's LANs from a default
					// route; the model, not knowing the host, keeps them.
				default:
					t.Errorf("TCP to %s: client %v, harness model %v", dst, got, want)
				}
			}
		})
	}
}

// hostLANs is the networks of this host's interfaces, which a client cuts
// from an advertised default route.
func hostLANs() *netipx.IPSet {
	var b netipx.IPSetBuilder

	_ = netmon.ForeachInterfaceAddress(func(_ netmon.Interface, p netip.Prefix) {
		if !p.IsSingleIP() && !tsaddr.IsTailscaleIP(p.Addr()) {
			b.AddPrefix(p.Masked())
			b.Remove(p.Addr())
		}
	})

	s, _ := b.IPSet()

	return s
}

// TestCanaryCapLookupOneNodePerAddress pins that, when two nodes hold the
// same address, the client decides a capability source by one of them:
// the one its netmap lists last, whatever the other holds. Address form
// admits the address whoever holds it. Fallback: reasonSharedAddress.
func TestCanaryCapLookupOneNodePerAddress(t *testing.T) {
	t.Parallel()

	rules := []tailcfg.FilterRule{{
		SrcIPs:   []string{capSourcePrefix + string(canaryCap)},
		DstPorts: web1Dsts(443, 443),
		IPProto:  []int{6},
	}}
	web1 := netip.MustParseAddr("100.64.0.10")

	verdict := func(peerOrder ...int) filter.Response {
		nodes := exampleNodes()
		nodes[0].CapMap = tailcfg.NodeCapMap{canaryCap: nil}
		nodes[3].CapMap = nil
		// db1 holds alice's IPv4 address besides its own IPv6 one.
		nodes[3].Addresses = []netip.Prefix{netip.PrefixFrom(canaryAlice, 32), netip.MustParsePrefix("fd7a:115c:a1e0::14/128")}

		peers := make([]*tailcfg.Node, 0, len(peerOrder))
		for _, i := range peerOrder {
			peers = append(peers, nodes[i])
		}

		f := canaryBackend(t, canaryNetmap(t, nodes[2], peers, rules), &ipn.Prefs{WantRunning: true})

		return runIn(f, ipproto.TCP, canaryAlice, web1, 443)
	}

	if got := verdict(3, 0); got != filter.Accept {
		t.Fatalf("setup: with the cap holder listed last, %s connects: %v, want Accept", canaryAlice, got)
	}

	if got := verdict(0, 3); got != filter.Drop {
		t.Errorf("with a node lacking the cap listed last, %s connects: %v; the client now checks every node holding "+
			"a source address, so fallback reasonSharedAddress can be reconsidered", canaryAlice, got)
	}
}

// TestCanaryCapLookupForgetsAddressOnRemoval pins the delta path of the
// lookup: a peer removed as a delta takes its addresses out of the index,
// and another peer holding one of them is not indexed again, so a
// capability source from that address finds no node until a whole peer
// list comes. Two nodes sharing alice's address both hold the cap here,
// so no fallback applies. The mapper sends a whole peer list after a
// removal or an address move leaves another node holding an address.
func TestCanaryCapLookupForgetsAddressOnRemoval(t *testing.T) {
	t.Parallel()

	rules := []tailcfg.FilterRule{{
		SrcIPs:   []string{capSourcePrefix + string(canaryCap)},
		DstPorts: web1Dsts(443, 443),
		IPProto:  []int{6},
	}}
	web1 := netip.MustParseAddr("100.64.0.10")

	nodes := exampleNodes()
	nodes[0].CapMap = tailcfg.NodeCapMap{canaryCap: nil}
	nodes[3].CapMap = tailcfg.NodeCapMap{canaryCap: nil}
	nodes[3].Addresses = []netip.Prefix{netip.PrefixFrom(canaryAlice, 32), netip.MustParsePrefix("fd7a:115c:a1e0::14/128")}

	// db1, listed last, is the node the client indexed alice's address to.
	b := canaryLocalBackend(t, canaryNetmap(t, nodes[2], []*tailcfg.Node{nodes[0], nodes[3]}, rules), &ipn.Prefs{WantRunning: true})
	if got := runIn(b.ForTest().GetFilter(), ipproto.TCP, canaryAlice, web1, 443); got != filter.Accept {
		t.Fatalf("setup: both holding the cap, %s connects: %v, want Accept", canaryAlice, got)
	}

	if !b.UpdateNetmapDelta([]netmap.NodeMutation{netmap.MakeNodeMutationRemove(nodes[3].ID)}) {
		t.Fatal("setup: the client refused the removal as a delta")
	}

	if got := runIn(b.ForTest().GetFilter(), ipproto.TCP, canaryAlice, web1, 443); got != filter.Drop {
		t.Errorf("after db1's removal as a delta, alice, holding the cap at %s, connects: %v; the client now indexes "+
			"another holder of a removed peer's address, so the mapper's peer list after such a removal can go", canaryAlice, got)
	}
}
