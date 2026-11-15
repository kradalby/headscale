// Packet-probe equivalence: two rule sets for one receiving node are built
// through the client's own packet filter and must answer every probe alike.
// Probes come from the rules themselves: every edge of every source,
// destination and port range, one address beyond each, the node's and its
// peers' addresses, in both families, for every protocol either side names
// and the client's defaults. A probe is a real packet, decoded and run
// through [filter.Filter.RunIn] as inbound traffic is, so ICMP, TCP SYN,
// UDP and other protocols each reach the matcher the client uses for them.

package v2

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

// clientView is what a receiving client knows when it filters an inbound
// packet. It is an input so a caller can vary what the client sees.
type clientView struct {
	// self holds the receiver's own addresses.
	self []netip.Addr

	// localNets holds every destination the client handles; see
	// [clientLocalNets].
	localNets *netipx.IPSet

	// known holds the addresses the client can tie to a node: its own and
	// its peers'.
	known []netip.Addr

	// hasCap answers whether a source address holds a capability; nil
	// holds none.
	hasCap filter.CapTestFunc
}

// clientDefaultRouteExclusions mirrors what the client cuts from an
// advertised default route (removeFromDefaultRoute in ipnlocal). It also
// cuts the host's LAN interfaces, which the model takes to be none.
var clientDefaultRouteExclusions = []netip.Prefix{
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	tsaddr.CGNATRange(),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	tsaddr.TailscaleULARange(),
}

// clientLocalNets returns the destinations a client handles, built as
// updateFilterLocked in ipnlocal builds them: its own addresses, its
// service IPs, every route it advertises whether approved or not, and
// 0.0.0.0 and :: when it is an app connector.
func clientLocalNets(own, advertised []netip.Prefix, appConnector bool, serviceIPs []netip.Addr) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, p := range own {
		b.AddPrefix(p)
	}

	for _, ip := range serviceIPs {
		b.Add(ip)
	}

	for _, r := range advertised {
		if r.Bits() != 0 {
			b.AddPrefix(r)

			continue
		}

		var def netipx.IPSetBuilder

		def.AddPrefix(r)

		for _, p := range clientDefaultRouteExclusions {
			def.RemovePrefix(p)
		}

		s, _ := def.IPSet()
		b.AddSet(s)
	}

	if appConnector {
		b.Add(netip.IPv4Unspecified())
		b.Add(netip.IPv6Unspecified())
	}

	s, _ := b.IPSet()

	return s
}

// netmapCaps answers capability questions about a rendered netmap as the
// receiving client does: an address names the node, self or peer, that
// has it among its own single addresses, and that node's CapMap answers.
type netmapCaps struct {
	byAddr map[netip.Addr]tailcfg.NodeView
	nodes  []tailcfg.NodeView
}

func newNetmapCaps(self tailcfg.NodeView, peers []tailcfg.NodeView) netmapCaps {
	nc := netmapCaps{byAddr: map[netip.Addr]tailcfg.NodeView{}}

	if self.Valid() {
		nc.nodes = append(nc.nodes, self)
	}

	nc.nodes = append(nc.nodes, peers...)

	for _, n := range nc.nodes {
		for _, p := range n.Addresses().All() {
			if p.IsSingleIP() {
				nc.byAddr[p.Addr()] = n
			}
		}
	}

	return nc
}

// hasCap is the client's srcIPHasCapForFilter.
func (nc netmapCaps) hasCap(src netip.Addr, c nodecap.Cap) bool {
	n, ok := nc.byAddr[src]

	return ok && c != "" && !n.UnsignedPeerAPIOnly() && n.HasCap(c)
}

// holders lists the own addresses of the nodes hasCap admits for c.
func (nc netmapCaps) holders(c nodecap.Cap) []netip.Addr {
	var out []netip.Addr

	for _, n := range nc.nodes {
		if c == "" || n.UnsignedPeerAPIOnly() || !n.HasCap(c) {
			continue
		}

		for _, p := range n.Addresses().All() {
			if p.IsSingleIP() {
				out = append(out, p.Addr())
			}
		}
	}

	return out
}

func (nc netmapCaps) addrs() []netip.Addr {
	return slices.SortedFunc(maps.Keys(nc.byAddr), netip.Addr.Compare)
}

// clientViewFromNetmap is what the client holding nm sees: local nets from
// its self node, caps and known addresses from its self node and peers.
func clientViewFromNetmap(nm *netmap.NetworkMap) clientView {
	self := nm.SelfNode
	nc := newNetmapCaps(self, nm.Peers)

	var (
		own, advertised []netip.Prefix
		serviceIPs      []netip.Addr
		appConnector    bool
		selfAddrs       []netip.Addr
	)

	if self.Valid() {
		own = self.Addresses().AsSlice()
		advertised = self.Hostinfo().RoutableIPs().AsSlice()
		appConnector = self.Hostinfo().AppConnector().EqualBool(true)

		mappings, _ := tailcfg.UnmarshalNodeCapViewJSON[tailcfg.ServiceIPMappings](self.CapMap(), nodecap.ServiceHost)
		for _, m := range mappings {
			for _, addrs := range m {
				serviceIPs = append(serviceIPs, addrs...)
			}
		}

		for _, p := range own {
			if p.IsSingleIP() {
				selfAddrs = append(selfAddrs, p.Addr())
			}
		}
	}

	return clientView{
		self:      selfAddrs,
		localNets: clientLocalNets(own, advertised, appConnector, serviceIPs),
		known:     nc.addrs(),
		hasCap:    nc.hasCap,
	}
}

// probe is one packet a peer sends the receiver.
type probe struct {
	proto    ipproto.Proto
	src, dst netip.Addr
	port     uint16
}

func (p probe) String() string {
	if probeHasPorts(p.proto) {
		return fmt.Sprintf("%v %s -> %s", p.proto, p.src, netip.AddrPortFrom(p.dst, p.port))
	}

	return fmt.Sprintf("%v %s -> %s", p.proto, p.src, p.dst)
}

// probeHasPorts reports whether the client reads a destination port for
// proto.
func probeHasPorts(proto ipproto.Proto) bool {
	return proto == ipproto.TCP || proto == ipproto.UDP || proto == ipproto.SCTP
}

// probePacket returns p as the client decodes it off the wire: an echo
// request for ICMP of the packet's family, a SYN for TCP, and for anything
// else a transport header the client reads by protocol.
func probePacket(p probe) *packet.Parsed {
	var b []byte

	switch {
	case p.proto == ipproto.ICMPv4 && p.src.Is4():
		b = packet.Generate(packet.ICMP4Header{Src: p.src, Dst: p.dst, Type: packet.ICMP4EchoRequest}, make([]byte, 8))
	case p.proto == ipproto.ICMPv6 && p.src.Is6():
		b = packet.Generate(packet.ICMP6Header{Src: p.src, Dst: p.dst, Type: packet.ICMP6EchoRequest}, make([]byte, 8))
	default:
		// A UDP header read as TCP has its flags in the payload's sixth
		// byte; the IP header is rewritten with the probe's protocol.
		payload := make([]byte, 12)
		payload[5] = byte(packet.TCPSyn)

		if p.src.Is4() {
			h := packet.UDP4Header{Src: p.src, Dst: p.dst, SrcPort: 40000, DstPort: p.port}
			b = packet.Generate(h, payload)
			h.IPProto = p.proto
			_ = h.IP4Header.Marshal(b)
		} else {
			h := packet.UDP6Header{Src: p.src, Dst: p.dst, SrcPort: 40000, DstPort: p.port}
			b = packet.Generate(h, payload)
			h.IPProto = p.proto
			_ = h.IP6Header.Marshal(b)
		}
	}

	q := new(packet.Parsed)
	q.Decode(b)

	return q
}

// verdictDiff is a probe the two rule sets answer differently.
type verdictDiff struct {
	probe     probe
	ref, cand filter.Response
}

// capsDiff is a source and destination the two rule sets grant different
// app capabilities.
type capsDiff struct {
	src, dst  netip.Addr
	ref, cand tailcfg.PeerCapMap
}

// probeReport is the outcome of [probeFilters].
type probeReport struct {
	probes, capPairs int

	parse    []string
	verdicts []verdictDiff
	caps     []capsDiff
}

func (r probeReport) equivalent() bool {
	return len(r.parse) == 0 && len(r.verdicts) == 0 && len(r.caps) == 0
}

// probeReportLines caps how many differences a report lists.
const probeReportLines = 20

func (r probeReport) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%d of %d probes and %d of %d capability lookups differ",
		len(r.verdicts), r.probes, len(r.caps), r.capPairs)

	for _, p := range r.parse {
		fmt.Fprintf(&sb, "\n  unparseable %s", p)
	}

	for i, d := range r.verdicts {
		if i == probeReportLines {
			fmt.Fprintf(&sb, "\n  ... %d more", len(r.verdicts)-i)

			break
		}

		fmt.Fprintf(&sb, "\n  %s: reference %v, candidate %v", d.probe, d.ref, d.cand)
	}

	for i, d := range r.caps {
		if i == probeReportLines {
			fmt.Fprintf(&sb, "\n  ... %d more", len(r.caps)-i)

			break
		}

		fmt.Fprintf(&sb, "\n  caps %s -> %s: reference %s, candidate %s", d.src, d.dst, peerCapsString(d.ref), peerCapsString(d.cand))
	}

	return sb.String()
}

func peerCapsString(m tailcfg.PeerCapMap) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "unmarshalable: " + err.Error()
	}

	return string(b)
}

// probeFilters builds ref and cand for the client view and reports every
// probe where they differ: the verdict on a new inbound flow, or the app
// capabilities a source holds towards a destination.
func probeFilters(ref, cand []tailcfg.FilterRule, view clientView) probeReport {
	return probeFiltersWith(ref, cand, view, false)
}

// probeFiltersWith is [probeFilters]; exhaustive probes every point the
// rules give, instead of one point per class the client cannot tell apart.
func probeFiltersWith(ref, cand []tailcfg.FilterRule, view clientView, exhaustive bool) probeReport {
	var rep probeReport

	refM, err := filter.MatchesFromFilterRules(ref)
	if err != nil {
		rep.parse = append(rep.parse, "reference: "+err.Error())
	}

	candM, err := filter.MatchesFromFilterRules(cand)
	if err != nil {
		rep.parse = append(rep.parse, "candidate: "+err.Error())
	}

	refF := filter.New(refM, view.hasCap, view.localNets, nil, nil, logger.Discard)
	candF := filter.New(candM, view.hasCap, view.localNets, nil, nil, logger.Discard)

	space := newProbeSpace(slices.Concat(refM, candM), view, exhaustive)

	for _, src := range space.srcs {
		for _, dst := range space.dsts {
			if src.Is4() != dst.Is4() {
				continue
			}

			rep.capPairs++

			refCaps, candCaps := refF.CapsWithValues(src, dst), candF.CapsWithValues(src, dst)
			if !samePeerCaps(refCaps, candCaps) {
				rep.caps = append(rep.caps, capsDiff{src: src, dst: dst, ref: refCaps, cand: candCaps})
			}

			for _, proto := range space.protos {
				ports := []uint16{0}
				if probeHasPorts(proto) {
					ports = space.ports
				}

				for _, port := range ports {
					p := probe{proto: proto, src: src, dst: dst, port: port}
					q := probePacket(p)

					rep.probes++

					r, c := refF.RunIn(q, 0), candF.RunIn(q, 0)
					if r != c {
						rep.verdicts = append(rep.verdicts, verdictDiff{probe: p, ref: r, cand: c})
					}
				}
			}
		}
	}

	return rep
}

// samePeerCaps compares app capabilities as an application reads them:
// the same capabilities, each with the same values in the same order,
// values compared as JSON.
func samePeerCaps(a, b tailcfg.PeerCapMap) bool {
	if len(a) != len(b) {
		return false
	}

	for c, av := range a {
		bv, ok := b[c]
		if !ok || len(av) != len(bv) {
			return false
		}

		for i := range av {
			if canonicalJSON(av[i]) != canonicalJSON(bv[i]) {
				return false
			}
		}
	}

	return true
}

func canonicalJSON(m tailcfg.RawMessage) string {
	var v any

	err := json.Unmarshal([]byte(m), &v)
	if err != nil {
		return "unparseable:" + string(m)
	}

	b, err := json.Marshal(v)
	if err != nil {
		return "unmarshalable:" + string(m)
	}

	return string(b)
}

// probeSpace is the probes' coordinates.
type probeSpace struct {
	srcs, dsts []netip.Addr
	ports      []uint16
	protos     []ipproto.Proto
}

// probeOutsiders stand for addresses no rule or node names.
var probeOutsiders = []netip.Addr{
	netip.MustParseAddr("192.0.2.1"),
	netip.MustParseAddr("2001:db8::1"),
}

// probePortless is tried in order for a protocol without ports that
// neither side names, so the client's path for other protocols is probed
// where it must refuse.
var probePortless = []ipproto.Proto{ipproto.GRE, 50, 51, 89, 103}

// newProbeSpace takes its points from ms, the matches of both sides, and
// the view. Unless exhaustive, it keeps one point per class the client
// cannot tell apart: a source by the source prefixes holding it and the
// caps it has, a destination by the destination, capability and local
// prefixes holding it and the pre-filter's special cases, a port by the
// port ranges holding it.
func newProbeSpace(ms []filter.Match, view clientView, exhaustive bool) probeSpace {
	var (
		srcAtoms, dstAtoms []netip.Prefix
		caps               []nodecap.Cap
		portAtoms          []filter.PortRange
		protos             []ipproto.Proto
	)

	for _, m := range ms {
		srcAtoms = append(srcAtoms, m.Srcs...)
		caps = append(caps, m.SrcCaps...)
		protos = append(protos, m.IPProto.AsSlice()...)

		for _, d := range m.Dsts {
			dstAtoms = append(dstAtoms, d.Net)
			portAtoms = append(portAtoms, d.Ports)
		}

		for _, c := range m.Caps {
			dstAtoms = append(dstAtoms, c.Dst)
		}
	}

	if view.localNets != nil {
		dstAtoms = append(dstAtoms, view.localNets.Prefixes()...)
	}

	srcAtoms = uniquePrefixes(srcAtoms)
	dstAtoms = uniquePrefixes(dstAtoms)

	slices.Sort(caps)
	caps = slices.Compact(caps)

	slices.SortFunc(portAtoms, func(a, b filter.PortRange) int {
		if a.First != b.First {
			return int(a.First) - int(b.First)
		}

		return int(a.Last) - int(b.Last)
	})
	portAtoms = slices.Compact(portAtoms)

	protos = append(protos, ipproto.TCP, ipproto.UDP, ipproto.SCTP, ipproto.ICMPv4, ipproto.ICMPv6)
	for _, p := range probePortless {
		if !slices.Contains(protos, p) {
			protos = append(protos, p)

			break
		}
	}

	slices.Sort(protos)
	protos = slices.Compact(protos)

	srcPoints := slices.Concat(view.self, view.known, probeOutsiders)
	for _, a := range slices.Concat(view.self, view.known) {
		srcPoints = append(srcPoints, a.Prev(), a.Next())
	}

	for _, p := range srcAtoms {
		srcPoints = append(srcPoints, prefixEdges(p)...)
	}

	dstPoints := slices.Concat(view.self, probeOutsiders)
	for _, a := range view.self {
		dstPoints = append(dstPoints, a.Prev(), a.Next())
	}

	for _, p := range dstAtoms {
		dstPoints = append(dstPoints, prefixEdges(p)...)
	}

	portPoints := make([]int, 0, 2+4*len(portAtoms))

	portPoints = append(portPoints, 0, 65535)
	for _, r := range portAtoms {
		portPoints = append(portPoints, int(r.First)-1, int(r.First), int(r.Last), int(r.Last)+1)
	}

	srcSig := func(a netip.Addr) string {
		var sb strings.Builder

		sb.WriteString(addrFamily(a))

		for _, p := range srcAtoms {
			sb.WriteByte(bit(p.Contains(a)))
		}

		for _, c := range caps {
			sb.WriteByte(bit(view.hasCap != nil && view.hasCap(a, c)))
		}

		return sb.String()
	}

	dstSig := func(a netip.Addr) string {
		var sb strings.Builder

		sb.WriteString(addrFamily(a))
		sb.WriteByte(bit(a.IsMulticast()))
		sb.WriteByte(bit(a.IsLinkLocalUnicast()))
		sb.WriteByte(bit(a == netip.AddrFrom4([4]byte{169, 254, 169, 254})))

		for _, p := range dstAtoms {
			sb.WriteByte(bit(p.Contains(a)))
		}

		return sb.String()
	}

	space := probeSpace{
		srcs:   representatives(srcPoints, srcSig, exhaustive),
		dsts:   representatives(dstPoints, dstSig, exhaustive),
		protos: protos,
	}

	seenPorts := map[string]bool{}

	for _, pp := range portPoints {
		if pp < 0 || pp > 65535 {
			continue
		}

		port := uint16(pp)

		var sb strings.Builder
		for _, r := range portAtoms {
			sb.WriteByte(bit(r.Contains(port)))
		}

		key := sb.String()
		if exhaustive {
			key = strconv.Itoa(pp)
		}

		if !seenPorts[key] {
			seenPorts[key] = true

			space.ports = append(space.ports, port)
		}
	}

	return space
}

// representatives keeps the valid points, the first of each signature, or
// every distinct point when exhaustive.
func representatives(points []netip.Addr, sig func(netip.Addr) string, exhaustive bool) []netip.Addr {
	seen := map[string]bool{}

	var out []netip.Addr

	for _, a := range points {
		if !a.IsValid() {
			continue
		}

		key := a.String()
		if !exhaustive {
			key = sig(a)
		}

		if !seen[key] {
			seen[key] = true

			out = append(out, a)
		}
	}

	return out
}

// prefixEdges is p's first and last address and the address beyond each.
func prefixEdges(p netip.Prefix) []netip.Addr {
	first := p.Masked().Addr()
	last := netipx.PrefixLastIP(p)

	return []netip.Addr{first, last, first.Prev(), last.Next()}
}

func addrFamily(a netip.Addr) string {
	if a.Is4() {
		return "4"
	}

	return "6"
}

func bit(b bool) byte {
	if b {
		return '1'
	}

	return '0'
}
