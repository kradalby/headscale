// Packet-probe equivalence: two rule sets for one receiving node are built
// through the client's own packet filter and must answer every probe alike.
// Probes come from the rules themselves: every edge of every source,
// destination and port range, one address beyond each, the node's and its
// peers' addresses, in both families, for every protocol either side names
// and the client's defaults. A probe is a real packet, decoded and run
// through [filter.Filter.RunIn] as inbound traffic is, so ICMP, TCP SYN,
// UDP and other protocols each reach the matcher the client uses for them.
//
// It shares no code with headscale's policy packages: the verdicts are the
// client's, and the view of what the client knows is built here, the way
// ipnlocal builds it. The client canaries in policy/v2 pin that view
// against a real client backend.

package policymodel

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

// ClientView is what a receiving client knows when it filters an inbound
// packet. It is an input so a caller can vary what the client sees.
type ClientView struct {
	// Self holds the receiver's own addresses.
	Self []netip.Addr

	// LocalNets holds every destination the client handles; see
	// [LocalNets].
	LocalNets *netipx.IPSet

	// Known holds the addresses the client can tie to a node: its own and
	// its peers'.
	Known []netip.Addr

	// HasCap answers whether a source address holds a capability; nil
	// holds none.
	HasCap filter.CapTestFunc
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

// LocalNets returns the destinations a client handles, built as
// updateFilterLocked in ipnlocal builds them: its own addresses, its
// service IPs, every route it advertises whether approved or not, and
// 0.0.0.0 and :: when it is an app connector.
func LocalNets(own, advertised []netip.Prefix, appConnector bool, serviceIPs []netip.Addr) *netipx.IPSet {
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

// NetmapCaps answers capability questions about a rendered netmap as the
// receiving client does: an address names the node, self or peer, that
// has it among its own single addresses, and that node's CapMap answers.
type NetmapCaps struct {
	byAddr map[netip.Addr]tailcfg.NodeView
	nodes  []tailcfg.NodeView
}

// NewNetmapCaps indexes self and peers as the client does: a later node
// holding an address replaces an earlier one.
func NewNetmapCaps(self tailcfg.NodeView, peers []tailcfg.NodeView) NetmapCaps {
	nc := NetmapCaps{byAddr: map[netip.Addr]tailcfg.NodeView{}}

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

// HasCap is the client's srcIPHasCapForFilter.
func (nc NetmapCaps) HasCap(src netip.Addr, c nodecap.Cap) bool {
	n, ok := nc.byAddr[src]

	return ok && c != "" && !n.UnsignedPeerAPIOnly() && n.HasCap(c)
}

// Holders lists the own addresses of the nodes HasCap admits for c.
func (nc NetmapCaps) Holders(c nodecap.Cap) []netip.Addr {
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

// Addrs is every address the netmap ties to a node, sorted.
func (nc NetmapCaps) Addrs() []netip.Addr {
	return slices.SortedFunc(maps.Keys(nc.byAddr), netip.Addr.Compare)
}

// ViewFromNetmap is what the client holding nm sees: local nets from its
// self node, caps and known addresses from its self node and peers.
func ViewFromNetmap(nm *netmap.NetworkMap) ClientView {
	self := nm.SelfNode
	nc := NewNetmapCaps(self, nm.Peers)

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

	return ClientView{
		Self:      selfAddrs,
		LocalNets: LocalNets(own, advertised, appConnector, serviceIPs),
		Known:     nc.Addrs(),
		HasCap:    nc.HasCap,
	}
}

// Probe is one packet a peer sends the receiver.
type Probe struct {
	Proto    ipproto.Proto
	Src, Dst netip.Addr
	Port     uint16
}

func (p Probe) String() string {
	if HasPorts(p.Proto) {
		return fmt.Sprintf("%v %s -> %s", p.Proto, p.Src, netip.AddrPortFrom(p.Dst, p.Port))
	}

	return fmt.Sprintf("%v %s -> %s", p.Proto, p.Src, p.Dst)
}

// CrossFamilyICMP reports whether p carries the other family's ICMP
// protocol number, which the client decodes as an unknown protocol.
func (p Probe) CrossFamilyICMP() bool {
	return p.Proto == ipproto.ICMPv4 && p.Src.Is6() || p.Proto == ipproto.ICMPv6 && p.Src.Is4()
}

// HasPorts reports whether the client reads a destination port for proto.
func HasPorts(proto ipproto.Proto) bool {
	return proto == ipproto.TCP || proto == ipproto.UDP || proto == ipproto.SCTP
}

// Packet returns p as the client decodes it off the wire: an echo request
// for ICMP of the packet's family, a SYN for TCP, and for anything else a
// transport header the client reads by protocol.
func (p Probe) Packet() *packet.Parsed {
	var b []byte

	switch {
	case p.Proto == ipproto.ICMPv4 && p.Src.Is4():
		b = packet.Generate(packet.ICMP4Header{Src: p.Src, Dst: p.Dst, Type: packet.ICMP4EchoRequest}, make([]byte, 8))
	case p.Proto == ipproto.ICMPv6 && p.Src.Is6():
		b = packet.Generate(packet.ICMP6Header{Src: p.Src, Dst: p.Dst, Type: packet.ICMP6EchoRequest}, make([]byte, 8))
	default:
		// A UDP header read as TCP has its flags in the payload's sixth
		// byte; the IP header is rewritten with the probe's protocol.
		payload := make([]byte, 12)
		payload[5] = byte(packet.TCPSyn)

		if p.Src.Is4() {
			h := packet.UDP4Header{Src: p.Src, Dst: p.Dst, SrcPort: 40000, DstPort: p.Port}
			b = packet.Generate(h, payload)
			h.IPProto = p.Proto
			_ = h.IP4Header.Marshal(b)
		} else {
			h := packet.UDP6Header{Src: p.Src, Dst: p.Dst, SrcPort: 40000, DstPort: p.Port}
			b = packet.Generate(h, payload)
			h.IPProto = p.Proto
			_ = h.IP6Header.Marshal(b)
		}
	}

	q := new(packet.Parsed)
	q.Decode(b)

	return q
}

// VerdictDiff is a probe the two rule sets answer differently.
type VerdictDiff struct {
	Probe     Probe
	Ref, Cand filter.Response
}

// CapsDiff is a source and destination the two rule sets grant different
// app capabilities.
type CapsDiff struct {
	Src, Dst  netip.Addr
	Ref, Cand tailcfg.PeerCapMap
}

// Report is the outcome of [Compare].
type Report struct {
	Probes, CapPairs int

	Parse    []string
	Verdicts []VerdictDiff
	Caps     []CapsDiff
}

// Equivalent reports whether the client enforces both rule sets alike.
func (r Report) Equivalent() bool {
	return len(r.Parse) == 0 && len(r.Verdicts) == 0 && len(r.Caps) == 0
}

// SplitCrossFamilyICMP takes out the one divergence capability form is
// allowed: a packet whose ICMP protocol number is the other family's,
// which the reference accepts and the candidate drops, since the client
// matches it by address only. It returns how many there were and the
// report without them, so a caller can require the rest to be empty and
// still see the count grow.
func (r Report) SplitCrossFamilyICMP() (int, Report) {
	rest := r
	rest.Verdicts = nil

	n := 0

	for _, d := range r.Verdicts {
		if d.Probe.CrossFamilyICMP() && d.Ref == filter.Accept && d.Cand == filter.Drop {
			n++

			continue
		}

		rest.Verdicts = append(rest.Verdicts, d)
	}

	return n, rest
}

// reportLines caps how many differences a report lists.
const reportLines = 20

func (r Report) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%d of %d probes and %d of %d capability lookups differ",
		len(r.Verdicts), r.Probes, len(r.Caps), r.CapPairs)

	for _, p := range r.Parse {
		fmt.Fprintf(&sb, "\n  unparseable %s", p)
	}

	for i, d := range r.Verdicts {
		if i == reportLines {
			fmt.Fprintf(&sb, "\n  ... %d more", len(r.Verdicts)-i)

			break
		}

		fmt.Fprintf(&sb, "\n  %s: reference %v, candidate %v", d.Probe, d.Ref, d.Cand)
	}

	for i, d := range r.Caps {
		if i == reportLines {
			fmt.Fprintf(&sb, "\n  ... %d more", len(r.Caps)-i)

			break
		}

		fmt.Fprintf(&sb, "\n  caps %s -> %s: reference %s, candidate %s", d.Src, d.Dst, PeerCapsString(d.Ref), PeerCapsString(d.Cand))
	}

	return sb.String()
}

// PeerCapsString is m as JSON, for messages.
func PeerCapsString(m tailcfg.PeerCapMap) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "unmarshalable: " + err.Error()
	}

	return string(b)
}

// Compare builds ref and cand for the client view and reports every probe
// where they differ: the verdict on a new inbound flow, or the app
// capabilities a source holds towards a destination.
func Compare(ref, cand []tailcfg.FilterRule, view ClientView) Report {
	return compare(ref, cand, view, false)
}

// CompareExhaustively is [Compare] probing every point the rules give,
// instead of one point per class the client cannot tell apart.
func CompareExhaustively(ref, cand []tailcfg.FilterRule, view ClientView) Report {
	return compare(ref, cand, view, true)
}

func compare(ref, cand []tailcfg.FilterRule, view ClientView, exhaustive bool) Report {
	var rep Report

	refM, err := filter.MatchesFromFilterRules(ref)
	if err != nil {
		rep.Parse = append(rep.Parse, "reference: "+err.Error())
	}

	candM, err := filter.MatchesFromFilterRules(cand)
	if err != nil {
		rep.Parse = append(rep.Parse, "candidate: "+err.Error())
	}

	refF := filter.New(refM, view.HasCap, view.LocalNets, nil, nil, logger.Discard)
	candF := filter.New(candM, view.HasCap, view.LocalNets, nil, nil, logger.Discard)

	space := newProbeSpace(slices.Concat(refM, candM), view, exhaustive)

	for _, src := range space.srcs {
		for _, dst := range space.dsts {
			if src.Is4() != dst.Is4() {
				continue
			}

			rep.CapPairs++

			refCaps, candCaps := refF.CapsWithValues(src, dst), candF.CapsWithValues(src, dst)
			if !SamePeerCaps(refCaps, candCaps) {
				rep.Caps = append(rep.Caps, CapsDiff{Src: src, Dst: dst, Ref: refCaps, Cand: candCaps})
			}

			for _, proto := range space.protos {
				ports := []uint16{0}
				if HasPorts(proto) {
					ports = space.ports
				}

				for _, port := range ports {
					p := Probe{Proto: proto, Src: src, Dst: dst, Port: port}
					q := p.Packet()

					rep.Probes++

					r, c := refF.RunIn(q, 0), candF.RunIn(q, 0)
					if r != c {
						rep.Verdicts = append(rep.Verdicts, VerdictDiff{Probe: p, Ref: r, Cand: c})
					}
				}
			}
		}
	}

	return rep
}

// SamePeerCaps compares app capabilities as an application reads them:
// the same capabilities, each with the same values in the same order,
// values compared as JSON.
func SamePeerCaps(a, b tailcfg.PeerCapMap) bool {
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
func newProbeSpace(ms []filter.Match, view ClientView, exhaustive bool) probeSpace {
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

	if view.LocalNets != nil {
		dstAtoms = append(dstAtoms, view.LocalNets.Prefixes()...)
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

	srcPoints := slices.Concat(view.Self, view.Known, probeOutsiders)
	for _, a := range slices.Concat(view.Self, view.Known) {
		srcPoints = append(srcPoints, a.Prev(), a.Next())
	}

	for _, p := range srcAtoms {
		srcPoints = append(srcPoints, PrefixEdges(p)...)
	}

	dstPoints := slices.Concat(view.Self, probeOutsiders)
	for _, a := range view.Self {
		dstPoints = append(dstPoints, a.Prev(), a.Next())
	}

	for _, p := range dstAtoms {
		dstPoints = append(dstPoints, PrefixEdges(p)...)
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
			sb.WriteByte(bit(view.HasCap != nil && view.HasCap(a, c)))
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

// uniquePrefixes is in without repeats, in first-seen order.
func uniquePrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(in))
	out := in[:0:0]

	for _, p := range in {
		if !seen[p] {
			seen[p] = true

			out = append(out, p)
		}
	}

	return out
}

// PrefixEdges is p's first and last address and the address beyond each.
func PrefixEdges(p netip.Prefix) []netip.Addr {
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
