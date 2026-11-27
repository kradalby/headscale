package v2_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// What a Tailscale client pays for a packet filter whose rule sources are
// capabilities its peers hold, against the same policy with the sources
// written as the members' addresses. Nothing here is headscale's: the
// rules are built by hand and run through the client's own filter.

// capLookup answers the filter's capability test as the client's local
// backend does: the source address to a peer, then the peer to its node,
// each under the backend's lock, then the node's CapMap.
type capLookup struct {
	mu     sync.Mutex
	byAddr map[netip.Addr]tailcfg.NodeID
	byID   map[tailcfg.NodeID]tailcfg.NodeView
}

func (l *capLookup) hasCap(src netip.Addr, c nodecap.Cap) bool {
	if c == "" {
		return false
	}

	l.mu.Lock()
	id, ok := l.byAddr[src]
	l.mu.Unlock()

	if !ok {
		return false
	}

	l.mu.Lock()
	n, ok := l.byID[id]
	l.mu.Unlock()

	return ok && !n.UnsignedPeerAPIOnly() && n.HasCap(c)
}

// clientPolicy is one policy in both wire forms: each rule lets one group
// reach every port of the receiver. Peer j is in group j%rules, so a
// group's addresses interleave with the others' as they do in a tailnet
// that grew over time, and the last peer is in none.
type clientPolicy struct {
	ipRules, capRules []tailcfg.FilterRule
	lookup            *capLookup
	local             *netipx.IPSet
	self              netip.Addr

	// hit is a member of the last rule's group only, which a filter finds
	// after trying every other rule; miss is a peer in no group.
	hit, miss netip.Addr
}

func newClientPolicy(tb testing.TB, rules, members int) *clientPolicy {
	tb.Helper()

	p := &clientPolicy{
		lookup: &capLookup{byAddr: map[netip.Addr]tailcfg.NodeID{}, byID: map[tailcfg.NodeID]tailcfg.NodeView{}},
		self:   netip.MustParseAddr("100.127.0.1"),
	}
	self6 := netip.MustParseAddr("fd7a:115c:a1e0:ffff::1")

	var local netipx.IPSetBuilder
	local.Add(p.self)
	local.Add(self6)

	var err error

	p.local, err = local.IPSet()
	require.NoError(tb, err)

	dsts := []tailcfg.NetPortRange{
		{IP: p.self.String(), Ports: tailcfg.PortRangeAny},
		{IP: self6.String(), Ports: tailcfg.PortRangeAny},
	}

	srcs := make([][]string, rules)
	v4, v6 := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")

	for j := range rules*members + 1 {
		node := &tailcfg.Node{
			ID:        tailcfg.NodeID(j + 1),
			Addresses: []netip.Prefix{netip.PrefixFrom(v4, 32), netip.PrefixFrom(v6, 128)},
		}

		if j < rules*members {
			g := j % rules
			node.CapMap = tailcfg.NodeCapMap{clientGroupCap(g): nil}
			srcs[g] = append(srcs[g], v4.String(), v6.String())
		}

		p.lookup.byAddr[v4], p.lookup.byAddr[v6] = node.ID, node.ID
		p.lookup.byID[node.ID] = node.View()

		switch j {
		case rules - 1:
			p.hit = v4
		case rules * members:
			p.miss = v4
		}

		v4, v6 = v4.Next(), v6.Next()
	}

	for g := range rules {
		p.ipRules = append(p.ipRules, tailcfg.FilterRule{SrcIPs: srcs[g], DstPorts: dsts})
		p.capRules = append(p.capRules, tailcfg.FilterRule{SrcIPs: []string{"cap:" + string(clientGroupCap(g))}, DstPorts: dsts})
	}

	return p
}

func clientGroupCap(g int) nodecap.Cap {
	return nodecap.Cap(fmt.Sprintf("https://headscale.net/cap/src/group:g%d", g))
}

// filter builds the client's filter from the rules as it does on every
// filter change, sharing state with prev as the client does.
func (p *clientPolicy) filter(rules []tailcfg.FilterRule, prev *filter.Filter) (*filter.Filter, error) {
	m, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		return nil, err
	}

	return filter.New(m, p.lookup.hasCap, p.local, nil, prev, logger.Discard), nil
}

// clientPacket is the first packet of a flow from src to dst port 22, set
// up as [filter.Filter.Check] sets one up, so a loop can reuse it.
func clientPacket(proto ipproto.Proto, src, dst netip.Addr) *packet.Parsed {
	q := &packet.Parsed{}
	q.Decode(bytes.Repeat([]byte{0xff}, 20))
	q.IPVersion = 4
	q.Src = netip.AddrPortFrom(src, 41641)
	q.Dst = netip.AddrPortFrom(dst, 22)
	q.IPProto = proto

	if proto == ipproto.TCP {
		q.TCPFlags = packet.TCPSyn
	}

	return q
}

var clientPolicySizes = []struct{ rules, members int }{
	{1, 10},
	{1, 100},
	{1, 1000},
	{10, 10},
	{10, 100},
	{10, 1000},
	{100, 10},
	{100, 100},
	{100, 1000},
}

var clientProtos = []struct {
	name  string
	proto ipproto.Proto
}{{"tcp-syn", ipproto.TCP}, {"udp", ipproto.UDP}, {"icmp", ipproto.ICMPv4}}

// BenchmarkClientFilterCheck times the filter's verdict on a new flow's
// first packet, which is where a capability source costs the client a
// lookup per rule tried. The verdicts of both forms are checked equal
// before timing.
func BenchmarkClientFilterCheck(b *testing.B) {
	for _, size := range clientPolicySizes {
		p := newClientPolicy(b, size.rules, size.members)
		ipFilter, err := p.filter(p.ipRules, nil)
		require.NoError(b, err)
		capFilter, err := p.filter(p.capRules, nil)
		require.NoError(b, err)

		forms := []struct {
			name string
			f    *filter.Filter
		}{{"ip", ipFilter}, {"cap", capFilter}}

		for _, proto := range clientProtos {
			for _, probe := range []struct {
				name string
				src  netip.Addr
				want filter.Response
			}{{"hit-last", p.hit, filter.Accept}, {"miss", p.miss, filter.Drop}} {
				q := clientPacket(proto.proto, probe.src, p.self)
				for _, form := range forms {
					require.Equal(b, probe.want, form.f.RunIn(q, 0), "%s %s %s", form.name, proto.name, probe.name)
				}

				for _, form := range forms {
					name := fmt.Sprintf("rules=%d/members=%d/form=%s/proto=%s/src=%s", size.rules, size.members, form.name, proto.name, probe.name)
					b.Run(name, func(b *testing.B) {
						b.ReportAllocs()

						for b.Loop() {
							form.f.RunIn(q, 0)
						}
					})
				}
			}
		}
	}
}

// BenchmarkClientFilterBuild times parsing the rules and building the
// filter, which the client redoes in full on every filter change.
// wire-bytes is the JSON of the rules.
func BenchmarkClientFilterBuild(b *testing.B) {
	for _, size := range clientPolicySizes {
		p := newClientPolicy(b, size.rules, size.members)

		for _, form := range []struct {
			name  string
			rules []tailcfg.FilterRule
		}{{"ip", p.ipRules}, {"cap", p.capRules}} {
			b.Run(fmt.Sprintf("rules=%d/members=%d/form=%s", size.rules, size.members, form.name), func(b *testing.B) {
				wire, err := json.Marshal(form.rules)
				require.NoError(b, err)

				prev, err := p.filter(form.rules, nil)
				require.NoError(b, err)

				b.ReportAllocs()

				for b.Loop() {
					prev, err = p.filter(form.rules, prev)
					if err != nil {
						b.Fatal(err)
					}
				}

				b.ReportMetric(float64(len(wire)), "wire-bytes")
			})
		}
	}
}
