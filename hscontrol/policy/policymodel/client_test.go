package policymodel

import (
	"net/netip"
	"testing"

	"tailscale.com/types/ipproto"
)

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
			p := Probe{Proto: proto, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), Port: 443}
			q := p.Packet()

			if q.IPProto != proto || q.Src.Addr() != p.Src || q.Dst.Addr() != p.Dst {
				t.Errorf("%s decodes as %v %s -> %s", p, q.IPProto, q.Src, q.Dst)
			}

			if HasPorts(proto) && q.Dst.Port() != p.Port {
				t.Errorf("%s decodes with port %d", p, q.Dst.Port())
			}

			if proto == ipproto.TCP && !q.IsTCPSyn() {
				t.Errorf("%s is not a SYN", p)
			}

			if (proto == ipproto.ICMPv4 && p.Src.Is4()) || (proto == ipproto.ICMPv6 && p.Src.Is6()) {
				if !q.IsEchoRequest() {
					t.Errorf("%s is not an echo request", p)
				}
			}
		}
	}
}
