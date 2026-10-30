package util

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
)

func TestMagicDNSRootDomains100(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("100.64.0.0/10"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("64.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("100.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("127.100.in-addr.arpa.")))
}

func TestMagicDNSRootDomains172(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.0.0/16"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("0.16.172.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("255.16.172.in-addr.arpa.")))
}

// Happens when netmask is a multiple of 4 bits (sounds likely).
func TestMagicDNSRootDomainsIPv6Single(t *testing.T) {
	domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/48"))

	assert.Len(t, domains, 1)
	assert.Equal(t, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.", domains[0].WithTrailingDot())
}

func TestMagicDNSRootDomainsIPv6SingleMultiple(t *testing.T) {
	domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/50"))

	yieldsRoot := func(dom string) bool {
		for _, candidate := range domains {
			if candidate.WithTrailingDot() == dom {
				return true
			}
		}

		return false
	}

	assert.Len(t, domains, 4)
	assert.True(t, yieldsRoot("0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("2.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("3.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
}

// A byte-aligned mask whose configured value carries host bits: the
// zones enumerate the masked octet 0..255, not the dirty octet onward.
func TestMagicDNSRootDomainsIPv4DirtyByteAligned(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.5.0/16"))

	assert.Len(t, domains, 256)
	assert.Equal(t, "0.16.172.in-addr.arpa.", domains[0].WithTrailingDot())
	assert.Equal(t, "255.16.172.in-addr.arpa.", domains[255].WithTrailingDot())
}

func TestMagicDNSRootDomainsIPv4PrefixBoundaries(t *testing.T) {
	tests := []struct {
		prefix string
		want   []dnsname.FQDN
	}{
		{
			// Host bits inside the covered octet: the zones must enumerate
			// the masked prefix's octet, 0..15, not 1..16.
			prefix: "10.1.0.0/12",
			want: []dnsname.FQDN{
				"0.10.in-addr.arpa.", "1.10.in-addr.arpa.", "2.10.in-addr.arpa.",
				"3.10.in-addr.arpa.", "4.10.in-addr.arpa.", "5.10.in-addr.arpa.",
				"6.10.in-addr.arpa.", "7.10.in-addr.arpa.", "8.10.in-addr.arpa.",
				"9.10.in-addr.arpa.", "10.10.in-addr.arpa.", "11.10.in-addr.arpa.",
				"12.10.in-addr.arpa.", "13.10.in-addr.arpa.", "14.10.in-addr.arpa.",
				"15.10.in-addr.arpa.",
			},
		},
		{
			prefix: "192.168.1.0/20",
			want: []dnsname.FQDN{
				"0.168.192.in-addr.arpa.", "1.168.192.in-addr.arpa.",
				"2.168.192.in-addr.arpa.", "3.168.192.in-addr.arpa.",
				"4.168.192.in-addr.arpa.", "5.168.192.in-addr.arpa.",
				"6.168.192.in-addr.arpa.", "7.168.192.in-addr.arpa.",
				"8.168.192.in-addr.arpa.", "9.168.192.in-addr.arpa.",
				"10.168.192.in-addr.arpa.", "11.168.192.in-addr.arpa.",
				"12.168.192.in-addr.arpa.", "13.168.192.in-addr.arpa.",
				"14.168.192.in-addr.arpa.", "15.168.192.in-addr.arpa.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			assert.Equal(t, tt.want, GenerateIPv4DNSRootDomain(netip.MustParsePrefix(tt.prefix)))
		})
	}
}

func TestMagicDNSRootDomainsIPv6PrefixBoundaries(t *testing.T) {
	tests := []struct {
		prefix string
		want   []dnsname.FQDN
	}{
		{
			prefix: "fd7a:115c:a1e0::/49",
			want: []dnsname.FQDN{
				"0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"2.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"3.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"4.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"5.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"6.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"7.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
			},
		},
		{
			prefix: "fd7a:115c:a1e0:8000::/49",
			want: []dnsname.FQDN{
				"8.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"9.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"a.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"b.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"c.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"d.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"e.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"f.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
			},
		},
		{
			prefix: "fd7a:115c:a1e0:8000::/50",
			want: []dnsname.FQDN{
				"8.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"9.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"a.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"b.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
			},
		},
		{
			prefix: "fd7a:115c:a1e0:bfff::1/50",
			want: []dnsname.FQDN{
				"8.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"9.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"a.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"b.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
			},
		},
		{
			prefix: "fd7a:115c:a1e0::/51",
			want: []dnsname.FQDN{
				"0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
			},
		},
		{
			prefix: "fd7a:115c:a1e0:e000::/51",
			want: []dnsname.FQDN{
				"e.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
				"f.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
			},
		},
		{
			prefix: "fd7a:115c:a1e0:bfff::1/52",
			want:   []dnsname.FQDN{"b.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."},
		},
		{
			prefix: "::/0",
			want:   []dnsname.FQDN{"ip6.arpa."},
		},
		{
			prefix: "fd7a:115c:a1e0::1/128",
			want:   []dnsname.FQDN{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			assert.Equal(t, tt.want, GenerateIPv6DNSRootDomain(netip.MustParsePrefix(tt.prefix)))
		})
	}
}
