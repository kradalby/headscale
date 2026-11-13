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

	assert.Len(t, domains, 1)
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("16.172.in-addr.arpa.")))
}

// An octet-aligned mask has no wildcard bits, so it must yield exactly one
// reverse-DNS name. Enumerating the next octet instead emits all 256 children
// of that name, which can overflow a resolver's per-link domain limit.
func TestMagicDNSRootDomainsOctetAligned(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		want   string
	}{
		{prefix: "0.0.0.0/0", want: "in-addr.arpa."},
		{prefix: "100.0.0.0/8", want: "100.in-addr.arpa."},
		{prefix: "100.120.0.5/24", want: "0.120.100.in-addr.arpa."},
		{prefix: "100.120.0.0/16", want: "120.100.in-addr.arpa."},
		{prefix: "100.120.0.0/24", want: "0.120.100.in-addr.arpa."},
		{prefix: "100.120.0.5/32", want: "5.0.120.100.in-addr.arpa."},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix(tt.prefix))

			assert.Len(t, domains, 1)
			assert.Contains(t, domains, must.Get(dnsname.ToFQDN(tt.want)))
		})
	}
}

// An unaligned mask stops inside an octet, leaving wildcard bits that must
// enumerate every value that octet takes within the prefix. RFC1035 reverse
// delegation is per-octet, so a mask longer than /24 enumerates host names
// rather than delegating classlessly (RFC2317), which is what Tailscale
// expects.
func TestMagicDNSRootDomainsUnaligned(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		count  int
		first  string
		last   string
		absent []string
	}{
		{
			prefix: "10.0.0.0/7",
			count:  2,
			first:  "10.in-addr.arpa.",
			last:   "11.in-addr.arpa.",
			absent: []string{"12.in-addr.arpa."},
		},
		{
			// Host bits set: the range starts at the masked octet.
			prefix: "100.65.0.0/10",
			count:  64,
			first:  "64.100.in-addr.arpa.",
			last:   "127.100.in-addr.arpa.",
			absent: []string{"128.100.in-addr.arpa."},
		},
		{
			prefix: "10.0.0.0/9",
			count:  128,
			first:  "0.10.in-addr.arpa.",
			last:   "127.10.in-addr.arpa.",
			absent: []string{"128.10.in-addr.arpa."},
		},
		{
			prefix: "100.64.0.0/10",
			count:  64,
			first:  "64.100.in-addr.arpa.",
			last:   "127.100.in-addr.arpa.",
			absent: []string{
				"63.100.in-addr.arpa.",
				"128.100.in-addr.arpa.",
			},
		},
		{
			prefix: "172.16.0.0/12",
			count:  16,
			first:  "16.172.in-addr.arpa.",
			last:   "31.172.in-addr.arpa.",
			absent: []string{
				"15.172.in-addr.arpa.",
				"32.172.in-addr.arpa.",
			},
		},
		{
			prefix: "100.120.0.0/17",
			count:  128,
			first:  "0.120.100.in-addr.arpa.",
			last:   "127.120.100.in-addr.arpa.",
			absent: []string{"128.120.100.in-addr.arpa."},
		},
		{
			prefix: "192.168.0.0/23",
			count:  2,
			first:  "0.168.192.in-addr.arpa.",
			last:   "1.168.192.in-addr.arpa.",
			absent: []string{"2.168.192.in-addr.arpa."},
		},
		{
			prefix: "100.120.0.0/25",
			count:  128,
			first:  "0.0.120.100.in-addr.arpa.",
			last:   "127.0.120.100.in-addr.arpa.",
			absent: []string{"128.0.120.100.in-addr.arpa."},
		},
		{
			prefix: "100.120.0.4/30",
			count:  4,
			first:  "4.0.120.100.in-addr.arpa.",
			last:   "7.0.120.100.in-addr.arpa.",
			absent: []string{
				"3.0.120.100.in-addr.arpa.",
				"8.0.120.100.in-addr.arpa.",
			},
		},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix(tt.prefix))

			assert.Len(t, domains, tt.count)
			assert.Contains(t, domains, must.Get(dnsname.ToFQDN(tt.first)))
			assert.Contains(t, domains, must.Get(dnsname.ToFQDN(tt.last)))

			for _, dom := range tt.absent {
				assert.NotContains(t, domains, must.Get(dnsname.ToFQDN(dom)))
			}
		})
	}
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
// zone names the masked network, exactly as a clean prefix does.
func TestMagicDNSRootDomainsIPv4DirtyByteAligned(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.5.0/16"))

	assert.Equal(t, []dnsname.FQDN{"16.172.in-addr.arpa."}, domains)
	assert.Equal(t, GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.0.0/16")), domains)
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
