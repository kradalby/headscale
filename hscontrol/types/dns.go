package types

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
)

// DNSView holds one snapshot's DNS settings and records. Its zero value has no
// DNS configuration or certificate eligibility. Mutable copies are for output only.
type DNSView struct {
	settings *dnsSettings
	records  views.Slice[tailcfg.DNSRecord]
}

type dnsSettings struct {
	wire       tailcfg.DNSConfigView
	baseDomain string
	// Raw metadata preserves the configured form for debug output; rendering
	// uses wire. Neither representation stores the revision's extra records.
	metadata DNSConfig
	// Provider configuration is construction-only. Challenge bookkeeping must
	// not affect isolation, and replacing the builder's provider cannot change it.
	isolates func(string) bool
}

// DNSView freezes the startup DNS builder. Runtime readers use Snapshot.DNS;
// constructing another view would discard the snapshot's record revision.
func (c *Config) DNSView() DNSView {
	wire := c.TailcfgDNSConfig.Clone()

	var records []tailcfg.DNSRecord
	if wire != nil {
		records = wire.ExtraRecords
		wire.ExtraRecords = nil

		for i := range records {
			records[i].Name = strings.ToLower(records[i].Name)
		}

		// Operator split-DNS zones with an empty resolver list parse to
		// nil; the wire form is the empty slice, which
		// [tailcfg.DNSConfig.Routes] documents as handled by Tailscale's
		// built-in resolver (100.100.100.100) — the same form the
		// MagicDNS zones below use.
		for domain, resolvers := range wire.Routes {
			if resolvers == nil {
				wire.Routes[domain] = []*dnstype.Resolver{}
			}
		}

		if wire.Proxied {
			var zones []dnsname.FQDN
			if c.PrefixV4 != nil {
				zones = append(zones, util.GenerateIPv4DNSRootDomain(*c.PrefixV4)...)
			}

			if c.PrefixV6 != nil {
				zones = append(zones, util.GenerateIPv6DNSRootDomain(*c.PrefixV6)...)
			}

			if wire.Routes == nil {
				wire.Routes = make(map[string][]*dnstype.Resolver)
			}

			for _, zone := range zones {
				// Empty, not nil (see above): the empty form hands these
				// zones to Tailscale's built-in resolver (100.100.100.100),
				// which answers the MagicDNS reverse lookups itself.
				wire.Routes[zone.WithoutTrailingDot()] = []*dnstype.Resolver{}
			}
		}
	}

	settings := &dnsSettings{wire: wire.View(), baseDomain: c.BaseDomain, metadata: cloneDNSMetadata(c.DNSConfig)}
	if iso, ok := c.DNSChallenge.Provider.(hsdns.Isolator); ok {
		settings.isolates = iso.Isolates
	}

	return DNSView{settings: settings, records: views.SliceOf(records)}
}

// WithExtraRecords owns and normalizes records before the graph publishes them.
// Static settings are shared by every revision of this view.
func (v DNSView) WithExtraRecords(records []tailcfg.DNSRecord) DNSView {
	records = lowercaseRecordNames(records)

	// The records manager republishes sets in map order; a canonical order
	// lets reordered no-op publications retain their graph revision.
	slices.SortFunc(records, func(a, b tailcfg.DNSRecord) int {
		return cmp.Or(
			strings.Compare(a.Name, b.Name),
			strings.Compare(a.Type, b.Type),
			strings.Compare(a.Value, b.Value),
		)
	})

	v.records = views.SliceOf(records)

	return v
}

// Equal lets normalized no-op publications retain their graph revision.
func (v DNSView) Equal(other DNSView) bool {
	return v.settings == other.settings && views.SliceEqual(v.records, other.records)
}

func (v DNSView) ExtraRecords() views.Slice[tailcfg.DNSRecord] { return v.records }

func (v DNSView) BaseDomain() string {
	if v.settings == nil {
		return ""
	}

	return v.settings.baseDomain
}

func (v DNSView) CertificatesEnabled() bool {
	return v.settings != nil && v.settings.metadata.Certificates.Enabled
}

func (v DNSView) ExtraRecordsPath() string {
	if v.settings == nil {
		return ""
	}

	return v.settings.metadata.ExtraRecordsPath
}

// AsStruct returns an independent wire copy for serialization and per-node
// resolver customization. Ordinary reads must not pay for this clone.
func (v DNSView) AsStruct() *tailcfg.DNSConfig {
	if v.settings == nil || !v.settings.wire.Valid() {
		return nil
	}

	wire := v.settings.wire.AsStruct()
	wire.ExtraRecords = v.records.AsSlice()

	return wire
}

// DebugConfig returns independent diagnostic metadata with this revision's
// records, not a builder for runtime rendering.
func (v DNSView) DebugConfig() DNSConfig {
	if v.settings == nil {
		return DNSConfig{}
	}

	metadata := cloneDNSMetadata(v.settings.metadata)
	metadata.ExtraRecords = v.records.AsSlice()

	return metadata
}

func cloneDNSMetadata(src DNSConfig) DNSConfig {
	src.ExtraRecords = nil
	src.SearchDomains = slices.Clone(src.SearchDomains)
	src.Nameservers.Global = slices.Clone(src.Nameservers.Global)

	src.Nameservers.Split = maps.Clone(src.Nameservers.Split)
	for domain, resolvers := range src.Nameservers.Split {
		src.Nameservers.Split[domain] = slices.Clone(resolvers)
	}

	return src
}

// extraRecordAtOrBelow matches TLS names case-insensitively; name is lowercase.
// Records live outside the wire config, so their guard holds even for a nil
// wire template.
func (v DNSView) extraRecordAtOrBelow(name string) bool {
	if v.settings == nil {
		return false
	}

	for _, r := range v.records.All() {
		rn := strings.TrimSuffix(r.Name, ".")
		if rn == name || strings.HasSuffix(rn, "."+name) {
			return true
		}
	}

	return false
}
