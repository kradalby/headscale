package propcheck

import (
	"fmt"
	"slices"
	"strings"

	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// DrawDNSRecords draws bounded lists of client-supported A and AAAA records.
// A small name/address pool deliberately produces duplicate records and names
// with different types or values. Nil, empty, mixed case and rooted names occur.
func DrawDNSRecords(t *rapid.T) []tailcfg.DNSRecord {
	if rapid.Bool().Draw(t, "nil records") {
		return nil
	}

	records := make([]tailcfg.DNSRecord, rapid.IntRange(0, 8).Draw(t, "record count"))
	for i := range records {
		name := rapid.SampledFrom([]string{"node", "service", "child.node", strings.Repeat("a", 63)}).Draw(t, "record label") + ".example.com"
		if rapid.Bool().Draw(t, "uppercase record") {
			name = strings.ToUpper(name)
		}

		if rapid.Bool().Draw(t, "rooted record") {
			name += "."
		}

		address := rapid.IntRange(1, 4).Draw(t, "record address")

		records[i] = tailcfg.DNSRecord{Name: name, Type: "A", Value: fmt.Sprintf("100.64.0.%d", address)}
		if rapid.Bool().Draw(t, "IPv6 record") {
			records[i].Type = "AAAA"
			records[i].Value = fmt.Sprintf("fd7a:115c:a1e0::%d", address)
		}
	}

	return records
}

// CanonicalDNSRecords specifies publication equivalence: lowercase names and
// lexicographic (name, type, value) ordering, preserving duplicates and values.
// A trailing dot is preserved on the wire; only certificate matching ignores it.
// Empty inputs have one reference representation (nil). The result owns storage.
// This reference uses sortable tuple encodings, independent of DNSView helpers.
func CanonicalDNSRecords(records []tailcfg.DNSRecord) []tailcfg.DNSRecord {
	if len(records) == 0 {
		return nil
	}

	keys := make([]string, 0, len(records))
	for _, record := range records {
		keys = append(keys, strings.Join([]string{strings.ToLower(record.Name), record.Type, record.Value}, "\x00"))
	}

	slices.Sort(keys)

	result := make([]tailcfg.DNSRecord, 0, len(keys))
	for _, key := range keys {
		fields := strings.Split(key, "\x00")
		result = append(result, tailcfg.DNSRecord{Name: fields[0], Type: fields[1], Value: fields[2]})
	}

	return result
}
