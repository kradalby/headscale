package v2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"

	"tailscale.com/tailcfg"
)

// With policy.filter_chunks a node's packet filter goes to its client as
// named chunks ([tailcfg.MapResponse.PacketFilters]), whatever form its
// sources are in: the client keeps the chunks it was sent, a response
// replaces the chunks it names and deletes those it names null, "*": null
// clears every chunk first, and the client concatenates the chunks in key
// order. Whether a session is sent chunks at all is [FilterDelivery]'s.
//
// A chunk is one rule, named by a hash of every field of the rule, so a
// name stands for exactly the rule sent under it, and so for its bytes: two
// chunks that differ never share a name, and an unchanged rule keeps its
// name across commits, nodes and sessions. A session therefore sends the
// names it has not sent and deletes the names that went, and compares
// nothing else. Names need not survive a restart or an upgrade: every map
// session starts with "*": null. The unit is the wire rule rather than the
// policy rule it came from because the rules a node is sent are not the
// policy's: they are cut to the node's own addresses and routes, address
// form merges rules of different grants and via rules of one class, and
// autogroup:self writes one rule per owner.
//
// The one exception is order: an application reads a capability's values
// in the order its rules come (the client filter's CapsWithValues), so every
// rule carrying a CapGrant, companions included, goes in one chunk, in the
// order the filter has them. No other rule's position decides a verdict:
// rules only allow.

const (
	// chunkClear clears every chunk the client holds, before the rest of
	// the response applies.
	chunkClear = "*"
	// chunkBase is the chunk the singular PacketFilter field sets, and the
	// one a whole filter goes under.
	chunkBase = "base"
	// ruleChunkPrefix names a chunk of one rule, capChunkPrefix the chunk
	// of every rule carrying a CapGrant; both are chunkPrefixLen long.
	ruleChunkPrefix = "r/"
	capChunkPrefix  = "c/"
	chunkPrefixLen  = 2
	// chunkHashBytes is how much of the hash a name carries: enough that
	// two contents never meet under one name.
	chunkHashBytes = 16
	// chunkNameLen is a name's length: a prefix, then the hash in base64.
	chunkNameLen = chunkPrefixLen + (chunkHashBytes*8+5)/6
)

// FilterChunks is a node's packet filter as its client holds it in named
// chunks. The zero value holds none.
type FilterChunks struct {
	// chunks are sorted by name, one per name.
	chunks []filterChunk

	// of is the filter the chunks were cut from, byRule the name each of
	// its rules went under ("" for a CapGrant rule), and capName and caps
	// the CapGrant chunk's, so a filter cut again reuses the names it
	// shares without building them again.
	of      []tailcfg.FilterRule
	byRule  []string
	capName string
	caps    []tailcfg.FilterRule
}

type filterChunk struct {
	name  string
	rules []tailcfg.FilterRule
	// at is the rule's index in the filter cut, or -1 for the CapGrant
	// chunk.
	at int
}

// ChunkFilter cuts rules into the chunks a client is sent.
func ChunkFilter(rules []tailcfg.FilterRule) FilterChunks {
	return FilterChunks{}.Recut(rules)
}

// Recut is [ChunkFilter], reusing what c, the chunks of an earlier filter,
// built: for rules that are c's own filter, every chunk. rules must not be
// modified while the chunks are held: a chunk of one rule is its slice of
// rules, and the same slice is taken to hold the same rules. Every other
// filter has each rule hashed, which costs about what comparing it would.
func (c FilterChunks) Recut(rules []tailcfg.FilterRule) FilterChunks {
	if sameRuleList(c.of, rules) {
		return c
	}

	buf := chunkBuffers.Get().(*[]byte) //nolint:forcetypeassert // the pool holds nothing else
	defer chunkBuffers.Put(buf)

	out := FilterChunks{of: rules, byRule: make([]string, len(rules))}
	same := c.of != nil && len(c.of) == len(rules)

	for i := range rules {
		if len(rules[i].CapGrant) > 0 {
			out.caps = append(out.caps, rules[i])

			continue
		}

		*buf = appendRule(append((*buf)[:0], 'r'), &rules[i])
		out.byRule[i] = c.nameFor(ruleChunkPrefix, *buf, i)
		same = same && out.byRule[i] == c.byRule[i]
	}

	// TODO(kradalby): chunks/capgrant-whole: every CapGrant rule of a
	// filter goes in one chunk, so a change of any one resends them all;
	// for a receiver sent addresses (a router, an exit node, a client other
	// than Tailscale's) that is every member joining or leaving a source
	// an app grant names. Chosen so a capability's values keep the order
	// an application reads them in. A fix splits the chunk by capability:
	// Filter.CapsWithValues appends values per capability
	// (https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/filter/filter.go),
	// so only rules naming a common capability need share a chunk. Counted
	// by BenchmarkChunkedWrites (chunks-sent/op); TestChunkFilterShape pins
	// the one chunk. No upstream reference: headscale's own delivery.
	if len(out.caps) > 0 {
		*buf = append((*buf)[:0], 'c')
		for i := range out.caps {
			*buf = appendRule(*buf, &out.caps[i])
		}

		out.capName = c.nameFor(capChunkPrefix, *buf, -1)
	}

	// The same names in the same places: c's chunks, over rules.
	if same && out.capName == c.capName {
		out.byRule = c.byRule
		out.chunks = slices.Clone(c.chunks)

		for i := range out.chunks {
			out.chunks[i].rules = out.caps
			if at := out.chunks[i].at; at >= 0 {
				out.chunks[i].rules = rules[at : at+1 : at+1]
			}
		}

		return out
	}

	out.chunks = make([]filterChunk, 0, len(rules)+1)

	for i, name := range out.byRule {
		if name != "" {
			out.chunks = append(out.chunks, filterChunk{name: name, rules: rules[i : i+1 : i+1], at: i})
		}
	}

	if out.capName != "" {
		out.chunks = append(out.chunks, filterChunk{name: out.capName, rules: out.caps, at: -1})
	}

	slices.SortFunc(out.chunks, func(a, b filterChunk) int { return strings.Compare(a.name, b.name) })

	// A rule sent twice is one chunk: rules only allow, so the second
	// copy decides nothing.
	out.chunks = slices.CompactFunc(out.chunks, func(a, b filterChunk) bool { return a.name == b.name })

	return out
}

// sameRuleList reports whether b is a, the filter chunks were cut from:
// the same slice, as a cached filter is from one render to the next, or
// both empty once a was cut (a nil a was never cut).
func sameRuleList(a, b []tailcfg.FilterRule) bool {
	if len(a) != len(b) {
		return false
	}

	return len(a) == 0 && a != nil || len(a) > 0 && &a[0] == &b[0]
}

var chunkBuffers = sync.Pool{New: func() any { return new([]byte) }}

// nameFor names the chunk of prefix whose rules encode to enc, returning
// the string c already holds for that name when it has one, so a name
// built again costs no allocation: at is the rule's index in c's filter,
// where an unmoved rule's name is, or -1.
func (c FilterChunks) nameFor(prefix string, enc []byte, at int) string {
	sum := sha256.Sum256(enc)

	var name [chunkNameLen]byte

	copy(name[:], prefix)
	base64.RawURLEncoding.Encode(name[chunkPrefixLen:], sum[:chunkHashBytes])

	switch {
	case at >= 0 && at < len(c.byRule) && c.byRule[at] == string(name[:]):
		return c.byRule[at]
	case at < 0 && c.capName == string(name[:]):
		return c.capName
	}

	lo, hi := 0, len(c.chunks)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1) //nolint:gosec // a midpoint of two lengths

		switch n := c.chunks[mid].name; {
		case n == string(name[:]):
			return n
		case n < string(name[:]):
			lo = mid + 1
		default:
			hi = mid
		}
	}

	return string(name[:])
}

// appendRule appends to b an encoding of every field of r in which every
// element delimits itself: a list starts with its length (0 for nil, so nil
// and empty differ), a string with its length, a number is a varint, a
// pointer starts with whether it is set, a prefix with its address's length.
// So the encoding decodes back to r, and two rules encode alike only when
// they are equal; TestChunkEncodingRoundTrips decodes it,
// TestChunkNameCoversEveryField edits every field tailcfg has.
func appendRule(b []byte, r *tailcfg.FilterRule) []byte {
	b = appendStrings(b, r.SrcIPs)
	b = appendInts(b, r.SrcBits) //nolint:staticcheck // deprecated, still on the wire

	b = appendLen(b, r.DstPorts == nil, len(r.DstPorts))
	for _, d := range r.DstPorts {
		b = appendString(b, d.IP)

		if d.Bits == nil { //nolint:staticcheck // deprecated, still on the wire
			b = append(b, 0)
		} else {
			b = binary.AppendVarint(append(b, 1), int64(*d.Bits)) //nolint:staticcheck // deprecated, still on the wire
		}

		b = binary.AppendUvarint(b, uint64(d.Ports.First))
		b = binary.AppendUvarint(b, uint64(d.Ports.Last))
	}

	b = appendInts(b, r.IPProto)

	b = appendLen(b, r.CapGrant == nil, len(r.CapGrant))
	for _, g := range r.CapGrant {
		b = appendLen(b, g.Dsts == nil, len(g.Dsts))
		for _, p := range g.Dsts {
			b = appendPrefix(b, p)
		}

		b = appendLen(b, g.Caps == nil, len(g.Caps)) //nolint:staticcheck // deprecated, still on the wire
		for _, c := range g.Caps {                   //nolint:staticcheck // deprecated, still on the wire
			b = appendString(b, string(c))
		}

		b = appendLen(b, g.CapMap == nil, len(g.CapMap))
		for _, k := range slices.Sorted(maps.Keys(g.CapMap)) {
			vs := g.CapMap[k]
			b = appendLen(appendString(b, string(k)), vs == nil, len(vs))

			for _, v := range vs {
				b = appendString(b, string(v))
			}
		}
	}

	return b
}

// appendPrefix appends p as its address's length in bytes (0, 4 or 16),
// the address, and its bits (-1 when invalid).
func appendPrefix(b []byte, p netip.Prefix) []byte {
	a := p.Addr()
	b = append(append(b, byte(a.BitLen()/8)), a.AsSlice()...) //nolint:gosec // 0, 4 or 16

	return binary.AppendVarint(b, int64(p.Bits()))
}

// appendLen appends a list's length, 0 for a nil list.
func appendLen(b []byte, isNil bool, n int) []byte {
	if isNil {
		return append(b, 0)
	}

	return binary.AppendUvarint(b, uint64(n)+1) //nolint:gosec // a length
}

func appendString(b []byte, s string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(s))), s...)
}

func appendStrings(b []byte, ss []string) []byte {
	b = appendLen(b, ss == nil, len(ss))
	for _, s := range ss {
		b = appendString(b, s)
	}

	return b
}

func appendInts(b []byte, is []int) []byte {
	b = appendLen(b, is == nil, len(is))
	for _, i := range is {
		b = binary.AppendVarint(b, int64(i))
	}

	return b
}

// Reset returns the PacketFilters that leave a client holding exactly c,
// whatever it held: "*": null, then every chunk. A stream's first response
// carries it, since a client may keep chunks across map sessions.
func (c FilterChunks) Reset() map[string][]tailcfg.FilterRule {
	out := make(map[string][]tailcfg.FilterRule, len(c.chunks)+1)
	out[chunkClear] = nil

	for _, ch := range c.chunks {
		out[ch.name] = ch.rules
	}

	return out
}

// Delta returns the PacketFilters taking a client holding held to c: the
// chunks of c that held lacks, and null for each of held's that c lacks;
// nil when they hold the same names, which hold the same rules.
func (c FilterChunks) Delta(held FilterChunks) map[string][]tailcfg.FilterRule {
	var out map[string][]tailcfg.FilterRule

	set := func(name string, rules []tailcfg.FilterRule) {
		if out == nil {
			out = make(map[string][]tailcfg.FilterRule)
		}

		out[name] = rules
	}

	i, j := 0, 0
	for i < len(c.chunks) || j < len(held.chunks) {
		switch {
		case j == len(held.chunks) || i < len(c.chunks) && c.chunks[i].name < held.chunks[j].name:
			set(c.chunks[i].name, c.chunks[i].rules)
			i++
		case i == len(c.chunks) || held.chunks[j].name < c.chunks[i].name:
			set(held.chunks[j].name, nil)
			j++
		default:
			i++
			j++
		}
	}

	return out
}

// Names returns the chunks' names, sorted.
func (c FilterChunks) Names() []string {
	out := make([]string, len(c.chunks))
	for i, ch := range c.chunks {
		out[i] = ch.name
	}

	return out
}

// Len returns how many chunks c holds.
func (c FilterChunks) Len() int { return len(c.chunks) }

// Chunk returns the rules held under name.
func (c FilterChunks) Chunk(name string) ([]tailcfg.FilterRule, bool) {
	i, ok := slices.BinarySearchFunc(c.chunks, name, func(ch filterChunk, n string) int { return strings.Compare(ch.name, n) })
	if !ok {
		return nil, false
	}

	return c.chunks[i].rules, true
}

// The client's side, as tailscale.com/control/controlclient's map session
// applies a response; what servers check a client assembles against, and
// pinned to the client by TestCanaryClientChunkMerge.

// ApplyResponse returns what a client holding c holds after resp: the
// singular PacketFilter sets "base", then PacketFilters applies.
func (c FilterChunks) ApplyResponse(resp *tailcfg.MapResponse) FilterChunks {
	if resp.PacketFilter != nil {
		c = c.Apply(map[string][]tailcfg.FilterRule{chunkBase: resp.PacketFilter})
	}

	return c.Apply(resp.PacketFilters)
}

// Apply returns what a client holding c holds after a response carrying
// update as its PacketFilters: "*": null clears every chunk first, a null
// chunk is deleted, any other replaces the chunk of its name.
func (c FilterChunks) Apply(update map[string][]tailcfg.FilterRule) FilterChunks {
	if update == nil {
		return c
	}

	held := make(map[string][]tailcfg.FilterRule, len(c.chunks)+len(update))

	if v, ok := update[chunkClear]; !ok || v != nil {
		for _, ch := range c.chunks {
			held[ch.name] = ch.rules
		}
	}

	for name, rules := range update {
		switch {
		case name == chunkClear:
		case rules == nil:
			delete(held, name)
		default:
			held[name] = rules
		}
	}

	out := FilterChunks{chunks: make([]filterChunk, 0, len(held))}
	for _, name := range slices.Sorted(maps.Keys(held)) {
		out.chunks = append(out.chunks, filterChunk{name: name, rules: held[name]})
	}

	return out
}

// Equal reports whether c and o hold the same chunks: the same names, the
// same rules under each.
func (c FilterChunks) Equal(o FilterChunks) bool {
	return slices.EqualFunc(c.chunks, o.chunks, func(a, b filterChunk) bool {
		return a.name == b.name && reflect.DeepEqual(a.rules, b.rules)
	})
}

// Rules returns the filter a client holding c enforces: every chunk's
// rules, chunks in key order.
func (c FilterChunks) Rules() []tailcfg.FilterRule {
	var out []tailcfg.FilterRule
	for _, ch := range c.chunks {
		out = append(out, ch.rules...)
	}

	return out
}
