package v2

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

// fullRule sets every field a filter rule has, so a test can change each.
func fullRule() tailcfg.FilterRule {
	bits := 32

	return tailcfg.FilterRule{
		SrcIPs:   []string{"100.64.0.1", "cap:" + capGroupEng},
		SrcBits:  []int{32}, //nolint:staticcheck // deprecated, still on the wire
		DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.10", Bits: &bits, Ports: tailcfg.PortRange{First: 443, Last: 443}}},
		IPProto:  []int{6},
		CapGrant: []tailcfg.CapGrant{{
			Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
			Caps:   []peercap.Cap{"example.com/cap/legacy"},
			CapMap: tailcfg.PeerCapMap{"example.com/cap/admin": {tailcfg.RawMessage(`{"role":"ops"}`)}},
		}},
	}
}

// leafEdits returns, for every leaf a value of v's type reaches, an edit
// of v changing that leaf: a reflection walk, so a field tailcfg adds is
// edited too, and fails when it meets a kind it cannot edit.
func leafEdits(t *testing.T, v reflect.Value, path string) map[string]func() {
	t.Helper()

	out := map[string]func(){}

	switch {
	case v.Type() == reflect.TypeFor[netip.Prefix]():
		out[path] = func() { v.Set(reflect.ValueOf(netip.MustParsePrefix("100.64.0.11/32"))) }
	case v.Type() == reflect.TypeFor[tailcfg.RawMessage]():
		out[path] = func() { v.SetBytes([]byte(`{"role":"dev"}`)) }
	case v.Kind() == reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).Name == "_" {
				continue
			}

			require.Truef(t, v.Field(i).CanSet(), "%s: unexported field %s", path, v.Type().Field(i).Name)
			maps.Copy(out, leafEdits(t, v.Field(i), path+"."+v.Type().Field(i).Name))
		}
	case v.Kind() == reflect.Slice:
		require.Positivef(t, v.Len(), "%s: the full rule sets every list", path)
		maps.Copy(out, leafEdits(t, v.Index(0), path+"[0]"))
	case v.Kind() == reflect.Map:
		require.Equalf(t, 1, v.Len(), "%s: the full rule sets every map, once", path)

		key := v.MapKeys()[0]
		val := v.MapIndex(key)
		out[path+"[key]"] = func() {
			v.SetMapIndex(key, reflect.Value{})
			v.SetMapIndex(reflect.ValueOf(peercap.Cap(key.String()+"/other")), val)
		}
		out[path+"[value]"] = func() {
			v.SetMapIndex(key, reflect.ValueOf([]tailcfg.RawMessage{tailcfg.RawMessage(`{"role":"dev"}`)}))
		}
	case v.Kind() == reflect.Pointer:
		require.Falsef(t, v.IsNil(), "%s: the full rule sets every pointer", path)

		return leafEdits(t, v.Elem(), path)
	case v.Kind() == reflect.String:
		out[path] = func() { v.SetString(v.String() + "x") }
	case v.CanInt():
		out[path] = func() { v.SetInt(v.Int() + 1) }
	case v.CanUint():
		out[path] = func() { v.SetUint(v.Uint() + 1) }
	default:
		t.Fatalf("%s: no edit for a %s", path, v.Type())
	}

	return out
}

// TestChunkNameCoversEveryField holds a chunk's name to every field of its
// rule: changing any leaf a rule has must rename it, or a session would
// take an edited rule for one its client holds.
func TestChunkNameCoversEveryField(t *testing.T) {
	t.Parallel()

	name := func(r tailcfg.FilterRule) string {
		t.Helper()

		// Without a CapGrant the rule is a chunk of its own; with one, it
		// is the CapGrant chunk. Name it both ways.
		c := ChunkFilter([]tailcfg.FilterRule{r, {SrcIPs: []string{"*"}}})

		return strings.Join(c.Names(), ",")
	}

	base := name(fullRule())
	require.Equal(t, base, name(fullRule()), "equal rules, built apart, share a name")

	probe := fullRule()
	edits := leafEdits(t, reflect.ValueOf(&probe).Elem(), "FilterRule")
	require.Greater(t, len(edits), 10, "test sanity: the walk reached the rule's leaves")

	// A recut from the unedited rule's chunks must not take the edited rule
	// for the one at its position, in the CapGrant chunk or a chunk of its
	// own.
	recut := func(from, to tailcfg.FilterRule) string {
		t.Helper()

		prev := ChunkFilter([]tailcfg.FilterRule{from, {SrcIPs: []string{"*"}}})

		c := prev.Recut([]tailcfg.FilterRule{to, {SrcIPs: []string{"*"}}})

		return strings.Join(c.Names(), ",")
	}

	for path := range edits {
		r := fullRule()
		leafEdits(t, reflect.ValueOf(&r).Elem(), "FilterRule")[path]()
		require.NotEqualf(t, base, name(r), "changing %s keeps the chunk's name", path)
		require.Equalf(t, name(r), recut(fullRule(), r), "a recut keeps the old name of %s", path)

		plain := fullRule()
		r.CapGrant, plain.CapGrant = nil, nil

		if !reflect.DeepEqual(r, plain) {
			require.NotEqualf(t, name(plain), name(r), "changing %s keeps the name of a rule without CapGrant", path)
			require.Equalf(t, name(r), recut(plain, r), "a recut keeps the old name of %s without CapGrant", path)
		}
	}
}

// TestChunkFilterShape pins how a filter is cut: a chunk per rule, every
// CapGrant rule in one chunk in the filter's order, a rule sent twice once.
func TestChunkFilterShape(t *testing.T) {
	t.Parallel()

	port := func(p uint16) tailcfg.FilterRule {
		return tailcfg.FilterRule{
			SrcIPs:   []string{"cap:" + capGroupEng},
			DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.10", Ports: tailcfg.PortRange{First: p, Last: p}}},
		}
	}
	app := func(role string) tailcfg.FilterRule {
		return tailcfg.FilterRule{
			SrcIPs: []string{"100.64.0.1"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
				CapMap: tailcfg.PeerCapMap{"example.com/cap/admin": {tailcfg.RawMessage(`{"role":"` + role + `"}`)}},
			}},
		}
	}

	rules := []tailcfg.FilterRule{app("b"), port(22), app("a"), port(443), port(22), app("b")}

	c := ChunkFilter(rules)

	names := c.Names()
	require.Len(t, names, 3, "22 once, 443, and the CapGrant chunk")
	require.True(t, slices.IsSorted(names))

	var capChunks int

	for _, n := range names {
		got, ok := c.Chunk(n)
		require.True(t, ok)

		switch {
		case strings.HasPrefix(n, capChunkPrefix):
			capChunks++

			require.Equal(t, []tailcfg.FilterRule{app("b"), app("a"), app("b")}, got,
				"CapGrant rules together, in the filter's order, each copy kept: an application sees values in this order")
		case strings.HasPrefix(n, ruleChunkPrefix):
			require.Len(t, got, 1)
			require.Contains(t, []tailcfg.FilterRule{port(22), port(443)}, got[0])
		default:
			t.Fatalf("chunk %q has no known prefix", n)
		}

		require.NotEqual(t, chunkClear, n)
		require.NotEqual(t, chunkBase, n)
	}

	require.Equal(t, 1, capChunks)

	empty := ChunkFilter(nil)
	require.Zero(t, empty.Len())
	require.Equal(t, map[string][]tailcfg.FilterRule{chunkClear: nil}, empty.Reset(), "an empty filter clears the client")
}

// TestChunkDeltaConverges is the session's invariant over random filters:
// whatever the client held, the first response leaves it holding the
// filter's chunks, and each delta after takes it from the last filter's
// chunks to the next's; recutting from the last filter names what a cut
// from scratch names.
func TestChunkDeltaConverges(t *testing.T) {
	t.Parallel()

	pool := make([]tailcfg.FilterRule, 0, 12)
	for i := range 6 {
		pool = append(pool, tailcfg.FilterRule{
			SrcIPs:   []string{fmt.Sprintf("100.64.0.%d", i%3+1)},
			DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.10", Ports: tailcfg.PortRange{First: uint16(i % 2), Last: 80}}}, //nolint:gosec // small
			IPProto:  []int{6 + 11*(i%2)},
		})
		pool = append(pool, tailcfg.FilterRule{
			SrcIPs: []string{fmt.Sprintf("100.64.0.%d", i+1)},
			CapGrant: []tailcfg.CapGrant{{
				Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
				CapMap: tailcfg.PeerCapMap{peercap.Cap(fmt.Sprintf("example.com/cap/%d", i%2)): nil},
			}},
		})
	}

	filterGen := rapid.Custom(func(rt *rapid.T) []tailcfg.FilterRule {
		idx := rapid.SliceOfN(rapid.IntRange(0, len(pool)-1), 0, 8).Draw(rt, "rules")
		out := make([]tailcfg.FilterRule, 0, len(idx))

		for _, i := range idx {
			// A copy built apart, as a cut builds it.
			out = append(out, fullCopy(pool[i]))
		}

		return out
	})

	rapid.Check(t, func(rt *rapid.T) {
		// What the client held before this stream: anything at all, the
		// chunks of an earlier session or of another server.
		stale := FilterChunks{}.Apply(map[string][]tailcfg.FilterRule{
			"base": filterGen.Draw(rt, "stale base"), "r/stale": filterGen.Draw(rt, "stale chunk"),
		})

		first := filterGen.Draw(rt, "first")
		sent := ChunkFilter(first)

		held := stale.Apply(sent.Reset())
		require.True(rt, held.Equal(sent), "the first response leaves the client holding exactly the filter's chunks")

		for step := range rapid.IntRange(1, 6).Draw(rt, "steps") {
			next := filterGen.Draw(rt, fmt.Sprintf("filter %d", step))

			recut := sent.Recut(next)

			fresh := ChunkFilter(next)
			require.True(rt, recut.Equal(fresh), "a recut names what a fresh cut names")

			d := recut.Delta(sent)
			if sent.Equal(recut) {
				require.Nil(rt, d, "no change, no PacketFilters")
			}

			_, cleared := d[chunkClear]
			require.False(rt, cleared, "a delta never clears")

			held = held.Apply(d)
			require.True(rt, held.Equal(fresh), "step %d: the client holds %v, a fresh session sends %v", step, held.Names(), fresh.Names())

			sent = recut
		}
	})
}

// fullCopy is r built apart: no list shared with r.
func fullCopy(r tailcfg.FilterRule) tailcfg.FilterRule {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}

	var out tailcfg.FilterRule
	if err := json.Unmarshal(b, &out); err != nil { //nolint:noinlineerr
		panic(err)
	}

	return out
}

// TestChunkRecutKeepsUnchangedNames pins the reuse a recut makes: a rule
// equal to one the chunks held keeps the name string they held, a rule
// that changed is named afresh, and a filter sharing its first rules with
// the one before but longer or shorter is cut as a fresh one is.
func TestChunkRecutKeepsUnchangedNames(t *testing.T) {
	t.Parallel()

	a := tailcfg.FilterRule{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}}}
	b := tailcfg.FilterRule{SrcIPs: []string{"100.64.0.2"}, DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}}}

	prev := ChunkFilter([]tailcfg.FilterRule{a, b})

	same := prev.Recut([]tailcfg.FilterRule{fullCopy(a), fullCopy(b)})
	require.Equal(t, prev.Names(), same.Names())
	require.Equal(t, prev.byRule, same.byRule)

	moved := fullCopy(b)
	moved.DstPorts[0].Ports.First = 1

	next := prev.Recut([]tailcfg.FilterRule{fullCopy(a), moved})
	require.Equal(t, prev.byRule[0], next.byRule[0])
	require.NotEqual(t, prev.byRule[1], next.byRule[1])

	d := next.Delta(prev)
	require.Equal(t, map[string][]tailcfg.FilterRule{prev.byRule[1]: nil, next.byRule[1]: {moved}}, d,
		"one rule edited: its old name deleted, its new one sent")

	// A filter that keeps its first rules and loses or gains one at the
	// end shares every name in place but is not the same filter.
	app := tailcfg.FilterRule{SrcIPs: []string{"100.64.0.3"}, CapGrant: []tailcfg.CapGrant{{
		Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
		CapMap: tailcfg.PeerCapMap{"example.com/cap/x": nil},
	}}}

	for _, rules := range [][]tailcfg.FilterRule{
		{fullCopy(a)},
		{fullCopy(a), fullCopy(b), {SrcIPs: []string{"*"}}},
		{fullCopy(a), fullCopy(b), app},
	} {
		got := prev.Recut(rules)
		require.True(t, got.Equal(ChunkFilter(rules)), "%d rules from 2: as a fresh cut", len(rules))
		require.ElementsMatch(t, rules, got.Rules(), "%d rules from 2: every rule held", len(rules))
	}

	require.True(t, ChunkFilter([]tailcfg.FilterRule{a, app}).Recut([]tailcfg.FilterRule{fullCopy(a)}).Equal(ChunkFilter([]tailcfg.FilterRule{a})),
		"the CapGrant chunk dropped")
}

// BenchmarkChunkRecut measures what a session pays to cut its filter into
// chunks: first, with every rule as it was, with one rule changed, and with
// one rule inserted at the top; json-marshal is encoding the filter once,
// as the first map does anyway.
func BenchmarkChunkRecut(b *testing.B) {
	filter := func(port uint16) []tailcfg.FilterRule {
		out := make([]tailcfg.FilterRule, 0, 30)
		for i := range 30 {
			out = append(out, tailcfg.FilterRule{
				SrcIPs:   []string{"cap:" + capGroupEng, fmt.Sprintf("100.64.%d.0/24", i)},
				DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.10", Ports: tailcfg.PortRange{First: uint16(1000 + i), Last: uint16(1000 + i)}}}, //nolint:gosec // small
				IPProto:  []int{6},
			})
		}

		out[7].DstPorts[0].Ports = tailcfg.PortRange{First: port, Last: port}

		return out
	}

	b.Run("json-marshal", func(b *testing.B) {
		rules := filter(1)

		b.ReportAllocs()

		for b.Loop() {
			_, err := json.Marshal(rules)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	for _, tt := range []struct {
		name     string
		prev     bool
		port     uint16
		inserted bool
	}{{"first", false, 2, false}, {"one-rule-changed", true, 2, false}, {"same-rules", true, 1, false}, {"rule-inserted-at-top", true, 1, true}} {
		b.Run(tt.name, func(b *testing.B) {
			var prev FilterChunks

			if tt.prev {
				prev = ChunkFilter(filter(1))
			}

			next := filter(tt.port)
			if tt.inserted {
				next = slices.Insert(next, 0, tailcfg.FilterRule{SrcIPs: []string{"*"}, DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}}})
			}

			b.ReportAllocs()

			for b.Loop() {
				prev.Recut(next)
			}
		})
	}
}

// chunkDecoder reads what [appendRule] writes, failing on anything left
// unread or short: that every encoding decodes back to its rule is what
// makes two different rules, or two different lists of them, encode apart.
type chunkDecoder struct {
	b   []byte
	err error
}

var errChunkDecode = errors.New("decoding a chunk")

func (d *chunkDecoder) fail(what string) {
	if d.err == nil {
		d.err = fmt.Errorf("%w: %s at %d bytes left", errChunkDecode, what, len(d.b))
	}
}

func (d *chunkDecoder) uvarint() uint64 {
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail("uvarint")

		return 0
	}

	d.b = d.b[n:]

	return v
}

func (d *chunkDecoder) varint() int64 {
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail("varint")

		return 0
	}

	d.b = d.b[n:]

	return v
}

func (d *chunkDecoder) bytes(n int) []byte {
	if n < 0 || n > len(d.b) {
		d.fail("bytes")

		return nil
	}

	out := d.b[:n]
	d.b = d.b[n:]

	return out
}

// list reads a list's length: nil for a nil list, else its length.
func (d *chunkDecoder) list() (int, bool) {
	n := d.uvarint()
	if n == 0 {
		return 0, true
	}

	return int(n - 1), false //nolint:gosec // a test's lengths
}

func (d *chunkDecoder) string() string { return string(d.bytes(int(d.uvarint()))) } //nolint:gosec // a test's lengths

func (d *chunkDecoder) strings() []string {
	n, isNil := d.list()
	if isNil {
		return nil
	}

	out := make([]string, n)
	for i := range out {
		out[i] = d.string()
	}

	return out
}

func (d *chunkDecoder) ints() []int {
	n, isNil := d.list()
	if isNil {
		return nil
	}

	out := make([]int, n)
	for i := range out {
		out[i] = int(d.varint())
	}

	return out
}

func (d *chunkDecoder) prefix() netip.Prefix {
	var a netip.Addr

	if raw := d.bytes(int(d.uvarint())); len(raw) > 0 { //nolint:gosec // 0, 4 or 16
		var ok bool

		a, ok = netip.AddrFromSlice(raw)
		if !ok {
			d.fail("address")
		}
	}

	return netip.PrefixFrom(a, int(d.varint()))
}

func (d *chunkDecoder) rule() tailcfg.FilterRule {
	var r tailcfg.FilterRule

	r.SrcIPs = d.strings()
	r.SrcBits = d.ints() //nolint:staticcheck // deprecated, still on the wire

	if n, isNil := d.list(); !isNil {
		r.DstPorts = make([]tailcfg.NetPortRange, n)

		for i := range r.DstPorts {
			p := &r.DstPorts[i]
			p.IP = d.string()

			if d.bytes(1)[0] == 1 {
				bits := int(d.varint())
				p.Bits = &bits //nolint:staticcheck // deprecated, still on the wire
			}

			p.Ports.First, p.Ports.Last = uint16(d.uvarint()), uint16(d.uvarint()) //nolint:gosec // ports
		}
	}

	r.IPProto = d.ints()

	if n, isNil := d.list(); !isNil {
		r.CapGrant = make([]tailcfg.CapGrant, n)

		for i := range r.CapGrant {
			g := &r.CapGrant[i]

			if n, isNil := d.list(); !isNil {
				g.Dsts = make([]netip.Prefix, n)
				for j := range g.Dsts {
					g.Dsts[j] = d.prefix()
				}
			}

			if n, isNil := d.list(); !isNil {
				g.Caps = make([]peercap.Cap, n) //nolint:staticcheck // deprecated, still on the wire
				for j := range g.Caps {         //nolint:staticcheck // deprecated, still on the wire
					g.Caps[j] = peercap.Cap(d.string()) //nolint:staticcheck // deprecated, still on the wire
				}
			}

			if n, isNil := d.list(); !isNil {
				g.CapMap = make(tailcfg.PeerCapMap, n)

				for range n {
					k := peercap.Cap(d.string())

					var vs []tailcfg.RawMessage

					if m, isNil := d.list(); !isNil {
						vs = make([]tailcfg.RawMessage, m)
						for j := range vs {
							vs[j] = tailcfg.RawMessage(d.string())
						}
					}

					g.CapMap[k] = vs
				}
			}
		}
	}

	return r
}

// ruleGen draws filter rules over every field, with nil and empty lists,
// prefixes of either family, mapped, zero and with bits out of range, and
// app capabilities holding several values.
var ruleGen = rapid.Custom(func(rt *rapid.T) tailcfg.FilterRule {
	str := rapid.StringN(0, 6, -1)

	strs := func(label string) []string {
		if rapid.Bool().Draw(rt, label+" nil") {
			return nil
		}

		return rapid.SliceOfN(str, 0, 3).Draw(rt, label)
	}

	ints := func(label string) []int {
		if rapid.Bool().Draw(rt, label+" nil") {
			return nil
		}

		return rapid.SliceOfN(rapid.IntRange(-300, 300), 0, 3).Draw(rt, label)
	}

	n := func(label string) (int, bool) {
		return rapid.IntRange(0, 3).Draw(rt, label), rapid.Bool().Draw(rt, label+" nil")
	}

	prefixes := rapid.SampledFrom([]netip.Prefix{
		{},
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("100.64.0.10/32"), netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::/0"), netip.MustParsePrefix("::/8"), netip.MustParsePrefix("fd7a:115c:a1e0::a/128"),
		netip.MustParsePrefix("::ffff:100.64.0.10/128"),
		netip.PrefixFrom(netip.MustParseAddr("100.64.0.1"), 33),
	})

	r := tailcfg.FilterRule{
		SrcIPs:  strs("srcs"),
		SrcBits: ints("bits"), //nolint:staticcheck // deprecated, still on the wire
		IPProto: ints("protos"),
	}

	if k, isNil := n("dsts"); !isNil {
		r.DstPorts = make([]tailcfg.NetPortRange, k)
		for i := range r.DstPorts {
			r.DstPorts[i].IP = str.Draw(rt, "ip")
			if rapid.Bool().Draw(rt, "bits set") {
				r.DstPorts[i].Bits = new(rapid.IntRange(-1, 128).Draw(rt, "bits")) //nolint:staticcheck // deprecated, still on the wire
			}

			r.DstPorts[i].Ports = tailcfg.PortRange{First: rapid.Uint16().Draw(rt, "first"), Last: rapid.Uint16().Draw(rt, "last")}
		}
	}

	if k, isNil := n("grants"); !isNil {
		r.CapGrant = make([]tailcfg.CapGrant, k)
		for i := range r.CapGrant {
			g := &r.CapGrant[i]

			if k, isNil := n("prefixes"); !isNil {
				g.Dsts = rapid.SliceOfN(prefixes, k, k).Draw(rt, "prefixes")
			}

			if caps := strs("caps"); caps != nil {
				g.Caps = make([]peercap.Cap, len(caps)) //nolint:staticcheck // deprecated, still on the wire
				for j, c := range caps {
					g.Caps[j] = peercap.Cap(c) //nolint:staticcheck // deprecated, still on the wire
				}
			}

			if k, isNil := n("capmap"); !isNil {
				g.CapMap = make(tailcfg.PeerCapMap, k)
				for range k {
					var vs []tailcfg.RawMessage

					if values := strs("values"); values != nil {
						vs = make([]tailcfg.RawMessage, len(values))
						for j, v := range values {
							vs[j] = tailcfg.RawMessage(v)
						}
					}

					g.CapMap[peercap.Cap(str.Draw(rt, "cap"))] = vs
				}
			}
		}
	}

	return r
})

// TestChunkEncodingRoundTrips decodes what names are hashed from back to
// the rules, a rule's and a CapGrant chunk's list of them alike: the
// encoding is injective, so a name stands for one rule, or one list.
func TestChunkEncodingRoundTrips(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		rules := rapid.SliceOfN(ruleGen, 1, 4).Draw(rt, "rules")

		one := appendRule(nil, &rules[0])
		d := &chunkDecoder{b: one}
		require.Equal(rt, rules[0], d.rule())
		require.NoError(rt, d.err)
		require.Empty(rt, d.b, "a rule's encoding ends where its rule does")

		var list []byte
		for i := range rules {
			list = appendRule(list, &rules[i])
		}

		d = &chunkDecoder{b: list}

		var got []tailcfg.FilterRule
		for len(d.b) > 0 && d.err == nil {
			got = append(got, d.rule())
		}

		require.NoError(rt, d.err)
		require.Equal(rt, rules, got, "a list encodes rule after rule, each delimiting itself")
	})

	// The pair the review found: one byte per prefix more than its address.
	a := tailcfg.FilterRule{CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/8")}}}}
	b := tailcfg.FilterRule{CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{netip.MustParsePrefix("::/0"), netip.MustParsePrefix("0.0.0.0/8")}}}}
	require.NotEqual(t, ChunkFilter([]tailcfg.FilterRule{a}).Names(), ChunkFilter([]tailcfg.FilterRule{b}).Names())
}
