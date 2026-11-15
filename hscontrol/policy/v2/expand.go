package v2

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/views"
)

// capSourcePrefix marks a [tailcfg.FilterRule.SrcIPs] entry the client
// matches by the source node's CapMap instead of by address.
const capSourcePrefix = "cap:"

// selectorCapPrefix names the cap a selector's members hold. Nothing sends
// it yet; the wire namespace is settled when caps are first emitted.
const selectorCapPrefix = "https://headscale.net/cap/src/"

// selectorCap is the cap the members of s hold.
func selectorCap(s Selector) nodecap.Cap { return nodecap.Cap(selectorCapPrefix + s.Name) }

// capHolders returns the addresses of the nodes holding a capability. The
// client looks caps up by a node's own addresses only, so holders give no
// routes.
type capHolders func(nodecap.Cap) []netip.Addr

// expandCapSources writes rules in IP form: every cap source becomes the
// addresses of its holders, written as the compile writes the sources of an
// identity alias (each address on its own, the list sorted as text without
// repeats, danger-all alone). A rule whose sources come to nothing is
// dropped, as the compile drops one; a capability rule stays, with empty
// sources, as the compile writes an app grant from nobody. Rules are then
// merged as the compile merges them: by class, sources and protocols, at
// the first rule with the key. Without cap sources, rules come back
// unchanged.
//
// classes holds each rule's merge class, nil when every rule is regular.
// The wire rule does not say which rules the compile keeps apart: a via
// rule merges only with via rules through the same tags, so its class
// names them.
func expandCapSources(rules []tailcfg.FilterRule, classes []string, holders capHolders) []tailcfg.FilterRule {
	if !slices.ContainsFunc(rules, hasCapSource) {
		return rules
	}

	return expandFilter(capFilter{rules: rules, classes: classes}, holders)
}

// capFilter is one receiver's filter in cap form, with what merging needs
// that the wire rules do not say.
type capFilter struct {
	rules []tailcfg.FilterRule
	// classes holds each rule's merge class; nil when every rule is
	// regular.
	classes []string
	// anchors holds, when the rules were cut from a longer list, where
	// each rule's merged rule sits in that list: the position of the first
	// rule there sharing its merge key, which may be a rule that does not
	// reach this receiver. Nil when the rules are the whole list, so a
	// merged rule sits at its first rule.
	anchors []int64

	// srcs and keys hold, by rule, its sources already expanded and its
	// merge key, where whoever cut the filter knows them: every receiver of
	// a rule shares one expansion. Nil entries, or nil slices, are worked
	// out from the holders.
	srcs [][]string
	keys []string
}

// expandFilter is [expandCapSources] on a filter of any shape, merging
// always: a filter cut for a receiver comes unmerged.
func expandFilter(f capFilter, holders capHolders) []tailcfg.FilterRule {
	var (
		out     = make([]tailcfg.FilterRule, 0, len(f.rules))
		keys    = make([]string, 0, len(f.rules))
		anchors = make([]int64, 0, len(f.rules))
	)

	for i, rule := range f.rules {
		switch {
		case f.srcs != nil && f.srcs[i] != nil:
			rule.SrcIPs = f.srcs[i]
		case hasCapSource(rule):
			rule.SrcIPs = expandSources(rule.SrcIPs, holders)
			if len(rule.SrcIPs) == 0 {
				if len(rule.CapGrant) == 0 {
					continue
				}

				// The compile writes a capability rule whose sources
				// resolve to nothing with empty sources, not none.
				rule.SrcIPs = []string{}
			}
		}

		var class string
		if f.classes != nil {
			class = f.classes[i]
		}

		anchor := int64(i)
		if f.anchors != nil {
			anchor = f.anchors[i]
		}

		key := ""
		if f.keys != nil {
			key = f.keys[i]
		}

		if key == "" {
			key = mergeKey(class, rule)
		}

		out = append(out, rule)
		keys = append(keys, key)
		anchors = append(anchors, anchor)
	}

	return mergeAnchored(out, keys, anchors)
}

// mergeKey is the key rules merge on: class, sources and protocols. A
// capability rule never merges.
func mergeKey(class string, rule tailcfg.FilterRule) string {
	return class + "|" + filterRuleKey(rule)
}

// mergeAnchored merges rules sharing a key into one, at the least anchor
// of the rules merged, their destinations in rule order. Capability rules
// stay as they are, at their own anchor.
func mergeAnchored(rules []tailcfg.FilterRule, keys []string, anchors []int64) []tailcfg.FilterRule {
	type group struct {
		anchor  int64
		members []int
	}

	var (
		groups = make([]group, 0, len(rules))
		byKey  = make(map[string]int, len(rules))
	)

	for i, rule := range rules {
		if len(rule.CapGrant) == 0 {
			if g, ok := byKey[keys[i]]; ok {
				groups[g].members = append(groups[g].members, i)
				groups[g].anchor = min(groups[g].anchor, anchors[i])

				continue
			}

			byKey[keys[i]] = len(groups)
		}

		groups = append(groups, group{anchor: anchors[i], members: []int{i}})
	}

	slices.SortStableFunc(groups, func(a, b group) int { return cmp.Compare(a.anchor, b.anchor) })

	out := make([]tailcfg.FilterRule, 0, len(groups))

	for _, g := range groups {
		first := rules[g.members[0]]
		if len(first.CapGrant) > 0 {
			out = append(out, first)

			continue
		}

		dsts := slices.Clip(first.DstPorts)

		if len(g.members) > 1 {
			n := 0
			for _, m := range g.members {
				n += len(rules[m].DstPorts)
			}

			dsts = make([]tailcfg.NetPortRange, 0, n)
			for _, m := range g.members {
				dsts = append(dsts, rules[m].DstPorts...)
			}
		}

		out = append(out, tailcfg.FilterRule{SrcIPs: first.SrcIPs, DstPorts: dsts, IPProto: first.IPProto})
	}

	return out
}

// hasCapSource reports whether rule names a source by capability.
func hasCapSource(rule tailcfg.FilterRule) bool {
	return slices.ContainsFunc(rule.SrcIPs, func(src string) bool {
		return strings.HasPrefix(src, capSourcePrefix)
	})
}

// expandSources replaces each cap source with its holders' addresses; see
// [formatSources] for the form.
func expandSources(srcs []string, holders capHolders) []string {
	out := make([]string, 0, len(srcs))

	for _, src := range srcs {
		capName, ok := strings.CutPrefix(src, capSourcePrefix)
		if !ok {
			out = append(out, src)

			continue
		}

		for _, addr := range holders(nodecap.Cap(capName)) {
			out = append(out, addr.String())
		}
	}

	return formatSources(out)
}

// formatSources writes a rule's sources as [buildSrcIPStrings] does: the
// union of every source's addresses sorted as text, or danger-all's "*"
// alone; nil when there are none.
func formatSources(srcs []string) []string {
	if len(srcs) == 0 {
		return nil
	}

	if slices.Contains(srcs, "*") {
		return []string{"*"}
	}

	slices.Sort(srcs)

	return slices.Compact(srcs)
}

// Expansion writes templates in IP form, as today's compile writes its
// filters, with membership read from postings: it is that compile driven
// by posting lists. It reads, besides the templates and the postings, the
// approved subnet routes for * sources, the addresses of the members it
// lists and the receiving node; never the node list.
//
// What the expansion computes once serves every receiver: each identity
// selector's addresses, each grant's sources and merge keys, and where each
// merged rule every node shares sits, which the compile decides over every
// node's rules at once. A receiver then costs the rules that reach it.
//
// It gives what the compile gives when the compile was fed the node list
// the postings were built from, sorted by ID (the compile lists an owner's
// nodes in list order, postings in ID order); [AuditFilters] checks both.
type Expansion struct {
	t      *Templates
	table  *SelectorTable
	posts  Postings
	node   func(types.NodeID) (types.NodeView, bool)
	routes []string

	// resolved holds what each identity selector resolves to: its members'
	// addresses, written as the compile writes a node alias.
	resolved []ResolvedAddresses
	grants   []grantExpansion
	// first holds, by merge key, the position of the first rule with that
	// key in the rule list every node's filter is cut from.
	first  map[string]int64
	owners []uint

	mu   sync.Mutex
	self map[selfKey][]ownRule

	// diagnose turns on byAddress, which counts owner nodes an identity
	// source names by an address alone, not being its member, and owner
	// nodes * leaves out: a test's evidence that it reached the case, not
	// work a filter needs.
	diagnose  bool
	byAddress int
}

// grantExpansion is what a grant template comes to under one membership.
type grantExpansion struct {
	// capSrcs are the sources as a cap-form rule writes them; srcStrs the
	// same expanded.
	capSrcs []string
	srcStrs []string
	// srcSets holds each source's addresses, for the sources that resolve
	// to any set, in policy order; srcIDs their selectors.
	srcSets []ResolvedAddresses
	srcIDs  []SelectorID
	// keys holds each ip rule's merge key, "" for a rule no node's filter
	// holds.
	keys     []string
	capGrant bool
	// dstIPs are the sources of the capability's companion rules: the
	// destinations' addresses.
	dstIPs []string
	// viaDsts are a via grant's destinations as prefixes, and viaKeys its
	// rules' merge keys, by ip entry.
	viaDsts []netip.Prefix
	viaKeys []string
}

type selfKey struct {
	grant int
	user  uint
}

// ownRule is an autogroup:self rule of one owner, before it is cut for a
// receiver, with each destination's range.
type ownRule struct {
	rule   tailcfg.FilterRule
	key    string
	ranges []netipx.IPRange
}

var errExpansion = errors.New("cannot expand templates")

// NewExpansion prepares t for expansion against posts, built for t's
// selector table. routes are the approved subnet routes of every node;
// node looks up the nodes the postings list.
func NewExpansion(t *Templates, posts Postings, routes []string, node func(types.NodeID) (types.NodeView, bool)) (*Expansion, error) {
	if t.err != nil {
		return nil, t.err
	}

	if posts.table != t.table() {
		return nil, fmt.Errorf("%w: postings of another selector table", errExpansion)
	}

	x := &Expansion{
		t: t, table: t.table(), posts: posts, node: node, routes: routes,
		resolved: make([]ResolvedAddresses, t.table().Len()),
		grants:   make([]grantExpansion, len(t.grants)),
		first:    map[string]int64{},
		self:     map[selfKey][]ownRule{},
	}

	for _, s := range x.table.sels {
		if s.Kind.HoldsNodes() {
			x.resolved[s.ID] = x.members(posts.Nodes(SelectorRole(s.ID)))
		}
	}

	for g, gt := range t.grants {
		if gt.none {
			continue
		}

		x.grants[g] = x.expandGrant(gt)

		if gt.kind == grantSelf && x.owners == nil {
			x.owners = []uint{}

			for r := range posts.All() {
				if uid, ok := r.Owner(); ok {
					x.owners = append(x.owners, uid)
				}
			}

			slices.Sort(x.owners)
		}

		for i, key := range x.grants[g].keys {
			if _, seen := x.first[key]; key != "" && !seen {
				x.first[key] = rulePos(g, 0, i)
			}
		}
	}

	return x, nil
}

// rulePos numbers a rule in the list a filter is cut from: by grant, then
// the rules every node shares before those of the receiver, then order.
func rulePos(grant, part, i int) int64 { return int64(grant)<<33 | int64(part)<<32 | int64(i) }

// members resolves the nodes ids to their addresses.
func (x *Expansion) members(ids []types.NodeID) ResolvedAddresses {
	var b netipx.IPSetBuilder

	for _, id := range ids {
		if n, ok := x.node(id); ok {
			n.AppendToIPSet(&b)
		}
	}

	set, _ := b.IPSet()
	res, _ := newNodeAddresses(set, nil)

	return res
}

// resolve returns what selector id resolves to and the compile's error
// for it: members for an identity selector, the literal for an address
// one, nothing for autogroup:self.
func (x *Expansion) resolve(id SelectorID) (ResolvedAddresses, error) {
	if x.table.Selector(id).Kind.HoldsNodes() {
		return x.resolved[id], nil
	}

	l := x.t.literals[id]

	return l.res, l.err
}

// holders lists the addresses of the members of the selector c names.
func (x *Expansion) holders(c nodecap.Cap) []netip.Addr {
	name, ok := strings.CutPrefix(string(c), selectorCapPrefix)
	if !ok {
		return nil
	}

	s, ok := x.table.Lookup(name)
	if !ok || !s.Kind.HoldsNodes() {
		return nil
	}

	return slices.Collect(x.resolved[s.ID].Iter())
}

func (x *Expansion) expandGrant(gt *GrantTemplate) grantExpansion {
	var ge grantExpansion

	identity := false

	for _, id := range gt.srcs {
		s := x.table.Selector(id)

		switch {
		case s.Kind.HoldsNodes():
			ge.capSrcs = append(ge.capSrcs, capSourcePrefix+string(selectorCap(s)))
			identity = true
		case s.Kind == SelectorDangerAll:
			// The wire writes danger-all as "*", alone.
			ge.capSrcs = append(ge.capSrcs, "*")
		default:
			if l := x.t.literals[id]; l.res != nil {
				ge.capSrcs = append(ge.capSrcs, l.res.Strings()...)
			}
		}

		if res, _ := x.resolve(id); res != nil {
			ge.srcSets = append(ge.srcSets, res)
			ge.srcIDs = append(ge.srcIDs, id)
		}
	}

	if gt.wildcard {
		ge.capSrcs = append(ge.capSrcs, x.routes...)
	}

	// Without a cap to expand, the sources are written now.
	if !identity {
		ge.capSrcs = formatSources(ge.capSrcs)
	}

	ge.srcStrs = expandSources(ge.capSrcs, x.holders)

	switch gt.kind {
	case grantVia:
		for _, id := range gt.dsts {
			res, err := x.resolve(id)
			if err == nil && res != nil {
				ge.viaDsts = append(ge.viaDsts, res.Prefixes()...)
			}
		}

		for _, ipr := range gt.ip {
			ge.viaKeys = append(ge.viaKeys, mergeKey(gt.viaClass, tailcfg.FilterRule{SrcIPs: ge.srcStrs, IPProto: ipr.proto}))
		}

		return ge
	case grantRegular, grantSelf:
	}

	ge.keys = make([]string, len(gt.ip))

	for i, ipr := range gt.ip {
		if len(ge.srcStrs) > 0 && x.hasDsts(gt, ipr.ports) {
			ge.keys[i] = mergeKey("", tailcfg.FilterRule{SrcIPs: ge.srcStrs, IPProto: ipr.proto})
		}
	}

	if gt.app == nil {
		return ge
	}

	for _, id := range gt.dsts {
		res, err := x.resolve(id)
		if err != nil || res == nil {
			continue
		}

		ge.capGrant = true
		ge.dstIPs = append(ge.dstIPs, res.Strings()...)
	}

	if ge.capGrant && gt.dstWildcard {
		ge.dstIPs = append(ge.dstIPs, x.routes...)
	}

	return ge
}

// hasDsts reports whether the rule over ports has a destination on any
// node: the compile writes no rule without.
func (x *Expansion) hasDsts(gt *GrantTemplate, ports []tailcfg.PortRange) bool {
	if len(ports) == 0 {
		return false
	}

	for _, id := range gt.dsts {
		if x.table.Selector(id).Kind == SelectorWildcard {
			return true
		}

		if res, _ := x.resolve(id); res != nil && len(res.Strings()) > 0 {
			return true
		}
	}

	return false
}

// receiver is what cutting a filter reads of the node receiving it.
type receiver struct {
	n types.NodeView
	// ips are its addresses, ascending; reach those and every route it
	// serves, approved and announced, exits included.
	ips    []netip.Addr
	reach  *netipx.IPSet
	routed bool
}

func newReceiver(n types.NodeView) receiver {
	rc := receiver{n: n, ips: slices.Clone(n.IPs())}
	slices.SortFunc(rc.ips, netip.Addr.Compare)

	var b netipx.IPSetBuilder

	for _, ip := range rc.ips {
		b.Add(ip)
	}

	subnets, exits := n.SubnetRoutes(), n.ExitRoutes()
	for _, p := range slices.Concat(subnets, exits) {
		b.AddPrefix(p)
	}

	rc.reach, _ = b.IPSet()
	rc.routed = len(subnets) > 0 || len(exits) > 0

	return rc
}

// reachesAny reports whether a * destination reaches the receiver.
func (rc receiver) reachesAny() bool { return len(rc.ips) > 0 || rc.routed }

// hostPrefixes returns the receiver's addresses in any of sets, as the
// single-address prefixes a capability rule is cut to, sorted.
func (rc receiver) hostPrefixes(sets ...ResolvedAddresses) []netip.Prefix {
	var out []netip.Prefix

	for _, ip := range rc.ips {
		if slices.ContainsFunc(sets, func(s ResolvedAddresses) bool { return s.Contains(ip) }) {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}

	slices.SortFunc(out, netip.Prefix.Compare)

	return slices.Compact(out)
}

// FilterForNode returns n's packet filter: what [PolicyManager.FilterForNode]
// gives for n when the compile was fed the users and the node list, sorted by
// ID, that the templates and postings describe, n among them.
func (x *Expansion) FilterForNode(n types.NodeView) []tailcfg.FilterRule {
	return expandFilter(x.capFilterFor(n, nil), x.holders)
}

// FilterShapes counts the shapes cutting filters met, so a test can tell
// its inputs reached each.
type FilterShapes struct {
	Receivers, Exit, Routed int
	// Shared, Self and Via count rules cut; CapGrant and Companion the
	// capability rules among them; Capped those with sources by cap.
	Shared, Self, Via, CapGrant, Companion, Capped int
	// SelfByAddress counts owner nodes a self rule's source names, or
	// leaves out, by address where membership would decide otherwise.
	SelfByAddress int
	// Anchored counts merged rules placed where a rule that does not reach
	// the receiver sits, ahead of every rule of theirs that does; OwnAnchored
	// those of them placed by one of the receiver's own rules. OwnUnreached
	// counts the receiver's own rules that reach nothing on it.
	Anchored, OwnAnchored, OwnUnreached int
}

// Add adds o's counts to s.
func (s *FilterShapes) Add(o FilterShapes) {
	s.Receivers += o.Receivers
	s.Exit += o.Exit
	s.Routed += o.Routed
	s.Shared += o.Shared
	s.Self += o.Self
	s.Via += o.Via
	s.CapGrant += o.CapGrant
	s.Companion += o.Companion
	s.Capped += o.Capped
	s.SelfByAddress += o.SelfByAddress
	s.Anchored += o.Anchored
	s.OwnAnchored += o.OwnAnchored
	s.OwnUnreached += o.OwnUnreached
}

// ruleShape is which part of the compile a cut rule comes from.
type ruleShape uint8

const (
	shapeShared ruleShape = iota
	shapeCapGrant
	shapeCompanion
	shapeSelf
	shapeVia
)

// cut collects one receiver's cap-form filter.
type cut struct {
	f      capFilter
	rc     receiver
	pos    []int64
	shapes []ruleShape

	// own holds, by merge key, the first position of the receiver's own
	// rules, the ones it alone gets (self, via), whether or not they reach
	// it: the compile merges before it reduces, so a rule of its own that
	// reaches nothing still decides where a merged rule sits. unreached
	// counts those that reach nothing.
	own       map[string]int64
	unreached int
}

// emit adds rule, which sits at pos in the full list and merges with every
// rule of key at the least of anchor and the receiver's own rules of key.
// srcs are its sources expanded, when the cut knows them.
func (c *cut) emit(rule tailcfg.FilterRule, class, key string, srcs []string, anchor, pos int64, shape ruleShape) {
	c.f.rules = append(c.f.rules, rule)
	c.f.classes = append(c.f.classes, class)
	c.f.keys = append(c.f.keys, key)
	c.f.srcs = append(c.f.srcs, srcs)
	c.f.anchors = append(c.f.anchors, anchor)
	c.pos = append(c.pos, pos)
	c.shapes = append(c.shapes, shape)
}

// placeOwn records a rule of the receiver's own at pos, emitted or not.
func (c *cut) placeOwn(key string, pos int64) {
	if at, ok := c.own[key]; !ok || pos < at {
		c.own[key] = pos
	}
}

// finish moves every rule's anchor to its key's first own rule where that
// comes first, and counts what was cut into st, when not nil.
func (c *cut) finish(st *FilterShapes) {
	for i, key := range c.f.keys {
		if at, ok := c.own[key]; ok && key != "" && at < c.f.anchors[i] {
			c.f.anchors[i] = at
		}
	}

	if st == nil {
		return
	}

	var shapes FilterShapes

	shapes.Receivers = 1
	shapes.OwnUnreached = c.unreached

	if c.rc.n.IsExitNode() {
		shapes.Exit = 1
	}

	if c.rc.routed {
		shapes.Routed = 1
	}

	// A group is anchored ahead of itself when none of its rules sits at
	// its anchor.
	type group struct {
		anchor  int64
		present bool
	}

	groups := map[string]*group{}

	for i, key := range c.f.keys {
		switch c.shapes[i] {
		case shapeShared:
			shapes.Shared++
		case shapeCapGrant:
			shapes.CapGrant++
		case shapeCompanion:
			shapes.Companion++
		case shapeSelf:
			shapes.Self++
		case shapeVia:
			shapes.Via++
		}

		if hasCapSource(c.f.rules[i]) {
			shapes.Capped++
		}

		if key == "" {
			continue
		}

		g, ok := groups[key]
		if !ok {
			g = &group{anchor: c.f.anchors[i]}
			groups[key] = g
		}

		g.anchor = min(g.anchor, c.f.anchors[i])
		g.present = g.present || c.pos[i] == c.f.anchors[i]
	}

	for key, g := range groups {
		if !g.present {
			shapes.Anchored++

			if at, ok := c.own[key]; ok && at == g.anchor {
				shapes.OwnAnchored++
			}
		}
	}

	st.Add(shapes)
}

// capFilterFor cuts n's filter from the templates in cap form: every rule
// that reaches n, with only the destinations that do, sources named by
// selector where a selector names them, in the order of the rule list
// every node's filter is cut from, each with where it merges. st, when not
// nil, counts what it cut.
func (x *Expansion) capFilterFor(n types.NodeView, st *FilterShapes) capFilter {
	c := &cut{f: capFilter{anchors: []int64{}}, rc: newReceiver(n), own: map[string]int64{}}

	for g, gt := range x.t.grants {
		if gt.none {
			continue
		}

		ge := &x.grants[g]

		switch gt.kind {
		case grantRegular:
			x.cutShared(c, g, gt, ge)
		case grantSelf:
			x.cutShared(c, g, gt, ge)
			x.cutSelf(c, g)
		case grantVia:
			x.cutVia(c, g, gt, ge)
		}
	}

	c.finish(st)

	return c.f
}

// cutShared cuts the rules of grant g every node's filter is cut from.
func (x *Expansion) cutShared(c *cut, g int, gt *GrantTemplate, ge *grantExpansion) {
	for i, ipr := range gt.ip {
		key := ge.keys[i]
		if key == "" {
			continue
		}

		dsts := x.dstPorts(gt, ipr.ports, c.rc)
		if len(dsts) == 0 {
			continue
		}

		c.emit(tailcfg.FilterRule{SrcIPs: ge.capSrcs, DstPorts: dsts, IPProto: ipr.proto}, "", key, ge.srcStrs,
			x.first[key], rulePos(g, 0, i), shapeShared)
	}

	if !ge.capGrant {
		return
	}

	next := len(gt.ip)

	var grants []tailcfg.CapGrant

	for _, id := range gt.dsts {
		res, err := x.resolve(id)
		if err != nil || res == nil {
			continue
		}

		if dsts := c.rc.hostPrefixes(res); len(dsts) > 0 {
			grants = append(grants, tailcfg.CapGrant{Dsts: dsts, CapMap: gt.app})
		}
	}

	if len(grants) > 0 {
		srcs := ge.srcStrs
		if srcs == nil {
			srcs = []string{}
		}

		pos := rulePos(g, 0, next)
		c.emit(tailcfg.FilterRule{SrcIPs: srcs, CapGrant: grants}, "", "", nil, pos, pos, shapeCapGrant)
	}

	for i, comp := range companionCaps {
		if _, ok := gt.app[comp.original]; !ok {
			continue
		}

		// Companions run the other way: from the destinations to the
		// sources.
		if dsts := c.rc.hostPrefixes(ge.srcSets...); len(dsts) > 0 {
			pos := rulePos(g, 0, next+1+i)
			c.emit(tailcfg.FilterRule{
				SrcIPs:   ge.dstIPs,
				CapGrant: []tailcfg.CapGrant{{Dsts: dsts, CapMap: tailcfg.PeerCapMap{comp.companion: nil}}},
			}, "", "", nil, pos, pos, shapeCompanion)
		}
	}
}

// dstPorts returns the destinations of a rule of gt over ports that reach
// rc, in the compile's order: by destination, address, then port.
func (x *Expansion) dstPorts(gt *GrantTemplate, ports []tailcfg.PortRange, rc receiver) []tailcfg.NetPortRange {
	var out []tailcfg.NetPortRange

	add := func(ip string) {
		for _, p := range ports {
			out = append(out, tailcfg.NetPortRange{IP: ip, Ports: p})
		}
	}

	for _, id := range gt.dsts {
		s := x.table.Selector(id)

		switch {
		case s.Kind == SelectorWildcard:
			if rc.reachesAny() {
				add("*")
			}
		case s.Kind.HoldsNodes():
			res := x.resolved[id]

			if !rc.routed {
				// Only its own addresses can reach a node without routes.
				for _, ip := range rc.ips {
					if res.Contains(ip) {
						add(ip.String())
					}
				}

				continue
			}

			for ip := range res.Iter() {
				if rc.reach.Contains(ip) {
					add(ip.String())
				}
			}
		default:
			for _, e := range x.t.literals[id].entries {
				if rc.reach.OverlapsRange(e.r) {
					add(e.str)
				}
			}
		}
	}

	return out
}

// cutSelf cuts grant g's autogroup:self rules for the receiver: its own
// user's, or, on an exit node, every owner's in user order. A rule that
// reaches nothing is not cut but keeps its place.
func (x *Expansion) cutSelf(c *cut, g int) {
	var uids []uint

	switch n := c.rc.n; {
	case n.IsExitNode():
		uids = x.owners
	case nodeHasUserIdentity(n):
		uids = []uint{n.User().ID()}
	}

	at := 0

	for _, uid := range uids {
		for _, o := range x.selfRules(g, uid) {
			pos := rulePos(g, 1, at)
			at++

			if o.key != "" {
				c.placeOwn(o.key, pos)
			}

			rule, ok := cutOwn(o, c.rc)
			if !ok {
				c.unreached++

				continue
			}

			anchor := pos
			if first, ok := x.first[o.key]; ok && o.key != "" {
				anchor = min(anchor, first)
			}

			c.emit(rule, "", o.key, nil, anchor, pos, shapeSelf)
		}
	}
}

// cutOwn cuts an owner's rule for rc: the destinations that reach it, or,
// for a capability rule, its addresses among each grant's.
func cutOwn(o ownRule, rc receiver) (tailcfg.FilterRule, bool) {
	rule := o.rule

	if len(rule.CapGrant) > 0 {
		var grants []tailcfg.CapGrant

		for _, cg := range rule.CapGrant {
			var b netipx.IPSetBuilder
			for _, p := range cg.Dsts {
				b.AddPrefix(p)
			}

			set, _ := b.IPSet()
			if dsts := rc.hostPrefixes(resolved{ips: *set}); len(dsts) > 0 {
				grants = append(grants, tailcfg.CapGrant{Dsts: dsts, CapMap: cg.CapMap})
			}
		}

		if len(grants) == 0 {
			return tailcfg.FilterRule{}, false
		}

		return tailcfg.FilterRule{SrcIPs: rule.SrcIPs, CapGrant: grants}, true
	}

	var dsts []tailcfg.NetPortRange

	for i, d := range rule.DstPorts {
		if rc.reach.OverlapsRange(o.ranges[i]) {
			dsts = append(dsts, d)
		}
	}

	if len(dsts) == 0 {
		return tailcfg.FilterRule{}, false
	}

	rule.DstPorts = dsts

	return rule, true
}

// selfRules returns uid's autogroup:self rules of grant g, built once.
func (x *Expansion) selfRules(g int, uid uint) []ownRule {
	x.mu.Lock()
	defer x.mu.Unlock()

	k := selfKey{grant: g, user: uid}
	if rules, ok := x.self[k]; ok {
		return rules
	}

	rules := x.buildSelfRules(x.t.grants[g], &x.grants[g], uid)
	x.self[k] = rules

	return rules
}

// buildSelfRules writes uid's autogroup:self rules as the compile does:
// per source, the owner's untagged nodes that source holds the address
// of, each its own rule.
func (x *Expansion) buildSelfRules(gt *GrantTemplate, ge *grantExpansion, uid uint) []ownRule {
	var nodes []types.NodeView

	for _, id := range x.posts.Nodes(OwnerRole(uid)) {
		if n, ok := x.node(id); ok {
			nodes = append(nodes, n)
		}
	}

	if len(nodes) == 0 {
		return nil
	}

	var (
		perSrc []ResolvedAddresses
		all    netipx.IPSetBuilder
	)

	// By address, not membership: a source names the owner's nodes whose
	// addresses it holds, for prefixes and * as for selectors.
	for i, set := range ge.srcSets {
		var named netipx.IPSetBuilder

		kind := x.table.Selector(ge.srcIDs[i]).Kind

		for _, n := range nodes {
			in := slices.ContainsFunc(n.IPs(), set.Contains)
			if in {
				n.AppendToIPSet(&named)
				n.AppendToIPSet(&all)
			}

			if x.diagnose && len(n.IPs()) > 0 {
				_, member := slices.BinarySearch(x.posts.Nodes(SelectorRole(ge.srcIDs[i])), n.ID())

				// A node without addresses gives no rule either way.
				if kind.HoldsNodes() && in != member || kind == SelectorWildcard && !in {
					x.byAddress++
				}
			}
		}

		s, _ := named.IPSet()
		if len(s.Ranges()) == 0 {
			continue
		}

		src, _ := newNodeAddresses(s, nil)
		perSrc = append(perSrc, src)
	}

	if len(perSrc) == 0 {
		return nil
	}

	var out []ownRule

	keyed := func(rule tailcfg.FilterRule) {
		o := ownRule{rule: rule, key: mergeKey("", rule)}
		for _, d := range rule.DstPorts {
			r, _ := util.ParseIPRange(d.IP)
			o.ranges = append(o.ranges, r)
		}

		out = append(out, o)
	}

	for _, ipr := range gt.ip {
		var dsts []tailcfg.NetPortRange

		// By node, then port, then address: not the order of other rules.
		for _, n := range nodes {
			for _, port := range ipr.ports {
				for _, ip := range n.IPs() {
					dsts = append(dsts, tailcfg.NetPortRange{IP: ip.String(), Ports: port})
				}
			}
		}

		if len(dsts) == 0 {
			continue
		}

		for _, src := range perSrc {
			keyed(tailcfg.FilterRule{SrcIPs: src.Strings(), DstPorts: dsts, IPProto: ipr.proto})
		}
	}

	if gt.app == nil {
		return out
	}

	set, _ := all.IPSet()
	union, _ := newNodeAddresses(set, nil)

	var (
		grants []tailcfg.CapGrant
		dstIPs []string
	)

	for _, n := range nodes {
		var dsts []netip.Prefix

		for _, ip := range n.IPs() {
			dsts = append(dsts, netip.PrefixFrom(ip, ip.BitLen()))
			dstIPs = append(dstIPs, ip.String())
		}

		grants = append(grants, tailcfg.CapGrant{Dsts: dsts, CapMap: gt.app})
	}

	out = append(out, ownRule{rule: tailcfg.FilterRule{SrcIPs: union.Strings(), CapGrant: grants}})

	for _, comp := range companionCaps {
		if _, ok := gt.app[comp.original]; ok {
			out = append(out, ownRule{rule: tailcfg.FilterRule{
				SrcIPs:   dstIPs,
				CapGrant: []tailcfg.CapGrant{{Dsts: union.Prefixes(), CapMap: tailcfg.PeerCapMap{comp.companion: nil}}},
			}})
		}
	}

	return out
}

// cutVia cuts grant g's rules for the receiver when it is one of the
// grant's via routers: the destinations its approved subnet routes
// overlap, and the internet on an exit node. A rule that reaches nothing
// is not cut but keeps its place.
func (x *Expansion) cutVia(c *cut, g int, gt *GrantTemplate, ge *grantExpansion) {
	rc := c.rc

	if len(ge.srcStrs) == 0 || !slices.ContainsFunc(gt.via, func(t Tag) bool { return rc.n.HasTag(string(t)) }) {
		return
	}

	subnets := rc.n.SubnetRoutes()

	var dsts []literalEntry

	for _, p := range ge.viaDsts {
		if slices.ContainsFunc(subnets, p.Overlaps) {
			dsts = append(dsts, literalEntry{str: filterIP(p), r: netipx.RangeOfPrefix(p)})
		}
	}

	if gt.viaInternet && rc.n.IsExitNode() {
		dsts = append(dsts, internetEntries()...)
	}

	if len(dsts) == 0 {
		return
	}

	for i, ipr := range gt.ip {
		if len(ipr.ports) == 0 {
			continue
		}

		// No rule every node shares merges with a via rule.
		pos := rulePos(g, 1, i)
		c.placeOwn(ge.viaKeys[i], pos)

		var ports []tailcfg.NetPortRange

		for _, d := range dsts {
			if !rc.reach.OverlapsRange(d.r) {
				continue
			}

			for _, port := range ipr.ports {
				ports = append(ports, tailcfg.NetPortRange{IP: d.str, Ports: port})
			}
		}

		if len(ports) == 0 {
			c.unreached++

			continue
		}

		c.emit(tailcfg.FilterRule{SrcIPs: ge.capSrcs, DstPorts: ports, IPProto: ipr.proto}, gt.viaClass, ge.viaKeys[i], ge.srcStrs,
			pos, pos, shapeVia)
	}
}

// internetEntries are [internetStrings] with their ranges.
var internetEntries = sync.OnceValue(func() []literalEntry {
	var out []literalEntry

	for _, s := range internetStrings() {
		r, err := util.ParseIPRange(s)
		if err == nil {
			out = append(out, literalEntry{str: s, r: r})
		}
	}

	return out
})

var errFilterAudit = errors.New("expanded filter differs from the compile's")

// FilterAudit is one snapshot's templates, membership and compile, as
// [AuditFilters] checks them.
type FilterAudit struct {
	Templates *Templates
	Postings  Postings
	Approvals SubnetApprovals
	// Nodes is the node list the policy compiles against; Users the users.
	Nodes views.Slice[types.NodeView]
	Users []types.User

	// Policy is the compile in force. Current reports that it compiled
	// these users and nodes. When it did not — a refused document keeps the
	// last good compile serving, compiled against older nodes — the oracle is
	// that last good document compiled afresh against these users and nodes:
	// the expansion follows membership under the policy in force, where the
	// served filter stays frozen at the nodes of its last good compile. That
	// is deliberate; the freeze is not behaviour to keep.
	Policy  *PolicyManager
	Current bool

	// TemplatesAudited reports that these templates matched a build from
	// scratch already: templates never change, so they still do.
	TemplatesAudited bool
}

// FilterReport counts what an audit compared.
type FilterReport struct {
	// Nodes counts the filters compared, Rules their rules.
	Nodes, Rules int
	// Fresh is set when the oracle was compiled afresh.
	Fresh bool
	// Shapes counts what cutting the filters met.
	Shapes FilterShapes
}

var errFilterAuditOrder = errors.New("the node list is not sorted by ID")

// AuditFilters checks that the templates are what a build from scratch
// gives, that the approved routes are every node's, and that every node's
// filter expanded from templates and postings equals the compile's,
// exactly. The node list must be sorted by ID, as the world keeps it: the
// compile lists an owner's nodes in list order, the postings in ID order.
// It is for debugging and tests: it expands every node's filter.
func AuditFilters(a FilterAudit) (FilterReport, error) {
	var rep FilterReport

	if a.Policy == nil {
		return rep, nil
	}

	if !slices.IsSortedFunc(a.Nodes.AsSlice(), func(m, n types.NodeView) int { return cmp.Compare(m.ID(), n.ID()) }) {
		return rep, errFilterAuditOrder
	}

	if !a.Templates.sel.Describes(a.Policy) {
		return rep, fmt.Errorf("%w: templates describe another policy than the compile in force", errFilterAudit)
	}

	if !a.TemplatesAudited {
		err := AuditTemplates(a.Templates)
		if err != nil {
			return rep, err
		}
	}

	if want := approvedSubnetRoutes(a.Nodes); !slices.Equal(a.Approvals.Strings(), want) {
		return rep, fmt.Errorf("%w: approved subnet routes %v, the nodes approve %v", errFilterAudit, a.Approvals.Strings(), want)
	}

	oracle := a.Policy
	if !a.Current {
		var err error

		oracle, err = NewPolicyManagerFrom(nil, a.Policy.src, a.Users, a.Nodes)
		if err != nil {
			return rep, fmt.Errorf("compiling the policy in force afresh: %w", err)
		}

		rep.Fresh = true
	}

	byID := make(map[types.NodeID]types.NodeView, a.Nodes.Len())
	for _, n := range a.Nodes.All() {
		byID[n.ID()] = n
	}

	x, err := NewExpansion(a.Templates, a.Postings, a.Approvals.Strings(), func(id types.NodeID) (types.NodeView, bool) {
		n, ok := byID[id]

		return n, ok
	})
	if err != nil {
		return rep, err
	}

	x.diagnose = true

	for _, n := range a.Nodes.All() {
		want, err := oracle.FilterForNode(n)
		if err != nil {
			return rep, err
		}

		got := expandFilter(x.capFilterFor(n, &rep.Shapes), x.holders)
		if !reflect.DeepEqual(want, got) {
			return rep, fmt.Errorf("%w: node %d:\ncompile  %v\nexpanded %v", errFilterAudit, n.ID(), want, got)
		}

		rep.Nodes++
		rep.Rules += len(got)
	}

	rep.Shapes.SelfByAddress = x.byAddress

	return rep, nil
}
