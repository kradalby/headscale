package v2

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/puzpuzpuz/xsync/v4"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/views"
)

// capSourcePrefix marks a [tailcfg.FilterRule.SrcIPs] entry the client
// matches by the source node's CapMap instead of by address.
const capSourcePrefix = "cap:"

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

	return expandFilter(capFilter{rules: rules, classes: classes}, holders, reasonAddressMode)
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
// always: a filter cut for a receiver comes unmerged. why is the reason the
// filter goes as addresses; there is none for writing them without one.
func expandFilter(f capFilter, holders capHolders, why ipReason) []tailcfg.FilterRule {
	if why == reasonNone {
		panic("policy v2: a filter written as addresses for no reason")
	}

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
	// A group is its first rule and the rules merged into it.
	type group struct {
		anchor int64
		first  int
		more   []int
	}

	// A filter is mostly a few rules: a scan finds a key faster than a map
	// is built.
	const scanned = 8

	var (
		groups = make([]group, 0, len(rules))
		byKey  map[string]int
	)

	if len(rules) > scanned {
		byKey = make(map[string]int, len(rules))
	}

	find := func(key string) (int, bool) {
		if byKey != nil {
			g, ok := byKey[key]

			return g, ok
		}

		for g := range groups {
			if f := groups[g].first; len(rules[f].CapGrant) == 0 && keys[f] == key {
				return g, true
			}
		}

		return 0, false
	}

	for i, rule := range rules {
		if len(rule.CapGrant) == 0 {
			if g, ok := find(keys[i]); ok {
				groups[g].more = append(groups[g].more, i)
				groups[g].anchor = min(groups[g].anchor, anchors[i])

				continue
			}

			if byKey != nil {
				byKey[keys[i]] = len(groups)
			}
		}

		groups = append(groups, group{anchor: anchors[i], first: i})
	}

	slices.SortStableFunc(groups, func(a, b group) int { return cmp.Compare(a.anchor, b.anchor) })

	out := make([]tailcfg.FilterRule, 0, len(groups))

	for _, g := range groups {
		first := rules[g.first]
		if len(first.CapGrant) > 0 {
			out = append(out, first)

			continue
		}

		dsts := slices.Clip(first.DstPorts)

		if len(g.more) > 0 {
			n := len(first.DstPorts)
			for _, m := range g.more {
				n += len(rules[m].DstPorts)
			}

			dsts = make([]tailcfg.NetPortRange, 0, n)

			dsts = append(dsts, first.DstPorts...)
			for _, m := range g.more {
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

	// The address part is built as it is read: resolved holds what each
	// identity selector resolves to, its members' addresses written as the
	// compile writes a node alias; grants each grant's expansion; first,
	// by merge key, the position of the first rule with that key in the
	// rule list every node's filter is cut from. Address form reads all of
	// it. Capability form and routing read a selector or a grant only
	// where a fallback writes it as addresses, so a membership change
	// nobody reads in address form builds none of it.
	resOnce   []sync.Once
	resolved  []ResolvedAddresses
	grantOnce []sync.Once
	grants    []grantExpansion
	firstOnce sync.Once
	first     map[string]int64
	// owners are the users with a node, read by exit nodes' self rules
	// and the census only: listing them walks every role.
	ownersOnce sync.Once
	owners     []uint

	// share gives the addresses nodes share, which capability form reads:
	// the filters the expansion serves work it out from the ones they
	// follow. Without, it is found from list.
	share func() *sharing

	mu   sync.Mutex
	self map[selfKey]*ownRules

	// list is the node list the postings were built from, which capability
	// form reads for the addresses nodes share; caps is what it needs
	// beyond address form, built on first use.
	list     views.Slice[types.NodeView]
	capsOnce sync.Once
	caps     *capInfo

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
// receiver, with each destination's range, and for a port rule its ip
// entry and source.
type ownRule struct {
	rule   tailcfg.FilterRule
	key    string
	ranges []netipx.IPRange
	ip     int
	src    SelectorID
}

// ownRules are one owner's autogroup:self rules of a grant; named holds,
// per source of the grant's expansion, how many of the owner's nodes with
// an address it names: an owner capability names every one.
type ownRules struct {
	rules []ownRule
	named []selfNaming
}

// selfNaming is how many of an owner's nodes a self rule's source names.
type selfNaming uint8

const (
	namedNone selfNaming = iota
	namedSome
	namedAll
)

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
		resOnce:   make([]sync.Once, t.table().Len()),
		resolved:  make([]ResolvedAddresses, t.table().Len()),
		grantOnce: make([]sync.Once, len(t.grants)),
		grants:    make([]grantExpansion, len(t.grants)),
		self:      map[selfKey]*ownRules{},
	}

	return x, nil
}

// ownerIDs returns the users with a node, sorted, listed once.
func (x *Expansion) ownerIDs() []uint {
	x.ownersOnce.Do(func() {
		for r := range x.posts.All() {
			if uid, ok := r.Owner(); ok {
				x.owners = append(x.owners, uid)
			}
		}

		slices.Sort(x.owners)
	})

	return x.owners
}

// res returns what identity selector id resolves to, built once.
func (x *Expansion) res(id SelectorID) ResolvedAddresses {
	x.resOnce[id].Do(func() {
		ids := x.posts.Nodes(SelectorRole(id))

		resolutionsBuilt.Add(1)
		membersExpanded.Add(uint64(len(ids)))

		x.resolved[id] = x.members(ids)
	})

	return x.resolved[id]
}

// grant returns grant g's expansion, built once.
func (x *Expansion) grant(g int) *grantExpansion {
	x.grantOnce[g].Do(func() {
		if gt := x.t.grants[g]; !gt.none {
			x.grants[g] = x.expandGrant(gt)
		}
	})

	return &x.grants[g]
}

// positions returns, by merge key, where the first rule with that key sits
// in the rule list every node's filter is cut from: every grant's
// expansion.
func (x *Expansion) positions() map[string]int64 {
	x.firstOnce.Do(func() {
		first := map[string]int64{}

		for g := range x.t.grants {
			for i, key := range x.grant(g).keys {
				if _, seen := first[key]; key != "" && !seen {
					first[key] = rulePos(g, 0, i)
				}
			}
		}

		x.first = first
	})

	return x.first
}

// srcIDs returns the sources of grant g that resolve to any set, in policy
// order, as its expansion lists them, without expanding it.
func (x *Expansion) srcIDs(g int) []SelectorID {
	var out []SelectorID

	for _, id := range x.t.grants[g].srcs {
		if x.table.Selector(id).Kind.HoldsNodes() || x.t.literals[id].res != nil {
			out = append(out, id)
		}
	}

	return out
}

// resolutionsBuilt and membersExpanded count the selector resolutions
// served filters built and the members those listed: work that follows a
// selector's size, not a change.
var (
	resolutionsBuilt atomic.Uint64
	membersExpanded  atomic.Uint64
)

// ServedWorkForTest returns, for tests outside the package, the selector
// resolutions served filters built, the members those listed, and the
// times every node's addresses were sorted, in that order.
func ServedWorkForTest() (uint64, uint64, uint64) {
	return resolutionsBuilt.Load(), membersExpanded.Load(), sharingScans.Load()
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
		return x.res(id), nil
	}

	l := x.t.literals[id]

	return l.res, l.err
}

// holders lists the addresses of the members of the selector c names, or
// of the owner nodes of the user it names.
func (x *Expansion) holders(c nodecap.Cap) []netip.Addr {
	name, ok := strings.CutPrefix(string(c), selectorCapPrefix)
	if !ok {
		return nil
	}

	if uid, ok := strings.CutPrefix(name, "owner:"); ok {
		id, err := strconv.ParseUint(uid, 10, 64)
		if err != nil {
			return nil
		}

		return slices.Collect(x.members(x.posts.Nodes(OwnerRole(uint(id)))).Iter())
	}

	s, ok := x.table.Lookup(name)
	if !ok || !s.Kind.HoldsNodes() {
		return nil
	}

	return slices.Collect(x.res(s.ID).Iter())
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
		// TODO(kradalby): policy/via-self: autogroup:self resolves to
		// nothing here, so a via grant to it gives its routers no rule.
		// TODO(kradalby): policy/via-reach: * resolves to the tailnet's
		// ranges here, so a via grant to * reaches no route outside them.
		// Both fail closed; policymodel.ViaSelf and policymodel.ViaReach
		// keep the plain readings and say what settles them.
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
	// ips are its addresses, ascending; reach those and, on a router,
	// every route it serves, approved and announced, exits included.
	ips    []netip.Addr
	reach  *netipx.IPSet
	routed bool
}

func newReceiver(n types.NodeView) receiver {
	rc := receiver{n: n, ips: slices.Clone(n.IPs())}
	slices.SortFunc(rc.ips, netip.Addr.Compare)

	subnets, exits := n.SubnetRoutes(), n.ExitRoutes()
	rc.routed = len(subnets) > 0 || len(exits) > 0

	// Most receivers reach their own addresses only, which need no set.
	if !rc.routed {
		return rc
	}

	var b netipx.IPSetBuilder

	for _, ip := range rc.ips {
		b.Add(ip)
	}

	for _, p := range slices.Concat(subnets, exits) {
		b.AddPrefix(p)
	}

	rc.reach, _ = b.IPSet()

	return rc
}

// overlaps reports whether r reaches the receiver.
func (rc receiver) overlaps(r netipx.IPRange) bool {
	if rc.routed {
		return rc.reach.OverlapsRange(r)
	}

	return slices.ContainsFunc(rc.ips, r.Contains)
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
	return expandFilter(x.capFilterFor(n, nil), x.holders, reasonAddressMode)
}

// Filter returns the rules every node's filter is reduced from, without
// each receiver's own: what [PolicyManager.Filter] gives, for debugging
// and the policy's tests. Its rules are in IP form.
func (x *Expansion) Filter() []tailcfg.FilterRule {
	var (
		rules []tailcfg.FilterRule
		keys  []string
	)

	for g, gt := range x.t.grants {
		if gt.none || gt.kind == grantVia {
			continue
		}

		ge := x.grant(g)

		for i, ipr := range gt.ip {
			if ge.keys[i] == "" {
				continue
			}

			rules = append(rules, tailcfg.FilterRule{SrcIPs: ge.srcStrs, DstPorts: x.allDstPorts(gt, ipr.ports), IPProto: ipr.proto})
			keys = append(keys, ge.keys[i])
		}

		if !ge.capGrant {
			continue
		}

		srcs := ge.srcStrs
		if srcs == nil {
			srcs = []string{}
		}

		var grants []tailcfg.CapGrant

		for _, id := range gt.dsts {
			res, err := x.resolve(id)
			if err == nil && res != nil {
				grants = append(grants, tailcfg.CapGrant{Dsts: res.Prefixes(), CapMap: gt.app})
			}
		}

		rules = append(rules, tailcfg.FilterRule{SrcIPs: srcs, CapGrant: grants})
		keys = append(keys, "")

		// Never nil, as the compile writes a companion to nobody.
		srcPrefixes := make([]netip.Prefix, 0, 2*len(ge.srcSets))
		for _, set := range ge.srcSets {
			srcPrefixes = append(srcPrefixes, set.Prefixes()...)
		}

		for _, rule := range companionCapGrantRules(ge.dstIPs, srcPrefixes, gt.app) {
			rules = append(rules, rule)
			keys = append(keys, "")
		}
	}

	return mergeKeyedRules(rules, keys)
}

// allDstPorts returns every destination of a rule of gt over ports, in the
// compile's order: by destination, address, then port.
func (x *Expansion) allDstPorts(gt *GrantTemplate, ports []tailcfg.PortRange) []tailcfg.NetPortRange {
	var out []tailcfg.NetPortRange

	add := func(ip string) {
		for _, p := range ports {
			out = append(out, tailcfg.NetPortRange{IP: ip, Ports: p})
		}
	}

	for _, id := range gt.dsts {
		switch s := x.table.Selector(id); {
		case s.Kind == SelectorWildcard:
			add("*")
		case s.Kind.HoldsNodes():
			for _, ip := range x.res(id).Strings() {
				add(ip)
			}
		default:
			for _, e := range x.t.literals[id].entries {
				add(e.str)
			}
		}
	}

	return out
}

// Filters serves packet filters from templates, postings and the approved
// subnet routes over one node list: the expansion is built on first use and
// each node's filter once, so it costs the sessions that render, not every
// commit. A change to any of its inputs makes new Filters; those made by
// [FollowFilters] carry over the cached filters [Filters.Changed] says the
// change cannot reach.
type Filters struct {
	t      *Templates
	posts  Postings
	routes []string
	// nodes is the node list the policy compiles against, sorted by ID.
	nodes views.Slice[types.NodeView]
	// mode is how sources are named: by address, or by capability where
	// no fallback applies. A receiver's facts are given when its filter is
	// read: they decide only which of its two forms it is sent.
	mode SourceMode

	once sync.Once
	x    *Expansion
	err  error

	// byNode holds the filters cut, by form: address form, then capability
	// form, which only capability mode cuts.
	byNode     [numForms]*xsync.Map[types.NodeID, []tailcfg.FilterRule]
	globalOnce sync.Once
	global     []tailcfg.FilterRule

	// id names these filters to the ones that follow them. sides, when
	// hasSides, tells who receives a rule; without them Changed says all.
	id       uint64
	sides    Sides
	hasSides bool

	// prevID names the filters these follow, whose change changeOnce
	// keeps. from is them, until the change is worked out: then carried
	// holds what they carried and cut, less what the change reaches (or
	// nothing, when every node's filter was compared and these cut their
	// own), and none of their inputs (an older document among them) stays
	// alive through these.
	prevID     uint64
	from       atomic.Pointer[Filters]
	carried    [numForms]atomic.Pointer[cutFilters]
	changeOnce sync.Once
	change     filterChange

	// fresh is [Filters.Fresh], once asked for.
	fresh atomic.Pointer[Filters]

	// shared is which selectors and owners nodes share an address across,
	// in capability mode: carried from the filters these follow when no
	// node that moved holds an address another node holds, else found from
	// the list when first read.
	shared atomic.Pointer[sharing]

	// census is [Filters.Census] less the receivers, counted once: from
	// censusFrom when set, else from every owner. counted is its count,
	// for the filters that follow, once done. censusFrom is set when f is
	// built and never after.
	censusOnce sync.Once
	census     FallbackCensus
	censusErr  error
	censusFrom *censusBase
	counted    atomic.Pointer[censusCount]
}

// cutFilters are filters cut for some nodes, carried from one Filters to
// the next: each carries what it was given and what it cut, less what its
// change reaches, an edit costing what moved.
type cutFilters = graph.Map[types.NodeID, []tailcfg.FilterRule]

func sameCut(a, b []tailcfg.FilterRule) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

var filtersIDs atomic.Uint64

// NewFilters returns the filters t expands to under posts, with approvals
// the approved subnet routes of nodes, the node list sorted by ID.
func NewFilters(t *Templates, posts Postings, approvals SubnetApprovals, nodes views.Slice[types.NodeView]) *Filters {
	return NewFiltersFor(AddressSources, t, posts, approvals, nodes)
}

// NewFiltersFor is [NewFilters] naming sources as mode says.
func NewFiltersFor(mode SourceMode, t *Templates, posts Postings, approvals SubnetApprovals, nodes views.Slice[types.NodeView]) *Filters {
	f := &Filters{
		t: t, posts: posts, routes: approvals.Strings(), nodes: nodes, mode: mode,
		id: filtersIDs.Add(1),
	}

	for i := range f.byNode {
		f.byNode[i] = xsync.NewMap[types.NodeID, []tailcfg.FilterRule]()
	}

	return f
}

// FollowFilters is [NewFilters] following prev, with sides those of the
// same commit: a node's filter that [Filters.Changed] says prev and these
// share is prev's slice, cut no second time.
func FollowFilters(prev *Filters, t *Templates, posts Postings, approvals SubnetApprovals, nodes views.Slice[types.NodeView], sides Sides) *Filters {
	return FollowFiltersFor(AddressSources, prev, t, posts, approvals, nodes, sides)
}

// FollowFiltersFor is [FollowFilters] naming sources as mode says.
func FollowFiltersFor(mode SourceMode, prev *Filters, t *Templates, posts Postings, approvals SubnetApprovals,
	nodes views.Slice[types.NodeView], sides Sides,
) *Filters {
	f := NewFiltersFor(mode, t, posts, approvals, nodes)
	f.sides, f.hasSides = sides, true

	if mode == CapabilitySources && prev != nil && prev.hasSides && prev.sides.from != nil && sides.from != nil &&
		prev.t.table() == t.table() {
		// What moved since prev: the nodes whose facts or roles did.
		moved := slices.Concat(graph.Changes(prev.sides.from, sides.from), graph.Changes(prev.posts.byRole.In, posts.byRole.In))

		f.followSharing(prev, moved)
		f.followCensus(prev, moved)
	}

	if prev != nil {
		from := prev

		// While prev's change is not worked out, it carries nothing yet:
		// follow what it would carry from, which a diff to f compares
		// directly. A run of commits nobody read then keeps one Filters
		// alive, not each.
		if p := prev.from.Load(); p != nil {
			from = p
		}

		f.prevID = from.id
		f.from.Store(from)
	}

	return f
}

// Uncached returns filters of the same inputs that share nothing with f
// and carry nothing over: an oracle for whatever f carried over.
func (f *Filters) Uncached() *Filters {
	u := NewFiltersFor(f.mode, f.t, f.posts, SubnetApprovals{}, f.nodes)
	u.routes = f.routes

	return u
}

// Fresh is [Filters.Uncached], one instance per f: what audits hold f to,
// each node cut once however often they ask.
func (f *Filters) Fresh() *Filters {
	if u := f.fresh.Load(); u != nil {
		return u
	}

	f.fresh.CompareAndSwap(nil, f.Uncached())

	return f.fresh.Load()
}

func (f *Filters) expansion() (*Expansion, error) {
	f.once.Do(func() {
		expansionBuilds.Add(1)

		f.x, f.err = NewExpansion(f.t, f.posts, f.routes, f.node)
		if f.x != nil {
			f.x.list, f.x.share = f.nodes, f.sharing
		}
	})

	return f.x, f.err
}

// followSharing gives f prev's addresses shared, unless a node whose
// facts or roles moved holds an address another node holds at either end,
// which is the only way what nodes share, or whose roles they cross, can
// move. Such a node leaves f to find them from the list when first read.
func (f *Filters) followSharing(prev *Filters, moved []types.NodeID) {
	sh := prev.shared.Load()
	if sh == nil {
		return
	}

	for _, id := range moved {
		for _, end := range [2]*Filters{prev, f} {
			n, ok := end.node(id)
			if !ok {
				continue
			}

			for _, ip := range n.IPs() {
				if ids, _ := end.sides.byAddr.Groups.Get(ip); len(ids) > 1 {
					return
				}
			}
		}
	}

	f.shared.Store(sh)
}

// sharing returns which selectors and owners nodes share an address
// across, found from the list unless carried over.
func (f *Filters) sharing() *sharing {
	if sh := f.shared.Load(); sh != nil {
		return sh
	}

	f.shared.CompareAndSwap(nil, findSharing(f.nodes, f.posts, f.t.table().Len()))

	return f.shared.Load()
}

// node looks id up in the sorted node list.
func (f *Filters) node(id types.NodeID) (types.NodeView, bool) {
	i, found := sort.Find(f.nodes.Len(), func(i int) int { return cmp.Compare(id, f.nodes.At(i).ID()) })
	if !found {
		return types.NodeView{}, false
	}

	return f.nodes.At(i), true
}

var errUnlisted = errors.New("node is not in the policy's node list")

// filterCuts counts the node filters [Filters.ForNode] cut, cached or not.
var filterCuts atomic.Uint64

// FilterCuts returns how many node filters served filters have cut, so a
// benchmark can tell what a cache keyed on input changes recomputes.
func FilterCuts() uint64 { return filterCuts.Load() }

// expansionBuilds counts the expansions [Filters] built.
var expansionBuilds atomic.Uint64

// ExpansionBuilds returns how many expansions served filters have built,
// each O(every selector's members and every grant), so a test can tell a
// write that rebuilds them.
func ExpansionBuilds() uint64 { return expansionBuilds.Load() }

// ForNode returns the packet filter of node id, for a receiver with facts
// facts, cut for the list's own view of it, so no caller's view can stand
// for another snapshot's facts: the same slice for every caller.
// Concurrent misses keep the first. A filter the filters f follows cut,
// and that [Filters.Changed] leaves out, is that one. Facts decide only
// which form id is sent, each cached apart, so a node whose facts flip
// reads its other form and no other node's filter moves.
func (f *Filters) ForNode(id types.NodeID, facts ReceiverFacts) ([]tailcfg.FilterRule, error) {
	why := receiverForm(f.mode, facts)
	form := formOf(why)

	if rules, ok := f.byNode[form].Load(id); ok {
		return rules, nil
	}

	n, ok := f.node(id)
	if !ok {
		return nil, fmt.Errorf("%w: %d", errUnlisted, id)
	}

	if from := f.from.Load(); from != nil {
		f.changeFrom(from)
	}

	if rules, ok := f.carried[form].Load().Get(id); ok {
		return rules, nil
	}

	if why != reasonNone && f.mode == CapabilitySources {
		addressCuts[why].Add(1)
	}

	return f.cut(n, form, why)
}

// cut cuts n's filter in form, as address form for why, and caches it.
func (f *Filters) cut(n types.NodeView, form filterForm, why ipReason) ([]tailcfg.FilterRule, error) {
	// TODO(kradalby): cost/address-form-recut: an address-form cut resolves
	// every selector its rules read over all their members, so a receiver
	// sent addresses (a subnet router or exit node under capsrc/local-nets,
	// a client other than Tailscale's) that a join names brings work the
	// size of the tailnet back to that join, which capability form avoids.
	// Accepted while those fallbacks stand. Fixing it takes resolutions
	// carried across commits and edited by the postings that moved, or
	// lifting the fallbacks. No upstream reference: headscale's own
	// expansion.
	x, err := f.expansion()
	if err != nil {
		return nil, err
	}

	filterCuts.Add(1)

	rules, _ := f.byNode[form].LoadOrStore(n.ID(), x.cutIn(n, form, why, nil))

	return rules, nil
}

// Mode returns how f names sources.
func (f *Filters) Mode() SourceMode { return f.mode }

// AddressForm returns node id's filter as address mode writes it from f's
// inputs, cut afresh: what its capability form must agree with.
func (f *Filters) AddressForm(id types.NodeID) ([]tailcfg.FilterRule, error) {
	n, ok := f.node(id)
	if !ok {
		return nil, fmt.Errorf("%w: %d", errUnlisted, id)
	}

	x, err := f.expansion()
	if err != nil {
		return nil, err
	}

	return x.FilterForNode(n), nil
}

// Global returns [Expansion.Filter], built once.
func (f *Filters) Global() ([]tailcfg.FilterRule, error) {
	x, err := f.expansion()
	if err != nil {
		return nil, err
	}

	f.globalOnce.Do(func() { f.global = x.Filter() })

	return f.global, nil
}

// filterChange is what [Filters.Changed] found. ids are named in either
// form; addr names more in address form only, capOnly, sorted, more in
// capability form only. compared reports that every node's filter was
// compared, so the filters followed hold a cut of every node in each form
// they did not name it in.
type filterChange struct {
	ids      []types.NodeID
	addr     addressReceivers
	capOnly  []types.NodeID
	all      bool
	compared bool
}

// addressReceivers are the receivers of the grants whose rules moved only
// where a receiver is sent their sources as addresses: a receiver sent
// them as capabilities reads none of what moved. They are the holders of
// those grants' destination atoms at either end, kept as the shared lists
// the sides hold, so the change names them without copying or walking
// them.
type addressReceivers struct {
	holders [][]types.NodeID
	// owners, when set, are both ends' postings: every owner node of
	// either is named too.
	owners []Postings
}

// empty reports whether no receiver is named in address form only.
func (a addressReceivers) empty() bool { return len(a.holders) == 0 && len(a.owners) == 0 }

// has reports whether node id receives one of the grants a names, at
// either end.
func (a addressReceivers) has(id types.NodeID) bool {
	return slices.ContainsFunc(a.holders, func(ids []types.NodeID) bool {
		_, found := slices.BinarySearch(ids, id)

		return found
	}) || slices.ContainsFunc(a.owners, func(p Postings) bool {
		rs, _ := p.byRole.In.Get(id)
		for r := range rs.All() {
			if _, ok := r.Owner(); ok {
				return true
			}
		}

		return false
	})
}

// lists returns every list of nodes a names.
func (a addressReceivers) lists() [][]types.NodeID {
	out := slices.Clone(a.holders)

	for _, p := range a.owners {
		for role, ids := range p.All() {
			if _, ok := role.Owner(); ok {
				out = append(out, ids)
			}
		}
	}

	return out
}

// Changed returns, sorted, the nodes whose filter, in either form, can
// differ between old and f, or all when it cannot tell: the nodes whose
// own facts moved; the receivers of every rule whose sources, merge key or
// capability moved; the nodes whose addresses, or routes, hold an address a
// destination gained or lost; the owners whose autogroup:self rules moved,
// by membership or by address; the receivers of every rule merged at a
// position that moved; the via routers of a via grant that moved; and,
// when any rule moved, every exit node and subnet router. Across a change
// of which selectors or grants there are, or without the sides
// [FollowFilters] gives, it compares every node's filter instead, form by
// form. The change from the filters f follows is worked out once. It lists
// every receiver of a rule whose sources only address form reads moved,
// and, across such a change, every node in each form old holds no cut of:
// routing asks [Filters.ChangedFor], which names each only where it is
// sent that form.
func (f *Filters) Changed(old *Filters) ([]types.NodeID, bool) {
	c, ok := f.changeFrom(old)
	if !ok || c.all || c.addr.empty() && len(c.capOnly) == 0 {
		return slices.Clip(c.ids), c.all || !ok
	}

	ids := slices.Concat(append([][]types.NodeID{c.ids, c.capOnly}, c.addr.lists()...)...)
	slices.Sort(ids)

	return slices.Compact(ids), false
}

// ChangedFor returns, sorted, the nodes whose filter in the form recv's
// facts send it can differ between old and f, or all: what [Filters.Changed]
// names, less each node named only in the form recv does not send it; the
// receivers named in address form only are found through recv's nodes not
// sent capabilities rather than every receiver. A node whose facts moved
// between the two is not named here: it is served its other form, and the
// caller names it.
func (f *Filters) ChangedFor(old *Filters, recv Receivers) ([]types.NodeID, bool) {
	c, ok := f.changeFrom(old)
	if !ok || c.all {
		return slices.Clip(c.ids), true
	}

	return c.namedFor(f.mode, recv), false
}

// namedFor returns, sorted, the nodes c names for receivers whose facts
// recv holds, each in the form those send it.
//
// The change is the filters', shared by every caller, which may append to
// what it is given: a slice of it comes clipped, so an append copies.
func (c filterChange) namedFor(mode SourceMode, recv Receivers) []types.NodeID {
	if c.addr.empty() && len(c.capOnly) == 0 {
		return slices.Clip(c.ids)
	}

	ids := slices.Clone(c.ids)

	for _, id := range recv.addressForm {
		if receiverForm(mode, recv.Of(id)) != reasonNone && c.addr.has(id) {
			ids = append(ids, id)
		}
	}

	for _, id := range c.capOnly {
		if receiverForm(mode, recv.Of(id)) == reasonNone {
			ids = append(ids, id)
		}
	}

	slices.Sort(ids)

	return slices.Compact(ids)
}

// changeFrom returns the change from old to f; false when there is no old
// to compare with, which routing takes as every node. The change from the
// filters f follows is worked out once, and decides what f carries over.
func (f *Filters) changeFrom(old *Filters) (filterChange, bool) {
	switch {
	case old == f:
		return filterChange{}, true
	case old == nil:
		return filterChange{}, false
	case old.id == f.prevID:
		f.changeOnce.Do(func() {
			f.change = changedFilters(old, f)
			if !f.change.all && !f.change.compared {
				for form := range f.carried {
					f.carried[form].Store(carryOver(old, filterForm(form), f.change))
				}
			}

			f.from.Store(nil)
		})

		return f.change, true
	}

	return changedFilters(old, f), true
}

// carryOver returns what old carried and cut in form, less what c names in
// that form, sorted: an edit costs the cuts kept and the carried filters
// dropped, and the address form ones a rule only address form reads
// reaches.
func carryOver(old *Filters, form filterForm, c filterChange) *cutFilters {
	base := old.carried[form].Load()
	if base == nil {
		base = graph.NewMap[types.NodeID](sameCut, nil)
	}

	addr := form == formAddress && !c.addr.empty()

	moved := func(id types.NodeID) bool {
		_, found := slices.BinarySearch(c.ids, id)

		return found || addr && c.addr.has(id)
	}

	e := base.Edit()

	old.byNode[form].Range(func(id types.NodeID, rules []tailcfg.FilterRule) bool {
		if !moved(id) {
			e.Set(id, rules)
		}

		return true
	})

	if base.Len() > 0 {
		for _, id := range c.ids {
			e.Delete(id)
		}

		if addr {
			for id := range base.All() {
				if c.addr.has(id) {
					e.Delete(id)
				}
			}
		}
	}

	return e.Done()
}

// filterRoute collects what moved between two filters, and whom it reaches.
type filterRoute struct {
	o, n   *Filters
	xo, xn *Expansion

	out map[types.NodeID]struct{}
	// moved are the nodes whose own facts moved; delta, by identity
	// selector, the addresses its resolution gained or lost; lits the
	// address selectors whose literal moved.
	moved []types.NodeID
	delta map[SelectorID][]netip.Addr
	lits  map[SelectorID]bool
	// touched is set once a rule moved: every exit node carries it, and
	// every subnet router is named unless narrow.
	touched bool
	narrow  bool
	// caps is set in capability mode, where a receiver sent capabilities
	// reads each grant's sources in capability form, not their addresses;
	// addr then collects the grants whose receivers are named in address
	// form only.
	caps bool
	addr map[int]struct{}
	// addrLists are more receivers named in address form only: owner
	// nodes whose self rules moved only there.
	addrLists [][]types.NodeID
	// cands are, in capability mode, the moved nodes and those whose
	// roles moved; moved2 is set once a grant's sources or destinations
	// resolve otherwise, owners once that reaches a self grant.
	cands          []types.NodeID
	moved2, owners bool
}

func changedFilters(o, n *Filters) filterChange { return routeFilters(o, n, false) }

// routeFilters is [Filters.Changed]'s diff. Narrow leaves out the subnet
// routers no moved rule reaches by its destinations: what routing would
// name were the cover and address indexes trusted, which a test holds to a
// fresh comparison.
func routeFilters(o, n *Filters, narrow bool) filterChange {
	all := filterChange{all: true}

	// TODO(kradalby): overwake/since-expansion-failed: templates that do not
	// expand name every node, which Snapshot.Since turns into waking every
	// session; only a template naming an alias its table lacks fails here,
	// which a table describing the document never holds. Name nothing past
	// the failure instead once that is shown unreachable. Tolerated by
	// TestSinceSoundOverAnyPair (global changes are not judged). No upstream
	// reference: headscale's own templates.
	xo, err := o.expansion()
	if err != nil {
		return all
	}

	xn, err := n.expansion()
	if err != nil {
		return all
	}

	// Grants that are not the same grants, position for position, cannot
	// be compared rule by rule: where merged rules sit moves with them.
	if !o.hasSides || !n.hasSides || o.t.table() != n.t.table() || len(o.t.grants) != len(n.t.grants) || o.mode != n.mode {
		return compareFilters(o, n)
	}

	r := &filterRoute{o: o, n: n, xo: xo, xn: xn, out: map[types.NodeID]struct{}{}, narrow: narrow, caps: n.mode == CapabilitySources}

	if r.caps && o.sides.from != nil && n.sides.from != nil {
		// Capability form reads addresses only where a fallback writes
		// them, so what moved is read off the nodes and roles that did,
		// never every selector's members: neither end's address part is
		// built here.
		r.candidates()
		r.deltas()
		r.literals()

		for g := range n.t.grants {
			r.grantDelta(g)
		}

		r.anchorsDelta()
	} else {
		r.movedNodes()
		r.resolutions()

		for g := range n.t.grants {
			r.grant(g)
		}

		r.anchors()
	}

	if r.touched {
		r.holders(atomExit)

		// A router's filter follows the nodes inside its routes through the
		// cover and address indexes; a stale one admits traffic into its
		// subnets, so a moved rule recuts every router rather than trust
		// them.
		//
		// TODO(kradalby): overwake/routers-wholesale: every exit node and
		// subnet router is named, recut and woken whenever any rule moved,
		// though most rules reach none of them (a join into a group a rule to
		// one tag names). Kept wholesale by decision, so a router's filter
		// never depends on incremental indexes only the debug audit checks:
		// a stale router filter admits traffic into a subnet. The narrow set
		// beside it (narrow, holders and destinations without routers) is
		// held sound by TestFiltersChangedSoundPreciseAndCarried and
		// TestFiltersChangedCoversEveryMovedFilter; switching to it needs a
		// production-path check of the indexes. Tolerated by
		// addressOnlyMeasure in TestFiltersChangedSoundPreciseAndCarried and
		// by the routers TestSessionsFollowGeneratedScenarios leaves out of
		// its join law. Subnet routers: docs/ref/routes.md. No upstream
		// reference: the decision is headscale's.
		if !r.narrow {
			r.routers()
		}
	}

	c := namesAll(slices.Sorted(maps.Keys(r.out)), n.nodes)
	if !c.all && (len(r.addr) > 0 || len(r.addrLists) > 0 || r.owners) {
		c.addr = r.addressReceivers()
	}

	return c
}

// addressReceivers describes the receivers named in address form only: the
// holders of the destination atoms of grants named so at each end, and the
// owner nodes self rules named.
func (r *filterRoute) addressReceivers() addressReceivers {
	var a addressReceivers

	for _, ids := range r.addrLists {
		if len(ids) > 0 {
			a.holders = append(a.holders, ids)
		}
	}

	if r.owners {
		a.owners = []Postings{r.o.posts, r.n.posts}
	}

	for _, s := range r.sides() {
		var atoms []Role

		for _, g := range slices.Sorted(maps.Keys(r.addr)) {
			gs := &s.plan.grants[g]
			atoms = append(atoms, gs.portDst...)
			atoms = append(atoms, gs.capDst...)
		}

		slices.SortFunc(atoms, compareRoles)

		for _, at := range slices.Compact(atoms) {
			if ids := s.Holders(at); len(ids) > 0 {
				a.holders = append(a.holders, ids)
			}
		}
	}

	return a
}

// namesAll returns ids as a change, all when they name every node of list:
// telling every session costs less than naming each.
func namesAll(ids []types.NodeID, list views.Slice[types.NodeView]) filterChange {
	if len(ids) < list.Len() {
		return filterChange{ids: ids}
	}

	for _, n := range list.All() {
		if _, found := slices.BinarySearch(ids, n.ID()); !found {
			return filterChange{ids: ids}
		}
	}

	return filterChange{all: true}
}

// compareFilters returns the nodes whose filter differs at the two ends,
// form by form: what o holds, cut or carried, against n's cut, which n
// keeps for the sessions that read it next. A form o holds no cut of may
// yet be served from o, to a session that took o before this ran, so the
// node is named in that form: the other form, which a flip of its facts or
// an earlier comparison can leave held alone, says nothing of it. A
// document edit that changes which selectors or grants there are pays a
// cut per form o holds.
func compareFilters(o, n *Filters) filterChange {
	forms := formAddress + 1
	if n.mode == CapabilitySources {
		forms = numForms
	}

	var ids, addrOnly, capOnly []types.NodeID

	for _, id := range listIDs(o.nodes, n.nodes) {
		nv, listed := n.node(id)

		// TODO(kradalby): overwake/compare-filters: across a document edit
		// that changes which selectors or grants there are, every node the
		// old filters hold a filter of is recut and compared, and every node
		// they hold none of is named; when they hold none at all, every node
		// is named and Snapshot.Since wakes everyone
		// (overwake/since-filters-unheld). Accepted: document edits are rare
		// and the cuts are what the next renders read. Fixing it takes
		// matching grants across tables by content rather than position, on
		// stable selector identities, so routeFilters can diff them. The
		// precision clause of TestFiltersChangedSoundPreciseAndCarried skips
		// document edits for it. No upstream reference: headscale's own
		// change routing.
		if !listed {
			ids = append(ids, id)

			continue
		}

		var moved [numForms]bool

		served := moved[:forms]
		for i := range served {
			form := filterForm(i) //nolint:gosec // below numForms
			was, held := o.heldIn(id, form)

			if !held {
				served[i] = true

				continue
			}

			is, err := n.cut(nv, form, recutReason(n.mode, form))
			served[i] = err != nil || !reflect.DeepEqual(was, is)
		}

		// Address mode serves no capability form, so address form is all.
		capMoved := moved[formCapability] || forms < numForms

		switch {
		case moved[formAddress] && capMoved:
			ids = append(ids, id)
		case moved[formAddress]:
			addrOnly = append(addrOnly, id)
		case moved[formCapability]:
			capOnly = append(capOnly, id)
		}
	}

	c := namesAll(ids, n.nodes)
	c.compared = true

	if !c.all {
		if len(addrOnly) > 0 {
			c.addr.holders = [][]types.NodeID{addrOnly}
		}

		c.capOnly = capOnly
	}

	return c
}

// heldIn returns the filter f holds for id in form, cut or carried,
// cutting none.
func (f *Filters) heldIn(id types.NodeID, form filterForm) ([]tailcfg.FilterRule, bool) {
	if rules, ok := f.byNode[form].Load(id); ok {
		return rules, true
	}

	return f.carried[form].Load().Get(id)
}

// listIDs returns, sorted, the IDs in either sorted list.
func listIDs(a, b views.Slice[types.NodeView]) []types.NodeID {
	out := make([]types.NodeID, 0, max(a.Len(), b.Len()))

	for i, j := 0, 0; i < a.Len() || j < b.Len(); {
		switch {
		case j == b.Len() || i < a.Len() && a.At(i).ID() < b.At(j).ID():
			out = append(out, a.At(i).ID())
			i++
		case i == a.Len() || b.At(j).ID() < a.At(i).ID():
			out = append(out, b.At(j).ID())
			j++
		default:
			out = append(out, a.At(i).ID())
			i++
			j++
		}
	}

	return out
}

func (r *filterRoute) add(ids ...types.NodeID) {
	for _, id := range ids {
		r.out[id] = struct{}{}
	}
}

// sides returns the sides of both ends.
func (r *filterRoute) sides() [2]Sides { return [2]Sides{r.o.sides, r.n.sides} }

// holders adds the nodes holding atom a at either end.
func (r *filterRoute) holders(a Role) {
	for _, s := range r.sides() {
		r.add(s.Holders(a)...)
	}
}

// routers adds every node serving a subnet route at either end.
func (r *filterRoute) routers() {
	for _, s := range r.sides() {
		for _, ids := range s.routers.Groups.All() {
			r.add(ids...)
		}
	}
}

// movedNodes adds the nodes that joined, left, or changed a fact the
// policy reads between the two node lists.
func (r *filterRoute) movedNodes() {
	a, b := r.o.nodes, r.n.nodes

	for i, j := 0, 0; i < a.Len() || j < b.Len(); {
		switch {
		case j == b.Len() || i < a.Len() && a.At(i).ID() < b.At(j).ID():
			r.moved = append(r.moved, a.At(i).ID())
			i++
		case i == a.Len() || b.At(j).ID() < a.At(i).ID():
			r.moved = append(r.moved, b.At(j).ID())
			j++
		default:
			if va, vb := a.At(i), b.At(j); va != vb && va.HasPolicyChange(vb) {
				r.moved = append(r.moved, va.ID())
			}

			i++
			j++
		}
	}

	// TODO(kradalby): overwake/policy-facts-moved: address mode's
	// counterpart of filterRoute.candidates; same over-name, same fix. No
	// upstream reference: headscale's own change routing.
	r.add(r.moved...)
}

// resolutions records which selectors resolve otherwise at the two ends.
func (r *filterRoute) resolutions() {
	r.delta = map[SelectorID][]netip.Addr{}

	for _, s := range r.n.t.table().sels {
		if !s.Kind.HoldsNodes() {
			continue
		}

		if d := addressDelta(r.xo.res(s.ID), r.xn.res(s.ID)); len(d) > 0 {
			r.delta[s.ID] = d
		}
	}

	if r.o.t == r.n.t {
		return
	}

	r.lits = map[SelectorID]bool{}

	for _, s := range r.n.t.table().sels {
		if !s.Kind.HoldsNodes() && !reflect.DeepEqual(r.o.t.literals[s.ID], r.n.t.literals[s.ID]) {
			r.lits[s.ID] = true
		}
	}
}

// candidates finds the nodes that joined, left, or changed a fact the
// policy reads, off the node maps' edit logs, and with them the nodes
// whose roles moved without: whose addresses can enter or leave a
// resolution.
func (r *filterRoute) candidates() {
	for _, id := range graph.Changes(r.o.sides.from, r.n.sides.from) {
		was, wasOK := r.o.node(id)
		is, isOK := r.n.node(id)

		if wasOK != isOK || wasOK && was != is && was.HasPolicyChange(is) {
			r.moved = append(r.moved, id)
		}
	}

	routedNodes.Add(uint64(len(r.moved)))

	// TODO(kradalby): overwake/policy-facts-moved: a node whose policy facts
	// moved is named and recut whether or not its own filter reads what
	// moved (an approval of a route it does not announce, a retag between
	// tags no rule tells apart). Safe: it costs a recut; the node's own
	// session is woken for its node change anyway. Fixing it takes naming it
	// only through the grants and destinations that read the facts that
	// moved. Tolerated by unmovedNamed ("policy facts moved") in
	// TestFiltersChangedSoundPreciseAndCarried. No upstream reference:
	// headscale's own change routing.
	r.add(r.moved...)

	r.cands = slices.Concat(r.moved, graph.Changes(r.o.posts.byRole.In, r.n.posts.byRole.In))
	slices.Sort(r.cands)
	r.cands = slices.Compact(r.cands)
}

// routedNodes counts the nodes routing in capability mode found moved:
// what it visits of the node list.
var routedNodes atomic.Uint64

// deltas records, by identity selector, the addresses its resolution
// gained or lost, as [addressDelta] of the two ends' resolutions finds
// them: an address can move only with a candidate holding it, and is in a
// resolution when one of its holders is a member.
func (r *filterRoute) deltas() {
	r.delta = map[SelectorID][]netip.Addr{}

	ends := [2]*Filters{r.o, r.n}

	in := func(end int, ip netip.Addr, sel SelectorID) bool {
		ids, _ := r.sides()[end].byAddr.Groups.Get(ip)

		return slices.ContainsFunc(ids, func(id types.NodeID) bool {
			rs, _ := ends[end].posts.byRole.In.Get(id)

			return rs.Has(SelectorRole(sel))
		})
	}

	seen := map[SelectorID]map[netip.Addr]bool{}

	for _, id := range r.cands {
		var (
			sels  []SelectorID
			addrs []netip.Addr
		)

		for _, f := range ends {
			rs, _ := f.posts.byRole.In.Get(id)
			for role := range rs.All() {
				if sel, ok := role.Selector(); ok && r.n.t.table().Selector(sel).Kind.HoldsNodes() {
					sels = append(sels, sel)
				}
			}

			if n, ok := f.node(id); ok {
				addrs = append(addrs, n.IPs()...)
			}
		}

		for _, sel := range sels {
			if seen[sel] == nil {
				seen[sel] = map[netip.Addr]bool{}
			}

			for _, ip := range addrs {
				if seen[sel][ip] {
					continue
				}

				seen[sel][ip] = true

				if in(0, ip, sel) != in(1, ip, sel) {
					r.delta[sel] = append(r.delta[sel], ip)
				}
			}
		}
	}
}

// literals records the address selectors whose literal a document edit
// moved.
func (r *filterRoute) literals() {
	if r.o.t == r.n.t {
		return
	}

	r.lits = map[SelectorID]bool{}

	for _, s := range r.n.t.table().sels {
		if !s.Kind.HoldsNodes() && !reflect.DeepEqual(r.o.t.literals[s.ID], r.n.t.literals[s.ID]) {
			r.lits[s.ID] = true
		}
	}
}

// moves reports whether what selectors ids resolve to can differ at the
// two ends; wildcard adds the approved subnet routes a * names.
func (r *filterRoute) moves(ids []SelectorID, wildcard bool) bool {
	if wildcard && !slices.Equal(r.o.routes, r.n.routes) {
		return true
	}

	return slices.ContainsFunc(ids, func(id SelectorID) bool { return len(r.delta[id]) > 0 || r.lits[id] })
}

// grantDelta is [filterRoute.grant] for capability mode, where what moved
// of a grant's sources and destinations is read off the deltas, not off
// the two ends' expansions: a grant whose sources or destinations resolve
// otherwise reaches its receivers sent addresses, and the others when its
// capability form sources moved.
func (r *filterRoute) grantDelta(g int) {
	gto, gtn := r.o.t.grants[g], r.n.t.grants[g]
	if gto.none && gtn.none {
		return
	}

	tmpl := gto != gtn
	srcMoved := r.moves(gto.srcs, gto.wildcard) || r.moves(gtn.srcs, gtn.wildcard)
	dstMoved := r.moves(gto.dsts, gto.dstWildcard) || r.moves(gtn.dsts, gtn.dstWildcard)

	if gto.kind == grantVia || gtn.kind == grantVia {
		if tmpl || srcMoved || dstMoved {
			r.viaRouters(gto, gtn)
		}

		if !tmpl || gto.kind == grantVia && gtn.kind == grantVia {
			return
		}
	}

	capMoved := !slices.Equal(r.xo.capForms().grants[g].srcs, r.xn.capForms().grants[g].srcs)

	switch {
	case tmpl || capMoved:
		r.touched, r.moved2 = true, true
		r.receivers(g, false)
	case srcMoved || dstMoved:
		// TODO(kradalby): overwake/address-pair-destinations: when only the
		// destinations moved, a grant with an app capability or a portless
		// rule (addressPair) names every receiver in every form, though
		// such a rule reads only the receiver's own addresses of its
		// destinations, which filterRoute.destinations names already (a node
		// leaving the destination of a GRE rule from *). Safe: a wake and a
		// recut that send nothing. Fixing it takes calling receivers only
		// when the sources moved, keeping the companions below for moved
		// destinations. The address form is forced by the client: app
		// capabilities are granted by address (Filter.CapsWithValues,
		// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/filter/filter.go) and a portless protocol is matched
		// by address (matches.matchProtoAndIPsOnlyIfAllPorts,
		// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/filter/match.go); tracking
		// https://github.com/tailscale/tailscale/issues/12542. Tolerated by overNamed
		// ("address-pair grant receiver") in
		// TestFiltersChangedSoundPreciseAndCarried and by the
		// app-or-portless class of ruleClass in
		// TestSessionsFollowGeneratedScenarios.
		r.touched, r.moved2 = true, true
		r.receivers(g, true)
	}

	// Companions run from the destinations to the sources, which receive
	// them.
	//
	// TODO(kradalby): overwake/companion-receivers: a companion rule's
	// receivers (the grant's sources) are named whenever the grant's sources
	// move, though a companion rule reads only the destinations' addresses
	// and the receiver's own (a node joining the sources of a relay grant
	// names every other source). Safe: a wake and a recut that send nothing.
	// Fixing it takes naming them on destination moves only, and the source
	// that moved as a subject. Companions:
	// https://tailscale.com/docs/features/taildrive and
	// https://tailscale.com/docs/features/peer-relay. Tolerated by overNamed
	// ("companion receiver") in TestFiltersChangedSoundPreciseAndCarried and
	// by the app-or-portless class of ruleClass in
	// TestSessionsFollowGeneratedScenarios.
	if tmpl || srcMoved || dstMoved {
		for _, s := range r.sides() {
			if gs := &s.plan.grants[g]; gs.comp {
				r.touched = true

				for _, a := range gs.compDst {
					r.add(s.Holders(a)...)
				}
			}
		}
	}

	r.destinations(gtn.dsts)

	if gto.kind == grantSelf || gtn.kind == grantSelf {
		r.self(g, gtn, tmpl || slices.ContainsFunc(gtn.srcs, func(id SelectorID) bool { return r.lits[id] }))
	}
}

// viaRouters adds the via routers of a via grant whose rules can have
// moved: every node carrying one of its tags at either end.
func (r *filterRoute) viaRouters(gto, gtn *GrantTemplate) {
	// TODO(kradalby): overwake/via-tag-holders: every holder of a via grant's
	// tags is named, though only one serving a route the grant's
	// destinations overlap, or an exit route, is cut a via rule (cutVia);
	// a holder serving none, or one sent capability form, holds nothing of
	// the grant (a member joining the sources names a tagged node with no
	// routes). Safe: a wake and a recut that send nothing. Fixing it takes
	// naming the tag holders that serve such a route, at either end. Via:
	// https://tailscale.com/docs/reference/syntax/grants. Tolerated by
	// overNamed ("via tag holder") in
	// TestFiltersChangedSoundPreciseAndCarried and by the via class of
	// ruleClass in TestSessionsFollowGeneratedScenarios.
	r.touched = true

	for _, gt := range [2]*GrantTemplate{gto, gtn} {
		for _, tag := range gt.via {
			if s, ok := r.n.t.table().Lookup(string(tag)); ok {
				r.add(r.o.posts.Nodes(SelectorRole(s.ID))...)
				r.add(r.n.posts.Nodes(SelectorRole(s.ID))...)
			}
		}
	}
}

// anchorsDelta is [filterRoute.anchors] for capability mode. Merge
// positions are address form's alone, and telling which moved means
// writing every merge key; so once any grant's sources or destinations
// resolve otherwise, every grant's receivers, and every owner's nodes,
// are named in address form only.
func (r *filterRoute) anchorsDelta() {
	if !r.moved2 {
		return
	}

	// TODO(kradalby): overwake/address-form-only: once any grant's sources or
	// destinations resolve otherwise, every grant's receivers and every owner
	// are named in address form, though a merge position moves only where a
	// merge key was gained or lost before a rule; with receivers(addressOnly)
	// it names every address-form receiver of a grant whose address form
	// alone moved. Safe: it reaches only nodes sent addresses (routers,
	// unknown clients, local nets), each recut and woken. Fixing it takes the
	// merge positions, which need every merge key: only worth it where
	// address-form receivers are many. Tolerated by addressOnlyMeasure in
	// TestFiltersChangedSoundPreciseAndCarried. No upstream reference:
	// address form's merge order is headscale's own.

	for g := range r.n.t.grants {
		for _, gt := range [2]*GrantTemplate{r.o.t.grants[g], r.n.t.grants[g]} {
			if !gt.none && gt.kind != grantVia && len(gt.ip) > 0 {
				r.addressOnly(g)
			}

			if !gt.none && gt.kind == grantSelf {
				r.owners = true
			}
		}
	}
}

// addressOnly names grant g's receivers in address form only.
func (r *filterRoute) addressOnly(g int) {
	if r.addr == nil {
		r.addr = map[int]struct{}{}
	}

	r.addr[g] = struct{}{}
}

// addressDelta returns the addresses in only one of a and b.
func addressDelta(a, b ResolvedAddresses) []netip.Addr {
	var as, bs []string
	if a != nil {
		as = a.Strings()
	}

	if b != nil {
		bs = b.Strings()
	}

	if slices.Equal(as, bs) {
		return nil
	}

	var out []netip.Addr

	for _, pair := range [2][2]ResolvedAddresses{{a, b}, {b, a}} {
		if pair[0] == nil {
			continue
		}

		for ip := range pair[0].Iter() {
			if pair[1] == nil || !pair[1].Contains(ip) {
				out = append(out, ip)
			}
		}
	}

	return out
}

// addresses adds the nodes holding one of addrs, and the routers whose
// subnet routes hold one, at either end.
func (r *filterRoute) addresses(addrs []netip.Addr) {
	for _, s := range r.sides() {
		for _, ip := range addrs {
			ids, _ := s.byAddr.Groups.Get(ip)
			r.add(ids...)

			containing(s.routers.Groups, s.routerLens, ip, func(_ netip.Prefix, ids []types.NodeID) { r.add(ids...) })
		}
	}
}

// receivers adds the nodes a rule of grant g every node shares can reach,
// at either end: those on its destination side. When only what address
// form reads moved, a receiver sent the grant's sources as capabilities
// reads none of it: in capability mode the grant's receivers are then
// named in address form only, unless a rule of it is written as addresses
// whatever the receiver.
func (r *filterRoute) receivers(g int, addressOnly bool) {
	if addressOnly && r.caps && !r.addressPair(g) {
		r.addressOnly(g)

		return
	}

	for _, s := range r.sides() {
		gs := &s.plan.grants[g]

		for _, a := range slices.Concat(gs.portDst, gs.capDst) {
			r.add(s.Holders(a)...)
		}
	}
}

// addressPair reports whether a receiver sent capabilities is sent some
// source of grant g's rules as addresses at either end, so whom they
// resolve to reaches it.
func (r *filterRoute) addressPair(g int) bool {
	return addressPair(r.o.t.grants[g]) || addressPair(r.n.t.grants[g])
}

// grant adds whom what moved of grant g reaches.
func (r *filterRoute) grant(g int) {
	gto, gtn := r.o.t.grants[g], r.n.t.grants[g]
	if gto.none && gtn.none {
		return
	}

	geo, gen := r.xo.grant(g), r.xn.grant(g)
	tmpl := gto != gtn

	if gto.kind == grantVia || gtn.kind == grantVia {
		r.via(gto, gtn, geo, gen)

		if !tmpl || gto.kind == grantVia && gtn.kind == grantVia {
			return
		}
	}

	// In capability form a receiver reads the grant's sources as written
	// for it, which change with membership only where they are addresses.
	capMoved := r.caps && !slices.Equal(r.xo.capForms().grants[g].srcs, r.xn.capForms().grants[g].srcs)

	switch {
	case tmpl || capMoved:
		r.touched = true
		r.receivers(g, false)
	case !slices.Equal(geo.srcStrs, gen.srcStrs) || !slices.Equal(geo.capSrcs, gen.capSrcs) ||
		!slices.Equal(geo.keys, gen.keys) || geo.capGrant != gen.capGrant:
		// TODO(kradalby): overwake/address-mode-grant-receivers: inherent in
		// address mode: every receiver of a grant whose sources moved is
		// named, as address form writes the sources' addresses into every
		// receiver's filter; capability form is the fix. The companions below
		// share overwake/companion-receivers. No upstream reference: the
		// address form is headscale's opt-out.
		r.touched = true
		r.receivers(g, true)
	}

	// Companions run from the destinations to the sources, which receive
	// them.
	if tmpl || !slices.Equal(geo.dstIPs, gen.dstIPs) || !sameSourceSets(geo, gen) {
		for _, s := range r.sides() {
			if gs := &s.plan.grants[g]; gs.comp {
				r.touched = true

				for _, a := range gs.compDst {
					r.add(s.Holders(a)...)
				}
			}
		}
	}

	r.destinations(gtn.dsts)

	if gto.kind == grantSelf || gtn.kind == grantSelf {
		r.self(g, gtn, tmpl || slices.ContainsFunc(gtn.srcs, func(id SelectorID) bool { return r.lits[id] }))
	}
}

// via adds the via routers of a via grant whose rules can have moved:
// every node carrying one of its tags at either end.
func (r *filterRoute) via(gto, gtn *GrantTemplate, geo, gen *grantExpansion) {
	if gto == gtn && slices.Equal(geo.srcStrs, gen.srcStrs) && slices.Equal(geo.viaDsts, gen.viaDsts) &&
		slices.Equal(geo.viaKeys, gen.viaKeys) {
		return
	}

	r.touched = true

	for _, gt := range [2]*GrantTemplate{gto, gtn} {
		for _, tag := range gt.via {
			if s, ok := r.n.t.table().Lookup(string(tag)); ok {
				r.add(r.o.posts.Nodes(SelectorRole(s.ID))...)
				r.add(r.n.posts.Nodes(SelectorRole(s.ID))...)
			}
		}
	}
}

// destinations adds the nodes whose reach of dsts can have moved: those
// holding, or routing over, an address a destination gained or lost, and
// those inside a literal that moved.
func (r *filterRoute) destinations(dsts []SelectorID) {
	// TODO(kradalby): overwake/delta-address-holders: the nodes holding, or
	// routing over, an address a destination gained or lost are named per
	// destination, though a node moving between two destinations of one rule
	// reaches the rule alike (a user renamed so that another destination of
	// the rule names it). Safe: a recut, and the holder is a subject of the
	// change. Fixing it takes comparing the receiver's reach of each rule at
	// both ends. Tolerated by unmovedNamed ("holds an address a destination
	// gained or lost") in TestFiltersChangedSoundPreciseAndCarried. No
	// upstream reference: headscale's own change routing.
	for _, id := range dsts {
		if d := r.delta[id]; len(d) > 0 {
			r.touched = true
			r.addresses(d)
		}

		if r.lits[id] {
			r.touched = true
			r.holders(literalRole(id))
		}
	}
}

// sameSourceSets reports whether a and b resolve each source alike.
func sameSourceSets(a, b *grantExpansion) bool {
	return slices.Equal(a.srcIDs, b.srcIDs) && slices.EqualFunc(a.srcSets, b.srcSets, func(x, y ResolvedAddresses) bool {
		return slices.Equal(x.Strings(), y.Strings())
	})
}

// self adds the nodes of every owner whose autogroup:self rules of grant g,
// gt at the new end, can have moved: all of them when all, else those whose
// nodes moved, and those a source names, by address, otherwise than it
// did. A self rule lists every node of its owner, and a source names an
// owner's node by its addresses: a node sharing an address with one that
// moved moves its owner's rules. In capability mode an owner whose rules
// go as its capability at both ends, naming the same sources, is named in
// address form only: its capability rule reads none of its nodes but the
// receiver.
func (r *filterRoute) self(g int, gt *GrantTemplate, all bool) {
	owners := map[uint]struct{}{}

	if all {
		for _, p := range [2]Postings{r.o.posts, r.n.posts} {
			for role := range p.All() {
				if uid, ok := role.Owner(); ok {
					owners[uid] = struct{}{}
				}
			}
		}
	} else {
		moved, _ := r.n.posts.Changed(r.o.posts)
		if r.caps {
			// The owner roles among the lists edited: comparing every edited
			// list, a member list among them, would cost its length.
			moved = r.n.posts.edited(r.o.posts)
		}

		for _, role := range moved {
			if uid, ok := role.Owner(); ok {
				owners[uid] = struct{}{}
			}
		}

		for _, id := range r.moved {
			r.ownersOf(id, owners)
		}

		for _, src := range gt.srcs {
			for _, ip := range r.delta[src] {
				for _, s := range r.sides() {
					ids, _ := s.byAddr.Groups.Get(ip)
					for _, id := range ids {
						r.ownersOf(id, owners)
					}
				}
			}
		}

		// An owner whose node began or stopped sharing an address with a
		// node not theirs is sent its rules in the other form.
		//
		// TODO(kradalby): overwake/owner-sharing-flip: such an owner's nodes
		// are named in every form, though the flip moves only the rules a
		// shared address sends as addresses (an owner node sharing an
		// address with another user's node that joins or leaves). Safe: a
		// recut. Fixing it takes naming them in the form whose self rules the
		// flip moves. The flip exists because the client asks one node per
		// address (LocalBackend.srcIPHasCapForFilter,
		// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/ipn/ipnlocal/local.go); tracking
		// https://github.com/tailscale/tailscale/issues/12542. Tolerated by unmovedNamed ("owner
		// sharing flipped") in TestFiltersChangedSoundPreciseAndCarried and by
		// the shared-address class of ruleClass in
		// TestSessionsFollowGeneratedScenarios.
		if r.caps {
			was, is := r.xo.capForms().ownerShared, r.xn.capForms().ownerShared
			for _, m := range [2]map[uint]bool{was, is} {
				for uid := range m {
					if was[uid] != is[uid] {
						owners[uid] = struct{}{}
					}
				}
			}
		}
	}

	if len(owners) == 0 {
		return
	}

	r.touched = true

	// TODO(kradalby): overwake/self-owners-every-form: an owner's nodes are
	// named in every form unless its self rules go as its capability at both
	// ends naming its nodes alike (selfAddressOnly); a self rule from a
	// source that is no identity, an app self grant (selfCapabilityOnly
	// declines every one), or a source whose naming moved without moving
	// the capability rule names them all (an owner node joining under
	// `* -> autogroup:self:22`). Safe: a recut and a wake. Fixing it takes
	// telling, per owner and form, whether the cut self rules moved. Self:
	// https://tailscale.com/docs/reference/targets-and-selectors#autogroupself.
	// Tolerated by unmovedNamed ("self owner whose rules are not
	// capability-only alike at both ends") in
	// TestFiltersChangedSoundPreciseAndCarried and by the self class of
	// ruleClass in TestSessionsFollowGeneratedScenarios.
	if !r.caps || all {
		r.ownerNodes(owners)

		return
	}

	for uid := range owners {
		if r.selfAddressOnly(g, uid) {
			r.addrLists = append(r.addrLists, r.o.posts.Nodes(OwnerRole(uid)), r.n.posts.Nodes(OwnerRole(uid)))

			continue
		}

		r.ownerNodes(map[uint]struct{}{uid: {}})
	}
}

// selfAddressOnly reports whether owner uid's rules of self grant g go as
// its capability at both ends with the same sources naming its nodes, so
// that only their address form can have moved.
func (r *filterRoute) selfAddressOnly(g int, uid uint) bool {
	var named [2][]selfNaming

	for end, x := range [2]*Expansion{r.xo, r.xn} {
		gt := x.t.grants[g]
		if gt.none || gt.kind != grantSelf {
			return false
		}

		named[end] = x.selfNamed(g, uid)
		if !x.selfCapabilityOnly(g, uid, named[end]) {
			return false
		}
	}

	return slices.Equal(named[0], named[1]) && slices.Equal(r.xo.srcIDs(g), r.xn.srcIDs(g))
}

// ownersOf adds to owners the users node id is an owner node of, at either
// end.
func (r *filterRoute) ownersOf(id types.NodeID, owners map[uint]struct{}) {
	for _, p := range [2]Postings{r.o.posts, r.n.posts} {
		rs, _ := p.byRole.In.Get(id)
		for role := range rs.All() {
			if uid, ok := role.Owner(); ok {
				owners[uid] = struct{}{}
			}
		}
	}
}

// ownerNodes adds the owner nodes of owners at either end.
func (r *filterRoute) ownerNodes(owners map[uint]struct{}) {
	for uid := range owners {
		r.add(r.o.posts.Nodes(OwnerRole(uid))...)
		r.add(r.n.posts.Nodes(OwnerRole(uid))...)
	}
}

// anchors adds the receivers of every rule merged at a position that moved:
// a merged rule sits at the first rule, of any receiver, with its key, so a
// key gained or lost earlier in the list reorders filters it never reached.
func (r *filterRoute) anchors() {
	keys := map[string]struct{}{}

	was, is := r.xo.positions(), r.xn.positions()

	for k, p := range is {
		if q, ok := was[k]; !ok || q != p {
			keys[k] = struct{}{}
		}
	}

	for k := range was {
		if _, ok := is[k]; !ok {
			keys[k] = struct{}{}
		}
	}

	if len(keys) == 0 {
		return
	}

	r.touched = true

	self := false

	for g, gt := range r.n.t.grants {
		og := r.o.t.grants[g]
		self = self || gt.kind == grantSelf && !gt.none || og.kind == grantSelf && !og.none
	}

	hit := func(ge *grantExpansion) bool {
		return slices.ContainsFunc(ge.keys, func(k string) bool { _, ok := keys[k]; return ok })
	}

	for g := range r.n.t.grants {
		geo, gen := r.xo.grant(g), r.xn.grant(g)
		if !hit(geo) && !hit(gen) {
			continue
		}

		r.receivers(g, true)

		// An owner's self rule merges there too when its sources are these:
		// the addresses of nodes of its own.
		for _, ge := range []*grantExpansion{geo, gen} {
			if self && hit(ge) {
				r.selfMerging(ge.srcStrs)
			}
		}
	}
}

// selfMerging adds the nodes of the owners holding every one of srcs, all
// addresses: a self rule's sources are its owner's nodes' addresses, so
// only such an owner can have one with their merge key.
func (r *filterRoute) selfMerging(srcs []string) {
	var owners map[uint]struct{}

	for _, src := range srcs {
		ip, err := netip.ParseAddr(src)
		if err != nil {
			return
		}

		held := map[uint]struct{}{}

		for _, s := range r.sides() {
			ids, _ := s.byAddr.Groups.Get(ip)
			for _, id := range ids {
				r.ownersOf(id, held)
			}
		}

		if owners == nil {
			owners = held
		} else {
			maps.DeleteFunc(owners, func(uid uint, _ struct{}) bool {
				_, ok := held[uid]

				return !ok
			})
		}

		if len(owners) == 0 {
			return
		}
	}

	r.ownerNodes(owners)
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

// cut collects one receiver's cap-form filter. pos and shapes are kept
// only when counting.
type cut struct {
	f      capFilter
	rc     receiver
	count  bool
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
	// Classes stay nil, every rule regular, until a via rule needs one.
	if class != "" && c.f.classes == nil {
		c.f.classes = make([]string, len(c.f.rules), cap(c.f.rules))
	}

	if c.f.classes != nil {
		c.f.classes = append(c.f.classes, class)
	}

	c.f.rules = append(c.f.rules, rule)
	c.f.keys = append(c.f.keys, key)
	c.f.srcs = append(c.f.srcs, srcs)
	c.f.anchors = append(c.f.anchors, anchor)

	if c.count {
		c.pos = append(c.pos, pos)
		c.shapes = append(c.shapes, shape)
	}
}

// placeOwn records a rule of the receiver's own at pos, emitted or not.
func (c *cut) placeOwn(key string, pos int64) {
	if c.own == nil {
		c.own = map[string]int64{}
	}

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
	c := &cut{f: capFilter{anchors: []int64{}}, rc: newReceiver(n), count: st != nil}

	for g, gt := range x.t.grants {
		if gt.none {
			continue
		}

		ge := x.grant(g)

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

		dsts := x.dstPorts(gt, ipr.ports, c.rc, false)
		if len(dsts) == 0 {
			continue
		}

		c.emit(tailcfg.FilterRule{SrcIPs: ge.capSrcs, DstPorts: dsts, IPProto: ipr.proto}, "", key, ge.srcStrs,
			x.positions()[key], rulePos(g, 0, i), shapeShared)
	}

	next := len(gt.ip)

	for _, cr := range x.capGrantRules(gt, ge, c.rc) {
		pos := rulePos(g, 0, next+cr.at)
		c.emit(cr.rule, "", "", nil, pos, pos, cr.shape)
	}
}

// capGrantRule is a rule of a grant's app capability, and where it sits
// among them: the capability rule, then each companion.
type capGrantRule struct {
	rule  tailcfg.FilterRule
	at    int
	shape ruleShape
}

// capGrantRules cuts grant gt's app capability rule and companions for rc.
func (x *Expansion) capGrantRules(gt *GrantTemplate, ge *grantExpansion, rc receiver) []capGrantRule {
	if !ge.capGrant {
		return nil
	}

	var (
		out    []capGrantRule
		grants []tailcfg.CapGrant
	)

	// TODO(kradalby): policy/app-values-repeated: one CapGrant per
	// destination entry, so a grant naming the receiver twice ("dst":
	// ["*", "*"]) gives its values twice (cosmetic). Tolerated, with what
	// settles it, in verdictClasses.judge (policy/v2/reference_test.go).
	for _, id := range gt.dsts {
		res, err := x.resolve(id)
		if err != nil || res == nil {
			continue
		}

		if dsts := rc.hostPrefixes(res); len(dsts) > 0 {
			grants = append(grants, tailcfg.CapGrant{Dsts: dsts, CapMap: gt.app})
		}
	}

	if len(grants) > 0 {
		srcs := ge.srcStrs
		if srcs == nil {
			srcs = []string{}
		}

		out = append(out, capGrantRule{rule: tailcfg.FilterRule{SrcIPs: srcs, CapGrant: grants}, shape: shapeCapGrant})
	}

	for i, comp := range companionCaps {
		if _, ok := gt.app[comp.original]; !ok {
			continue
		}

		// Companions run the other way: from the destinations to the
		// sources.
		if dsts := rc.hostPrefixes(ge.srcSets...); len(dsts) > 0 {
			out = append(out, capGrantRule{rule: tailcfg.FilterRule{
				SrcIPs:   ge.dstIPs,
				CapGrant: []tailcfg.CapGrant{{Dsts: dsts, CapMap: tailcfg.PeerCapMap{comp.companion: nil}}},
			}, at: 1 + i, shape: shapeCompanion})
		}
	}

	return out
}

// dstPorts returns the destinations of a rule of gt over ports that reach
// rc, in the compile's order: by destination, address, then port. byRole
// tells a receiver without routes inside an identity destination by its
// membership where no node outside the destination holds a member's
// address, which then decides it alike, so capability form need not
// resolve the destination.
func (x *Expansion) dstPorts(gt *GrantTemplate, ports []tailcfg.PortRange, rc receiver, byRole bool) []tailcfg.NetPortRange {
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
			if !rc.routed && byRole && !x.capForms().shared[id] {
				if rs, _ := x.posts.byRole.In.Get(rc.n.ID()); rs.Has(SelectorRole(id)) {
					for _, ip := range rc.ips {
						add(ip.String())
					}
				}

				continue
			}

			res := x.res(id)

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
			// TODO(kradalby): policy/unrouted-whole-destination: an entry
			// is written whole once it reaches the node, so the client also
			// accepts the rest of it inside a route the node announces
			// unapproved (fails open, narrow). Tolerated, with what settles
			// it, in verdictClasses.judge (policy/v2/reference_test.go).
			for _, e := range x.t.literals[id].entries {
				if rc.overlaps(e.r) {
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
//
// TODO(kradalby): policy/others-self: a router of another user's device
// takes none of that user's self rules for what it routes (fails
// closed); see policymodel.OthersSelf.
func (x *Expansion) cutSelf(c *cut, g int) {
	var uids []uint

	switch n := c.rc.n; {
	case n.IsExitNode():
		uids = x.ownerIDs()
	case nodeHasUserIdentity(n):
		uids = []uint{n.User().ID()}
	}

	at := 0

	for _, uid := range uids {
		for _, o := range x.selfRules(g, uid).rules {
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
			if first, ok := x.positions()[o.key]; ok && o.key != "" {
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
		if rc.overlaps(o.ranges[i]) {
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
func (x *Expansion) selfRules(g int, uid uint) *ownRules {
	x.mu.Lock()
	defer x.mu.Unlock()

	k := selfKey{grant: g, user: uid}
	if rules, ok := x.self[k]; ok {
		return rules
	}

	rules := x.buildSelfRules(x.t.grants[g], x.grant(g), uid)
	x.self[k] = rules

	return rules
}

// buildSelfRules writes uid's autogroup:self rules as the compile does:
// per source, the owner's untagged nodes that source holds the address
// of, each its own rule.
func (x *Expansion) buildSelfRules(gt *GrantTemplate, ge *grantExpansion, uid uint) *ownRules {
	var nodes []types.NodeView

	for _, id := range x.posts.Nodes(OwnerRole(uid)) {
		if n, ok := x.node(id); ok {
			nodes = append(nodes, n)
		}
	}

	own := &ownRules{named: make([]selfNaming, len(ge.srcSets))}

	if len(nodes) == 0 {
		return own
	}

	var (
		perSrc []ResolvedAddresses
		srcOf  []SelectorID
		all    netipx.IPSetBuilder
	)

	// By address, not membership: a source names the owner's nodes whose
	// addresses it holds, for prefixes and * as for selectors.
	for i, set := range ge.srcSets {
		var named netipx.IPSetBuilder

		kind := x.table.Selector(ge.srcIDs[i]).Kind
		own.named[i] = naming(nodes, set)

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
		srcOf = append(srcOf, ge.srcIDs[i])
	}

	if len(perSrc) == 0 {
		return own
	}

	var out []ownRule

	keyed := func(rule tailcfg.FilterRule, ip int, src SelectorID) {
		o := ownRule{rule: rule, key: mergeKey("", rule), ip: ip, src: src}
		for _, d := range rule.DstPorts {
			r, _ := util.ParseIPRange(d.IP)
			o.ranges = append(o.ranges, r)
		}

		out = append(out, o)
	}

	for ip, ipr := range gt.ip {
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

		for k, src := range perSrc {
			keyed(tailcfg.FilterRule{SrcIPs: src.Strings(), DstPorts: dsts, IPProto: ipr.proto}, ip, srcOf[k])
		}
	}

	own.rules = out

	if gt.app == nil {
		return own
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

	out = append(out, ownRule{rule: tailcfg.FilterRule{SrcIPs: union.Strings(), CapGrant: grants}, ip: -1})

	for _, comp := range companionCaps {
		if _, ok := gt.app[comp.original]; ok {
			out = append(out, ownRule{rule: tailcfg.FilterRule{
				SrcIPs:   dstIPs,
				CapGrant: []tailcfg.CapGrant{{Dsts: union.Prefixes(), CapMap: tailcfg.PeerCapMap{comp.companion: nil}}},
			}, ip: -1})
		}
	}

	own.rules = out

	return own
}

// naming is how many of nodes, an owner's, a source resolving to set names
// by address.
func naming(nodes []types.NodeView, set ResolvedAddresses) selfNaming {
	some, every := false, true

	for _, n := range nodes {
		in := slices.ContainsFunc(n.IPs(), set.Contains)
		some = some || in
		every = every && (in || len(n.IPs()) == 0)
	}

	switch {
	case some && every:
		return namedAll
	case some:
		return namedSome
	}

	return namedNone
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

	// TODO(kradalby): policy/via-reach: subnet routes only, exits for
	// autogroup:internet alone (fails closed).
	// TODO(kradalby): policy/via-own-address: each overlapping destination
	// is written whole, so a router whose route sits inside a wider
	// destination also accepts the grant's sources to its own address
	// (fails open). See policymodel.ViaReach and policymodel.ViaOwnAddress.
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
			if !rc.overlaps(d.r) {
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

// cutFor cuts n's filter as a receiver with facts f is sent it under mode;
// see [Expansion.cutIn]. log, when not nil, records every decision.
func (x *Expansion) cutFor(n types.NodeView, mode SourceMode, f ReceiverFacts, log *formLog) []tailcfg.FilterRule {
	why := receiverForm(mode, f)
	if log != nil {
		log.layout = why
	}

	return x.cutIn(n, formOf(why), why, log)
}

// cutIn cuts n's filter in form: address form as [Expansion.FilterForNode]
// writes it, sent for why, a reason that sends the receiver every source
// as addresses; else capability form.
func (x *Expansion) cutIn(n types.NodeView, form filterForm, why ipReason, log *formLog) []tailcfg.FilterRule {
	if form == formAddress {
		return expandFilter(x.capFilterFor(n, nil), x.holders, why)
	}

	return x.capFormFor(n, log)
}

// capFormFor cuts n's filter in capability form: every rule that reaches n,
// with only the destinations that do, in the order of the grants, each
// grant's rules merged where they share their sources and protocols. A
// rule whose sources are capabilities is written whoever holds them, so it
// stays while members come and go; a source a fallback applies to is
// written as addresses, as address form writes it. Via rules reach only
// routers, which are cut in address form.
func (x *Expansion) capFormFor(n types.NodeView, log *formLog) []tailcfg.FilterRule {
	ci := x.capForms()
	rc := newReceiver(n)

	out := []tailcfg.FilterRule{}

	var rules []formRule

	for g, gt := range x.t.grants {
		if gt.none || gt.kind == grantVia {
			continue
		}

		gc := &ci.grants[g]
		rules = rules[:0]

		for _, ipr := range gt.ip {
			dsts := x.dstPorts(gt, ipr.ports, rc, true)
			if len(dsts) == 0 {
				continue
			}

			if why := ruleForm(false, ipr.proto); why != reasonNone {
				// As address form writes it: not at all without sources.
				if ge := x.grant(g); len(ge.srcStrs) > 0 {
					rules = append(rules, formRule{
						rule:    tailcfg.FilterRule{SrcIPs: addressSources(why, ge.srcStrs), DstPorts: dsts, IPProto: ipr.proto},
						reasons: []ipReason{why},
					})
				}

				continue
			}

			if len(gc.srcs) == 0 {
				continue
			}

			for _, why := range gc.reasons {
				addressSources(why, nil)
			}

			rules = append(rules, formRule{rule: tailcfg.FilterRule{SrcIPs: gc.srcs, DstPorts: dsts, IPProto: ipr.proto}, reasons: gc.reasons})
		}

		var crs []capGrantRule
		if gt.app != nil {
			crs = x.capGrantRules(gt, x.grant(g), rc)
		}

		for _, cr := range crs {
			app, comp := ci.appForms(x, g)

			fs := app
			if cr.shape == shapeCompanion {
				fs = comp
			}

			for _, why := range fs.reasons {
				addressSources(why, nil)
			}

			cr.rule.SrcIPs = fs.srcs
			rules = append(rules, formRule{rule: cr.rule, reasons: fs.reasons})
		}

		if gt.kind == grantSelf && nodeHasUserIdentity(n) {
			rules = x.capFormSelf(rules, g, gt, rc)
		}

		for _, fr := range mergeGrant(rules) {
			out = append(out, fr.rule)
			log.rule(fr.reasons...)
		}
	}

	return out
}

// formRule is a rule cut in capability form and why its address sources
// are.
type formRule struct {
	rule    tailcfg.FilterRule
	reasons []ipReason
}

// capFormSelf appends grant g's autogroup:self rules of rc's own user, in
// the order address form writes them: per ip entry, per source, then the
// app capability's.
func (x *Expansion) capFormSelf(rules []formRule, g int, gt *GrantTemplate, rc receiver) []formRule {
	uid := rc.n.User().ID()
	named := x.selfNamed(g, uid)
	srcs := x.srcIDs(g)

	// An address form rule of the owner's, cut for rc.
	byAddress := func(match func(ownRule) bool, why ipReason) {
		for _, o := range x.selfRules(g, uid).rules {
			if !match(o) {
				continue
			}

			if rule, ok := cutOwn(o, rc); ok {
				rule.SrcIPs = addressSources(why, rule.SrcIPs)
				rules = append(rules, formRule{rule: rule, reasons: []ipReason{why}})
			}
		}
	}

	for ip, ipr := range gt.ip {
		if len(ipr.ports) == 0 {
			continue
		}

		for k, src := range srcs {
			// A source naming none of the owner's nodes gives no rule in
			// either form.
			if named[k] == namedNone {
				continue
			}

			why := x.selfForm(ipr.proto, src, uid, named[k] == namedAll)
			if why != reasonNone {
				byAddress(func(o ownRule) bool { return o.ip == ip && o.src == src }, why)

				continue
			}

			// The owner's nodes reach rc only through its own addresses:
			// none of theirs is another node's.
			dsts := make([]tailcfg.NetPortRange, 0, len(ipr.ports)*len(rc.ips))

			for _, port := range ipr.ports {
				for _, a := range rc.n.IPs() {
					dsts = append(dsts, tailcfg.NetPortRange{IP: a.String(), Ports: port})
				}
			}

			if len(dsts) > 0 {
				rules = append(rules, formRule{rule: tailcfg.FilterRule{
					SrcIPs: []string{capSourcePrefix + string(ownerCap(uid))}, DstPorts: dsts, IPProto: ipr.proto,
				}})
			}
		}
	}

	// The app capability rule and its companions run from and to every
	// node of the owner's a source names.
	if gt.app == nil {
		return rules
	}

	app := ruleForm(true, nil)
	for k, src := range srcs {
		if app == reasonNone && named[k] != namedNone {
			app = x.selfForm(nil, src, uid, named[k] == namedAll)
		}
	}

	if app != reasonNone {
		byAddress(func(o ownRule) bool { return o.ip < 0 }, app)

		return rules
	}

	for _, o := range x.selfRules(g, uid).rules {
		if rule, ok := cutOwn(o, rc); o.ip < 0 && ok {
			rule.SrcIPs = []string{capSourcePrefix + string(ownerCap(uid))}
			rules = append(rules, formRule{rule: rule})
		}
	}

	return rules
}

// mergeGrant merges one grant's rules that share their sources and
// protocols into the first of them, their destinations in order; app
// capability rules stay apart. Rules of different grants are never
// merged: each grant's rules stay its own.
func mergeGrant(rules []formRule) []formRule {
	if len(rules) < 2 {
		return rules
	}

	out := make([]formRule, 0, len(rules))
	keys := make([]string, 0, len(rules))

	for _, fr := range rules {
		key := ""
		if len(fr.rule.CapGrant) == 0 {
			key = mergeKey("", fr.rule)
		}

		i := slices.Index(keys, key)
		if key == "" || i < 0 {
			out = append(out, fr)
			keys = append(keys, key)

			continue
		}

		m := &out[i]
		m.rule.DstPorts = append(slices.Clip(m.rule.DstPorts), fr.rule.DstPorts...)

		for _, why := range fr.reasons {
			if !slices.Contains(m.reasons, why) {
				m.reasons = append(slices.Clip(m.reasons), why)
			}
		}
	}

	return out
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

		got := expandFilter(x.capFilterFor(n, &rep.Shapes), x.holders, reasonAddressMode)
		if !reflect.DeepEqual(want, got) {
			return rep, fmt.Errorf("%w: node %d:\ncompile  %v\nexpanded %v", errFilterAudit, n.ID(), want, got)
		}

		rep.Nodes++
		rep.Rules += len(got)
	}

	if want, _ := oracle.Filter(); !reflect.DeepEqual(want, x.Filter()) {
		return rep, fmt.Errorf("%w: global filter:\ncompile  %v\nexpanded %v", errFilterAudit, want, x.Filter())
	}

	rep.Shapes.SelfByAddress = x.byAddress

	return rep, nil
}
