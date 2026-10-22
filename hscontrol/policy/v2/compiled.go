package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
)

// grantCategory classifies a grant by what per-node work it needs.
type grantCategory int

const (
	// grantCategoryRegular requires no per-node work. The pre-compiled
	// rules are complete and only need [policyutil.ReduceFilterRules].
	grantCategoryRegular grantCategory = iota

	// grantCategorySelf has autogroup:self destinations that must be
	// expanded per-node to same-user untagged device IPs.
	grantCategorySelf

	// grantCategoryVia has Via tags that route rules to specific
	// nodes based on their tags and advertised routes.
	grantCategoryVia
)

// compiledGrant is a grant with its sources already resolved to IP
// addresses. The expensive work (alias → IP resolution) is done once
// here. Extracting rules for a specific node reads from pre-resolved
// data without re-resolving.
type compiledGrant struct {
	category grantCategory

	// srcIPStrings is the final SrcIPs for non-self rules, with
	// nonWildcardSrcs appended to match Tailscale SaaS behavior.
	srcIPStrings []string

	hasWildcard  bool
	hasDangerAll bool

	// rules are the pre-compiled filter rules for non-self, non-via
	// destinations. For regular grants this is the complete output.
	// For self grants with mixed destinations (self + other), this
	// is the non-self portion only.
	rules []tailcfg.FilterRule

	// self is non-nil when the grant has autogroup:self destinations.
	self *selfGrantData

	// via is non-nil when the grant has Via tags.
	via *viaGrantData
}

// selfGrantData holds data needed for per-node autogroup:self
// compilation. Sources are already resolved.
type selfGrantData struct {
	resolvedSrcs      []ResolvedAddresses
	internetProtocols []ProtocolPort
	app               tailcfg.PeerCapMap
}

// viaGrantData holds data needed for per-node via-grant compilation.
// Sources are already resolved into srcIPStrings; destinations are
// pre-resolved into prefixes plus a flag for autogroup:internet, which
// the consumers handle separately because its gate is per-node
// (IsExitNode()) rather than per-prefix overlap.
type viaGrantData struct {
	viaTags              []Tag
	resolvedDsts         []netip.Prefix
	hasAutoGroupInternet bool
	internetProtocols    []ProtocolPort
	srcIPStrings         []string
}

// resolveViaDestinations splits a via grant's destinations into the
// flat list of IP prefixes they resolve to plus a flag for
// autogroup:internet. Every alias kind goes through [Alias.Resolve] so
// adding a new alias type to the policy parser does not silently
// disappear from the via path. Non-IP alias kinds (tag, user, group,
// wildcard) resolve to /32 host IPs that never overlap with subnet
// route advertisements and therefore contribute nothing here.
func resolveViaDestinations(
	pol *Policy,
	users types.Users,
	nodes views.Slice[types.NodeView],
	dsts Aliases,
) ([]netip.Prefix, bool) {
	var (
		prefixes             []netip.Prefix
		hasAutoGroupInternet bool
	)

	for _, d := range dsts {
		if ag, ok := d.(*AutoGroup); ok && ag.Is(AutoGroupInternet) {
			hasAutoGroupInternet = true

			continue
		}

		ips, err := d.Resolve(pol, users, nodes)
		if err != nil || ips == nil {
			continue
		}

		prefixes = append(prefixes, ips.Prefixes()...)
	}

	return prefixes, hasAutoGroupInternet
}

// userNodeIndex maps user IDs to their untagged nodes. Built once per
// policy or node-set change and read from many goroutines under
// [PolicyManager.mu]; readers must hold the lock (or the snapshot
// returned to them).
type userNodeIndex map[uint][]types.NodeView

func buildUserNodeIndex(
	nodes views.Slice[types.NodeView],
) userNodeIndex {
	idx := make(userNodeIndex)

	for _, n := range nodes.All() {
		if !n.IsTagged() && n.User().Valid() {
			uid := n.User().ID()
			idx[uid] = append(idx[uid], n)
		}
	}

	return idx
}

// compileNodeAttrs returns the per-node CapMap derived from policy
// nodeAttrs plus the tailnet-wide [Policy.RandomizeClientPort] flag.
//
// Returns an error when a target alias fails to resolve so the caller
// surfaces a corrupt policy instead of silently granting a partial set
// of attrs.
func (pol *Policy) compileNodeAttrs(
	users types.Users,
	nodes views.Slice[types.NodeView],
) (map[types.NodeID]tailcfg.NodeCapMap, error) {
	empty := map[types.NodeID]tailcfg.NodeCapMap{}

	if pol == nil {
		return empty, nil
	}

	if len(pol.NodeAttrs) == 0 && !pol.RandomizeClientPort {
		return empty, nil
	}

	result := make(map[types.NodeID]tailcfg.NodeCapMap)
	stamp := func(id types.NodeID, attr nodecap.Cap) {
		capMap, ok := result[id]
		if !ok {
			capMap = tailcfg.NodeCapMap{}
			result[id] = capMap
		}

		// nil [tailcfg.RawMessage] matches the wire format from a
		// Tailscale-hosted control plane: capabilities without companion
		// data marshal as null rather than []. Storing nil keeps the
		// merge stable and lets the compat test diff cleanly against
		// captured netmaps.
		if _, exists := capMap[attr]; !exists {
			capMap[attr] = nil
		}
	}

	// Cache each node's IPs once per call. Without the cache, the
	// node-attr inner loop would call [types.NodeView.IPs] once per attr
	// per node — O(grants × nodes) allocations of a 2-element slice
	// for what is invariant per node within a single policy compile.
	type nodeIPs struct {
		id  types.NodeID
		ips []netip.Addr
	}

	nodeList := make([]nodeIPs, 0, nodes.Len())
	for _, n := range nodes.All() {
		nodeList = append(nodeList, nodeIPs{id: n.ID(), ips: n.IPs()})
	}

	if pol.RandomizeClientPort {
		for _, ni := range nodeList {
			stamp(ni.id, nodecap.RandomizeClientPort)
		}
	}

	for _, na := range pol.NodeAttrs {
		if len(na.Attrs) == 0 {
			continue
		}

		resolved, err := na.Targets.Resolve(pol, users, nodes)
		if err != nil {
			return nil, fmt.Errorf("nodeAttrs target %s: %w", na.Targets, err)
		}

		if resolved == nil {
			continue
		}

		for _, ni := range nodeList {
			if !slices.ContainsFunc(ni.ips, resolved.Contains) {
				continue
			}

			for _, attr := range na.Attrs {
				stamp(ni.id, attr)
			}
		}
	}

	return result, nil
}

// compileGrants resolves all policy grants into [compiledGrant] structs.
// Source resolution and non-self destination resolution happens once
// here. This is the single resolution path that replaces the
// duplicated work in [Policy.compileFilterRules] and the autogroup:self
// expansion.
func (pol *Policy) compileGrants(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []compiledGrant {
	compiled, _ := pol.compileGrantsFrom(nil, nil, users, nodes)

	return compiled
}

// compiledGrantResult is one grant's compile, kept for the next compile:
// cg is nil for a grant that compiled to nothing or failed.
type compiledGrantResult struct {
	cg *compiledGrant
}

// compileGrantsFrom compiles every grant, reusing prev, the results of a
// compile of the same policy and users, for each grant the change since
// cannot reach. prev and change are nil for a compile from scratch.
func (pol *Policy) compileGrantsFrom(
	prev []compiledGrantResult,
	change *nodeChange,
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]compiledGrant, []compiledGrantResult) {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return nil, nil
	}

	grants := slices.Clip(pol.Grants)
	for _, acl := range pol.ACLs {
		grants = append(grants, aclToGrants(acl)...)
	}

	if len(prev) != len(grants) {
		prev, change = nil, nil
	}

	results := make([]compiledGrantResult, len(grants))
	compiled := make([]compiledGrant, 0, len(grants))
	srcs := sourceCache{}

	for i, grant := range grants {
		if change != nil && !change.reaches(grant) {
			results[i] = prev[i]
		} else {
			cg, err := pol.compileOneGrant(grant, users, nodes, srcs)
			if err != nil {
				log.Trace().Err(err).Msg("compiling grant")
			}

			results[i] = compiledGrantResult{cg: cg}
		}

		if results[i].cg != nil {
			compiled = append(compiled, *results[i].cg)
		}
	}

	return compiled, results
}

// nodeChange summarises what changed in the nodes between two compiles,
// as grant compilation reads them: which tags and users gained or lost a
// node or one of its addresses or routes, whether any node joined, left
// or moved between owners, and whether approved routes changed.
type nodeChange struct {
	tags       map[Tag]struct{}
	users      map[uint]struct{}
	membership bool // a node joined, left or changed its tags or owner
	routes     bool // a node's approved routes changed
}

func diffNodes(prev map[types.NodeID]types.NodeView, nodes views.Slice[types.NodeView]) *nodeChange {
	c := &nodeChange{tags: map[Tag]struct{}{}, users: map[uint]struct{}{}}

	note := func(n types.NodeView) {
		for _, t := range n.Tags().All() {
			c.tags[Tag(t)] = struct{}{}
		}

		if !n.IsTagged() && n.User().Valid() {
			c.users[n.User().ID()] = struct{}{}
		}
	}

	seen := make(map[types.NodeID]struct{}, nodes.Len())

	for _, n := range nodes.All() {
		seen[n.ID()] = struct{}{}

		old, ok := prev[n.ID()]
		if ok && old == n {
			continue
		}

		note(n)

		if !ok {
			c.membership = true
			c.routes = c.routes || len(n.AllApprovedRoutes()) > 0

			continue
		}

		note(old)

		if old.IsTagged() != n.IsTagged() || !views.SliceEqual(old.Tags(), n.Tags()) ||
			old.TypedUserID() != n.TypedUserID() {
			c.membership = true
		}

		if !slices.Equal(old.AllApprovedRoutes(), n.AllApprovedRoutes()) {
			c.routes = true
		}
	}

	for id, old := range prev {
		if _, ok := seen[id]; !ok {
			note(old)

			c.membership = true
			c.routes = c.routes || len(old.AllApprovedRoutes()) > 0
		}
	}

	return c
}

// reaches reports whether the change can alter grant's compile: a tag or
// user it names gained or lost a node or address, its autogroups' members
// moved, or, for a wildcard, which carries every approved subnet, routes
// changed. Groups and users are checked against any user-owned change;
// addresses and hosts never change with nodes.
func (c *nodeChange) reaches(grant Grant) bool {
	aliases := slices.Concat(grant.Sources, grant.Destinations)

	for _, t := range grant.Via {
		if _, ok := c.tags[t]; ok {
			return true
		}
	}

	for _, a := range aliases {
		switch a := a.(type) {
		case *Tag:
			if _, ok := c.tags[*a]; ok {
				return true
			}
		case *Username, *Group:
			if len(c.users) > 0 {
				return true
			}
		case *AutoGroup:
			if c.membership || len(c.users) > 0 || len(c.tags) > 0 {
				return true
			}
		case Asterix:
			if c.routes {
				return true
			}
		case *Host, *Prefix:
		default:
			return true
		}
	}

	return false
}

// compileOneGrant resolves a single grant into a [compiledGrant].
// All source resolution happens here. Non-self, non-via destination
// resolution also happens here. Per-node data (self dests, via
// matching) is stored for deferred compilation.
//
//nolint:gocyclo,cyclop
func (pol *Policy) compileOneGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
	srcs sourceCache,
) (*compiledGrant, error) {
	// Via grants: resolve sources, store deferred data.
	if len(grant.Via) > 0 {
		return pol.compileOneViaGrant(grant, users, nodes)
	}

	// Split destinations into self vs other.
	var autogroupSelfDests, otherDests []Alias

	for _, dest := range grant.Destinations {
		if ag, ok := dest.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			autogroupSelfDests = append(autogroupSelfDests, dest)
		} else {
			otherDests = append(otherDests, dest)
		}
	}

	// Resolve sources per-alias, tracking non-wildcard sources
	// separately so we can preserve their IPs alongside the
	// wildcard CGNAT ranges (matching Tailscale SaaS behavior).
	sources := srcs.get(pol, grant.Sources, users, nodes)

	resolvedSrcs, err := sources.all, sources.err
	if err != nil {
		return nil, err
	}

	// Literally empty src=[] or dst=[] produces no rules.
	if len(grant.Sources) == 0 || len(grant.Destinations) == 0 {
		return nil, nil //nolint:nilnil
	}

	if len(resolvedSrcs) == 0 && grant.App == nil {
		return nil, nil //nolint:nilnil
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)
	srcIPStrings := sources.strings(hasWildcard, hasDangerAll, nodes)

	cg := &compiledGrant{
		srcIPStrings: srcIPStrings,
		hasWildcard:  hasWildcard,
		hasDangerAll: hasDangerAll,
	}

	// Compile non-self destination rules (done once, shared).
	if len(otherDests) > 0 {
		cg.rules = pol.compileOtherDests(
			users, nodes, grant, otherDests,
			resolvedSrcs, srcIPStrings,
		)
	}

	// Classify and store deferred self data. The struct literal already
	// initializes category to grantCategoryRegular (the zero value).
	if len(autogroupSelfDests) > 0 {
		cg.category = grantCategorySelf
		cg.self = &selfGrantData{
			resolvedSrcs:      resolvedSrcs,
			internetProtocols: grant.InternetProtocols,
			app:               grant.App,
		}
	}

	return cg, nil
}

// mergeResolvedSrcs merges every prefix from the resolved sources into a
// single [resolved] address set.
func mergeResolvedSrcs(resolvedSrcs []ResolvedAddresses) (resolved, error) {
	var b netipx.IPSetBuilder

	for _, ips := range resolvedSrcs {
		if r, ok := ips.(resolved); ok {
			b.AddSet(&r.ips)

			continue
		}

		for _, pref := range ips.Prefixes() {
			b.AddPrefix(pref)
		}
	}

	return newResolved(&b)
}

// sourceCache holds each source list's resolution for one compile: an ACL
// compiles to one grant per destination, all sharing its sources, and
// resolving and merging them is most of a wide ACL's compile.
type sourceCache map[sourcesKey]*grantSources

// sourcesKey names a source list by its backing array, which the grants
// of one ACL share.
type sourcesKey struct {
	first *Alias
	n     int
}

// grantSources is a source list resolved per alias, all and without
// wildcards, and its SrcIPs once built.
type grantSources struct {
	all, nonWild []ResolvedAddresses
	err          error

	built bool
	strs  []string
}

// get resolves sources, once per source list; c may be nil.
func (c sourceCache) get(
	pol *Policy,
	sources Aliases,
	users types.Users,
	nodes views.Slice[types.NodeView],
) *grantSources {
	key := sourcesKey{n: len(sources)}
	if len(sources) > 0 {
		key.first = &sources[0]
	}

	if s, ok := c[key]; ok {
		return s
	}

	s := &grantSources{}
	s.all, s.nonWild, s.err = resolveSources(pol, sources, users, nodes)

	if c != nil {
		c[key] = s
	}

	return s
}

// strings returns the SrcIPs of the sources. Both flags follow from the
// sources, so every grant sharing them asks the same. The slice is shared
// and clipped, so a caller appending to it copies.
func (s *grantSources) strings(hasWildcard, hasDangerAll bool, nodes views.Slice[types.NodeView]) []string {
	if !s.built {
		s.strs = slices.Clip(buildSrcIPStrings(s.all, s.nonWild, hasWildcard, hasDangerAll, nodes))
		s.built = true
	}

	return s.strs
}

// compileOneViaGrant resolves sources for a via grant and stores the
// deferred per-node data. The actual via-node matching and route
// intersection happens in [compileViaForNode].
func (pol *Policy) compileOneViaGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*compiledGrant, error) {
	if len(grant.InternetProtocols) == 0 {
		return nil, nil //nolint:nilnil
	}

	resolvedSrcs, _, err := resolveSources(
		pol, grant.Sources, users, nodes,
	)
	if err != nil {
		return nil, err
	}

	if len(resolvedSrcs) == 0 {
		return nil, nil //nolint:nilnil
	}

	// Build merged SrcIPs.
	srcResolved, err := mergeResolvedSrcs(resolvedSrcs)
	if err != nil {
		return nil, err
	}

	if srcResolved.Empty() {
		return nil, nil //nolint:nilnil
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)

	resolvedDsts, hasAutoGroupInternet := resolveViaDestinations(
		pol, users, nodes, grant.Destinations,
	)

	return &compiledGrant{
		category: grantCategoryVia,
		via: &viaGrantData{
			viaTags:              grant.Via,
			resolvedDsts:         resolvedDsts,
			hasAutoGroupInternet: hasAutoGroupInternet,
			internetProtocols:    grant.InternetProtocols,
			srcIPStrings: srcIPsWithRoutes(
				srcResolved, hasWildcard, hasDangerAll, nodes,
			),
		},
	}, nil
}

// resolveSources resolves grant sources per-alias, returning the
// resolved addresses and a separate slice of non-wildcard sources.
// This is the canonical source-resolution path. Its output lands in
// [compiledGrant.srcIPStrings] (among other places) and callers on the
// hot path should prefer reading that over calling [Alias.Resolve] again.
func resolveSources(
	pol *Policy,
	sources Aliases,
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]ResolvedAddresses, []ResolvedAddresses, error) {
	var all, nonWild []ResolvedAddresses

	for i, src := range sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).
				Msg("resolving source ips")
		}

		if ips != nil {
			all = append(all, ips)

			if _, isWildcard := sources[i].(Asterix); !isWildcard {
				nonWild = append(nonWild, ips)
			}
		}
	}

	return all, nonWild, nil
}

// buildSrcIPStrings builds the final SrcIPs string slice from
// resolved sources, preserving non-wildcard IPs alongside wildcard
// CGNAT ranges to match Tailscale SaaS behavior.
func buildSrcIPStrings(
	resolvedSrcs, nonWildcardSrcs []ResolvedAddresses,
	hasWildcard, hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	srcResolved, err := mergeResolvedSrcs(resolvedSrcs)
	if err != nil || srcResolved.Empty() {
		return nil
	}

	srcIPStrs := srcIPsWithRoutes(
		srcResolved, hasWildcard, hasDangerAll, nodes,
	)

	// When sources include a wildcard (*) alongside explicit
	// sources (tags, groups, etc.), Tailscale preserves the
	// individual IPs from non-wildcard sources alongside the
	// merged CGNAT ranges rather than absorbing them.
	if hasWildcard && len(nonWildcardSrcs) > 0 {
		seen := set.SetOf(srcIPStrs)

		for _, ips := range nonWildcardSrcs {
			for _, s := range ips.Strings() {
				if !seen.Contains(s) {
					seen.Add(s)
					srcIPStrs = append(srcIPStrs, s)
				}
			}
		}
	}

	return srcIPStrs
}

type resolvedDestination struct {
	Alias

	addresses ResolvedAddresses
	err       error
}

func (dst resolvedDestination) Resolve(
	_ *Policy,
	_ types.Users,
	_ views.Slice[types.NodeView],
) (ResolvedAddresses, error) {
	return dst.addresses, dst.err
}

// compileOtherDests compiles filter rules for non-self, non-via
// destinations. This produces both [tailcfg.FilterRule.DstPorts] rules
// (from [Grant.InternetProtocols]) and [tailcfg.CapGrant] rules (from
// [Grant.App]).
func (pol *Policy) compileOtherDests(
	users types.Users,
	nodes views.Slice[types.NodeView],
	grant Grant,
	otherDests Aliases,
	resolvedSrcs []ResolvedAddresses,
	srcIPStrings []string,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	// Reuse resolutions while keeping the port encoder's partial-error handling
	// and logging. Wildcards must retain their special port and companion rules.
	if len(grant.InternetProtocols) > 1 ||
		(len(grant.InternetProtocols) > 0 && grant.App != nil) {
		resolvedDests := make(Aliases, len(otherDests))
		for i, dst := range otherDests {
			resolvedDests[i] = dst
			if _, wildcard := dst.(Asterix); wildcard {
				continue
			}

			addresses, err := dst.Resolve(pol, users, nodes)
			resolvedDests[i] = resolvedDestination{
				Alias:     dst,
				addresses: addresses,
				err:       err,
			}
		}

		otherDests = resolvedDests
	}

	// DstPorts rules from InternetProtocols.
	for _, ipp := range grant.InternetProtocols {
		destPorts := pol.destinationsToNetPortRange(
			users, nodes, otherDests, ipp.Ports,
		)

		if len(destPorts) > 0 && len(srcIPStrings) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcIPStrings,
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	// CapGrant rules from App.
	if grant.App != nil {
		capSrcIPStrs := srcIPStrings

		// When sources resolved to empty but App is set,
		// Tailscale still produces the CapGrant rule with
		// empty SrcIPs.
		if capSrcIPStrs == nil {
			capSrcIPStrs = []string{}
		}

		var (
			capGrants    []tailcfg.CapGrant
			dstIPStrings []string
		)

		for _, dst := range otherDests {
			ips, err := dst.Resolve(pol, users, nodes)
			if err != nil {
				continue
			}

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   ips.Prefixes(),
				CapMap: grant.App,
			})

			dstIPStrings = append(dstIPStrings, ips.Strings()...)
		}

		if len(capGrants) > 0 {
			srcPrefixes := make([]netip.Prefix, 0, len(resolvedSrcs)*2)
			for _, ips := range resolvedSrcs {
				srcPrefixes = append(
					srcPrefixes, ips.Prefixes()...,
				)
			}

			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   capSrcIPStrs,
				CapGrant: capGrants,
			})

			dstsHaveWildcard := sourcesHaveWildcard(otherDests)
			if dstsHaveWildcard {
				dstIPStrings = append(
					dstIPStrings,
					approvedSubnetRoutes(nodes)...,
				)
			}

			rules = append(
				rules,
				companionCapGrantRules(
					dstIPStrings, srcPrefixes, grant.App,
				)...,
			)
		}
	}

	return rules
}

// hasPerNodeGrants reports whether any [compiledGrant] requires
// per-node filter compilation (via grants or autogroup:self).
func hasPerNodeGrants(grants []compiledGrant) bool {
	for i := range grants {
		if grants[i].category != grantCategoryRegular {
			return true
		}
	}

	return false
}

// globalFilterRules extracts global filter rules from [compiledGrant]s.
// Via grants produce no global rules (they are per-node only); regular
// grants contribute their full pre-compiled ruleset; self grants
// contribute their non-self portion.
func globalFilterRules(grants []compiledGrant) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range grants {
		if grants[i].category == grantCategoryVia {
			continue
		}

		rules = append(rules, grants[i].rules...)
	}

	return mergeFilterRules(rules)
}

// filterRulesForNode produces unreduced filter rules for a specific
// node by combining pre-compiled global rules with per-node self and
// via rules. Regular grants emit their pre-compiled rules as-is.
// Self grants add autogroup:self expansion. Via grants add
// tag-matched, route-intersected rules.
func filterRulesForNode(
	grants []compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range grants {
		// Pre-compiled rules apply to all grant categories
		// (empty for via-only grants).
		rules = append(rules, grants[i].rules...)
		rules = append(rules, grantRulesForNode(&grants[i], node, userIdx)...)
	}

	return mergeFilterRules(rules)
}

// sharedRules returns the pre-compiled rules of every grant: what
// [filterRulesForNode] gives every node before its own rules.
func sharedRules(grants []compiledGrant) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule
	for i := range grants {
		rules = append(rules, grants[i].rules...)
	}

	return mergeFilterRules(rules)
}

// nodeOnlyRules returns the rules [filterRulesForNode] adds for node alone
// (autogroup:self, via), unmerged.
func (pm *PolicyManager) nodeOnlyRules(node types.NodeView) []tailcfg.FilterRule {
	rules := make([]tailcfg.FilterRule, 0, len(pm.compiledGrants))
	for i := range pm.compiledGrants {
		rules = append(rules, pm.grantRulesFor(i, node)...)
	}

	return rules
}

// grantRulesForNode returns the rules a per-node grant category adds for
// node.
func grantRulesForNode(cg *compiledGrant, node types.NodeView, userIdx userNodeIndex) []tailcfg.FilterRule {
	switch cg.category {
	case grantCategorySelf:
		return compileAutogroupSelf(cg, node, userIdx)
	case grantCategoryVia:
		return compileViaForNode(cg, node)
	case grantCategoryRegular:
		return nil
	}

	return nil
}

// compileAutogroupSelf produces filter rules for autogroup:self
// destinations for a specific node. Only called for grants with
// self destinations and only produces rules for untagged nodes.
func compileAutogroupSelf(
	cg *compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) []tailcfg.FilterRule {
	if node.IsTagged() || cg.self == nil || !node.User().Valid() {
		return nil
	}

	return compileSelfForUser(cg, userIdx[node.User().ID()])
}

// exitNodeSelfRules returns the autogroup:self rules of every user
// other than the node's own for an exit node, whose exit routes contain
// every self destination. Only the packet filter needs them: they never
// make the exit node a peer, and expanding every user for peer matching
// would cost O(users) per exit node on each peer map build.
func exitNodeSelfRules(
	grants []compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) []tailcfg.FilterRule {
	if !node.IsExitNode() {
		return nil
	}

	var rules []tailcfg.FilterRule

	for i := range grants {
		cg := &grants[i]
		if cg.self == nil {
			continue
		}

		for _, uid := range slices.Sorted(maps.Keys(userIdx)) {
			// compileAutogroupSelf already covers an untagged node's own user.
			if !node.IsTagged() && node.User().Valid() && node.User().ID() == uid {
				continue
			}

			rules = append(rules, compileSelfForUser(cg, userIdx[uid])...)
		}
	}

	return rules
}

// compileSelfForUser produces the autogroup:self rules for one user's
// untagged devices.
func compileSelfForUser(
	cg *compiledGrant,
	sameUserNodes []types.NodeView,
) []tailcfg.FilterRule {
	if len(sameUserNodes) == 0 {
		return nil
	}

	var rules []tailcfg.FilterRule

	// Filter sources to only same-user untagged devices.
	srcResolved := filterSourcesToSameUser(
		cg.self.resolvedSrcs, sameUserNodes,
	)
	if srcResolved == nil || srcResolved.Empty() {
		return nil
	}

	// DstPorts rules from InternetProtocols.
	for _, ipp := range cg.self.internetProtocols {
		var destPorts []tailcfg.NetPortRange

		for _, n := range sameUserNodes {
			for _, port := range ipp.Ports {
				for _, ip := range n.IPs() {
					destPorts = append(
						destPorts,
						tailcfg.NetPortRange{
							IP:    ip.String(),
							Ports: port,
						},
					)
				}
			}
		}

		if len(destPorts) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcResolved.Strings(),
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	// CapGrant rules from App.
	if cg.self.app != nil {
		var (
			capGrants    []tailcfg.CapGrant
			dstIPStrings []string
		)

		for _, n := range sameUserNodes {
			var dsts []netip.Prefix
			for _, ip := range n.IPs() {
				dsts = append(
					dsts,
					netip.PrefixFrom(ip, ip.BitLen()),
				)
				dstIPStrings = append(
					dstIPStrings, ip.String(),
				)
			}

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   dsts,
				CapMap: cg.self.app,
			})
		}

		if len(capGrants) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcResolved.Strings(),
				CapGrant: capGrants,
			})

			rules = append(
				rules,
				companionCapGrantRules(
					dstIPStrings,
					srcResolved.Prefixes(),
					cg.self.app,
				)...,
			)
		}
	}

	return rules
}

// filterSourcesToSameUser intersects resolved source addresses with
// same-user untagged device IPs, returning only the addresses that
// belong to those devices.
func filterSourcesToSameUser(
	resolvedSrcs []ResolvedAddresses,
	sameUserNodes []types.NodeView,
) ResolvedAddresses {
	var srcIPs netipx.IPSetBuilder

	for _, ips := range resolvedSrcs {
		for _, n := range sameUserNodes {
			if slices.ContainsFunc(n.IPs(), ips.Contains) {
				n.AppendToIPSet(&srcIPs)
			}
		}
	}

	srcResolved, err := newResolved(&srcIPs)
	if err != nil {
		return nil
	}

	return srcResolved
}

// compileViaForNode produces via-grant filter rules for a specific
// node. Only produces rules when the node matches one of the via
// tags and advertises routes that match the grant destinations.
func compileViaForNode(
	cg *compiledGrant,
	node types.NodeView,
) []tailcfg.FilterRule {
	if cg.via == nil {
		return nil
	}

	// Check if node matches any via tag.
	matchesVia := false

	for _, viaTag := range cg.via.viaTags {
		if node.HasTag(string(viaTag)) {
			matchesVia = true

			break
		}
	}

	if !matchesVia {
		return nil
	}

	// [types.NodeView.SubnetRoutes] excludes exit routes, so the overlap
	// gate below sees only subnet advertisements. autogroup:internet on
	// a via-tagged exit advertiser is handled separately because its
	// eligibility is per-node ([types.NodeView.IsExitNode]) rather than
	// per-prefix overlap.
	nodeSubnetRoutes := node.SubnetRoutes()

	var viaDstPrefixes []netip.Prefix

	for _, dstPrefix := range cg.via.resolvedDsts {
		// Equality would reject any broader or narrower dst relative
		// to the advertised route. Containment in either direction
		// matches the operator's authorisation: a broader dst restricts
		// traffic to the subset the router serves; a narrower dst rides
		// on a router covering more than the operator asked for. The
		// rule emits the literal dst either way because that is what
		// the policy authorised.
		if slices.ContainsFunc(nodeSubnetRoutes, dstPrefix.Overlaps) {
			viaDstPrefixes = append(viaDstPrefixes, dstPrefix)
		}
	}

	// autogroup:internet on a via-tagged exit advertiser becomes a rule
	// whose DstPorts enumerate [util.TheInternet]. The matchers derived
	// from this rule let [types.NodeView.CanAccess] surface the exit node
	// to the grant source via [matcher.Match.DestsIsTheInternet].
	// [policyutil.ReduceFilterRules] strips the rule from the wire format
	// on non-exit advertisers, preserving SaaS PacketFilter encoding.
	if cg.via.hasAutoGroupInternet && node.IsExitNode() {
		viaDstPrefixes = append(
			viaDstPrefixes,
			util.TheInternet().Prefixes()...,
		)
	}

	if len(viaDstPrefixes) == 0 {
		return nil
	}

	// Build rules using pre-resolved srcIPStrings.
	var rules []tailcfg.FilterRule

	for _, ipp := range cg.via.internetProtocols {
		var destPorts []tailcfg.NetPortRange

		for _, prefix := range viaDstPrefixes {
			for _, port := range ipp.Ports {
				destPorts = append(
					destPorts,
					tailcfg.NetPortRange{
						IP:    prefix.String(),
						Ports: port,
					},
				)
			}
		}

		if len(destPorts) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   cg.via.srcIPStrings,
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	return rules
}
