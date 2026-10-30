package v2

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/puzpuzpuz/xsync/v4"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/multierr"
)

// ErrInvalidTagOwner is returned when a tag owner is not an [Alias] type.
var ErrInvalidTagOwner = errors.New("tag owner is not an Alias")

// PolicyManager is a policy compiled against one set of users and nodes.
// Nothing modifies it once [NewPolicyManager] returns, so reads take no
// lock; a change to the policy, users or nodes compiles a new one.
type PolicyManager struct {
	pol   *Policy
	users []types.User

	// src is the document compiled, and grantResults each grant's compile,
	// for [NewPolicyManagerFrom].
	src          []byte
	grantResults []compiledGrantResult
	aliases      aliasCache
	// matcherCache holds the matcher of each global rule, by content.
	matcherCache map[string]matcher.Match

	sideOnce sync.Once
	sides    *sideIndex

	// dsts parses the destinations of the rules reduced per node, once;
	// primeOnce gives it the compiled grants' shared rules.
	dsts      policyutil.DstCache
	primeOnce sync.Once

	// id identifies this compile. change is [PolicyManager.FilterChangedNodes]
	// from the compile with id changeFrom, the one this one was made from;
	// an id, so a compile does not keep the one before it alive. Set
	// before pm is shared.
	id         uint64
	changeFrom uint64
	change     []types.NodeID
	changeAll  bool
	nodes      views.Slice[types.NodeView]
	// nodesByID indexes nodes; see [PolicyManager.cacheable].
	nodesByID map[types.NodeID]types.NodeView

	filter []tailcfg.FilterRule
	// reducer reduces filter for each node, parsing it once.
	reducer  *policyutil.Reducer
	matchers []matcher.Match

	tagOwnerMap    map[Tag]*netipx.IPSet
	exitSet        *netipx.IPSet
	autoApproveMap map[netip.Prefix]*netipx.IPSet

	// compiledGrants are the grants with sources pre-resolved.
	// The single source of truth for filter compilation. Both
	// global and per-node filter rules are derived from these.
	compiledGrants []compiledGrant
	userNodeIdx    userNodeIndex

	// needsPerNodeFilter is true when any compiled grant requires
	// per-node work (autogroup:self or via grants).
	needsPerNodeFilter bool

	// nodeAttrsMap is the per-node CapMap compiled from policy.NodeAttrs.
	nodeAttrsMap map[types.NodeID]tailcfg.NodeCapMap

	// Per-node answers, filled on first read. xsync.Maps so concurrent
	// readers can fill them.
	sshPolicyMap *xsync.Map[sshKey, *tailcfg.SSHPolicy]
	// sshPreps holds the node-independent SSH compile, by server URL.
	sshPreps *xsync.Map[string, *sshPrep]

	viaOnce sync.Once
	via     *viaPrep

	// selfRules holds the compiled autogroup:self rules per grant and
	// user; see [PolicyManager.grantRulesFor].
	selfRules *xsync.Map[selfRulesKey, []tailcfg.FilterRule]
	// filterRulesMap holds reduced rules, for packet filters.
	filterRulesMap *xsync.Map[types.NodeID, []tailcfg.FilterRule]
	// matchersForNodeMap holds matchers from UNREDUCED rules. Only the
	// needsPerNodeFilter path fills it; otherwise every node gets
	// pm.matchers.
	matchersForNodeMap *xsync.Map[types.NodeID, []matcher.Match]
}

// validateUserReferences surfaces ambiguous user@ tokens at policy load so
// duplicate DB rows fail loudly instead of silently dropping rules.
// Missing-user tokens stay tolerant. Empty users → no-op for
// syntax-only checks.
func validateUserReferences(pol *Policy, users types.Users) error {
	if pol == nil || len(users) == 0 {
		return nil
	}

	var errs []error

	check := func(u *Username) {
		if u == nil {
			return
		}

		_, err := u.resolveUser(users)
		if err != nil && errors.Is(err, ErrMultipleUsersFound) {
			errs = append(errs, err)
		}
	}

	checkAlias := func(a Alias) {
		if u, ok := a.(*Username); ok {
			check(u)
		}
	}

	checkOwner := func(o Owner) {
		if u, ok := o.(*Username); ok {
			check(u)
		}
	}

	checkAutoApprover := func(aa AutoApprover) {
		if u, ok := aa.(*Username); ok {
			check(u)
		}
	}

	for _, usernames := range pol.Groups {
		for i := range usernames {
			check(&usernames[i])
		}
	}

	for _, owners := range pol.TagOwners {
		for _, o := range owners {
			checkOwner(o)
		}
	}

	for _, approvers := range pol.AutoApprovers.Routes {
		for _, aa := range approvers {
			checkAutoApprover(aa)
		}
	}

	for _, aa := range pol.AutoApprovers.ExitNode {
		checkAutoApprover(aa)
	}

	for _, acl := range pol.ACLs {
		for _, src := range acl.Sources {
			checkAlias(src)
		}

		for _, dst := range acl.Destinations {
			checkAlias(dst.Alias)
		}
	}

	for _, ssh := range pol.SSHs {
		for _, src := range ssh.Sources {
			checkAlias(src)
		}

		for _, dst := range ssh.Destinations {
			checkAlias(dst)
		}
	}

	return multierr.New(errs...)
}

// NewPolicyManager compiles the policy in b against users and nodes. It
// returns an error if the policy is invalid or does not compile.
func NewPolicyManager(b []byte, users []types.User, nodes views.Slice[types.NodeView]) (*PolicyManager, error) {
	return NewPolicyManagerFrom(nil, b, users, nodes)
}

// NewPolicyManagerFrom is [NewPolicyManager] reusing, from prev, a compile
// of the same document and users, each grant the node changes since cannot
// reach. prev may be nil.
func NewPolicyManagerFrom(prev *PolicyManager, b []byte, users []types.User, nodes views.Slice[types.NodeView]) (*PolicyManager, error) {
	var (
		pol *Policy
		err error
	)

	// The same document parses to the same policy, which is only read.
	if prev != nil && bytes.Equal(prev.src, b) {
		pol = prev.pol
	} else {
		pol, err = unmarshalPolicy(b)
		if err != nil {
			return nil, fmt.Errorf("parsing policy: %w", err)
		}
	}

	err = validateUserReferences(pol, users)
	if err != nil {
		return nil, fmt.Errorf("validating policy user references: %w", err)
	}

	// One tag index serves every resolution in this compile.
	indexed := pol.withNodesByTag(nodes)
	if indexed != nil {
		indexed.aliases = aliasCache{}
	}

	// Compile all grants once. Both global and per-node filter
	// rules are derived from these compiled grants.
	var (
		prevGrants []compiledGrantResult
		change     *nodeChange
	)

	if prev != nil && bytes.Equal(prev.src, b) && types.SamePolicyUsers(prev.users, users) {
		prevGrants, change = prev.grantResults, diffNodes(prev.nodesByID, nodes)
		if indexed != nil {
			indexed.aliases = prev.aliases.carry(change)
		}
	}

	grants, grantResults := indexed.compileGrantsFrom(prevGrants, change, users, nodes)

	// Order matters, tags might be used in autoapprovers, so we need to ensure
	// that the map for tag owners is resolved before resolving autoapprovers.
	// TODO(kradalby): Order might not matter after #2417
	tagMap, err := resolveTagOwners(indexed, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("resolving tag owners map: %w", err)
	}

	autoMap, exitSet, err := resolveAutoApprovers(indexed, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("resolving auto approvers map: %w", err)
	}

	var (
		prevAttrs map[types.NodeID]tailcfg.NodeCapMap
		prevNodes map[types.NodeID]types.NodeView
	)

	if change != nil {
		prevAttrs, prevNodes = prev.nodeAttrsMap, prev.nodesByID
	}

	nodeAttrs, err := indexed.compileNodeAttrsFrom(prevAttrs, prevNodes, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("compiling nodeAttrs: %w", err)
	}

	filter := tailcfg.FilterAllowAll
	if pol != nil && (pol.ACLs != nil || pol.Grants != nil) {
		filter = globalFilterRules(grants)
	}

	var prevMatchers map[string]matcher.Match
	if prev != nil {
		prevMatchers = prev.matcherCache
	}

	matchers, matcherCache := cachedMatches(filter, prevMatchers)

	pm := &PolicyManager{
		id:                 compileIDs.Add(1),
		src:                b,
		grantResults:       grantResults,
		aliases:            indexed.aliasesOrNil(),
		pol:                pol,
		users:              users,
		nodes:              nodes,
		nodesByID:          nodeIDViewMap(nodes),
		filter:             filter,
		reducer:            policyutil.NewReducer(filter),
		matchers:           matchers,
		matcherCache:       matcherCache,
		tagOwnerMap:        tagMap,
		exitSet:            exitSet,
		autoApproveMap:     autoMap,
		compiledGrants:     grants,
		userNodeIdx:        buildUserNodeIndex(nodes),
		needsPerNodeFilter: hasPerNodeGrants(grants),
		nodeAttrsMap:       nodeAttrs,
		sshPolicyMap:       xsync.NewMap[sshKey, *tailcfg.SSHPolicy](),
		sshPreps:           xsync.NewMap[string, *sshPrep](),
		selfRules:          xsync.NewMap[selfRulesKey, []tailcfg.FilterRule](),
		filterRulesMap:     xsync.NewMap[types.NodeID, []tailcfg.FilterRule](),
		matchersForNodeMap: xsync.NewMap[types.NodeID, []matcher.Match](),
	}

	// Prepare SSH for every server URL prev served, from prev when only
	// nodes changed, so the change to each node's SSH policy is known.
	if prev != nil {
		prev.sshPreps.Range(func(baseURL string, last *sshPrep) bool {
			if change == nil {
				last = nil
			}

			prep, err := indexed.prepareSSHFrom(last, change, baseURL, users, nodes)
			if err == nil {
				pm.sshPreps.Store(baseURL, prep)
			}

			return true
		})
	}

	pm.inheritFilters(prev)

	return pm, nil
}

// sshKey is a node's SSH policy as served from one server URL, which its
// check actions embed.
type sshKey struct {
	baseURL string
	node    types.NodeID
}

// SSHPolicy returns the [tailcfg.SSHPolicy] for node, compiling and
// caching on first access. Rules use SessionDuration = 0 (no
// auto-approval) and emit check URLs of the form
// /machine/ssh/action/{src}/to/{dst}?local_user={local_user} per the
// SaaS wire format.
func (pm *PolicyManager) SSHPolicy(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error) {
	key := sshKey{baseURL, node.ID()}
	if sshPol, ok := pm.sshPolicyMap.Load(key); ok {
		return sshPol, nil
	}

	prep, ok := pm.sshPreps.Load(baseURL)
	if !ok {
		var err error

		prep, err = pm.pol.prepareSSH(baseURL, pm.users, pm.nodes)
		if err != nil {
			return nil, fmt.Errorf("compiling SSH policy: %w", err)
		}

		pm.sshPreps.Store(baseURL, prep)
	}

	sshPol := prep.forNode(node)

	if pm.cacheable(node) {
		pm.sshPolicyMap.Store(key, sshPol)
	}

	return sshPol, nil
}

// SSHCheckParams resolves the SSH check period for src logging in to dst
// as localUser by looking up the current policy. This avoids trusting URL
// parameters that a client could tamper with. First-match wins across
// the policy's SSH rules; a rule only matches when it lets src log in as
// localUser, as the client does when it picks the rule.
//
// Returns (duration, true) when a matching rule is found and
// (0, false) when none is. A (0, true) return means the matched rule
// uses a zero check period (re-check every session).
func (pm *PolicyManager) SSHCheckParams(
	srcNodeID, dstNodeID types.NodeID,
	localUser string,
) (time.Duration, bool) {
	if pm.pol == nil || len(pm.pol.SSHs) == 0 {
		return 0, false
	}

	// Find the source and destination node views.
	var srcNode, dstNode types.NodeView

	for _, n := range pm.nodes.All() {
		nid := n.ID()
		if nid == srcNodeID {
			srcNode = n
		}

		if nid == dstNodeID {
			dstNode = n
		}

		if srcNode.Valid() && dstNode.Valid() {
			break
		}
	}

	if !srcNode.Valid() || !dstNode.Valid() {
		return 0, false
	}

	// Iterate SSH rules to find the first matching check rule.
	for _, rule := range pm.pol.SSHs {
		if rule.Action != SSHActionCheck {
			continue
		}

		// Resolve sources and check if src node matches.
		srcIPs, err := rule.Sources.Resolve(pm.pol, pm.users, pm.nodes)
		if err != nil || srcIPs == nil {
			continue
		}

		if !slices.ContainsFunc(srcNode.IPs(), srcIPs.Contains) {
			continue
		}

		if !pm.sshRuleAllowsUser(rule, srcNode, localUser) {
			continue
		}

		// Check if dst node matches any destination.
		hasOtherDests := false

		for _, dst := range rule.Destinations {
			if ag, isAG := dst.(*AutoGroup); isAG && ag.Is(AutoGroupSelf) {
				if sshNodesShareUser(srcNode, dstNode) {
					return checkPeriodFromRule(rule), true
				}

				continue
			}

			hasOtherDests = true

			dstIPs, err := dst.Resolve(pm.pol, pm.users, pm.nodes)
			if err != nil || dstIPs == nil {
				continue
			}

			if slices.ContainsFunc(dstNode.IPs(), dstIPs.Contains) {
				return checkPeriodFromRule(rule), true
			}
		}

		// Localpart self-access: a source outside dst still gets the rule
		// for its own user's nodes, or itself if tagged (compileSSHPolicy).
		if hasOtherDests && rule.Users.ContainsLocalpart() &&
			slices.ContainsFunc(dstNode.IPs(), srcIPs.Contains) {
			if dstNode.IsTagged() {
				if srcNodeID == dstNodeID {
					return checkPeriodFromRule(rule), true
				}
			} else if sshNodesShareUser(srcNode, dstNode) {
				return checkPeriodFromRule(rule), true
			}
		}
	}

	return 0, false
}

// sshNodesShareUser matches user-owned nodes with hydrated user associations.
// IsTagged alone does not guard User().ID(): the node table can hold a
// non-tagged node whose UserID is set but whose User association is nil.
func sshNodesShareUser(srcNode, dstNode types.NodeView) bool {
	return !srcNode.IsTagged() && !dstNode.IsTagged() &&
		srcNode.User().Valid() && dstNode.User().Valid() &&
		srcNode.User().ID() == dstNode.User().ID()
}

// sshRuleAllowsUser reports whether rule lets src log in as localUser,
// mirroring the SSHUsers maps compileSSHPolicy emits: root when listed,
// other users via autogroup:nonroot or a literal name, and anyone, root
// included, whose name is the source user's localpart.
func (pm *PolicyManager) sshRuleAllowsUser(rule SSH, srcNode types.NodeView, localUser string) bool {
	isRoot := localUser == "root"

	switch {
	case localUser == "":
		return false
	case isRoot && rule.Users.ContainsRoot(),
		!isRoot && rule.Users.ContainsNonRoot(),
		!isRoot && slices.Contains(rule.Users.NormalUsers(), SSHUser(localUser)):
		return true
	case srcNode.IsTagged() || !srcNode.User().Valid() || !rule.Users.ContainsLocalpart():
		return false
	}

	lp, ok := resolveLocalparts(rule.Users.LocalpartEntries(), pm.users)[srcNode.User().ID()]

	return ok && lp == localUser
}

// cachedMatches is [matcher.MatchesFromFilterRules] reusing, from prev,
// the matcher of each rule that did not change: building one parses every
// address the rule names, and a recompile after a join changes few rules.
func cachedMatches(rules []tailcfg.FilterRule, prev map[string]matcher.Match) ([]matcher.Match, map[string]matcher.Match) {
	matches := make([]matcher.Match, len(rules))
	next := make(map[string]matcher.Match, len(rules))

	for i, rule := range rules {
		key := matchKey(rule)

		m, ok := prev[key]
		if !ok {
			m, ok = next[key]
		}

		if !ok {
			m = matcher.MatchFromFilterRule(rule)
		}

		matches[i], next[key] = m, m
	}

	return matches, next
}

// matchKey identifies a rule by what its matcher reads.
func matchKey(rule tailcfg.FilterRule) string {
	var b strings.Builder

	for _, s := range rule.SrcIPs {
		b.WriteString(s)
		b.WriteByte(',')
	}

	b.WriteByte('>')

	for _, d := range rule.DstPorts {
		b.WriteString(d.IP)
		b.WriteByte(',')
	}

	for _, cg := range rule.CapGrant {
		for _, p := range cg.Dsts {
			b.WriteString(p.String())
			b.WriteByte(',')
		}
	}

	return b.String()
}

// inheritFilters carries prev's reduced filters over for the nodes whose
// filter [PolicyManager.FilterChangedNodes] says cannot have changed and
// whose own record did not: a recompile after a join would otherwise have
// every node reduce its filter again.
func (pm *PolicyManager) inheritFilters(prev *PolicyManager) {
	changed, all := pm.FilterChangedNodes(prev)

	// The hub asks the same of the commit's two compiles.
	if prev != nil {
		pm.changeFrom, pm.change, pm.changeAll = prev.id, changed, all
	}

	if all {
		return
	}

	keep := func(id types.NodeID) bool {
		if _, hit := slices.BinarySearch(changed, id); hit {
			return false
		}

		n, ok := pm.nodesByID[id]

		return ok && n == prev.nodesByID[id]
	}

	prev.filterRulesMap.Range(func(id types.NodeID, rules []tailcfg.FilterRule) bool {
		if keep(id) {
			pm.filterRulesMap.Store(id, rules)
		}

		return true
	})

	prev.sshPolicyMap.Range(func(k sshKey, ssh *tailcfg.SSHPolicy) bool {
		if keep(k.node) {
			pm.sshPolicyMap.Store(k, ssh)
		}

		return true
	})
}

// FilterChangedNodes returns the nodes whose packet filter or SSH policy
// can differ between prev and pm, any two compiles: the destinations of
// every shared rule that changed, every node serving routes, which a rule
// can reach by overlap, the nodes a changed SSH rule reaches, and, for
// autogroup:self and via grants, the nodes whose own rules changed. all
// is set when it cannot narrow it: per-node rules under a document or
// users change, or self grants whose sources are not users.
func (pm *PolicyManager) FilterChangedNodes(prev *PolicyManager) ([]types.NodeID, bool) {
	if pm != nil && prev != nil && pm.changeFrom == prev.id {
		return pm.change, pm.changeAll
	}

	if pm == nil || prev == nil || pm.pol == nil {
		return nil, true
	}

	perNode := pm.needsPerNodeFilter || prev.needsPerNodeFilter
	if perNode && (!bytes.Equal(pm.src, prev.src) || !types.SamePolicyUsers(pm.users, prev.users)) {
		return nil, true
	}

	filters, all := pm.filterChangedNodes(prev, perNode)
	if all {
		return nil, true
	}

	ssh, all := pm.sshChangedNodes(prev)
	if all {
		return nil, true
	}

	var own []types.NodeID
	if perNode {
		own, all = pm.ownRulesChangedNodes(prev)
		if all {
			return nil, true
		}
	}

	out := slices.Concat(filters, ssh, own)
	slices.Sort(out)

	return slices.Compact(out), false
}

// ownRulesChangedNodes returns the nodes whose own rules can differ
// between prev and pm, compiles of the same document and users: for a
// self grant that compiled differently, the nodes of the users whose
// nodes changed, and every exit node, which carries every user's self
// rules; for a via grant, every node with one of its via tags.
func (pm *PolicyManager) ownRulesChangedNodes(prev *PolicyManager) ([]types.NodeID, bool) {
	if len(pm.grantResults) != len(prev.grantResults) {
		return nil, true
	}

	grants := pm.pol.allGrants()
	if len(grants) != len(pm.grantResults) {
		return nil, true
	}

	var (
		self    bool
		viaTags []string
	)

	for i, g := range grants {
		was, is := prev.grantResults[i].cg, pm.grantResults[i].cg
		if was == is {
			continue
		}

		for _, cg := range []*compiledGrant{was, is} {
			switch {
			case cg == nil:
			case cg.category == grantCategorySelf:
				// A user's self rules then follow only their own nodes.
				if slices.ContainsFunc(g.Sources, notUserSource) {
					return nil, true
				}

				self = true
			case cg.category == grantCategoryVia && cg.via != nil:
				for _, t := range cg.via.viaTags {
					viaTags = append(viaTags, string(t))
				}
			}
		}
	}

	if !self && len(viaTags) == 0 {
		return nil, false
	}

	var users map[uint]struct{}
	if self {
		users = diffNodes(prev.nodesByID, pm.nodes).users
	}

	var out []types.NodeID

	for _, m := range []*PolicyManager{prev, pm} {
		for uid := range users {
			for _, n := range m.userNodeIdx[uid] {
				out = append(out, n.ID())
			}
		}

		if self {
			out = append(out, m.sideIndex().exits...)
		}

		if len(viaTags) > 0 {
			for _, n := range m.nodes.All() {
				if slices.ContainsFunc(viaTags, n.HasTag) {
					out = append(out, n.ID())
				}
			}
		}
	}

	return out, false
}

// notUserSource reports whether a is anything but users: a user, a group
// or autogroup:member.
func notUserSource(a Alias) bool {
	switch a := a.(type) {
	case *Username, *Group:
		return false
	case *AutoGroup:
		return !a.Is(AutoGroupMember)
	default:
		return true
	}
}

// sshChangedNodes returns the nodes whose SSH policy can differ between
// prev and pm: for every rule that prepared differently, the nodes in its
// destinations, the users' own nodes for autogroup:self, and its sources
// when it has localpart users, who get self-access rules.
func (pm *PolicyManager) sshChangedNodes(prev *PolicyManager) ([]types.NodeID, bool) {
	// SSH prepares on first use: until a session has asked prev, there is
	// nothing to compare, and one may still render from it.
	if (len(pm.pol.SSHs) > 0 || prev.pol != nil && len(prev.pol.SSHs) > 0) && prev.sshPreps.Size() == 0 {
		return nil, true
	}

	var (
		ranges []netipx.IPRange
		users  []uint
		all    bool
	)

	addSet := func(set *netipx.IPSet) {
		if set != nil {
			ranges = append(ranges, set.Ranges()...)
		}
	}

	prev.sshPreps.Range(func(baseURL string, last *sshPrep) bool {
		next, ok := pm.sshPreps.Load(baseURL)
		if !ok {
			all = true

			return false
		}

		byIndex := map[int][2]*sshRulePrep{}
		for _, r := range last.rules {
			pair := byIndex[r.index]
			pair[0] = r
			byIndex[r.index] = pair
		}

		for _, r := range next.rules {
			pair := byIndex[r.index]
			pair[1] = r
			byIndex[r.index] = pair
		}

		for _, pair := range byIndex {
			if pair[0] == pair[1] {
				continue
			}

			for _, r := range pair {
				if r == nil {
					continue
				}

				addSet(r.dests)

				if r.self {
					users = append(users, r.userIDs...)
				}

				if r.localpart {
					var b netipx.IPSetBuilder

					addResolved(&b, r.srcIPs)

					set, err := b.IPSet()
					if err != nil {
						all = true

						return false
					}

					addSet(set)
				}
			}
		}

		return true
	})

	if all {
		return nil, true
	}

	var out []types.NodeID

	for _, m := range []*PolicyManager{prev, pm} {
		idx := m.sideIndex()
		for _, r := range ranges {
			out = append(out, idx.inRange(r)...)
		}

		for _, uid := range users {
			for _, n := range m.userNodeIdx[uid] {
				out = append(out, n.ID())
			}
		}
	}

	return out, false
}

// sideIndex is the address index of pm's nodes, built once.
func (pm *PolicyManager) sideIndex() *sideIndex {
	pm.sideOnce.Do(func() { pm.sides = newSideIndex(pm.nodes) })

	return pm.sides
}

// filterChangedNodes is the shared packet filter part of
// [FilterChangedNodes]. Under per-node rules every grant's shared rules
// make the filter, via grants' too.
func (pm *PolicyManager) filterChangedNodes(prev *PolicyManager, perNode bool) ([]types.NodeID, bool) {
	was, is := prev.filter, pm.filter
	if perNode {
		was, is = sharedRules(prev.compiledGrants), sharedRules(pm.compiledGrants)
	}

	changed := changedRules(was, is)
	if len(changed) == 0 {
		return nil, false
	}

	var (
		out    []types.NodeID
		ranges []netipx.IPRange
	)

	for _, rule := range changed {
		for _, d := range rule.DstPorts {
			if d.IP == "*" {
				return nil, true
			}

			r, err := util.ParseIPRange(d.IP)
			if err != nil {
				return nil, true
			}

			ranges = append(ranges, r)
		}

		for _, cg := range rule.CapGrant {
			for _, p := range cg.Dsts {
				ranges = append(ranges, netipx.RangeOfPrefix(p))
			}
		}
	}

	for _, m := range []*PolicyManager{prev, pm} {
		idx := m.sideIndex()

		for _, r := range idx.routers {
			out = append(out, r.ID())
		}

		// Exit nodes serve routes too: every destination reaches them.
		out = append(out, idx.exits...)

		for _, r := range ranges {
			out = append(out, idx.inRange(r)...)
		}
	}

	slices.Sort(out)

	return slices.Compact(out), false
}

// changedRules returns the rules in only one of a and b.
func changedRules(a, b []tailcfg.FilterRule) []tailcfg.FilterRule {
	count := func(rules []tailcfg.FilterRule) map[string]int {
		m := make(map[string]int, len(rules))
		for _, r := range rules {
			m[ruleKey(r)]++
		}

		return m
	}

	inA, inB := count(a), count(b)

	var out []tailcfg.FilterRule

	for _, r := range a {
		if inB[ruleKey(r)] == 0 {
			out = append(out, r)
		}
	}

	for _, r := range b {
		if inA[ruleKey(r)] == 0 {
			out = append(out, r)
		}
	}

	return out
}

// ruleKey is a rule's content, in full.
func ruleKey(r tailcfg.FilterRule) string {
	var b strings.Builder

	for _, s := range r.SrcIPs {
		b.WriteString(s)
		b.WriteByte(',')
	}

	b.WriteByte('|')

	for _, p := range r.IPProto {
		b.WriteString(strconv.Itoa(p))
		b.WriteByte(',')
	}

	b.WriteByte('|')

	for _, d := range r.DstPorts {
		b.WriteString(d.IP)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(int(d.Ports.First)))
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(int(d.Ports.Last)))
		b.WriteByte(',')
	}

	for _, cg := range r.CapGrant {
		b.WriteByte('|')

		for _, p := range cg.Dsts {
			b.WriteString(p.String())
			b.WriteByte(',')
		}

		for _, c := range slices.Sorted(maps.Keys(cg.CapMap)) {
			b.WriteString(strconv.Quote(string(c)))
			b.WriteByte('=')

			for _, v := range cg.CapMap[c] {
				b.WriteString(strconv.Quote(string(v)))
				b.WriteByte(';')
			}
		}
	}

	return b.String()
}

// compileIDs numbers compiles; see [PolicyManager.id].
var compileIDs atomic.Uint64

// SameForPeers reports whether pm and prev render every node as a peer
// the same: neither has per-node rules (autogroup:self, via), so peer
// visibility and routes read only the global filter, and both hold the
// same filter and node capabilities. A recompile after a join usually
// does, and then no session needs to look at its peers again.
func (pm *PolicyManager) SameForPeers(prev *PolicyManager) bool {
	return pm != nil && prev != nil &&
		!pm.needsPerNodeFilter && !prev.needsPerNodeFilter &&
		reflect.DeepEqual(pm.filter, prev.filter) &&
		reflect.DeepEqual(pm.nodeAttrsMap, prev.nodeAttrsMap)
}

// Filter returns the current filter rules for the entire tailnet and the associated matchers.
func (pm *PolicyManager) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	if pm == nil {
		return nil, nil
	}

	return pm.filter, pm.matchers
}

// PeerClasses holds who sees whom. Nodes in a class share one sorted
// view of every node they see, including the members themselves when
// the class sees itself.
// Classes group nodes by which rules they match; per-node rules can split
// them further. Views cost O(nodes × classes), which can reach O(nodes²)
// when identities and rules grow with the tailnet.
type PeerClasses struct {
	classOf map[types.NodeID]int
	views   [][]types.NodeID
	// joined records the build joined classes on opposite sides of each
	// matcher instead of scanning every pair: both compute the same
	// relation, so it only says which path ran.
	joined bool

	// sides keeps what the build learnt of each node, for the next.
	sides *sideCache
}

// sideCache holds each node's matcher sides by matcher content: a
// recompile after a join changes few rules, and a node that did not
// change keeps its side of every rule that did not.
type sideCache struct {
	keys  []string // content of each matcher, by index
	nodes map[types.NodeID]cachedSides
}

type cachedSides struct {
	node     types.NodeView
	src, dst []uint64
}

// View returns the nodes id sees, sorted, possibly including id itself.
// It is shared and must not be modified.
func (c *PeerClasses) View(id types.NodeID) []types.NodeID {
	if c == nil {
		return nil
	}

	if i, ok := c.classOf[id]; ok {
		return c.views[i]
	}

	return nil
}

// Views returns every class's view. They are shared and must not be
// modified.
func (c *PeerClasses) Views() [][]types.NodeID {
	if c == nil {
		return nil
	}

	return c.views
}

// Peers returns the nodes id sees, sorted, without id.
func (c *PeerClasses) Peers(id types.NodeID) []types.NodeID {
	view := c.View(id)

	if i, found := slices.BinarySearch(view, id); found {
		return slices.Delete(slices.Clone(view), i, i+1)
	}

	return slices.Clone(view)
}

// Reuse replaces each view of c that equals one of prev by prev's, so
// readers that kept a view see it unchanged by identity.
func (c *PeerClasses) Reuse(prev *PeerClasses) {
	if c == nil || prev == nil {
		return
	}

	// Each class is compared once, with the previous view of one member.
	done := make([]bool, len(c.views))

	for id, ci := range c.classOf {
		pi, ok := prev.classOf[id]
		if !ok || done[ci] {
			continue
		}

		done[ci] = true

		if v, pv := c.views[ci], prev.views[pi]; !sameSlice(v, pv) && slices.Equal(v, pv) {
			c.views[ci] = pv
		}
	}
}

func sameSlice(a, b []types.NodeID) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// Same reports whether every node sees the same nodes in c and o.
func (c *PeerClasses) Same(o *PeerClasses) bool {
	if c == o {
		return true
	}

	if c == nil || o == nil || len(c.classOf) != len(o.classOf) {
		return false
	}

	return len(c.Changed(o)) == 0
}

// Changed returns the nodes whose peers differ between old and c, as
// compared once per pair of classes.
func (c *PeerClasses) Changed(old *PeerClasses) []types.NodeID {
	if old == nil {
		return slices.Collect(maps.Keys(c.classOf))
	}

	type pair struct{ a, b int }

	same := map[pair]bool{}

	var out []types.NodeID

	for id, b := range c.classOf {
		a, ok := old.classOf[id]
		if !ok {
			out = append(out, id)

			continue
		}

		p := pair{a, b}

		eq, seen := same[p]
		if !seen {
			eq = slices.Equal(old.views[a], c.views[b])
			same[p] = eq
		}

		if !eq {
			out = append(out, id)
		}
	}

	for id := range old.classOf {
		if _, ok := c.classOf[id]; !ok {
			out = append(out, id)
		}
	}

	return out
}

// BuildPeerClasses works out who sees whom among nodes; see [PeerClasses].
// It agrees with [PolicyManager.BuildPeerMap]. prev, the previous build,
// may be nil; what it learnt of unchanged nodes is reused.
func (pm *PolicyManager) BuildPeerClasses(nodes views.Slice[types.NodeView], prev *PeerClasses) *PeerClasses {
	c := &PeerClasses{classOf: make(map[types.NodeID]int, nodes.Len())}
	if pm == nil {
		return c
	}

	matchers := pm.matchers
	if pm.needsPerNodeFilter {
		// Every node reads the grants' shared rules and its own
		// (autogroup:self, via); a node's peers are those the shared rules
		// give its class, plus those its own rules link it to.
		matchers = matcher.MatchesFromFilterRules(sharedRules(pm.compiledGrants))
	}

	var cache *sideCache
	if prev != nil {
		cache = prev.sides
	}

	srcOf, dstOf, sides := cachedMatcherSides(matchers, nodes, cache)
	c.sides = sides

	// A class is a pair of sides; nodes come in ID order, so members do.
	byKey := map[string]int{}

	var (
		members    [][]types.NodeID
		srcs, dsts [][]uint64
	)

	for i, n := range nodes.All() {
		k := sidesKey(srcOf[i], dstOf[i])

		ci, ok := byKey[k]
		if !ok {
			ci = len(members)
			byKey[k] = ci

			members = append(members, nil)
			srcs, dsts = append(srcs, srcOf[i]), append(dsts, dstOf[i])
		}

		members[ci] = append(members[ci], n.ID())
		c.classOf[n.ID()] = ci
	}

	// Join only classes on opposite sides of a rule when that visits
	// fewer pairs. Diverse sparse policies otherwise scan C² pairs of
	// matcher bitsets even when every class sees just one other class.
	indexed := len(members) > 1
	if indexed {
		// A posting costs a word too. Do not transpose dense sides into
		// larger lists just to discover that the pair scan was cheaper.
		var words, postings int

		for _, classes := range [2][][]uint64{srcs, dsts} {
			for _, mask := range classes {
				words += len(mask)
				for _, word := range mask {
					postings += bits.OnesCount64(word)
				}
			}
		}

		indexed = postings <= words
	}

	var byRule [][2][]int
	if indexed {
		byRule = make([][2][]int, len(matchers))

		for side, classes := range [2][][]uint64{srcs, dsts} {
			for ci, mask := range classes {
				for w, word := range mask {
					for word != 0 {
						k := 64*w + bits.TrailingZeros64(word) //nolint:mnd
						byRule[k][side] = append(byRule[k][side], ci)
						word &= word - 1
					}
				}
			}
		}

		// Repeated dense rules can join the same pair many times. Keep
		// the short-circuit pair scan when joining would do more work.
		budget := len(members) * len(members) / 2
		for _, sides := range byRule {
			budget -= len(sides[0]) * len(sides[1])
			if budget < 0 {
				indexed = false
				break
			}
		}
	}

	var seenAt []int
	if indexed {
		seenAt = make([]int, len(members))
	}

	for a := range members {
		var seen [][]types.NodeID

		if indexed {
			for side, mask := range [2][]uint64{srcs[a], dsts[a]} {
				for w, word := range mask {
					for word != 0 {
						k := 64*w + bits.TrailingZeros64(word) //nolint:mnd
						for _, b := range byRule[k][1-side] {
							if seenAt[b] != a+1 {
								seenAt[b] = a + 1
								seen = append(seen, members[b])
							}
						}

						word &= word - 1
					}
				}
			}
		} else {
			for b := range members {
				if canAccessSides(srcs[a], dsts[b]) || canAccessSides(srcs[b], dsts[a]) {
					seen = append(seen, members[b])
				}
			}
		}

		view := slices.Concat(seen...)
		slices.Sort(view)
		c.views = append(c.views, view)
	}

	c.joined = indexed

	if pm.needsPerNodeFilter {
		pm.addNodeOnlyPeers(c, nodes)
	}

	return c
}

// addNodeOnlyPeers adds to c the peers each node's own rules link it to:
// a node is linked to every node on the other side of one of its own
// rules. Nodes are found by address range, not by trying every node.
func (pm *PolicyManager) addNodeOnlyPeers(c *PeerClasses, nodes views.Slice[types.NodeView]) {
	idx := newSideIndex(nodes)

	// A grant gives each node in to the nodes in set as peers. Rules a
	// user's untagged nodes share make one grant for all of them, so a
	// self clique costs a grant, not a link per pair.
	type grant struct{ to, set []types.NodeID }

	var grants []grant

	give := func(to, set []types.NodeID) {
		if len(to) > 0 && len(set) > 0 {
			grants = append(grants, grant{to: to, set: set})
		}
	}

	// connect adds what rule m, held by owners, connects: an owner on one
	// side sees the other side, which sees the owner.
	connect := func(owners []types.NodeID, m *matcher.Match) {
		srcs, dsts := idx.srcs(m), idx.dsts(m)

		if os := intersectSorted(owners, srcs); len(os) > 0 {
			give(os, dsts)
			give(dsts, os)
		}

		if od := intersectSorted(owners, dsts); len(od) > 0 {
			give(od, srcs)
			give(srcs, od)
		}
	}

	// Without via grants a node's own rules are its user's self rules,
	// the same for every untagged node of the user: compile them once.
	hasVia := slices.ContainsFunc(pm.compiledGrants, func(g compiledGrant) bool { return g.category == grantCategoryVia })

	var (
		users []uint
		owned = map[uint][]types.NodeID{}
		first = map[uint]types.NodeView{}
	)

	for _, n := range nodes.All() {
		if uid := n.User(); !hasVia && !n.IsTagged() && uid.Valid() {
			if _, seen := owned[uid.ID()]; !seen {
				users = append(users, uid.ID())
				first[uid.ID()] = n
			}

			owned[uid.ID()] = append(owned[uid.ID()], n.ID())

			continue
		}

		for _, m := range matcher.MatchesFromFilterRules(pm.nodeOnlyRules(n)) {
			connect([]types.NodeID{n.ID()}, &m)
		}
	}

	for _, uid := range users {
		slices.Sort(owned[uid])

		for _, m := range matcher.MatchesFromFilterRules(pm.nodeOnlyRules(first[uid])) {
			connect(owned[uid], &m)
		}
	}

	gets := map[types.NodeID][]int{}

	for gi, g := range grants {
		for _, id := range g.to {
			gets[id] = append(gets[id], gi)
		}
	}

	// Nodes of one class receiving the same grants share one view.
	shared := map[string]int{}

	var key strings.Builder

	for _, n := range nodes.All() {
		gs, ok := gets[n.ID()]
		if !ok {
			continue
		}

		ci := c.classOf[n.ID()]

		key.Reset()
		key.WriteString(strconv.Itoa(ci))

		for _, gi := range gs {
			key.WriteByte(',')
			key.WriteString(strconv.Itoa(gi))
		}

		if vi, ok := shared[key.String()]; ok {
			c.classOf[n.ID()] = vi

			continue
		}

		base := c.views[ci]

		var extra []types.NodeID

		for _, gi := range gs {
			for _, p := range grants[gi].set {
				if _, found := slices.BinarySearch(base, p); !found {
					extra = append(extra, p)
				}
			}
		}

		if len(extra) == 0 {
			shared[key.String()] = ci

			continue
		}

		view := slices.Concat(base, extra)
		slices.Sort(view)

		shared[key.String()] = len(c.views)
		c.classOf[n.ID()] = len(c.views)
		c.views = append(c.views, slices.Compact(view))
	}
}

// intersectSorted returns the IDs in both sorted a and b.
func intersectSorted(a, b []types.NodeID) []types.NodeID {
	var out []types.NodeID

	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			out = append(out, a[i])
			i, j = i+1, j+1
		}
	}

	return out
}

// sideIndex finds the nodes on one side of a matcher, as
// [types.NodeView.CanAccessWithRoutes] tests them: by address, by an
// overlapping subnet route, and, as a destination, exit nodes for an
// internet destination.
type sideIndex struct {
	byIP    []ipNode // sorted by address
	routers []types.NodeView
	exits   []types.NodeID
}

type ipNode struct {
	ip netip.Addr
	id types.NodeID
}

func newSideIndex(nodes views.Slice[types.NodeView]) *sideIndex {
	idx := &sideIndex{}

	for _, n := range nodes.All() {
		if !n.Valid() {
			continue
		}

		for _, ip := range n.IPs() {
			idx.byIP = append(idx.byIP, ipNode{ip: ip, id: n.ID()})
		}

		if len(n.SubnetRoutes()) > 0 {
			idx.routers = append(idx.routers, n)
		}

		if n.IsExitNode() {
			idx.exits = append(idx.exits, n.ID())
		}
	}

	slices.SortFunc(idx.byIP, func(a, b ipNode) int { return a.ip.Compare(b.ip) })

	return idx
}

func (idx *sideIndex) inSet(set *netipx.IPSet) []types.NodeID {
	if set == nil {
		return nil
	}

	var out []types.NodeID
	for _, r := range set.Ranges() {
		out = append(out, idx.inRange(r)...)
	}

	return out
}

// inRange returns the nodes with an address in r.
func (idx *sideIndex) inRange(r netipx.IPRange) []types.NodeID {
	var out []types.NodeID

	i, _ := slices.BinarySearchFunc(idx.byIP, r.From(), func(e ipNode, ip netip.Addr) int { return e.ip.Compare(ip) })
	for ; i < len(idx.byIP) && idx.byIP[i].ip.Compare(r.To()) <= 0; i++ {
		out = append(out, idx.byIP[i].id)
	}

	return out
}

func (idx *sideIndex) srcs(m *matcher.Match) []types.NodeID {
	out := idx.inSet(m.Srcs())

	for _, r := range idx.routers {
		if m.SrcsOverlapsPrefixes(r.SubnetRoutes()...) {
			out = append(out, r.ID())
		}
	}

	slices.Sort(out)

	return slices.Compact(out)
}

func (idx *sideIndex) dsts(m *matcher.Match) []types.NodeID {
	out := idx.inSet(m.Dests())

	for _, r := range idx.routers {
		if m.DestsOverlapsPrefixes(r.SubnetRoutes()...) {
			out = append(out, r.ID())
		}
	}

	if m.DestsIsTheInternet() {
		out = append(out, idx.exits...)
	}

	slices.Sort(out)

	return slices.Compact(out)
}

// cachedMatcherSides is [matcherSides] that reuses, for a node unchanged
// since prev, its sides of the matchers prev also had.
func cachedMatcherSides(
	matchers []matcher.Match,
	nodes views.Slice[types.NodeView],
	prev *sideCache,
) ([][]uint64, [][]uint64, *sideCache) {
	next := &sideCache{
		keys:  make([]string, len(matchers)),
		nodes: make(map[types.NodeID]cachedSides, nodes.Len()),
	}

	oldIdx := map[string]int{}

	for k := range matchers {
		next.keys[k] = matcherKey(&matchers[k])
	}

	if prev != nil {
		for k, key := range prev.keys {
			if _, dup := oldIdx[key]; !dup {
				oldIdx[key] = k
			}
		}
	}

	// Which new matchers prev knew, and where.
	from := make([]int, len(matchers))
	fresh := make([]int, 0, len(matchers))

	for k, key := range next.keys {
		if old, ok := oldIdx[key]; ok {
			from[k] = old
		} else {
			from[k] = -1
			fresh = append(fresh, k)
		}
	}

	all := make([]int, len(matchers))
	for k := range all {
		all[k] = k
	}

	words := (len(matchers) + 63) / 64 //nolint:mnd
	srcOf := make([][]uint64, nodes.Len())
	dstOf := make([][]uint64, nodes.Len())

	for i, n := range nodes.All() {
		if !n.Valid() {
			continue
		}

		evaluate := all

		if old, ok := prev.lookup(n); ok {
			evaluate = fresh

			for k, o := range from {
				if o < 0 {
					continue
				}

				if bitSet(old.src, o) {
					srcOf[i] = setBit(srcOf[i], words, k)
				}

				if bitSet(old.dst, o) {
					dstOf[i] = setBit(dstOf[i], words, k)
				}
			}
		}

		ips, subnet, isExit := n.IPs(), n.SubnetRoutes(), n.IsExitNode()
		routed := len(subnet) > 0

		for _, k := range evaluate {
			m := &matchers[k]

			if m.SrcsContainsIPs(ips...) || (routed && m.SrcsOverlapsPrefixes(subnet...)) {
				srcOf[i] = setBit(srcOf[i], words, k)
			}

			if m.DestsContainsIP(ips...) || (routed && m.DestsOverlapsPrefixes(subnet...)) ||
				(isExit && m.DestsIsTheInternet()) {
				dstOf[i] = setBit(dstOf[i], words, k)
			}
		}

		next.nodes[n.ID()] = cachedSides{node: n, src: srcOf[i], dst: dstOf[i]}
	}

	return srcOf, dstOf, next
}

// lookup returns what c knows of n, when n is the same stored node.
func (c *sideCache) lookup(n types.NodeView) (cachedSides, bool) {
	if c == nil {
		return cachedSides{}, false
	}

	old, ok := c.nodes[n.ID()]

	return old, ok && old.node == n
}

// matcherKey identifies a matcher by what it matches.
func matcherKey(m *matcher.Match) string {
	var b strings.Builder

	for _, p := range m.Srcs().Prefixes() {
		b.WriteString(p.String())
		b.WriteByte(',')
	}

	b.WriteByte('>')

	for _, p := range m.Dests().Prefixes() {
		b.WriteString(p.String())
		b.WriteByte(',')
	}

	return b.String()
}

func bitSet(side []uint64, k int) bool {
	return side != nil && side[k/64]&(1<<(k%64)) != 0 //nolint:mnd
}

func setBit(side []uint64, words, k int) []uint64 {
	if side == nil {
		side = make([]uint64, words)
	}

	side[k/64] |= 1 << (k % 64) //nolint:mnd

	return side
}

// matcherSides evaluates, per node, which of matchers it is a source and
// a destination of, as bitsets: bit k of a set stands for matchers[k].
// nil is the side of no matcher.
func matcherSides(matchers []matcher.Match, nodes views.Slice[types.NodeView]) ([][]uint64, [][]uint64) {
	words := (len(matchers) + 63) / 64 //nolint:mnd
	srcOf := make([][]uint64, nodes.Len())
	dstOf := make([][]uint64, nodes.Len())

	for i, n := range nodes.All() {
		if !n.Valid() {
			continue
		}

		ips, subnet, isExit := n.IPs(), n.SubnetRoutes(), n.IsExitNode()
		routed := len(subnet) > 0

		for k := range matchers {
			m := &matchers[k]

			if m.SrcsContainsIPs(ips...) || (routed && m.SrcsOverlapsPrefixes(subnet...)) {
				if srcOf[i] == nil {
					srcOf[i] = make([]uint64, words)
				}

				srcOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
			}

			if m.DestsContainsIP(ips...) || (routed && m.DestsOverlapsPrefixes(subnet...)) ||
				(isExit && m.DestsIsTheInternet()) {
				if dstOf[i] == nil {
					dstOf[i] = make([]uint64, words)
				}

				dstOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
			}
		}
	}

	return srcOf, dstOf
}

// sidesKey renders a node's matcher sides as a map key. Each side is
// marked nil or length-prefixed, so no two pairs of sides share a key:
// joining raw words with a separator byte would let one pair's words
// spell another's separator.
func sidesKey(src, dst []uint64) string {
	b := make([]byte, 0, 2*binary.MaxVarintLen64+8*(len(src)+len(dst)))

	for _, side := range [][]uint64{src, dst} {
		if side == nil {
			b = append(b, 0)

			continue
		}

		b = append(b, 1)
		b = binary.AppendUvarint(b, uint64(len(side)))

		for _, w := range side {
			b = binary.LittleEndian.AppendUint64(b, w)
		}
	}

	return string(b)
}

// canAccessSides reports whether a source side reaches a destination
// side: they share a matcher.
func canAccessSides(src, dst []uint64) bool {
	if src == nil || dst == nil {
		return false
	}

	for w := range src {
		if src[w]&dst[w] != 0 {
			return true
		}
	}

	return false
}

// BuildPeerMap constructs peer relationship maps for the given nodes.
// For global filters, it uses the global filter matchers for all nodes.
// For autogroup:self policies (empty global filter), it builds per-node
// peer maps using each node's specific filter rules.
//
// Compared to [policy.ReduceNodes], which builds the list per node, we end
// up with doing the full work for every node O(n^2), while this will reduce
// the list as we see relationships while building the map, making it
// O(n^2/2) in the end, but with less work per node.
//
//nolint:gocyclo // global and autogroup:self paths, each with a per-node matcher index
func (pm *PolicyManager) BuildPeerMap(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	// If we have a global filter, use it for all nodes (normal case).
	// Via grants require the per-node path because the global filter
	// skips via grants (compileFilterRules: if len(grant.Via) > 0 { continue }).
	if !pm.needsPerNodeFilter {
		ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

		// A matcher lets a reach b when a satisfies its source side and b
		// its destination side, exactly as [types.Node.CanAccess] tests
		// them, and each side depends on one node only. So evaluate both
		// sides once per node, as bitsets over pm.matchers, instead of
		// once per pair: a can reach b iff a's source set and b's
		// destination set intersect. That turns the O(n^2 * matchers)
		// scan into O(n * matchers) set lookups plus O(n^2) word ANDs.
		// Bit k of a set stands for pm.matchers[k]: it lives in word k/64
		// at position k%64, so 64 matchers fit in one uint64.
		ids := make([]types.NodeID, nodes.Len())
		for i, n := range nodes.All() {
			ids[i] = n.ID()
		}

		srcOf, dstOf := matcherSides(pm.matchers, nodes)
		canAccess := canAccessSides

		// Build the map of all peers according to the matchers.
		for i := range ids {
			for j := i + 1; j < len(ids); j++ {
				if ids[i] == ids[j] {
					continue
				}

				if canAccess(srcOf[i], dstOf[j]) || canAccess(srcOf[j], dstOf[i]) {
					ret[ids[i]] = append(ret[ids[i]], ids[j])
					ret[ids[j]] = append(ret[ids[j]], ids[i])
				}
			}
		}

		return ret
	}

	// Precompute each node's subnet routes and exit-node status once; the
	// O(n^2) pair scans below would otherwise recompute them for every pair.
	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	// For autogroup:self or via grants, build per-node peer relationships
	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	// Pre-compute per-node matchers using unreduced compiled rules
	// We need unreduced rules to determine peer relationships correctly.
	// Reduced rules only show destinations where the node is the target,
	// but peer relationships require the full bidirectional access rules.
	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	for _, node := range nodes.All() {
		unreduced := pm.unreducedRules(node)
		nodeMatchers[node.ID()] = matcher.MatchesFromFilterRules(unreduced)
	}

	// Check each node pair for peer relationships.
	// Start j at i+1 to avoid checking the same pair twice and creating duplicates.
	// We use symmetric visibility: if EITHER node can access the other, BOTH see
	// each other. This matches the global filter path behavior and ensures that
	// one-way access rules (e.g., admin -> tagged server) still allow both nodes
	// to see each other as peers, which is required for network connectivity.
	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			// Check all access directions for symmetric peer visibility.
			// For via grants, filter rules exist on the via-designated node
			// (e.g., router-a) with sources being the client (group-a).
			// We need to check BOTH:
			//   1. nodeI.CanAccess(matchersI, nodeJ) — can nodeI reach nodeJ?
			//   2. nodeJ.CanAccess(matchersI, nodeI) — can nodeJ reach nodeI
			//      using nodeI's matchers? (reverse direction: the matchers
			//      on the via node accept traffic FROM the source)
			// Same for matchersJ in both directions.
			canIAccessJ := hasFilterI && nodeI.CanAccessWithRoutes(matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)
			canJAccessI := hasFilterJ && nodeJ.CanAccessWithRoutes(matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canJReachI := hasFilterI && nodeJ.CanAccessWithRoutes(matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canIReachJ := hasFilterJ && nodeI.CanAccessWithRoutes(matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)

			if canIAccessJ || canJAccessI || canJReachI || canIReachJ {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())
			}
		}
	}

	return ret
}

// unreducedRules returns the unreduced compiled filter rules
// for a node, combining pre-compiled global rules with per-node self
// and via rules from the stored compiled grants.
func (pm *PolicyManager) unreducedRules(node types.NodeView) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range pm.compiledGrants {
		rules = append(rules, pm.compiledGrants[i].rules...)
		rules = append(rules, pm.grantRulesFor(i, node)...)
	}

	return mergeFilterRules(rules)
}

// grantRulesFor is [grantRulesForNode] for pm's grant i. A self grant's
// rules depend only on the node's user, so they are compiled once per
// user, not once per node.
func (pm *PolicyManager) grantRulesFor(i int, node types.NodeView) []tailcfg.FilterRule {
	cg := &pm.compiledGrants[i]
	if cg.category != grantCategorySelf {
		return grantRulesForNode(cg, node, pm.userNodeIdx)
	}

	if node.IsTagged() || cg.self == nil || !node.User().Valid() {
		return nil
	}

	key := selfRulesKey{grant: i, user: node.User().ID()}
	if rules, ok := pm.selfRules.Load(key); ok {
		return rules
	}

	rules := compileSelfForUser(cg, pm.userNodeIdx[key.user])
	pm.dsts.Prime(rules)
	pm.selfRules.Store(key, rules)

	return rules
}

type selfRulesKey struct {
	grant int
	user  uint
}

// FilterForNode returns the filter rules for a specific node, already reduced
// to only include rules relevant to that node.
//
// Fast path (!needsPerNodeFilter): reduces global filter per-node.
// Slow path (needsPerNodeFilter): combines global + self + via rules
// from the stored compiled grants, then reduces.
//
// Both paths derive from the same compiledGrants, ensuring there is
// no divergence between global and per-node filter output.
func (pm *PolicyManager) FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error) {
	if pm == nil {
		return nil, nil
	}

	if rules, ok := pm.filterRulesMap.Load(node.ID()); ok {
		return rules, nil
	}

	var reduced []tailcfg.FilterRule
	if !pm.needsPerNodeFilter {
		reduced = pm.reducer.Reduce(node)
	} else {
		pm.primeOnce.Do(func() {
			for i := range pm.compiledGrants {
				pm.dsts.Prime(pm.compiledGrants[i].rules)
			}
		})

		unreduced := append(
			pm.unreducedRules(node),
			exitNodeSelfRules(pm.compiledGrants, node, pm.userNodeIdx)...,
		)
		reduced = pm.dsts.Reduce(node, unreduced)
	}

	if pm.cacheable(node) {
		pm.filterRulesMap.Store(node.ID(), reduced)
	}

	return reduced, nil
}

// MatchersForNode returns the matchers for peer relationship determination for a specific node.
// These are UNREDUCED matchers - they include all rules where the node could be either source or destination.
// This is different from [PolicyManager.FilterForNode] which returns REDUCED rules for packet filtering.
//
// For global policies: returns the global matchers (same for all nodes)
// For autogroup:self: returns node-specific matchers from unreduced compiled rules.
//
// Per-node results are cached so [PolicyManager.BuildPeerMap]'s O(N²)
// slow path avoids recomputing matchers for every pair.
func (pm *PolicyManager) MatchersForNode(node types.NodeView) ([]matcher.Match, error) {
	if pm == nil {
		return nil, nil
	}

	// For global policies, return the shared global matchers.
	// Via grants require per-node matchers because the global matchers
	// are empty for via-grant-only policies.
	if !pm.needsPerNodeFilter {
		return pm.matchers, nil
	}

	if cached, ok := pm.matchersForNodeMap.Load(node.ID()); ok {
		return cached, nil
	}

	// For autogroup:self or via grants, derive matchers from
	// the stored compiled grants for this specific node.
	unreduced := pm.unreducedRules(node)
	matchers := matcher.MatchesFromFilterRules(unreduced)

	if pm.cacheable(node) {
		pm.matchersForNodeMap.Store(node.ID(), matchers)
	}

	return matchers, nil
}

// cacheable reports whether a per-node result computed from node may be
// cached under its ID: only when node agrees with the view pm was compiled
// from on every field the result reads. A caller holding a view from
// another snapshot, such as a mapper's pre-write one, would otherwise leave
// its answer for every later reader.
func (pm *PolicyManager) cacheable(node types.NodeView) bool {
	own, ok := pm.nodesByID[node.ID()]

	return ok && !node.HasPolicyChange(own) && !node.HasNetworkChanges(own)
}

// nodeIDViewMap indexes a slice of node views by node ID; on duplicate IDs
// the last view wins.
func nodeIDViewMap(s views.Slice[types.NodeView]) map[types.NodeID]types.NodeView {
	m := make(map[types.NodeID]types.NodeView, s.Len())
	for _, n := range s.All() {
		m[n.ID()] = n
	}

	return m
}

// NodeCanHaveTag checks if a node can have the specified tag during client-initiated
// registration or reauth flows (e.g., tailscale up --advertise-tags).
//
// This function is NOT used by the admin API's [state.State.SetNodeTags] - admins can
// set any existing tag on any node by calling [state.State.SetNodeTags] directly,
// which bypasses this authorization check.
func (pm *PolicyManager) NodeCanHaveTag(node types.NodeView, tag string) bool {
	if pm == nil {
		return false
	}

	if pm.pol == nil {
		return false
	}

	// Check if tag exists in policy
	owners, exists := pm.pol.TagOwners[Tag(tag)]
	if !exists {
		return false
	}

	// Check if node's owner can assign this tag via the pre-resolved tagOwnerMap.
	// The tagOwnerMap contains IP sets built from resolving TagOwners entries
	// (usernames/groups) to their nodes' IPs, so checking if the node's IP
	// is in the set answers "does this node's owner own this tag?"
	if ips, ok := pm.tagOwnerMap[Tag(tag)]; ok {
		if slices.ContainsFunc(node.IPs(), ips.Contains) {
			return true
		}
	}

	// For new nodes being registered, their IP may not yet be in the tagOwnerMap.
	// Fall back to checking the node's user directly against the TagOwners.
	// This handles the case where a user registers a new node with --advertise-tags.
	if node.User().Valid() {
		for _, owner := range owners {
			if pm.userMatchesOwner(node.User(), owner) {
				return true
			}
		}
	}

	return false
}

// UserCanHaveTag reports whether the given user is one of the tag's owners
// (directly or via a group). It is the user half of [PolicyManager.NodeCanHaveTag]:
// re-authentication authorises requested tags against the authenticating user,
// because a tag-owned node carries no user and its IP is not in any owner set,
// so only the user presenting the credential can prove ownership.
func (pm *PolicyManager) UserCanHaveTag(user types.UserView, tag string) bool {
	if pm == nil || !user.Valid() {
		return false
	}

	if pm.pol == nil {
		return false
	}

	owners, exists := pm.pol.TagOwners[Tag(tag)]
	if !exists {
		return false
	}

	for _, owner := range owners {
		if pm.userMatchesOwner(user, owner) {
			return true
		}
	}

	return false
}

// TagOwnedByTags reports whether a credential holding ownerTags is authorised to
// apply tag. It is true when tag is one of ownerTags, or when tag's tagOwners
// chain (tag-to-tag ownership) transitively includes one of ownerTags. This is
// the tag-level check used when an OAuth access token mints an auth key: the
// requested tags must each be owned by the token's tags, so an operator token
// tagged tag:k8s-operator may mint tag:k8s keys when the policy declares
// "tag:k8s": ["tag:k8s-operator"]. It is purely tag-relational and does not
// consult node IPs.
func (pm *PolicyManager) TagOwnedByTags(tag string, ownerTags []string) bool {
	if pm == nil {
		return false
	}

	owns := make(map[string]bool, len(ownerTags))
	for _, t := range ownerTags {
		owns[t] = true
	}

	// A credential may always apply a tag it directly holds; this needs no policy.
	if owns[tag] {
		return true
	}

	// Owned-by delegation requires the policy's tagOwners.
	if pm.pol == nil {
		return false
	}

	// Walk tag-to-tag ownership transitively, guarding against cycles.
	visited := make(map[Tag]bool)

	var walk func(t Tag) bool

	walk = func(t Tag) bool {
		if visited[t] {
			return false
		}

		visited[t] = true

		for _, owner := range pm.pol.TagOwners[t] {
			ot, ok := owner.(*Tag)
			if !ok {
				continue
			}

			if owns[string(*ot)] || walk(*ot) {
				return true
			}
		}

		return false
	}

	return walk(Tag(tag))
}

// userMatchesOwner checks if a user matches a tag owner entry.
// This is used as a fallback when the node's IP is not in the [PolicyManager.tagOwnerMap].
func (pm *PolicyManager) userMatchesOwner(user types.UserView, owner Owner) bool {
	switch o := owner.(type) {
	case *Username:
		if o == nil {
			return false
		}
		// Resolve the username to find the user it refers to
		resolvedUser, err := o.resolveUser(pm.users)
		if err != nil {
			return false
		}

		return user.ID() == resolvedUser.ID

	case *Group:
		if o == nil || pm.pol == nil {
			return false
		}
		// Resolve the group to get usernames
		usernames, ok := pm.pol.Groups[*o]
		if !ok {
			return false
		}
		// Check if the user matches any username in the group
		for _, uname := range usernames {
			resolvedUser, err := uname.resolveUser(pm.users)
			if err != nil {
				continue
			}

			if user.ID() == resolvedUser.ID {
				return true
			}
		}

		return false

	default:
		return false
	}
}

// TagExists reports whether the given tag is defined in the policy.
func (pm *PolicyManager) TagExists(tag string) bool {
	if pm == nil {
		return false
	}

	if pm.pol == nil {
		return false
	}

	_, exists := pm.pol.TagOwners[Tag(tag)]

	return exists
}

func (pm *PolicyManager) NodeCanApproveRoute(node types.NodeView, route netip.Prefix) bool {
	if pm == nil {
		return false
	}

	// If the route to-be-approved is an exit route, then we need to check
	// if the node is in allowed to approve it. This is treated differently
	// than the auto-approvers, as the auto-approvers are not allowed to
	// approve the whole /0 range.
	// However, an auto approver might be /0, meaning that they can approve
	// all routes available, just not exit nodes.
	if tsaddr.IsExitRoute(route) {
		if pm.exitSet == nil {
			return false
		}

		return slices.ContainsFunc(node.IPs(), pm.exitSet.Contains)
	}

	// The fast path is that a node requests to approve a prefix
	// where there is an exact entry, e.g. 10.0.0.0/8, then
	// check and return quickly
	if approvers, ok := pm.autoApproveMap[route]; ok {
		canApprove := slices.ContainsFunc(node.IPs(), approvers.Contains)
		if canApprove {
			return true
		}
	}

	// The slow path is that the node tries to approve
	// 10.0.10.0/24, which is a part of 10.0.0.0/8, then we
	// cannot just lookup in the prefix map and have to check
	// if there is a "parent" prefix available.
	for prefix, approveAddrs := range pm.autoApproveMap {
		// Check if prefix is larger (so containing) and then overlaps
		// the route to see if the node can approve a subset of an autoapprover
		if prefix.Bits() <= route.Bits() && prefix.Overlaps(route) {
			canApprove := slices.ContainsFunc(node.IPs(), approveAddrs.Contains)
			if canApprove {
				return true
			}
		}
	}

	return false
}

// viaPrep is the part of [PolicyManager.ViaRoutesForPeer] that is the same
// for every viewer and peer: the grants, what each one's sources and
// destinations resolve to, and each via grant's elected router per route.
type viaPrep struct {
	grants   []Grant
	srcs     []*netipx.IPSet
	dsts     [][]netip.Prefix
	internet []bool
	// primary holds, per via grant, the lowest-ID node carrying one of
	// its via tags for static policy inspection. Live snapshots elect
	// from routers using current availability instead.
	primary []map[netip.Prefix]types.NodeID
	scopes  map[netip.Prefix][]viaScope
}

type viaScope struct {
	grant      int
	candidates views.Slice[types.NodeID]
}

type viaKey struct {
	grant  int
	prefix netip.Prefix
}

// viaPrep returns the policy's via preparation, building it on first use.
func (pm *PolicyManager) viaPrep() *viaPrep {
	if pm == nil {
		return nil
	}

	pm.viaOnce.Do(func() {
		if pm.pol == nil || !slices.ContainsFunc(pm.pol.Grants, Grant.HasVia) {
			return
		}

		grants := slices.Clone(pm.pol.Grants)
		for _, acl := range pm.pol.ACLs {
			grants = append(grants, aclToGrants(acl)...)
		}

		prep := &viaPrep{
			grants:   grants,
			srcs:     make([]*netipx.IPSet, len(grants)),
			dsts:     make([][]netip.Prefix, len(grants)),
			internet: make([]bool, len(grants)),
			primary:  make([]map[netip.Prefix]types.NodeID, len(grants)),
			scopes:   make(map[netip.Prefix][]viaScope),
		}

		// Grants sharing tags and destinations elect from the same
		// routers and win the same primaries: build each combination once
		// and share its candidates.
		candidates := make([]map[netip.Prefix][]types.NodeID, 0, len(grants))
		primaries := make([]map[netip.Prefix]types.NodeID, 0, len(grants))

		for i, grant := range grants {
			var b netipx.IPSetBuilder

			for _, src := range grant.Sources {
				ips, err := src.Resolve(pm.pol, pm.users, pm.nodes)
				if err != nil || ips == nil {
					continue
				}

				for _, p := range ips.Prefixes() {
					b.AddPrefix(p)
				}
			}

			prep.srcs[i], _ = b.IPSet()
			prep.dsts[i], prep.internet[i] = resolveViaDestinations(pm.pol, pm.users, pm.nodes, grant.Destinations)

			if !grant.HasVia() {
				candidates = append(candidates, nil)
				primaries = append(primaries, nil)

				continue
			}

			var (
				routers map[netip.Prefix][]types.NodeID
				primary map[netip.Prefix]types.NodeID
			)

			for j := range i {
				if slices.Equal(grants[j].Via, grant.Via) && slices.Equal(prep.dsts[j], prep.dsts[i]) {
					routers, primary = candidates[j], primaries[j]

					break
				}
			}

			if routers == nil {
				routers = make(map[netip.Prefix][]types.NodeID)

				for _, node := range pm.nodes.All() {
					if !slices.ContainsFunc(grant.Via, func(t Tag) bool { return node.HasTag(string(t)) }) {
						continue
					}

					for _, route := range node.SubnetRoutes() {
						if !slices.ContainsFunc(prep.dsts[i], route.Overlaps) {
							continue
						}

						routers[route] = append(routers[route], node.ID())
					}
				}

				primary = make(map[netip.Prefix]types.NodeID, len(routers))

				// ids are sorted, so the first is the lowest-ID router.
				for prefix, ids := range routers {
					slices.Sort(ids)
					primary[prefix] = ids[0]
				}
			}

			candidates = append(candidates, routers)
			primaries = append(primaries, primary)

			for prefix, ids := range routers {
				prep.scopes[prefix] = append(prep.scopes[prefix], viaScope{i, views.SliceOf(ids)})
			}

			prep.primary[i] = primary
		}

		pm.via = prep
	})

	return pm.via
}

// ViaRoutes binds immutable live elections to the policy defining their scopes.
// An empty election still applies that policy's exclusions and exit steering.
type ViaRoutes struct {
	policy  *PolicyManager
	winners *graph.Map[viaKey, types.NodeID]
}

// ElectViaRoutes revisits only scopes a change can move: those reached by
// touched prefixes, and — when the policy binding changed — those whose
// candidate membership moved with it. A different policy document starts
// every election anew. elect runs synchronously with read-only candidates
// and the scope's prior winner; it must use the caller's in-progress
// snapshot. The boolean reports winner changes; callers must adopt the
// returned policy binding even when it is false.
func (pm *PolicyManager) ElectViaRoutes(previous *ViaRoutes, touched map[netip.Prefix]struct{}, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) (*ViaRoutes, bool) {
	e := newViaElection(previous)
	// Only the same document gives positional scopes the same meaning.
	continuous := previous != nil && previous.policy != nil && pm != nil && previous.policy.pol == pm.pol

	prep := pm.viaPrep()

	// candidates returns the previous binding's candidates for a scope, and
	// whether it had any: a scope only keeps its winner when both its key
	// and its candidates survive a recompile.
	candidates := func(old *viaPrep, k viaKey) (views.Slice[types.NodeID], bool) {
		if old == nil {
			return views.Slice[types.NodeID]{}, false
		}

		for _, scope := range old.scopes[k.prefix] {
			if scope.grant == k.grant {
				return scope.candidates, true
			}
		}

		return views.Slice[types.NodeID]{}, false
	}

	switch {
	case previous != nil && previous.policy == pm:
		// Same binding, so prep still describes these nodes. A failed
		// compile also lands here: it keeps the previous policy manager,
		// whose scopes were frozen against an older node list — the same
		// last-good staleness the compiled policy serves everywhere.
		if prep != nil {
			for prefix := range touched {
				for _, scope := range prep.scopes[prefix] {
					e.electScope(prefix, scope, continuous, elect)
				}
			}
		}
	case continuous:
		// A same-document recompile rebuilt the policy against new nodes.
		// Revisit scopes whose prefixes a changed router names or whose
		// candidates moved; the rest keep their winners.
		old := previous.policy.viaPrep()
		seen := make(map[viaKey]struct{})

		if prep != nil {
			for prefix, scopes := range prep.scopes {
				for _, scope := range scopes {
					k := viaKey{scope.grant, prefix}
					seen[k] = struct{}{}

					if _, ok := touched[prefix]; !ok {
						if prev, had := candidates(old, k); had && sameNodeIDSlice(prev, scope.candidates) {
							continue
						}
					}

					e.electScope(prefix, scope, continuous, elect)
				}
			}
		}

		for k := range e.winners.All() {
			if _, ok := seen[k]; !ok {
				e.set(k, 0, false)
			}
		}
	default:
		return pm.electAll(previous, elect)
	}

	binding, changed := e.result(pm)
	if !changed && previous != nil && previous.policy == pm {
		return previous, false
	}

	return binding, changed
}

// electAll elects every scope from previous's winners, dropping keys the
// policy no longer scopes. A different document, a first election, and the
// from-scratch audit take it.
func (pm *PolicyManager) electAll(previous *ViaRoutes, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) (*ViaRoutes, bool) {
	e := newViaElection(previous)
	continuous := previous != nil && previous.policy != nil && pm != nil && previous.policy.pol == pm.pol

	seen := make(map[viaKey]struct{})

	if prep := pm.viaPrep(); prep != nil {
		for prefix, scopes := range prep.scopes {
			for _, scope := range scopes {
				seen[viaKey{scope.grant, prefix}] = struct{}{}
				e.electScope(prefix, scope, continuous, elect)
			}
		}
	}

	for k := range e.winners.All() {
		if _, ok := seen[k]; !ok {
			e.set(k, 0, false)
		}
	}

	return e.result(pm)
}

// AuditViaElections recomputes every scope from previous — the incumbents
// the adopted election was seeded with — and reports whether the outcome
// matches the election the world adopted. It is the from-scratch reference
// for HEADSCALE_DEBUG_POLICY_AUDIT.
func (pm *PolicyManager) AuditViaElections(previous, elected *ViaRoutes, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) bool {
	want, _ := pm.electAll(previous, elect)

	var have *graph.Map[viaKey, types.NodeID]
	if elected != nil && elected.policy == pm {
		have = elected.winners
	}

	return sameViaWinners(want.winners, have)
}

// sameViaWinners compares two election winner maps.
func sameViaWinners(a, b *graph.Map[viaKey, types.NodeID]) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return (a == nil || a.Len() == 0) && (b == nil || b.Len() == 0)
	}

	if a.Len() != b.Len() {
		return false
	}

	for k, v := range a.All() {
		if w, ok := b.Get(k); !ok || w != v {
			return false
		}
	}

	return true
}

// viaElection stages one election pass over the winners of previous.
type viaElection struct {
	winners *graph.Map[viaKey, types.NodeID]
	edit    *graph.MapEdit[viaKey, types.NodeID]
}

func newViaElection(previous *ViaRoutes) *viaElection {
	// A pass over a carried binding reuses its winners; only a first
	// election builds a fresh map.
	if previous != nil && previous.winners != nil {
		return &viaElection{winners: previous.winners}
	}

	return &viaElection{winners: graph.NewMap[viaKey](func(a, b types.NodeID) bool { return a == b }, nil)}
}

func (e *viaElection) set(k viaKey, id types.NodeID, present bool) {
	// Read the staged edit once it exists: a later pass over the same
	// key must see what this election already staged.
	old, existed := e.winners.Get(k)
	if e.edit != nil {
		old, existed = e.edit.Get(k)
	}

	if existed == present && (!present || old == id) {
		return
	}

	if e.edit == nil {
		e.edit = e.winners.Edit()
	}

	if present {
		e.edit.Set(k, id)
	} else {
		e.edit.Delete(k)
	}
}

func (e *viaElection) electScope(prefix netip.Prefix, scope viaScope, continuous bool, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) {
	k := viaKey{scope.grant, prefix}

	var incumbent types.NodeID
	if continuous {
		// Read the staged edit once it exists, as set does: a scope
		// elected earlier in this pass is its own incumbent.
		incumbent, _ = e.winners.Get(k)
		if e.edit != nil {
			incumbent, _ = e.edit.Get(k)
		}
	}

	id, ok := elect(scope.candidates, incumbent)
	e.set(k, id, ok)
}

func (e *viaElection) result(pm *PolicyManager) (*ViaRoutes, bool) {
	next := e.winners
	if e.edit != nil {
		next = e.edit.Done()
	}

	return &ViaRoutes{policy: pm, winners: next}, next != e.winners
}

// sameNodeIDSlice compares two sorted node ID slices without copying them.
func sameNodeIDSlice(a, b views.Slice[types.NodeID]) bool {
	if a.Len() != b.Len() {
		return false
	}

	for i := range a.Len() {
		if a.At(i) != b.At(i) {
			return false
		}
	}

	return true
}

// ForPeer resolves routes using only this result's policy and live elections.
func (v *ViaRoutes) ForPeer(viewer, peer types.NodeView) types.ViaRouteResult {
	if v == nil {
		return types.ViaRouteResult{}
	}

	return v.policy.viaRoutesForPeer(viewer, peer, func(grant int, prefix netip.Prefix) types.NodeID {
		id, _ := v.winners.Get(viaKey{grant, prefix})
		return id
	})
}

// ChangedNodes includes losing and gaining routers between retained snapshots,
// not just the latest transaction. Expired map history falls back to comparison.
func (v *ViaRoutes) ChangedNodes(previous *ViaRoutes) []types.NodeID {
	var before, after *graph.Map[viaKey, types.NodeID]
	if previous != nil {
		before = previous.winners
	}

	if v != nil {
		after = v.winners
	}

	var ids []types.NodeID

	for _, k := range graph.Changes(before, after) {
		if id, ok := before.Get(k); ok {
			ids = append(ids, id)
		}

		if id, ok := after.Get(k); ok {
			ids = append(ids, id)
		}
	}

	slices.Sort(ids)

	return slices.Compact(ids)
}

// HasOutage reports whether any elected winner is unavailable while none of
// its scope's candidates is: the routers coming back should be elected
// together, not one write at a time. A scope whose routers are all offline
// elects no winner, so it is invisible here — the same blind spot the global
// election's routes map has. available decides availability against the
// caller's in-progress snapshot.
func (v *ViaRoutes) HasOutage(available func(types.NodeID) bool) bool {
	if v == nil {
		return false
	}

	prep := v.policy.viaPrep()
	if prep == nil {
		return false
	}

	for k, id := range v.winners.All() {
		if available(id) {
			continue
		}

		// An available candidate would win the next election; only a
		// scope with none left is an outage. A winner whose scope the
		// policy no longer scopes — which the election cannot produce —
		// is not one.
		scoped, anyAvailable := false, false

		for _, scope := range prep.scopes[k.prefix] {
			if scope.grant != k.grant {
				continue
			}

			scoped = true

			for _, candidate := range scope.candidates.All() {
				if available(candidate) {
					anyAvailable = true

					break
				}
			}
		}

		if scoped && !anyAvailable {
			return true
		}
	}

	return false
}

// ViaRoutesForPeer computes via grant effects for a viewer-peer pair.
// For each via grant where the viewer matches the source, the prefixes the
// peer advertises among the grant's destinations go into
// [types.ViaRouteResult.Include] when this inspection elects the peer for
// them — exit routes steer per node and need no election — and into
// [types.ViaRouteResult.Exclude] otherwise, including when no router wins
// the scope.
//
// This is static policy inspection, not live routing. Snapshots use ViaRoutes.
func (pm *PolicyManager) ViaRoutesForPeer(viewer, peer types.NodeView) types.ViaRouteResult {
	return pm.viaRoutesForPeer(viewer, peer, func(grant int, prefix netip.Prefix) types.NodeID {
		// Zero when no router of this scope advertises the prefix: the
		// scope elects nobody, so nothing routes through the peer.
		id, _ := pm.viaPrep().primary[grant][prefix]
		return id
	})
}

//nolint:gocyclo // via-grant election followed by regular-grant overlap
func (pm *PolicyManager) viaRoutesForPeer(viewer, peer types.NodeView, primary func(int, netip.Prefix) types.NodeID) types.ViaRouteResult {
	var result types.ViaRouteResult

	prep := pm.viaPrep()
	if prep == nil {
		return result
	}

	// Self-steering doesn't apply.
	if viewer.ID() == peer.ID() {
		return result
	}

	grants := prep.grants
	viewerIPs := viewer.IPs()
	viewerSubnets := viewer.SubnetRoutes()

	matchViewer := func(i int) bool {
		return prep.srcs[i] != nil && (slices.ContainsFunc(viewerIPs, prep.srcs[i].Contains) ||
			slices.ContainsFunc(viewerSubnets, prep.srcs[i].OverlapsPrefix))
	}
	resolvedDstPrefixes, grantHasAutoGroupInternet := prep.dsts, prep.internet

	for i, grant := range grants {
		if !grant.HasVia() {
			continue
		}

		if !matchViewer(i) {
			continue
		}

		// Filter rules and [tailcfg.Node.AllowedIPs] are different layers.
		// The filter rule carries the dst (the authorisation surface).
		// [tailcfg.Node.AllowedIPs] carries the advertised route (the
		// routing fact the viewer needs to pick this peer). This loop
		// builds the AllowedIPs side, so it emits routes — not dst
		// prefixes.
		peerSubnetRoutes := peer.SubnetRoutes()

		var matchedPrefixes []netip.Prefix

		for _, dstPrefix := range resolvedDstPrefixes[i] {
			for _, route := range peerSubnetRoutes {
				// A route can cover several destinations of one grant;
				// it is still one route the peer carries.
				if dstPrefix.Overlaps(route) && !slices.Contains(matchedPrefixes, route) {
					matchedPrefixes = append(matchedPrefixes, route)
				}
			}
		}

		// Per-viewer steering for autogroup:internet: a peer advertising
		// approved exit routes is the via-tagged node's analogue of
		// "advertises the destination". The downstream Include/Exclude
		// split below restricts the viewer to exit nodes carrying the
		// via tag.
		if grantHasAutoGroupInternet[i] && peer.IsExitNode() {
			matchedPrefixes = append(matchedPrefixes, peer.ExitRoutes()...)
		}

		if len(matchedPrefixes) == 0 {
			continue
		}

		// Check if peer has any of the via tags.
		peerHasVia := false

		for _, viaTag := range grant.Via {
			if peer.HasTag(string(viaTag)) {
				peerHasVia = true

				break
			}
		}

		// Elect within each grant before combining contributions: one
		// group's failure must not cancel another group's authorization.
		for _, prefix := range matchedPrefixes {
			include := peerHasVia
			// Exit routes use per-node steering, not subnet HA elections.
			if include && !tsaddr.IsExitRoute(prefix) {
				include = peer.ID() == primary(i, prefix)
			}

			if include {
				result.Include = append(result.Include, prefix)
			} else {
				result.Exclude = append(result.Exclude, prefix)
			}
		}
	}

	if len(result.Include) > 0 || len(result.Exclude) > 0 {
		// Check for regular (non-via) grants covering the same prefix.
		// When a regular grant also covers a prefix that a via grant
		// included, defer to global HA primary election (UsePrimary).
		// When a regular grant covers a prefix that a via grant excluded
		// (peer lacks via tag), remove the exclusion so
		// [state.State.RoutesForPeer] can apply normal
		// [policy.ReduceRoutes] + primary logic.
		for i, grant := range grants {
			if grant.HasVia() {
				continue
			}

			if !matchViewer(i) {
				continue
			}

			// A non-via grant covering subnets that a via grant included
			// defers to global HA primary election. Match by overlap so
			// a broader or narrower regular dst still catches the
			// routes the via grant added to Include.
			for _, dstPrefix := range resolvedDstPrefixes[i] {
				for _, p := range result.Include {
					if !tsaddr.IsExitRoute(p) && dstPrefix.Overlaps(p) &&
						!slices.Contains(result.UsePrimary, p) {
						result.UsePrimary = append(result.UsePrimary, p)
					}
				}

				// Every address overlaps an exit route, so overlap
				// only decides for subnet routes.
				result.Exclude = slices.DeleteFunc(result.Exclude, func(p netip.Prefix) bool {
					return !tsaddr.IsExitRoute(p) && dstPrefix.Overlaps(p)
				})
			}

			// A regular grant to the internet lets the viewer use any
			// exit node, not just the via-tagged ones.
			if grantReachesInternet(grant) {
				result.Exclude = slices.DeleteFunc(result.Exclude, tsaddr.IsExitRoute)
			}
		}
	}

	return result
}

// grantReachesInternet reports whether a grant's destinations include
// the internet. Neither the wildcard nor autogroup:internet resolves
// to 0.0.0.0/0, so check the aliases themselves.
func grantReachesInternet(grant Grant) bool {
	return slices.ContainsFunc(grant.Destinations, func(d Alias) bool {
		if ag, ok := d.(*AutoGroup); ok {
			return ag.Is(AutoGroupInternet)
		}

		_, ok := d.(Asterix)

		return ok
	})
}

func (pm *PolicyManager) Version() int {
	return 2
}

func (pm *PolicyManager) DebugString() string {
	if pm == nil {
		return "PolicyManager is not setup"
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "PolicyManager (v%d):\n\n", pm.Version())

	sb.WriteString("\n\n")

	if pm.pol != nil {
		pol, err := json.MarshalIndent(pm.pol, "", "  ")
		if err == nil {
			sb.WriteString("Policy:\n")
			sb.Write(pol)
			sb.WriteString("\n\n")
		}
	}

	fmt.Fprintf(&sb, "AutoApprover (%d):\n", len(pm.autoApproveMap))

	for prefix, approveAddrs := range pm.autoApproveMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range approveAddrs.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	fmt.Fprintf(&sb, "TagOwner (%d):\n", len(pm.tagOwnerMap))

	for prefix, tagOwners := range pm.tagOwnerMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range tagOwners.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	if pm.filter != nil {
		filter, err := json.MarshalIndent(pm.filter, "", "  ")
		if err == nil {
			sb.WriteString("Compiled filter:\n")
			sb.Write(filter)
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("\n\n")
	sb.WriteString("Matchers:\n")
	sb.WriteString("an internal structure used to filter nodes and routes\n")

	for _, match := range pm.matchers {
		sb.WriteString(match.DebugString())
		sb.WriteString("\n")
	}

	sb.WriteString("\n\n")
	sb.WriteString("Nodes:\n")

	for _, node := range pm.nodes.All() {
		sb.WriteString(node.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// flattenTags resolves nested tag-owner references. Cycles
// (tag:a -> tag:b -> tag:a, or tag:a -> tag:a) drop the cycle-causing
// edge and contribute no addresses; non-cycle owners on the cycled tags
// still resolve. Undefined-tag references remain a hard error.
func flattenTags(tagOwners TagOwners, tag Tag, visiting map[Tag]bool, chain []Tag) (Owners, error) {
	if visiting[tag] {
		return nil, nil
	}

	visiting[tag] = true

	chain = append(chain, tag)
	defer delete(visiting, tag)

	var result Owners

	for _, owner := range tagOwners[tag] {
		switch o := owner.(type) {
		case *Tag:
			if _, ok := tagOwners[*o]; !ok {
				return nil, fmt.Errorf("tag %q %w %q", tag, ErrUndefinedTagReference, *o)
			}

			nested, err := flattenTags(tagOwners, *o, visiting, chain)
			if err != nil {
				return nil, err
			}

			result = append(result, nested...)
		default:
			result = append(result, owner)
		}
	}

	return result, nil
}

// flattenTagOwners flattens all [TagOwners] by resolving nested tags and detecting cycles.
// It will return a new [TagOwners] map where all the [Tag] types have been resolved to their underlying [Owners].
func flattenTagOwners(tagOwners TagOwners) (TagOwners, error) {
	ret := make(TagOwners)

	for tag := range tagOwners {
		flattened, err := flattenTags(tagOwners, tag, make(map[Tag]bool), nil)
		if err != nil {
			return nil, err
		}

		slices.SortFunc(flattened, func(a, b Owner) int {
			return cmp.Compare(a.String(), b.String())
		})
		ret[tag] = slices.CompactFunc(flattened, func(a, b Owner) bool {
			return a.String() == b.String()
		})
	}

	return ret, nil
}

// resolveTagOwners resolves the [TagOwners] to a map of [Tag] to [netipx.IPSet].
// The resulting map can be used to quickly look up the IPSet for a given [Tag].
// It is intended for internal use in a [PolicyManager].
func resolveTagOwners(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (map[Tag]*netipx.IPSet, error) {
	if p == nil {
		return make(map[Tag]*netipx.IPSet), nil
	}

	if len(p.TagOwners) == 0 {
		return make(map[Tag]*netipx.IPSet), nil
	}

	ret := make(map[Tag]*netipx.IPSet)

	tagOwners, err := flattenTagOwners(p.TagOwners)
	if err != nil {
		return nil, err
	}

	for tag, owners := range tagOwners {
		var ips netipx.IPSetBuilder

		for _, owner := range owners {
			switch o := owner.(type) {
			case *Tag:
				// After flattening, Tag types should not appear in the owners list.
				// If they do, skip them as they represent already-resolved references.

			case Alias:
				// If it does not resolve, that means the tag is not associated with any IP addresses.
				resolved, _ := p.resolveAlias(o, users, nodes)
				addResolved(&ips, resolved)

			default:
				// Should never happen - after flattening, all owners should be Alias types
				return nil, fmt.Errorf("%w: %v", ErrInvalidTagOwner, owner)
			}
		}

		ipSet, err := ips.IPSet()
		if err != nil {
			return nil, err
		}

		ret[tag] = ipSet
	}

	return ret, nil
}

// NodeCapMap returns the policy-derived CapMap for the given node, or
// nil when the node has no nodeAttrs entries that target it. The
// returned map is a fresh container; its values are shared with the
// manager and must be treated as read-only.
func (pm *PolicyManager) NodeCapMap(id types.NodeID) tailcfg.NodeCapMap {
	if pm == nil {
		return nil
	}

	src := pm.nodeAttrsMap[id]
	if len(src) == 0 {
		return nil
	}

	out := make(tailcfg.NodeCapMap, len(src))
	maps.Copy(out, src)

	return out
}

// NodeCapMaps returns the per-node policy CapMap. The map and its
// [tailcfg.NodeCapMap] values are the manager's own, shared by every
// render, and must be treated as read-only.
func (pm *PolicyManager) NodeCapMaps() map[types.NodeID]tailcfg.NodeCapMap {
	if pm == nil {
		return nil
	}

	return pm.nodeAttrsMap
}

// Audit compiles src from scratch and returns how pm, which compiled the
// same document, users and nodes incrementally, differs from it: in the
// global filter, tag owners, auto-approvers, node attributes, peers, or
// any node's filter or SSH policy. It is for debugging and tests; it
// costs a full compile and a render of every node.
func (pm *PolicyManager) Audit(src []byte, users []types.User, nodes views.Slice[types.NodeView]) error {
	fresh, err := NewPolicyManager(src, users, nodes)
	if err != nil {
		return fmt.Errorf("compiling from scratch: %w", err)
	}

	for _, c := range []struct {
		what     string
		inc, fsh any
	}{
		{"filter", pm.filter, fresh.filter},
		{"tag owners", pm.tagOwnerMap, fresh.tagOwnerMap},
		{"auto-approvers", pm.autoApproveMap, fresh.autoApproveMap},
		{"exit auto-approvers", pm.exitSet, fresh.exitSet},
		{"node attributes", pm.nodeAttrsMap, fresh.nodeAttrsMap},
		{"peers", pm.BuildPeerMap(nodes), fresh.BuildPeerMap(nodes)},
	} {
		if !reflect.DeepEqual(c.inc, c.fsh) {
			return fmt.Errorf("%w: %s", errAuditMismatch, c.what)
		}
	}

	// The peer classes the world builds, not only the pair scan, must
	// match a fresh compile's peers; the pair scans matched above.
	err = pm.AuditPeers(pm.BuildPeerClasses(nodes, nil), nodes)
	if err != nil {
		return err
	}

	for _, n := range nodes.All() {
		err := auditNode(pm, fresh, n, nodes)
		if err != nil {
			return err
		}
	}

	var sshErr error

	pm.sshPreps.Range(func(baseURL string, _ *sshPrep) bool {
		for _, n := range nodes.All() {
			inc, err := pm.SSHPolicy(baseURL, n)
			if err != nil {
				sshErr = err

				return false
			}

			fsh, err := fresh.SSHPolicy(baseURL, n)
			if err != nil {
				sshErr = err

				return false
			}

			if !reflect.DeepEqual(inc, fsh) {
				sshErr = fmt.Errorf("%w: SSH policy of node %d", errAuditMismatch, n.ID())

				return false
			}
		}

		return true
	})

	return sshErr
}

// AuditPeers returns how classes, built by pm from nodes, differ from
// pm's pair scan of the same nodes. Like [PolicyManager.Audit] it is for
// debugging and tests: the scan is quadratic.
func (pm *PolicyManager) AuditPeers(classes *PeerClasses, nodes views.Slice[types.NodeView]) error {
	want := pm.BuildPeerMap(nodes)

	for _, n := range nodes.All() {
		inc, fsh := classes.Peers(n.ID()), want[n.ID()]
		if len(inc) != 0 || len(fsh) != 0 {
			slices.Sort(fsh)

			if !slices.Equal(inc, fsh) {
				return fmt.Errorf("%w: peer classes of node %d", errAuditMismatch, n.ID())
			}
		}
	}

	return nil
}

var errAuditMismatch = errors.New("incremental compile differs from a compile from scratch")

// auditNode compares what pm and fresh, a compile from scratch, give node:
// its filter, the matchers that decide which routes it sees, and the via
// routes each other node serves it.
func auditNode(pm, fresh *PolicyManager, n types.NodeView, nodes views.Slice[types.NodeView]) error {
	inc, err := pm.FilterForNode(n)
	if err != nil {
		return err
	}

	fsh, err := fresh.FilterForNode(n)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(inc, fsh) {
		return fmt.Errorf("%w: filter of node %d", errAuditMismatch, n.ID())
	}

	incM, err := pm.MatchersForNode(n)
	if err != nil {
		return err
	}

	fshM, err := fresh.MatchersForNode(n)
	if err != nil {
		return err
	}

	debug := func(ms []matcher.Match) []string {
		out := make([]string, len(ms))
		for i := range ms {
			out[i] = ms[i].DebugString()
		}

		return out
	}

	if !slices.Equal(debug(incM), debug(fshM)) {
		return fmt.Errorf("%w: matchers of node %d", errAuditMismatch, n.ID())
	}

	for _, peer := range nodes.All() {
		if !reflect.DeepEqual(pm.ViaRoutesForPeer(n, peer), fresh.ViaRoutesForPeer(n, peer)) {
			return fmt.Errorf("%w: via routes node %d gets from %d", errAuditMismatch, n.ID(), peer.ID())
		}
	}

	return nil
}
