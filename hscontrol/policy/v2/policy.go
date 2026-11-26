package v2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog/log"
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
//
// It serves what the graph's cells do not: SSH, node attributes, tag
// owners, auto-approvers, DERP, and which document is in force. Packet
// filters, peers and via steering in address form are compiled from
// scratch on first read (see [PolicyManager.addresses]): nothing serves
// them, and the policy audit and the tests hold what is served against
// them.
type PolicyManager struct {
	resolvedPol *Policy
	pol         *Policy
	users       []types.User

	// src is the document compiled, for [NewPolicyManagerFrom].
	src     []byte
	aliases aliasCache

	sideOnce sync.Once
	sides    *sideIndex

	nodes views.Slice[types.NodeView]
	// nodesByID indexes nodes; see [PolicyManager.cacheable].
	nodesByID map[types.NodeID]types.NodeView

	tagOwnerMap    map[Tag]*netipx.IPSet
	exitSet        *netipx.IPSet
	autoApproveMap map[netip.Prefix]*netipx.IPSet

	userNodeIdx userNodeIndex

	// nodeAttrsMap is the per-node CapMap compiled from policy.NodeAttrs.
	nodeAttrsMap map[types.NodeID]tailcfg.NodeCapMap

	// Per-node answers, filled on first read. xsync.Maps so concurrent
	// readers can fill them.
	sshPolicyMap *xsync.Map[sshKey, *tailcfg.SSHPolicy]
	// sshPreps holds the node-independent SSH compile, by server URL.
	sshPreps *xsync.Map[string, *sshPrep]

	addrOnce sync.Once
	addr     *addressCompile
}

// addressCompile is a policy's packet filters, peer matchers and via
// steering in address form, compiled from scratch over its users and
// nodes, with no alias resolved before: an oracle shares no state with
// the compile before it.
type addressCompile struct {
	indexed *Policy

	// compiledGrants are the grants with sources pre-resolved, from which
	// both the global and the per-node filters derive.
	compiledGrants []compiledGrant
	// needsPerNodeFilter is true when any compiled grant requires
	// per-node work (autogroup:self or via grants).
	needsPerNodeFilter bool

	filter []tailcfg.FilterRule
	// reducer reduces filter for each node, parsing it once.
	reducer  *policyutil.Reducer
	matchers []matcher.Match

	// dsts parses the destinations of the rules reduced per node, once;
	// primeOnce gives it the compiled grants' shared rules.
	dsts      policyutil.DstCache
	primeOnce sync.Once

	viaOnce sync.Once
	via     *viaPrep

	// selfRules holds the compiled autogroup:self rules per grant and
	// user; see [PolicyManager.grantRulesFor].
	selfRules *xsync.Map[selfRulesKey, keyedRules]
	// filterRulesMap holds reduced rules, for packet filters.
	filterRulesMap *xsync.Map[types.NodeID, []tailcfg.FilterRule]
	// matchersForNodeMap holds matchers from UNREDUCED rules. Only the
	// needsPerNodeFilter path fills it; otherwise every node gets
	// matchers.
	matchersForNodeMap *xsync.Map[types.NodeID, []matcher.Match]
}

// addressCompiles counts the address compiles built.
var addressCompiles atomic.Uint64

// AddressCompiles returns how many address compiles have been built, so a
// test can hold a path to building none: only the policy audit and tests
// may read the oracle.
func AddressCompiles() uint64 { return addressCompiles.Load() }

// addresses returns pm's address compile, building it on first use.
func (pm *PolicyManager) addresses() *addressCompile {
	pm.addrOnce.Do(func() {
		addressCompiles.Add(1)

		indexed := pm.pol.withNodesByTag(pm.nodes).withResolvedGroups(pm.users, pm.nodes)
		if indexed != nil {
			indexed.aliases = aliasCache{}
		}

		grants := indexed.compileGrants(pm.users, pm.nodes)

		var filter []tailcfg.FilterRule
		if pm.pol == nil || (pm.pol.ACLs == nil && pm.pol.Grants == nil) {
			filter = noRulesFilter(pm.users, pm.nodes)
		} else {
			filter = globalFilterRules(grants)
		}

		pm.addr = &addressCompile{
			indexed:            indexed,
			compiledGrants:     grants,
			needsPerNodeFilter: hasPerNodeGrants(grants),
			filter:             filter,
			reducer:            policyutil.NewReducer(filter),
			matchers:           matcher.MatchesFromFilterRules(filter),
			selfRules:          xsync.NewMap[selfRulesKey, keyedRules](),
			filterRulesMap:     xsync.NewMap[types.NodeID, []tailcfg.FilterRule](),
			matchersForNodeMap: xsync.NewMap[types.NodeID, []matcher.Match](),
		}
	})

	return pm.addr
}

// validateUserReferences surfaces ambiguous user@ tokens at policy load so
// duplicate DB rows fail loudly instead of silently dropping rules.
// Missing-user tokens stay tolerant. Empty users → no-op for
// syntax-only checks.
//
// It returns the ambiguous tokens, sorted and without repeats, and an error
// naming each once, in the same order: groups and owners are maps, so
// anything keyed on the walk order would differ between runs over the same
// document and users.
func validateUserReferences(pol *Policy, users types.Users) ([]string, error) {
	if pol == nil || len(users) == 0 {
		return nil, nil
	}

	found := map[string]error{}

	check := func(u *Username) {
		if u == nil {
			return
		}

		_, err := u.resolveUser(users)
		if err != nil && errors.Is(err, ErrMultipleUsersFound) {
			found[u.String()] = err
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

	for _, grant := range pol.Grants {
		for _, src := range grant.Sources {
			checkAlias(src)
		}

		for _, dst := range grant.Destinations {
			checkAlias(dst)
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

	for _, na := range pol.NodeAttrs {
		for _, target := range na.Targets {
			checkAlias(target)
		}
	}

	tokens := slices.Sorted(maps.Keys(found))

	errs := make([]error, len(tokens))
	for i, token := range tokens {
		errs[i] = found[token]
	}

	return tokens, multierr.New(errs...)
}

// ValidateUserReferences reports the user@ tokens of pm's document that
// several of its users answer to. Loading a document refuses them; a
// compile resolves them to nobody.
func (pm *PolicyManager) ValidateUserReferences() error {
	_, err := pm.AmbiguousUserReferences()

	return err
}

// AmbiguousUserReferences is [PolicyManager.ValidateUserReferences] that
// also returns the ambiguous tokens, sorted: the set a caller compares to
// tell whether the ambiguity changed, which the error text is not a stable
// key for.
func (pm *PolicyManager) AmbiguousUserReferences() ([]string, error) {
	tokens, err := validateUserReferences(pm.pol, pm.users)
	if err != nil {
		return tokens, fmt.Errorf("validating policy user references: %w", err)
	}

	return nil, nil
}

// NewPolicyManager loads the policy in b: it compiles it against users and
// nodes, rejecting invalid documents and logging ambiguous stored user names.
// ValidatePolicy enforces the stricter user-write boundary.
func NewPolicyManager(b []byte, users []types.User, nodes views.Slice[types.NodeView]) (*PolicyManager, error) {
	pm, err := NewPolicyManagerFrom(nil, b, users, nodes)
	if err != nil {
		return nil, err
	}

	err = pm.ValidateUserReferences()
	if err != nil {
		log.Error().Err(err).Msg("ambiguous policy users at boot")
	}

	return pm, nil
}

// NewPolicyManagerFrom is [NewPolicyManager] reusing, from prev, a compile
// of the same document and users, what the node changes since cannot have
// moved: resolved aliases, node attributes and SSH. prev may be nil. It
// does not refuse an ambiguous user name: users change under an accepted
// document, and that must not fail its compile.
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

	// One tag index serves every resolution in this compile.
	indexed := pol.withNodesByTag(nodes).withResolvedGroups(users, nodes)
	if indexed != nil {
		indexed.aliases = aliasCache{}
	}

	var change *nodeChange

	if prev != nil && bytes.Equal(prev.src, b) && types.SamePolicyUsers(prev.users, users) {
		change = diffNodes(prev.nodesByID, nodes)
		change.indexUsers(pol, users)

		if indexed != nil {
			indexed.aliases = prev.aliases.carry(change)
		}
	}

	// Order matters, tags might be used in autoapprovers, so we need to ensure
	// that the map for tag owners is resolved before resolving autoapprovers.
	// TODO(kradalby): Order might not matter after #2417
	//
	// TODO(capsrc/owners): lift when tag owners and auto-approvers are read off the role cells
	// TODO(kradalby): capsrc/owners: both are resolved to address sets at
	// every compile, and the compile runs at every policy-fact commit, so
	// a join costs the size of every owner and approver it resolves.
	// No client dependency: headscale's own compile.
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

	pm := &PolicyManager{
		src:            b,
		aliases:        indexed.aliasesOrNil(),
		pol:            pol,
		resolvedPol:    indexed,
		users:          users,
		nodes:          nodes,
		nodesByID:      nodeIDViewMap(nodes),
		tagOwnerMap:    tagMap,
		exitSet:        exitSet,
		autoApproveMap: autoMap,
		userNodeIdx:    buildUserNodeIndex(nodes),
		nodeAttrsMap:   nodeAttrs,
		sshPolicyMap:   xsync.NewMap[sshKey, *tailcfg.SSHPolicy](),
		sshPreps:       xsync.NewMap[string, *sshPrep](),
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

	if prev == nil || !bytes.Equal(prev.src, b) {
		warnMalformedNextDNSAttrs(pol)
	}

	pm.inheritSSH(prev)

	return pm, nil
}

// inheritSSH carries prev's SSH policies over for the nodes whose policy
// [PolicyManager.SSHChangedNodes] says cannot have changed and whose own
// record did not: a recompile after a join would otherwise have every
// session it wakes prepare its SSH policy again.
func (pm *PolicyManager) inheritSSH(prev *PolicyManager) {
	if prev == nil {
		return
	}

	changed, all := pm.SSHChangedNodes(prev)
	if all {
		return
	}

	slices.Sort(changed)
	changed = slices.Compact(changed)

	prev.sshPolicyMap.Range(func(k sshKey, ssh *tailcfg.SSHPolicy) bool {
		if _, hit := slices.BinarySearch(changed, k.node); hit {
			return true
		}

		n, ok := pm.nodesByID[k.node]
		if old := prev.nodesByID[k.node]; ok && (n == old || !n.HasPolicyChange(old)) {
			pm.sshPolicyMap.Store(k, ssh)
		}

		return true
	})
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

// SSHPolicyAfresh is [PolicyManager.SSHPolicy] filling none of its caches:
// for an audit, since which rules SSH prepared is what
// [PolicyManager.SSHChangedNodes] compares.
func (pm *PolicyManager) SSHPolicyAfresh(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error) {
	if sshPol, ok := pm.sshPolicyMap.Load(sshKey{baseURL, node.ID()}); ok {
		return sshPol, nil
	}

	prep, ok := pm.sshPreps.Load(baseURL)
	if !ok {
		var err error

		prep, err = pm.pol.prepareSSH(baseURL, pm.users, pm.nodes)
		if err != nil {
			return nil, fmt.Errorf("compiling SSH policy: %w", err)
		}
	}

	return prep.forNode(node), nil
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
	case localUser == uidZeroLogin:
	case isRoot && rule.Users.ContainsRoot(),
		!isRoot && rule.Users.ContainsNonRoot(),
		!isRoot && slices.Contains(rule.Users.NormalUsers(), SSHUser(localUser)):
		return true
	}

	if !nodeHasUserIdentity(srcNode) || !rule.Users.ContainsLocalpart() {
		return false
	}

	lp, ok := resolveLocalparts(rule.Users.LocalpartEntries(), pm.users)[srcNode.User().ID()]

	return ok && lp == localUser
}

// SSHChangedNodes returns the nodes whose SSH policy can differ between
// prev and pm, any two compiles, or all when it cannot tell: the compile
// serves SSH, so it alone can say whom an SSH change reaches. Either side
// nil, as when no policy has compiled, sets all.
func (pm *PolicyManager) SSHChangedNodes(prev *PolicyManager) ([]types.NodeID, bool) {
	switch {
	case pm == prev:
		return nil, false
	case pm == nil || prev == nil:
		return nil, true
	case !pm.HasSSH() && !prev.HasSSH():
		return nil, false
	case pm.pol == nil || prev.pol == nil:
		return nil, true
	}

	return pm.sshChangedNodes(prev)
}

// HasSSH reports whether pm's policy has SSH rules: without, every node is
// sent the same empty SSH policy whatever the nodes.
func (pm *PolicyManager) HasSSH() bool {
	return pm != nil && pm.pol != nil && len(pm.pol.SSHs) > 0
}

// sshChangedNodes returns the nodes whose SSH policy can differ between
// prev and pm: for every rule that prepared differently, the nodes in its
// destinations, the users' own nodes for autogroup:self, and its sources
// when it has localpart users, who get self-access rules.
func (pm *PolicyManager) sshChangedNodes(prev *PolicyManager) ([]types.NodeID, bool) {
	// SSH prepares on first use: until a session has asked prev, there is
	// nothing to compare, and one may still render from it.
	//
	// TODO(kradalby): overwake/since-ssh-unprepared: that all wakes every
	// session; fixing it takes preparing prev's rules here, at the cost of
	// the preparation sessions would have made. No upstream reference:
	// headscale's own SSH routing.
	if (len(pm.pol.SSHs) > 0 || prev.pol != nil && len(prev.pol.SSHs) > 0) && prev.sshPreps.Size() == 0 {
		return nil, true
	}

	// TODO(kradalby): overwake/ssh-changed-nodes: every node in the
	// destinations of a rule that prepared differently is named, with the
	// owners' nodes for autogroup:self and the sources with localpart
	// users, though most of their SSH policies do not move (a member
	// joining an SSH rule's source group names every destination whose
	// policy lists principals by user). Safe: a wake and an SSH policy
	// resent unchanged. Fixing it takes comparing each named node's
	// prepared policy at both ends. Tolerated by the ssh class of
	// ruleClass in TestSessionsFollowGeneratedScenarios. SSH:
	// https://tailscale.com/docs/features/tailscale-ssh.

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

// hasViaGrants reports whether [PolicyManager.ViaRoutesForPeer] can steer
// a route. It reads the policy's grants, not the compiled ones: a via grant
// without ip compiles to no rule, so needsPerNodeFilter misses it, yet it
// still steers its destinations to the via routers.
func (pm *PolicyManager) hasViaGrants() bool {
	return pm.pol != nil && slices.ContainsFunc(pm.pol.Grants, Grant.HasVia)
}

// Filter returns the global filter rules of pm's address compile and their
// matchers.
func (pm *PolicyManager) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	if pm == nil {
		return nil, nil
	}

	a := pm.addresses()

	return a.filter, a.matchers
}

// PeerClasses holds who sees whom, as classes of nodes keyed by side set
// (see [RolePeers]): nodes in a class share one sorted view of every node
// they see, including the members themselves when the class sees itself.
type PeerClasses struct {
	keyed *keyedClasses
}

// View returns the nodes id sees, sorted, possibly including id itself.
// It is shared and must not be modified.
func (c *PeerClasses) View(id types.NodeID) []types.NodeID {
	if c == nil || c.keyed == nil {
		return nil
	}

	return c.keyed.view(id)
}

// Readers returns the nodes whose view holds id, as lists whose union they
// are; lists are shared and must not be modified. Views are not symmetric:
// an exit node sees every source of a capability grant whose destination
// reaches the internet, which does not see it. So the nodes a change of id
// reaches are these, not id's own view.
func (c *PeerClasses) Readers(id types.NodeID) [][]types.NodeID {
	if c == nil || c.keyed == nil {
		return nil
	}

	return c.keyed.readers(id)
}

// Views returns every class's view, each once. They are shared and must
// not be modified.
func (c *PeerClasses) Views() [][]types.NodeID {
	if c == nil || c.keyed == nil {
		return nil
	}

	type key struct {
		first *types.NodeID
		n     int
	}

	var (
		out   [][]types.NodeID
		seen  = map[key]struct{}{}
		empty bool
	)

	// Classes share views; each is listed once.
	for _, v := range c.keyed.views.All() {
		if len(v) == 0 {
			if !empty {
				empty = true

				out = append(out, v)
			}

			continue
		}

		k := key{&v[0], len(v)}
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}

			out = append(out, v)
		}
	}

	return out
}

// size returns the number of nodes c holds.
func (c *PeerClasses) size() int {
	if c == nil || c.keyed == nil {
		return 0
	}

	return c.keyed.sides.sets.Len()
}

// Peers returns the nodes id sees, sorted, without id.
func (c *PeerClasses) Peers(id types.NodeID) []types.NodeID {
	view := c.View(id)

	if i, found := slices.BinarySearch(view, id); found {
		return slices.Delete(slices.Clone(view), i, i+1)
	}

	return slices.Clone(view)
}

// Same reports whether every node sees the same nodes in c and o.
func (c *PeerClasses) Same(o *PeerClasses) bool {
	if c == o {
		return true
	}

	if c.size() != o.size() {
		return false
	}

	return len(c.Changed(o)) == 0
}

// Changed returns the nodes whose peers differ between old and c.
func (c *PeerClasses) Changed(old *PeerClasses) []types.NodeID {
	switch {
	case c == nil || c.keyed == nil:
		return old.held()
	case old == nil || old.keyed == nil:
		return c.held()
	}

	return c.keyed.changedSince(old.keyed)
}

// held returns every node c holds.
func (c *PeerClasses) held() []types.NodeID {
	if c == nil || c.keyed == nil {
		return nil
	}

	var out []types.NodeID

	for id := range c.keyed.sides.sets.All() {
		out = append(out, id)
	}

	return out
}

func sameSlice(a, b []types.NodeID) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// sideIndex finds nodes by address, for the nodes an SSH rule reaches.
type sideIndex struct {
	byIP []ipNode // sorted by address
}

type ipNode struct {
	ip netip.Addr
	id types.NodeID
}

func newSideIndex(nodes views.Slice[types.NodeView]) *sideIndex {
	addresses := 0

	for _, n := range nodes.All() {
		if !n.Valid() {
			continue
		}

		if n.IPv4().Valid() {
			addresses++
		}

		if n.IPv6().Valid() {
			addresses++
		}
	}

	idx := &sideIndex{}
	if addresses > 0 {
		idx.byIP = make([]ipNode, 0, addresses)
	}

	for _, n := range nodes.All() {
		if !n.Valid() {
			continue
		}

		for _, ip := range n.IPs() {
			idx.byIP = append(idx.byIP, ipNode{ip: ip, id: n.ID()})
		}
	}

	slices.SortFunc(idx.byIP, func(a, b ipNode) int { return a.ip.Compare(b.ip) })

	return idx
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

	a := pm.addresses()

	// Precompute each node's route ranges and exit-node status once; the
	// O(n^2) pair scans below would otherwise recompute them for every pair.
	type nodeRoutes struct {
		subnet []netipx.IPRange
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{
			subnet: types.RouteRanges(n.SubnetRoutes()), isExit: n.IsExitNode(),
		}
	}

	// If we have a global filter, use it for all nodes (normal case).
	// Via grants require the per-node path because the global filter
	// skips via grants (compileFilterRules: if len(grant.Via) > 0 { continue }).
	if !a.needsPerNodeFilter {
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
		words := (len(a.matchers) + 63) / 64 //nolint:mnd
		ids := make([]types.NodeID, nodes.Len())
		srcOf := make([][]uint64, nodes.Len()) // nil: source of no matcher
		dstOf := make([][]uint64, nodes.Len()) // nil: destination of no matcher
		capSrc := make([]bool, nodes.Len())

		for i, n := range nodes.All() {
			ids[i] = n.ID()
			if !n.Valid() {
				continue
			}

			ips, ri := n.IPs(), routeInfo[n.ID()]

			for k := range a.matchers {
				m := &a.matchers[k]

				if matcherReachesSource(m, ips, ri.subnet) {
					if srcOf[i] == nil {
						srcOf[i] = make([]uint64, words)
					}

					srcOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
					capSrc[i] = capSrc[i] || m.CapDestsIsTheInternet()
				}

				if matcherReachesDestination(m, ips, ri.subnet, ri.isExit) {
					if dstOf[i] == nil {
						dstOf[i] = make([]uint64, words)
					}

					dstOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
				}
			}
		}

		canAccess := func(src, dst []uint64) bool {
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

		// Build the map of all peers according to the matchers.
		for i := range ids {
			for j := i + 1; j < len(ids); j++ {
				if ids[i] == ids[j] {
					continue
				}

				linked := canAccess(srcOf[i], dstOf[j]) || canAccess(srcOf[j], dstOf[i])
				if linked || sameUser(nodes.At(i), nodes.At(j)) {
					ret[ids[i]] = append(ret[ids[i]], ids[j])
					ret[ids[j]] = append(ret[ids[j]], ids[i])

					continue
				}

				addCapSourceOnExit(ret, ids[i], ids[j], capSrc[i], routeInfo[ids[j]].isExit)
				addCapSourceOnExit(ret, ids[j], ids[i], capSrc[j], routeInfo[ids[i]].isExit)
			}
		}

		return ret
	}

	// For autogroup:self or via grants, build per-node peer relationships
	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	// Pre-compute per-node matchers using unreduced compiled rules
	// We need unreduced rules to determine peer relationships correctly.
	// Reduced rules only show destinations where the node is the target,
	// but peer relationships require the full bidirectional access rules.
	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	capSrc := make(map[types.NodeID]bool, nodes.Len())

	for _, node := range nodes.All() {
		ms := pm.nodeMatchers(node, viaPeerRule)
		nodeMatchers[node.ID()] = ms
		capSrc[node.ID()] = slices.ContainsFunc(ms, func(m matcher.Match) bool {
			return m.CapDestsIsTheInternet() &&
				matcherReachesSource(&m, node.IPs(), routeInfo[node.ID()].subnet)
		})
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
			// For via grants, rules exist on the via-designated node
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

			linked := canIAccessJ || canJAccessI || canJReachI || canIReachJ
			if linked || sameUser(nodeI, nodeJ) {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())

				continue
			}

			addCapSourceOnExit(ret, nodeI.ID(), nodeJ.ID(), capSrc[nodeI.ID()], riJ.isExit)
			addCapSourceOnExit(ret, nodeJ.ID(), nodeI.ID(), capSrc[nodeJ.ID()], riI.isExit)
		}
	}

	return ret
}

// unreducedRules returns the unreduced compiled filter rules
// for a node, combining pre-compiled global rules with per-node self
// and via rules from the stored compiled grants.
func (pm *PolicyManager) unreducedRules(node types.NodeView) []tailcfg.FilterRule {
	a := pm.addresses()

	var (
		rules []tailcfg.FilterRule
		keys  []string
	)

	for i := range a.compiledGrants {
		cg := &a.compiledGrants[i]
		rules = append(rules, cg.rules...)
		keys = append(keys, cg.ruleKeys...)

		own := pm.grantRulesFor(i, node)
		if cg.self != nil && node.IsExitNode() {
			own = nil
			for _, uid := range slices.Sorted(maps.Keys(pm.userNodeIdx)) {
				own = append(own, pm.selfFor(i, uid).rules...)
			}
		}

		rules = append(rules, own...)
		for _, rule := range own {
			if cg.via != nil {
				keys = append(keys, viaRuleKey(cg, rule))
			} else {
				keys = append(keys, filterRuleKey(rule))
			}
		}
	}

	return mergeKeyedRules(rules, keys)
}

// grantRulesFor is [grantRulesForNode] for pm's grant i. A self grant's
// rules depend only on the node's user, so they are compiled once per
// user, not once per node.
func (pm *PolicyManager) grantRulesFor(i int, node types.NodeView) []tailcfg.FilterRule {
	cg := &pm.addresses().compiledGrants[i]
	if cg.category != grantCategorySelf {
		return grantRulesForNode(cg, node, pm.userNodeIdx)
	}

	if !nodeHasUserIdentity(node) {
		return nil
	}

	return pm.selfFor(i, node.User().ID()).rules
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

	a := pm.addresses()

	if rules, ok := a.filterRulesMap.Load(node.ID()); ok {
		return rules, nil
	}

	var reduced []tailcfg.FilterRule
	if !a.needsPerNodeFilter {
		reduced = a.reducer.Reduce(node)
	} else {
		a.primeOnce.Do(func() {
			for i := range a.compiledGrants {
				a.dsts.Prime(a.compiledGrants[i].rules)
			}
		})

		unreduced := pm.unreducedRules(node)
		reduced = a.dsts.Reduce(node, unreduced)
	}

	if pm.cacheable(node) {
		a.filterRulesMap.Store(node.ID(), reduced)
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
	a := pm.addresses()

	if !a.needsPerNodeFilter {
		return a.matchers, nil
	}

	if cached, ok := a.matchersForNodeMap.Load(node.ID()); ok {
		return cached, nil
	}

	// For autogroup:self or via grants, derive matchers from
	// the stored compiled grants for this specific node.
	matchers := pm.nodeMatchers(node, compileViaForNode)

	if pm.cacheable(node) {
		a.matchersForNodeMap.Store(node.ID(), matchers)
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

	// A credential may always apply a tag it directly holds; this needs no policy.
	if slices.Contains(ownerTags, tag) {
		return true
	}

	if pm.pol == nil {
		return false
	}

	return slices.ContainsFunc(pm.pol.TagOwners[Tag(tag)], func(owner Owner) bool {
		ot, ok := owner.(*Tag)

		return ok && slices.Contains(ownerTags, string(*ot))
	})
}

// userMatchesOwner reports whether owner names user, as the owner's
// address set names the user's nodes ([namedUsers]): a new node, or a
// tagged one, is in no owner's address set.
func (pm *PolicyManager) userMatchesOwner(user types.UserView, owner Owner) bool {
	switch o := owner.(type) {
	case *Username:
		return o != nil && slices.Contains(namedUsers(o, pm.users), user.ID())
	case *Group:
		if o == nil || pm.pol == nil {
			return false
		}

		return slices.ContainsFunc(pm.pol.Groups[*o], func(u Username) bool {
			return slices.Contains(namedUsers(&u, pm.users), user.ID())
		})
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

	// Approvers match by address, each held by one node: NewState refuses a
	// shared or missing one.

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
	dstSets  []*netipx.IPSet
	internet []bool
	// reachesInternet is the regular grant's immutable destination test;
	// rebuilding its IPSet for every viewer/router pair costs tailnet size.
	reachesInternet []bool
	// primary holds, per via grant, the lowest-ID node carrying one of
	// its via tags for static policy inspection. Live snapshots elect
	// from routers using current availability instead.
	primary []map[netip.Prefix]types.NodeID
	// via holds each grant's election identity, its [viaTags]; empty for
	// a grant without via.
	via    []string
	scopes map[netip.Prefix][]viaScope
}

// viaScope is one election: the routers carrying one of via's tags that
// advertise the scope's prefix.
type viaScope struct {
	via        string
	candidates views.Slice[types.NodeID]
}

// viaKey identifies an election by content, not grant position: the via
// tags and the route fix the candidates, so the same key in another
// document is the same election and keeps its incumbent.
type viaKey struct {
	via    string
	prefix netip.Prefix
}

// viaTags is the order-free identity of a via tag list. Each tag is
// quoted: a tag may hold any separator a plain join would use, and two
// lists sharing a key would share one election.
func viaTags(tags []Tag) string {
	s := make([]string, len(tags))
	for i, t := range tags {
		s[i] = strconv.Quote(string(t))
	}

	slices.Sort(s)

	return strings.Join(slices.Compact(s), ",")
}

// viaPrep returns the policy's via preparation, building it on first use.
func (pm *PolicyManager) viaPrep() *viaPrep {
	if pm == nil {
		return nil
	}

	a := pm.addresses()

	a.viaOnce.Do(func() {
		if !pm.hasViaGrants() {
			return
		}

		grants := slices.Clone(pm.pol.Grants)
		for _, acl := range pm.pol.ACLs {
			dsts := make(Aliases, 0, len(acl.Destinations))
			for _, d := range acl.Destinations {
				dsts = append(dsts, d.Alias)
			}

			grants = append(grants, Grant{Sources: acl.Sources, Destinations: dsts})
		}

		for _, grant := range pm.pol.Grants {
			if app, ok := grant.appPart(); ok {
				grants = append(grants, app)
			}
		}

		prep := &viaPrep{
			grants:          grants,
			srcs:            make([]*netipx.IPSet, len(grants)),
			dsts:            make([][]netip.Prefix, len(grants)),
			dstSets:         make([]*netipx.IPSet, len(grants)),
			internet:        make([]bool, len(grants)),
			reachesInternet: make([]bool, len(grants)),
			primary:         make([]map[netip.Prefix]types.NodeID, len(grants)),
			via:             make([]string, len(grants)),
			scopes:          make(map[netip.Prefix][]viaScope),
		}

		scoped := make(map[viaKey]struct{})

		// Grants sharing tags and destinations elect from the same
		// routers and win the same primaries: build each combination once
		// and share its candidates.
		candidates := make([]map[netip.Prefix][]types.NodeID, 0, len(grants))
		primaries := make([]map[netip.Prefix]types.NodeID, 0, len(grants))

		for i, grant := range grants {
			var b netipx.IPSetBuilder

			for _, src := range grant.Sources {
				ips, err := src.Resolve(a.indexed, pm.users, pm.nodes)
				if err != nil || ips == nil {
					continue
				}

				for _, p := range ips.Prefixes() {
					b.AddPrefix(p)
				}
			}

			prep.srcs[i], _ = b.IPSet()
			prep.dsts[i], prep.internet[i] = resolveViaDestinations(pm.pol, pm.users, pm.nodes, grant.Destinations)
			// A public prefix steers the exit routes as autogroup:internet
			// does.
			prep.internet[i] = prep.internet[i] || grant.HasVia() && reachInternet(prep.dsts[i])

			if !grant.HasVia() {
				var dst netipx.IPSetBuilder
				for _, prefix := range prep.dsts[i] {
					dst.AddPrefix(prefix)
				}

				prep.dstSets[i], _ = dst.IPSet()
				prep.reachesInternet[i] = grantReachesInternet(grant, prep.dsts[i])

				candidates = append(candidates, nil)
				primaries = append(primaries, nil)

				continue
			}

			prep.via[i] = viaTags(grant.Via)

			var (
				routers map[netip.Prefix][]types.NodeID
				primary map[netip.Prefix]types.NodeID
			)

			for j := range i {
				if prep.via[j] == prep.via[i] && slices.Equal(prep.dsts[j], prep.dsts[i]) {
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

			// Grants sharing tags share each route's election.
			for prefix, ids := range routers {
				k := viaKey{prep.via[i], prefix}
				if _, ok := scoped[k]; ok {
					continue
				}

				scoped[k] = struct{}{}

				prep.scopes[prefix] = append(prep.scopes[prefix], viaScope{prep.via[i], views.SliceOf(ids)})
			}

			prep.primary[i] = primary
		}

		a.via = prep
	})

	return a.via
}

// ViaRoutes binds immutable live elections to what defines their scopes
// and steering: a via plan and the side sets it steers by, as served (see
// [ElectViaPlan]), or a compiled policy, which the policy audit holds the
// served elections against. An empty election still applies its binding's
// exclusions and exit steering.
type ViaRoutes struct {
	policy *PolicyManager

	plan  *ViaPlan
	sides Sides

	winners *graph.Map[viaKey, types.NodeID]
}

// WithoutPolicy retains only the election winners, for change tracking,
// dropping the binding — a compiled policy, or a via plan and the sides —
// so a holder pins neither. The result supports ChangedNodes, not
// steering.
func (v *ViaRoutes) WithoutPolicy() *ViaRoutes {
	if v == nil {
		return nil
	}

	return &ViaRoutes{winners: v.winners}
}

// ElectViaAfresh elects every scope of pm's via grants afresh, each seeded with
// previous's winner as its incumbent, dropping keys pm no longer scopes;
// previous may be nil. elect runs synchronously with read-only candidates
// and the scope's prior winner; it must use the caller's snapshot. It is
// the from-scratch election the served one, over the via plan (see
// [ElectViaPlan]), is held to.
func (pm *PolicyManager) ElectViaAfresh(previous *ViaRoutes, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) *ViaRoutes {
	e := newViaElection(previous)

	seen := make(map[viaKey]struct{})

	if prep := pm.viaPrep(); prep != nil {
		for prefix, scopes := range prep.scopes {
			for _, scope := range scopes {
				seen[viaKey{scope.via, prefix}] = struct{}{}
				e.electScope(prefix, scope, elect)
			}
		}
	}

	for k := range e.winners.All() {
		if _, ok := seen[k]; !ok {
			e.set(k, 0, false)
		}
	}

	r, _ := e.result(pm)

	return r
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

func (e *viaElection) electScope(prefix netip.Prefix, scope viaScope, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) {
	k := viaKey{scope.via, prefix}

	// Read the staged edit once it exists, as set does: a scope elected
	// earlier in this pass is its own incumbent.
	incumbent, _ := e.winners.Get(k)
	if e.edit != nil {
		incumbent, _ = e.edit.Get(k)
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

// ForPeer resolves routes using only this result's binding and live
// elections.
func (v *ViaRoutes) ForPeer(viewer, peer types.NodeView) types.ViaRouteResult {
	if v == nil {
		return types.ViaRouteResult{}
	}

	if v.plan != nil {
		return v.plan.Steer(v.sides, viewer, peer, func(key string, prefix netip.Prefix) types.NodeID {
			id, _ := v.winners.Get(viaKey{key, prefix})

			return id
		})
	}

	if v.policy == nil {
		return types.ViaRouteResult{}
	}

	// The callback runs only when the policy has a via preparation.
	prep := v.policy.viaPrep()

	return v.policy.viaRoutesForPeer(viewer, peer, func(grant int, prefix netip.Prefix) types.NodeID {
		id, _ := v.winners.Get(viaKey{prep.via[grant], prefix})
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

	var scopes map[netip.Prefix][]viaScope

	switch {
	case v.plan != nil:
		scopes = v.plan.scopes
	case v.policy.viaPrep() != nil:
		scopes = v.policy.viaPrep().scopes
	default:
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

		for _, scope := range scopes[k.prefix] {
			if scope.via != k.via {
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
		if grantHasAutoGroupInternet[i] {
			matchedPrefixes = append(matchedPrefixes, peer.OfferedExitRoutes()...)
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

			// Most node-only grants cannot reach these routes. Keep the
			// ordered prefix scan only for grants that can affect steering.
			overlaps := func(p netip.Prefix) bool {
				return !tsaddr.IsExitRoute(p) && prep.dstSets[i].OverlapsPrefix(p)
			}
			if !prep.reachesInternet[i] &&
				!slices.ContainsFunc(result.Include, overlaps) &&
				!slices.ContainsFunc(result.Exclude, overlaps) {
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
			if prep.reachesInternet[i] {
				result.Exclude = slices.DeleteFunc(result.Exclude, tsaddr.IsExitRoute)
			}
		}
	}

	result.Include = uniquePrefixes(result.Include)
	result.Exclude = uniquePrefixes(result.Exclude)

	return result
}

// grantReachesInternet reports whether a grant's destinations include
// the internet. Neither the wildcard nor autogroup:internet resolves
// to 0.0.0.0/0, so check the aliases themselves.
func grantReachesInternet(grant Grant, dsts []netip.Prefix) bool {
	if len(grant.InternetProtocols) == 0 && len(grant.App) > 0 {
		return false
	}

	internetAlias := slices.ContainsFunc(grant.Destinations, func(d Alias) bool {
		if ag, ok := d.(*AutoGroup); ok {
			return ag.Is(AutoGroupInternet)
		}

		_, ok := d.(Asterix)

		return ok
	})
	if internetAlias {
		return true
	}

	var b netipx.IPSetBuilder
	for _, p := range dsts {
		b.AddPrefix(p)
	}

	// Resolved prefixes are valid, so the builder cannot fail.
	set, _ := b.IPSet()

	return util.HasInternetDestination(set)
}

func (pm *PolicyManager) Version() int {
	return 2
}

// DebugStringFor returns the compile's document, auto-approvers, tag owners
// and node list, with filter, the global filter served, and its matchers.
// The address compile has no say: a debug page must not build it.
func (pm *PolicyManager) DebugStringFor(filter []tailcfg.FilterRule) string {
	if pm == nil {
		return "PolicyManager is not setup"
	}

	return pm.debugString("Served global filter (expanded from the policy's templates and membership; "+
		"each node is sent its reduction, with its own autogroup:self and via rules)", filter)
}

func (pm *PolicyManager) debugString(filterLabel string, filter []tailcfg.FilterRule) string {
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

	fmt.Fprintf(&sb, "AutoApprover (%d, the compile's):\n", len(pm.autoApproveMap))

	for prefix, approveAddrs := range pm.autoApproveMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range approveAddrs.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	fmt.Fprintf(&sb, "TagOwner (%d, the compile's):\n", len(pm.tagOwnerMap))

	for prefix, tagOwners := range pm.tagOwnerMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range tagOwners.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	if filter != nil {
		out, err := json.MarshalIndent(filter, "", "  ")
		if err == nil {
			sb.WriteString(filterLabel + ":\n")
			sb.Write(out)
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("\n\n")
	sb.WriteString("Matchers of that filter:\n")

	for _, match := range matcher.MatchesFromFilterRules(filter) {
		sb.WriteString(match.DebugString())
		sb.WriteString("\n")
	}

	sb.WriteString("\n\n")
	sb.WriteString("Nodes the compile ran against:\n")

	for _, node := range pm.nodes.All() {
		sb.WriteString(node.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// resolveTagOwners resolves the [TagOwners] to a map of [Tag] to [netipx.IPSet].
// The resulting map can be used to quickly look up the IPSet for a given [Tag].
// It is intended for internal use in a [PolicyManager].
func resolveTagOwners(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (map[Tag]*netipx.IPSet, error) {
	ret := make(map[Tag]*netipx.IPSet)
	if p == nil {
		return ret, nil
	}

	for tag, owners := range p.TagOwners {
		var ips netipx.IPSetBuilder

		for _, owner := range owners {
			switch o := owner.(type) {
			case *Tag:
				// validate refuses this; a policy built in code can still
				// name one.
				if _, ok := p.TagOwners[*o]; !ok {
					return nil, fmt.Errorf("tagOwners[%q]: %q: %w",
						string(tag), string(*o), ErrUndefinedTagReference)
				}
			case Alias:
				// If it does not resolve, that means the tag is not associated with any IP addresses.
				resolved, _ := p.resolveAlias(o, users, nodes)
				if resolved != nil {
					for _, pref := range resolved.Prefixes() {
						ips.AddPrefix(pref)
					}
				}

			default:
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

	if pm.nodeAttrsMap == nil {
		return map[types.NodeID]tailcfg.NodeCapMap{}
	}

	return pm.nodeAttrsMap
}

// Audit compiles src from scratch and returns how pm, which compiled the
// same document, users and nodes incrementally, differs from it in what
// pm serves: tag owners, auto-approvers, node attributes, or any node's
// SSH policy. It is for debugging and tests; it costs a full compile and
// every node's SSH policy.
func (pm *PolicyManager) Audit(src []byte, users []types.User, nodes views.Slice[types.NodeView]) error {
	fresh, err := NewPolicyManagerFrom(nil, src, users, nodes)
	if err != nil {
		return fmt.Errorf("compiling from scratch: %w", err)
	}

	for _, c := range []struct {
		what     string
		inc, fsh any
	}{
		{"tag owners", pm.tagOwnerMap, fresh.tagOwnerMap},
		{"auto-approvers", pm.autoApproveMap, fresh.autoApproveMap},
		{"exit auto-approvers", pm.exitSet, fresh.exitSet},
		{"node attributes", pm.nodeAttrsMap, fresh.nodeAttrsMap},
	} {
		if !reflect.DeepEqual(c.inc, c.fsh) {
			return fmt.Errorf("%w: %s", errAuditMismatch, c.what)
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

var errAuditMismatch = errors.New("incremental compile differs from a compile from scratch")

var ErrPolicyEmpty = errors.New(`policy is empty, use "{}" to allow all`)

func warnMalformedNextDNSAttrs(pol *Policy) {
	bad := pol.malformedNextDNSAttrs()
	if len(bad) == 0 {
		return
	}

	log.Warn().
		Strs(zf.NodeAttrs, bad).
		Msg("nextdns attrs have no effect: a profile must match [A-Za-z0-9._-]{1,64}")
}

func (pm *PolicyManager) DERPMap() *tailcfg.DERPMap {
	if pm == nil {
		return nil
	}

	if pm.pol == nil {
		return nil
	}

	return pm.pol.DERPMap
}

func sameUser(a, b types.NodeView) bool {
	if a.IsTagged() || b.IsTagged() {
		return false
	}

	userA, okA := a.UserID().GetOk()
	userB, okB := b.UserID().GetOk()

	return okA && okB && userA == userB
}

func addCapSourceOnExit(
	ret map[types.NodeID][]types.NodeID,
	src, exit types.NodeID,
	srcHasCap, isExit bool,
) {
	if srcHasCap && isExit {
		ret[exit] = append(ret[exit], src)
	}
}

func matcherReachesSource(m *matcher.Match, ips []netip.Addr, routes []netipx.IPRange) bool {
	return m.SrcsContainsIPs(ips...) || (len(routes) > 0 && m.SrcsOverlapsRanges(routes))
}

func matcherReachesDestination(
	m *matcher.Match,
	ips []netip.Addr,
	routes []netipx.IPRange,
	isExit bool,
) bool {
	return m.DestsContainsIP(ips...) || (len(routes) > 0 && m.DestsOverlapsRanges(routes)) ||
		(isExit && m.DestsIsTheInternet())
}

func (pm *PolicyManager) nodeMatchers(node types.NodeView, viaRules func(*compiledGrant, types.NodeView) []tailcfg.FilterRule) []matcher.Match {
	return slices.Concat(pm.addresses().matchers, pm.nodeOnlyMatchers(node, viaRules))
}

func uniquePrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(in))

	out := in[:0]
	for _, p := range in {
		if !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}

	return out
}

func (pm *PolicyManager) selfFor(i int, uid uint) keyedRules {
	key := selfRulesKey{grant: i, user: uid}
	a := pm.addresses()

	if rules, ok := a.selfRules.Load(key); ok {
		return rules
	}

	rules, _ := a.selfRules.LoadOrStore(key, newKeyedRules(compileSelfForUser(&a.compiledGrants[i], pm.userNodeIdx[uid])))
	a.dsts.Prime(rules.rules)

	return rules
}

func (pm *PolicyManager) nodeOnlyMatchers(node types.NodeView, viaRules func(*compiledGrant, types.NodeView) []tailcfg.FilterRule) []matcher.Match {
	var ms []matcher.Match

	a := pm.addresses()

	for i := range a.compiledGrants {
		cg := &a.compiledGrants[i]
		switch cg.category {
		case grantCategoryRegular:
		case grantCategorySelf:
			if nodeHasUserIdentity(node) {
				ms = append(ms, pm.selfFor(i, node.User().ID()).matchers...)
			}
		case grantCategoryVia:
			for _, rule := range viaRules(cg, node) {
				ms = append(ms, matcher.MatchFromFilterRuleSrcs(rule, cg.via.srcSet).ViaRouter())
			}
		}
	}

	return ms
}
