package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/views"
)

var (
	ErrInvalidAction = errors.New("invalid action")
	errSelfInSources = errors.New("autogroup:self cannot be used in sources")
)

// companionCap pairs a well-known Tailscale capability with its
// companion capability.
type companionCap struct {
	original  peercap.Cap
	companion peercap.Cap
}

// companionCaps lists certain well-known Tailscale capabilities and
// their companion capability. When a grant includes one of these
// capabilities, Tailscale automatically generates an additional
// [tailcfg.FilterRule] with the companion capability and a nil CapMap value.
// The slice is ordered by the original capability name so that
// generated companion rules are emitted deterministically.
var companionCaps = []companionCap{
	{peercap.Taildrive, peercap.TaildriveSharer},
	{peercap.Relay, peercap.RelayTarget},
}

// companionCapGrantRules returns additional [tailcfg.FilterRule]s for any
// well-known capabilities that have companion caps. Companion rules
// are **reversed**: SrcIPs come from the original destinations and
// CapGrant Dsts come from the original sources. This allows
// [policyutil.ReduceFilterRules] to distribute companion rules to source
// nodes (e.g. drive-sharer goes to the member nodes, not the destination).
// Rules are ordered by the original capability name.
//
// dstIPStrings are the resolved destination IPs as strings (used as
// companion SrcIPs). srcPrefixes are the resolved source IPs as
// [netip.Prefix] (used as companion CapGrant Dsts).
func companionCapGrantRules(
	dstIPStrings []string,
	srcPrefixes []netip.Prefix,
	capMap tailcfg.PeerCapMap,
) []tailcfg.FilterRule {
	companions := make([]tailcfg.FilterRule, 0, len(companionCaps))

	for _, c := range companionCaps {
		if _, ok := capMap[c.original]; ok {
			companions = append(companions, tailcfg.FilterRule{
				SrcIPs: dstIPStrings,
				CapGrant: []tailcfg.CapGrant{
					{
						Dsts: srcPrefixes,
						CapMap: tailcfg.PeerCapMap{
							c.companion: nil,
						},
					},
				},
			})
		}
	}

	return companions
}

// sourcesHaveWildcard returns true if any of the source aliases is
// a wildcard (*). Used to determine whether approved subnet routes
// should be appended to [tailcfg.FilterRule.SrcIPs].
func sourcesHaveWildcard(srcs Aliases) bool {
	for _, src := range srcs {
		if _, ok := src.(Asterix); ok {
			return true
		}
	}

	return false
}

// sourcesHaveDangerAll returns true if any of the source aliases is
// autogroup:danger-all. When present, [tailcfg.FilterRule.SrcIPs] should
// be ["*"] to represent all IP addresses including non-Tailscale addresses.
func sourcesHaveDangerAll(srcs Aliases) bool {
	for _, src := range srcs {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupDangerAll) {
			return true
		}
	}

	return false
}

// srcIPsWithRoutes returns the [tailcfg.FilterRule.SrcIPs] string slice,
// appending approved subnet routes when the sources include a wildcard.
// When hasDangerAll is true, returns ["*"] to represent all IPs.
func srcIPsWithRoutes(
	resolved ResolvedAddresses,
	hasWildcard bool,
	hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	if hasDangerAll {
		return []string{"*"}
	}

	ips := resolved.Strings()
	if hasWildcard {
		ips = append(ips, approvedSubnetRoutes(nodes)...)
	}

	return ips
}

// compileFilterRules takes a set of nodes and a [Policy] and generates a
// set of Tailscale compatible [tailcfg.FilterRule]s used to allow traffic
// on clients.
func (pol *Policy) compileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return noRulesFilter(users, nodes)
	}

	return globalFilterRules(pol.compileGrants(users, nodes))
}

func (pol *Policy) destinationsToNetPortRange(
	users types.Users,
	nodes views.Slice[types.NodeView],
	dests Aliases,
	ports []tailcfg.PortRange,
) []tailcfg.NetPortRange {
	var ret []tailcfg.NetPortRange

	for _, dest := range dests {
		// Check if destination is a wildcard - use "*" directly instead of expanding
		if _, isWildcard := dest.(Asterix); isWildcard {
			for _, port := range ports {
				ret = append(ret, tailcfg.NetPortRange{
					IP:    "*",
					Ports: port,
				})
			}

			continue
		}

		ips, err := dest.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving destination ips")
		}

		if ips == nil {
			log.Debug().Caller().Msgf("destination resolved to nil ips: %v", dest)
			continue
		}

		for _, ip := range ips.Strings() {
			for _, port := range ports {
				ret = append(ret, tailcfg.NetPortRange{
					IP:    ip,
					Ports: port,
				})
			}
		}
	}

	return ret
}

// compileFilterRulesForNode compiles filter rules for a specific node.
func (pol *Policy) compileFilterRulesForNode(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return noRulesFilter(users, nodes)
	}

	grants := pol.compileGrants(users, nodes)
	userIdx := buildUserNodeIndex(nodes)
	precomputeSelfRules(grants, userIdx)

	return filterRulesForNode(grants, node, userIdx)
}

var sshAccept = tailcfg.SSHAction{
	Reject:                    false,
	Accept:                    true,
	AllowAgentForwarding:      true,
	AllowLocalPortForwarding:  true,
	AllowRemotePortForwarding: true,
}

// checkPeriodFromRule extracts the check period duration from an [SSH] rule.
// Returns [SSHCheckPeriodDefault] if no checkPeriod is configured,
// 0 if checkPeriod is "always", or the configured duration otherwise.
// This is used server-side by [PolicyManager.SSHCheckParams] to resolve the
// real period when the client calls back; the wire format always sends 0.
func checkPeriodFromRule(rule SSH) time.Duration {
	switch {
	case rule.CheckPeriod == nil:
		return SSHCheckPeriodDefault
	case rule.CheckPeriod.Always:
		return 0
	default:
		return rule.CheckPeriod.Duration
	}
}

func sshCheck(baseURL string) tailcfg.SSHAction {
	holdURL := baseURL + "/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"

	return tailcfg.SSHAction{
		Reject:          false,
		Accept:          false,
		SessionDuration: 0,
		// Replaced in the client:
		//   * $SRC_NODE_IP (URL escaped)
		//   * $SRC_NODE_ID (Node.ID as int64 string)
		//   * $DST_NODE_IP (URL escaped)
		//   * $DST_NODE_ID (Node.ID as int64 string)
		//   * $SSH_USER (URL escaped, ssh user requested)
		//   * $LOCAL_USER (URL escaped, local user mapped)
		HoldAndDelegate:           holdURL,
		AllowAgentForwarding:      false,
		AllowLocalPortForwarding:  false,
		AllowRemotePortForwarding: false,
	}
}

// compileSSHPolicy compiles the SSH rules node receives.
func (pol *Policy) compileSSHPolicy(
	baseURL string,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	prep, err := pol.prepareSSH(baseURL, users, nodes)
	if err != nil {
		return nil, err
	}

	return prep.forNode(node), nil
}

// sshPrep is the part of an SSH policy's compile that is the same for
// every node: each rule's sources, principals, users and destinations.
// Compiling it once per policy keeps a node's compile from walking every
// node again.
type sshPrep struct {
	rules []*sshRulePrep
}

// sshRulePrep is one SSH rule with live sources, prepared.
type sshRulePrep struct {
	userRules map[uint][]*tailcfg.SSHRule
	destRules []*tailcfg.SSHRule
	// index is the rule's position in the policy's SSH rules.
	index int

	srcIPs    ResolvedAddresses
	action    tailcfg.SSHAction
	acceptEnv []string

	// userMap always has a root entry.
	userMap map[string]string
	// localpart is set when the rule has localpart entries;
	// localpartByUser maps a user to theirs.
	localpart       bool
	localpartByUser map[uint]string

	userIDs          []uint
	principalsByUser map[uint][]*tailcfg.SSHPrincipal
	tagged           []*tailcfg.SSHPrincipal
	// all is every user's principals, then the tagged ones (a node with
	// N tags appears N times, as in SaaS).
	all []*tailcfg.SSHPrincipal

	self bool
	// dests holds the destinations other than autogroup:self; nil when
	// there are none.
	dests *netipx.IPSet
}

func (pol *Policy) prepareSSH(
	baseURL string,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*sshPrep, error) {
	return pol.prepareSSHFrom(nil, nil, baseURL, users, nodes)
}

// prepareSSHFrom is [Policy.prepareSSH] reusing, from prev, a prepare of
// the same document and users, each rule the change since cannot reach.
// prev and change are nil to prepare from scratch.
func (pol *Policy) prepareSSHFrom(
	prev *sshPrep,
	change *nodeChange,
	baseURL string,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*sshPrep, error) {
	prep := &sshPrep{}
	if pol == nil {
		return prep, nil
	}

	var last map[int]*sshRulePrep

	if prev != nil && change != nil {
		last = make(map[int]*sshRulePrep, len(prev.rules))
		for _, r := range prev.rules {
			last[r.index] = r
		}
	}

	sources := make(map[string]*sshRulePrep)

	for index, rule := range pol.SSHs {
		if last != nil && !change.movesSSH(rule) {
			// A rule prepared to nothing stays that way.
			if r := last[index]; r != nil {
				prep.rules = append(prep.rules, r)
				sources[strings.Join(r.srcIPs.Strings(), ",")] = r
			}

			continue
		}

		r, err := pol.prepareSSHRule(index, rule, baseURL, users, nodes)
		if err != nil {
			return nil, err
		}

		if r != nil {
			key := strings.Join(r.srcIPs.Strings(), ",")
			if prior, ok := sources[key]; ok {
				r.srcIPs, r.userIDs, r.principalsByUser, r.tagged, r.all = prior.srcIPs, prior.userIDs, prior.principalsByUser, prior.tagged, prior.all
				for uid, rules := range r.userRules {
					for _, rule := range rules {
						rule.Principals = r.principalsByUser[uid]
					}
				}

				if !r.localpart {
					for _, rule := range r.destRules {
						rule.Principals = r.all
					}
				}
			} else {
				sources[key] = r
			}

			prep.rules = append(prep.rules, r)
		}
	}

	return prep, nil
}

// prepareSSHRule prepares one SSH rule; nil when its sources resolve to
// nothing.
func (pol *Policy) prepareSSHRule(
	index int,
	rule SSH,
	baseURL string,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*sshRulePrep, error) {
	r := &sshRulePrep{index: index}

	var otherDests []Alias

	for _, dst := range rule.Destinations {
		if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			r.self = true
		} else {
			otherDests = append(otherDests, dst)
		}
	}

	srcIPs, err := pol.resolveAliases(Aliases(rule.Sources), users, nodes)
	if err != nil {
		log.Trace().Caller().Err(err).Msgf(
			"ssh policy compilation failed resolving source ips for rule %+v", rule,
		)
	}

	if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
		return nil, nil //nolint:nilnil // a rule without sources prepares to nothing
	}

	r.srcIPs = srcIPs

	switch rule.Action {
	case SSHActionAccept:
		r.action = sshAccept
	case SSHActionCheck:
		r.action = sshCheck(baseURL)
	default:
		return nil, fmt.Errorf(
			"parsing SSH policy, unknown action %q, index: %d: %w",
			rule.Action, index, err,
		)
	}

	r.acceptEnv = rule.AcceptEnv

	const rootUser = "root"

	r.userMap = make(map[string]string, len(rule.Users))
	if rule.Users.ContainsNonRoot() {
		r.userMap["*"] = "="
	}

	if rule.Users.ContainsRoot() {
		r.userMap[rootUser] = rootUser
	} else {
		r.userMap[rootUser] = ""
	}

	for _, u := range rule.Users.NormalUsers() {
		r.userMap[u.String()] = u.String()
	}

	r.userMap[uidZeroLogin] = ""

	r.localpart = rule.Users.ContainsLocalpart()
	if r.localpart {
		r.localpartByUser = resolveLocalparts(rule.Users.LocalpartEntries(), users)
	}

	r.userIDs, r.principalsByUser, r.tagged = groupSourcesByUser(nodes, srcIPs)

	for _, uid := range r.userIDs {
		r.all = append(r.all, r.principalsByUser[uid]...)
	}

	r.all = append(r.all, r.tagged...)

	if len(otherDests) > 0 {
		var dest netipx.IPSetBuilder

		for _, dst := range otherDests {
			ips, err := pol.resolveAlias(dst, users, nodes)
			if err != nil {
				log.Trace().Caller().Err(err).
					Msgf("resolving destination ips")
			}

			if ips != nil {
				for _, pref := range ips.Prefixes() {
					dest.AddPrefix(pref)
				}
			}
		}

		r.dests, err = dest.IPSet()
		if err != nil {
			return nil, err
		}
	}

	if r.self || r.localpart {
		r.userRules = make(map[uint][]*tailcfg.SSHRule, len(r.userIDs))
		for _, uid := range r.userIDs {
			r.userRules[uid] = r.rules(r.principalsByUser[uid], uid, true)
		}
	}

	if r.dests != nil {
		if r.localpart {
			for _, uid := range r.userIDs {
				r.destRules = append(r.destRules, r.userRules[uid]...)
			}

			if len(r.tagged) > 0 {
				r.destRules = append(r.destRules, r.rules(r.tagged, 0, false)...)
			}
		} else if len(r.all) > 0 {
			r.destRules = r.rules(r.all, 0, false)
		}
	}

	return r, nil
}

// forNode returns the SSH rules node receives. Never nil: clients read a
// nil SSHPolicy as "keep the previous rules", so revoked access would
// stay. SaaS sends "rules":[].
func (prep *sshPrep) forNode(node types.NodeView) *tailcfg.SSHPolicy {
	// Never nil: clients read a nil SSHPolicy as "keep the previous
	// rules", so revoked access would stay. SaaS sends "rules":[].
	rules := []*tailcfg.SSHRule{}

	for _, cr := range prep.rules {
		// Handle autogroup:self destinations.
		// Tagged nodes can't match autogroup:self.
		if cr.self && nodeHasUserIdentity(node) {
			rules = append(rules, cr.userRules[node.User().ID()]...)
		}

		// Handle other destinations.
		if cr.dests == nil {
			continue
		}

		if node.InIPSet(cr.dests) {
			// Node is a destination — emit rules.
			rules = append(rules, cr.destRules...)
		} else if cr.localpart &&
			slices.ContainsFunc(node.IPs(), cr.srcIPs.Contains) {
			// Self-access: source node not in destination set
			// receives rules scoped to its own user.
			if node.IsTagged() {
				var builder netipx.IPSetBuilder

				node.AppendToIPSet(&builder)

				ipSet, err := builder.IPSet()
				if err == nil && ipSet != nil {
					if principals := ipSetToPrincipals(ipSet); len(principals) > 0 {
						rules = append(rules, cr.rules(principals, 0, false)...)
					}
				}
			} else if node.User().Valid() {
				rules = append(rules, cr.userRules[node.User().ID()]...)
			}
		}
	}

	// Sort rules: check (HoldAndDelegate) before accept, per Tailscale
	// evaluation order (most-restrictive first).
	slices.SortStableFunc(rules, func(a, b *tailcfg.SSHRule) int {
		aIsCheck := a.Action != nil && a.Action.HoldAndDelegate != ""

		bIsCheck := b.Action != nil && b.Action.HoldAndDelegate != ""
		if aIsCheck == bIsCheck {
			return 0
		}

		if aIsCheck {
			return -1
		}

		return 1
	})

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}
}

// ipSetToPrincipals converts an [netipx.IPSet] into SSH principals, one per address.
func ipSetToPrincipals(ipSet *netipx.IPSet) []*tailcfg.SSHPrincipal {
	if ipSet == nil {
		return nil
	}

	var principals []*tailcfg.SSHPrincipal

	for addr := range util.IPSetAddrIter(ipSet) {
		principals = append(principals, &tailcfg.SSHPrincipal{
			NodeIP: addr.String(),
		})
	}

	return principals
}

// resolveLocalparts maps each user whose email matches a localpart:*@<domain>
// entry to their email local-part. Returns userID → localPart (e.g. {1: "alice"}).
// This is a pure data function — no node walking or IP resolution.
func resolveLocalparts(
	entries []SSHUser,
	users types.Users,
) map[uint]string {
	if len(entries) == 0 {
		return nil
	}

	result := make(map[uint]string)

	for _, entry := range entries {
		domain, err := entry.ParseLocalpart()
		if err != nil {
			log.Warn().Err(err).Msgf(
				"skipping invalid localpart entry %q during SSH compilation",
				entry,
			)

			continue
		}

		for _, user := range users {
			if user.Email == "" {
				continue
			}

			localpart, emailDomain, found := strings.CutLast(user.Email, "@")
			if !found {
				continue
			}

			if !strings.EqualFold(emailDomain, domain) {
				continue
			}

			// The client looks a numeric login up as a UID, so 0@domain would
			// reach root and another number someone else's account.
			_, notNumeric := strconv.ParseUint(localpart, util.Base10, 32)
			if notNumeric == nil {
				continue
			}

			result[user.ID] = localpart
		}
	}

	return result
}

// groupSourcesByUser groups source node IPs by user ownership. Returns sorted
// user IDs for deterministic iteration, per-user principals, and tagged principals.
// Only includes nodes whose IPs are in the srcIPs set.
func groupSourcesByUser(
	nodes views.Slice[types.NodeView],
	srcIPs ResolvedAddresses,
) ([]uint, map[uint][]*tailcfg.SSHPrincipal, []*tailcfg.SSHPrincipal) {
	userIPSets := make(map[uint]*netipx.IPSetBuilder)

	var taggedPrincipals []*tailcfg.SSHPrincipal

	for _, n := range nodes.All() {
		if !slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
			continue
		}

		if n.IsTagged() {
			// Tailscale SaaS resolves autogroup:tagged by
			// iterating tag membership lists. A node with N
			// tags produces N copies of its IPs in the
			// principal list. Match that behavior so the SSH
			// wire format is identical.
			for range n.Tags().Len() {
				for _, ip := range n.IPs() {
					taggedPrincipals = append(taggedPrincipals,
						&tailcfg.SSHPrincipal{NodeIP: ip.String()})
				}
			}

			continue
		}

		if !n.User().Valid() {
			continue
		}

		uid := n.User().ID()

		if _, ok := userIPSets[uid]; !ok {
			userIPSets[uid] = &netipx.IPSetBuilder{}
		}

		n.AppendToIPSet(userIPSets[uid])
	}

	var userIDs []uint

	principalsByUser := make(map[uint][]*tailcfg.SSHPrincipal, len(userIPSets))

	for uid, builder := range userIPSets {
		ipSet, err := builder.IPSet()
		if err != nil || ipSet == nil {
			continue
		}

		if principals := ipSetToPrincipals(ipSet); len(principals) > 0 {
			principalsByUser[uid] = principals
			userIDs = append(userIDs, uid)
		}
	}

	slices.Sort(userIDs)

	return userIDs, principalsByUser, taggedPrincipals
}

// filterRuleKey generates a unique key for merging based on [tailcfg.FilterRule.SrcIPs]
// and [tailcfg.FilterRule.IPProto].
func filterRuleKey(rule tailcfg.FilterRule) string {
	return fmt.Sprintf("%s|%v", strings.Join(rule.SrcIPs, ","), rule.IPProto)
}

// mergeFilterRules merges rules with identical [tailcfg.FilterRule.SrcIPs] and
// [tailcfg.FilterRule.IPProto] by combining their [tailcfg.FilterRule.DstPorts].
// DstPorts are NOT deduplicated to match Tailscale behavior.
// [tailcfg.CapGrant] rules (which have no [tailcfg.FilterRule.DstPorts]) are
// passed through without merging since [tailcfg.CapGrant] and
// [tailcfg.FilterRule.DstPorts] are mutually exclusive in a
// [tailcfg.FilterRule].

func ruleKeys(rules []tailcfg.FilterRule) []string {
	// sharedSrcIPs identifies a SrcIPs slice by its backing array.
	type sharedSrcIPs struct {
		first   *string
		n       int
		ipProto string
	}

	built := make(map[sharedSrcIPs]string)
	keys := make([]string, len(rules))

	for i, rule := range rules {
		if len(rule.CapGrant) > 0 {
			continue
		}

		shared := sharedSrcIPs{
			n:       len(rule.SrcIPs),
			ipProto: fmt.Sprint(rule.IPProto),
		}
		if len(rule.SrcIPs) > 0 {
			shared.first = &rule.SrcIPs[0]
		}

		key, ok := built[shared]
		if !ok {
			key = filterRuleKey(rule)
			built[shared] = key
		}

		keys[i] = key
	}

	return keys
}

func mergeKeyedRules(rules []tailcfg.FilterRule, keys []string) []tailcfg.FilterRule {
	if len(rules) <= 1 {
		return rules
	}

	keyToIdx := make(map[string]int)
	owned := make(map[int]bool)
	result := make([]tailcfg.FilterRule, 0, len(rules))

	for i, rule := range rules {
		if len(rule.CapGrant) > 0 {
			result = append(result, rule)

			continue
		}

		if idx, ok := keyToIdx[keys[i]]; ok {
			if !owned[idx] {
				result[idx].DstPorts = slices.Clone(result[idx].DstPorts)
				owned[idx] = true
			}

			result[idx].DstPorts = append(result[idx].DstPorts, rule.DstPorts...)

			continue
		}

		keyToIdx[keys[i]] = len(result)
		result = append(result, tailcfg.FilterRule{
			SrcIPs:   rule.SrcIPs,
			DstPorts: slices.Clip(rule.DstPorts),
			IPProto:  rule.IPProto,
		})
	}

	return result
}

func filterIP(pref netip.Prefix) string {
	if pref.IsSingleIP() {
		return pref.Addr().String()
	}

	return pref.String()
}

func noRulesFilter(users types.Users, nodes views.Slice[types.NodeView]) []tailcfg.FilterRule {
	return globalFilterRules(allowAllPolicy().compileGrants(users, nodes))
}

var allowAllPolicy = sync.OnceValue(func() *Policy {
	pol, err := unmarshalPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	if err != nil {
		panic(err)
	}

	return pol
})

const uidZeroLogin = "0"

func (r *sshRulePrep) rules(
	principals []*tailcfg.SSHPrincipal,
	uid uint,
	hasUID bool,
) []*tailcfg.SSHRule {
	rules := []*tailcfg.SSHRule{{
		Principals: principals,
		SSHUsers:   r.userMap,
		Action:     &r.action,
		AcceptEnv:  r.acceptEnv,
	}}

	if hasUID {
		if lp, ok := r.localpartByUser[uid]; ok {
			rules = append(rules, &tailcfg.SSHRule{
				Principals: principals,
				SSHUsers:   map[string]string{lp: lp},
				Action:     &r.action,
				AcceptEnv:  r.acceptEnv,
			})
		}
	}

	return rules
}
