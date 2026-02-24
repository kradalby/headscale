package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var (
	ErrInvalidAction = errors.New("invalid action")
	errSelfInSources = errors.New("autogroup:self cannot be used in sources")
)

// compileFilterRules takes a set of nodes and an ACLPolicy and generates a
// set of Tailscale compatible FilterRules used to allow traffic on clients.
func (pol *Policy) compileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil || pol.ACLs == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != ActionAccept {
			return nil, ErrInvalidAction
		}

		srcIPs, err := acl.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
			continue
		}

		protocols := acl.Protocol.parseProtocol()

		var destPorts []tailcfg.NetPortRange

		for _, dest := range acl.Destinations {
			// Check if destination is a wildcard - use "*" directly instead of expanding
			if _, isWildcard := dest.Alias.(Asterix); isWildcard {
				for _, port := range dest.Ports {
					destPorts = append(destPorts, tailcfg.NetPortRange{
						IP:    "*",
						Ports: port,
					})
				}

				continue
			}

			// autogroup:internet does not generate packet filters - it's handled
			// by exit node routing via AllowedIPs, not by packet filtering.
			if ag, isAutoGroup := dest.Alias.(*AutoGroup); isAutoGroup && ag.Is(AutoGroupInternet) {
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

			prefixes := ips.Prefixes()

			for _, pref := range prefixes {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}

		if len(destPorts) == 0 {
			continue
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   ipSetToPrefixStringList(srcIPs),
			DstPorts: destPorts,
			IPProto:  protocols,
		})
	}

	return mergeFilterRules(rules), nil
}

// compileFilterRulesForNode compiles filter rules for a specific node.
func (pol *Policy) compileFilterRulesForNode(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != ActionAccept {
			return nil, ErrInvalidAction
		}

		aclRules, err := pol.compileACLWithAutogroupSelf(acl, users, node, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("compiling ACL")
			continue
		}

		for _, rule := range aclRules {
			if rule != nil {
				rules = append(rules, *rule)
			}
		}
	}

	return mergeFilterRules(rules), nil
}

// compileACLWithAutogroupSelf compiles a single ACL rule, handling
// autogroup:self per-node while supporting all other alias types normally.
// It returns a slice of filter rules because when an ACL has both autogroup:self
// and other destinations, they need to be split into separate rules with different
// source filtering logic.
//
//nolint:gocyclo // complex ACL compilation logic
func (pol *Policy) compileACLWithAutogroupSelf(
	acl ACL,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]*tailcfg.FilterRule, error) {
	var (
		autogroupSelfDests []AliasWithPorts
		otherDests         []AliasWithPorts
	)

	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			autogroupSelfDests = append(autogroupSelfDests, dest)
		} else {
			otherDests = append(otherDests, dest)
		}
	}

	protocols := acl.Protocol.parseProtocol()

	var rules []*tailcfg.FilterRule

	var resolvedSrcIPs []*netipx.IPSet

	for _, src := range acl.Sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if ips != nil {
			resolvedSrcIPs = append(resolvedSrcIPs, ips)
		}
	}

	if len(resolvedSrcIPs) == 0 {
		return rules, nil
	}

	// Handle autogroup:self destinations (if any)
	// Tagged nodes don't participate in autogroup:self (identity is tag-based, not user-based)
	if len(autogroupSelfDests) > 0 && !node.IsTagged() {
		// Pre-filter to same-user untagged devices once - reuse for both sources and destinations
		sameUserNodes := make([]types.NodeView, 0)

		for _, n := range nodes.All() {
			if !n.IsTagged() && n.User().ID() == node.User().ID() {
				sameUserNodes = append(sameUserNodes, n)
			}
		}

		if len(sameUserNodes) > 0 {
			// Filter sources to only same-user untagged devices
			var srcIPs netipx.IPSetBuilder

			for _, ips := range resolvedSrcIPs {
				for _, n := range sameUserNodes {
					// Check if any of this node's IPs are in the source set
					if slices.ContainsFunc(n.IPs(), ips.Contains) {
						n.AppendToIPSet(&srcIPs)
					}
				}
			}

			srcSet, err := srcIPs.IPSet()
			if err != nil {
				return nil, err
			}

			if srcSet != nil && len(srcSet.Prefixes()) > 0 {
				var destPorts []tailcfg.NetPortRange

				for _, dest := range autogroupSelfDests {
					for _, n := range sameUserNodes {
						for _, port := range dest.Ports {
							for _, ip := range n.IPs() {
								destPorts = append(destPorts, tailcfg.NetPortRange{
									IP:    netip.PrefixFrom(ip, ip.BitLen()).String(),
									Ports: port,
								})
							}
						}
					}
				}

				if len(destPorts) > 0 {
					rules = append(rules, &tailcfg.FilterRule{
						SrcIPs:   ipSetToPrefixStringList(srcSet),
						DstPorts: destPorts,
						IPProto:  protocols,
					})
				}
			}
		}
	}

	if len(otherDests) > 0 {
		var srcIPs netipx.IPSetBuilder

		for _, ips := range resolvedSrcIPs {
			srcIPs.AddSet(ips)
		}

		srcSet, err := srcIPs.IPSet()
		if err != nil {
			return nil, err
		}

		if srcSet != nil && len(srcSet.Prefixes()) > 0 {
			var destPorts []tailcfg.NetPortRange

			for _, dest := range otherDests {
				// Check if destination is a wildcard - use "*" directly instead of expanding
				if _, isWildcard := dest.Alias.(Asterix); isWildcard {
					for _, port := range dest.Ports {
						destPorts = append(destPorts, tailcfg.NetPortRange{
							IP:    "*",
							Ports: port,
						})
					}

					continue
				}

				// autogroup:internet does not generate packet filters - it's handled
				// by exit node routing via AllowedIPs, not by packet filtering.
				if ag, isAutoGroup := dest.Alias.(*AutoGroup); isAutoGroup && ag.Is(AutoGroupInternet) {
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

				prefixes := ips.Prefixes()

				for _, pref := range prefixes {
					for _, port := range dest.Ports {
						pr := tailcfg.NetPortRange{
							IP:    pref.String(),
							Ports: port,
						}
						destPorts = append(destPorts, pr)
					}
				}
			}

			if len(destPorts) > 0 {
				rules = append(rules, &tailcfg.FilterRule{
					SrcIPs:   ipSetToPrefixStringList(srcSet),
					DstPorts: destPorts,
					IPProto:  protocols,
				})
			}
		}
	}

	return rules, nil
}

func sshAction(accept bool) tailcfg.SSHAction {
	return tailcfg.SSHAction{
		Reject:                    !accept,
		Accept:                    accept,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}
}

//nolint:gocyclo // complex SSH policy compilation logic
func (pol *Policy) compileSSHPolicy(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	if pol == nil || pol.SSHs == nil || len(pol.SSHs) == 0 {
		return nil, nil //nolint:nilnil // intentional: no SSH policy when none configured
	}

	log.Trace().Caller().Msgf("compiling SSH policy for node %q", node.Hostname())

	var rules []*tailcfg.SSHRule

	for index, rule := range pol.SSHs {
		// Separate destinations into autogroup:self and others
		// This is needed because autogroup:self requires filtering sources to same-user only,
		// while other destinations should use all resolved sources
		var (
			autogroupSelfDests []Alias
			otherDests         []Alias
		)

		for _, dst := range rule.Destinations {
			if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				autogroupSelfDests = append(autogroupSelfDests, dst)
			} else {
				otherDests = append(otherDests, dst)
			}
		}

		// Note: Tagged nodes can't match autogroup:self destinations, but can still match other destinations

		// Resolve sources once - we'll use them differently for each destination type
		srcIPs, err := rule.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("ssh policy compilation failed resolving source ips for rule %+v", rule)
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
			continue
		}

		var action tailcfg.SSHAction

		switch rule.Action {
		case SSHActionAccept:
			action = sshAction(true)
		case SSHActionCheck:
			action = tailcfg.SSHAction{
				HoldAndDelegate: "https://unused/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER",
			}
		default:
			return nil, fmt.Errorf("parsing SSH policy, unknown action %q, index: %d: %w", rule.Action, index, err)
		}

		// Capture acceptEnv for passthrough to compiled SSH rules
		acceptEnv := rule.AcceptEnv

		// Build the "common" userMap for non-localpart entries (root, autogroup:nonroot, specific users).
		const rootUser = "root"

		commonUserMap := make(map[string]string, len(rule.Users))
		if rule.Users.ContainsNonRoot() {
			commonUserMap["*"] = "="
		}

		// Tailscale always denies root unless explicitly allowed.
		// When root is not in the users list, add "root": "" (deny).
		// When root IS listed, set "root": "root" (allow, overrides deny).
		if rule.Users.ContainsRoot() {
			commonUserMap[rootUser] = rootUser
		} else {
			commonUserMap[rootUser] = ""
		}

		for _, u := range rule.Users.NormalUsers() {
			commonUserMap[u.String()] = u.String()
		}

		// Resolve localpart entries into per-user rules.
		// Each localpart:*@<domain> entry maps users in that domain to their email local-part.
		// Because SSHUsers is a static map per rule, we need a separate rule per user
		// to constrain each user to only their own local-part.
		localpartEntries := rule.Users.LocalpartEntries()
		hasLocalpart := len(localpartEntries) > 0

		localpartRules := resolveLocalpartRules(
			localpartEntries,
			users,
			nodes,
			srcIPs,
			&action,
			acceptEnv,
		)

		// Determine whether the common userMap has any entries worth emitting.
		hasCommonUsers := len(commonUserMap) > 0

		// Handle autogroup:self destinations (if any)
		// Note: Tagged nodes can't match autogroup:self, so skip this block for tagged nodes
		if len(autogroupSelfDests) > 0 && !node.IsTagged() {
			// Build destination set for autogroup:self (same-user untagged devices only)
			var dest netipx.IPSetBuilder

			for _, n := range nodes.All() {
				if !n.IsTagged() && n.User().ID() == node.User().ID() {
					n.AppendToIPSet(&dest)
				}
			}

			destSet, err := dest.IPSet()
			if err != nil {
				return nil, err
			}

			// Only create rule if this node is in the destination set
			if node.InIPSet(destSet) {
				// Filter sources to only same-user untagged devices
				// Pre-filter to same-user untagged devices for efficiency
				sameUserNodes := make([]types.NodeView, 0)

				for _, n := range nodes.All() {
					if !n.IsTagged() && n.User().ID() == node.User().ID() {
						sameUserNodes = append(sameUserNodes, n)
					}
				}

				var filteredSrcIPs netipx.IPSetBuilder

				for _, n := range sameUserNodes {
					// Check if any of this node's IPs are in the source set
					if slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
						n.AppendToIPSet(&filteredSrcIPs) // Found this node, move to next
					}
				}

				filteredSrcSet, err := filteredSrcIPs.IPSet()
				if err != nil {
					return nil, err
				}

				if filteredSrcSet != nil && len(filteredSrcSet.Prefixes()) > 0 {
					// Emit common rule if there are non-localpart users
					if hasCommonUsers {
						var principals []*tailcfg.SSHPrincipal
						for addr := range util.IPSetAddrIter(filteredSrcSet) {
							principals = append(principals, &tailcfg.SSHPrincipal{
								NodeIP: addr.String(),
							})
						}

						if len(principals) > 0 {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: principals,
								SSHUsers:   commonUserMap,
								Action:     &action,
								AcceptEnv:  acceptEnv,
							})
						}
					}

					// Emit per-user localpart rules, filtered to autogroup:self sources
					for _, lpRule := range localpartRules {
						var filteredPrincipals []*tailcfg.SSHPrincipal

						for _, p := range lpRule.Principals {
							addr, err := netip.ParseAddr(p.NodeIP)
							if err != nil {
								continue
							}

							if filteredSrcSet.Contains(addr) {
								filteredPrincipals = append(filteredPrincipals, p)
							}
						}

						if len(filteredPrincipals) > 0 {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: filteredPrincipals,
								SSHUsers:   lpRule.SSHUsers,
								Action:     lpRule.Action,
								AcceptEnv:  acceptEnv,
							})
						}
					}
				}
			}
		}

		// Handle other destinations (if any)
		if len(otherDests) > 0 {
			// Build destination set for other destinations
			var dest netipx.IPSetBuilder

			for _, dst := range otherDests {
				ips, err := dst.Resolve(pol, users, nodes)
				if err != nil {
					log.Trace().Caller().Err(err).Msgf("resolving destination ips")
				}

				if ips != nil {
					dest.AddSet(ips)
				}
			}

			destSet, err := dest.IPSet()
			if err != nil {
				return nil, err
			}

			// Only create rule if this node is in the destination set
			if node.InIPSet(destSet) {
				// Emit rules for this destination node. When localpart entries
				// exist, interleave common and localpart rules per source user
				// to match Tailscale SaaS ordering: each user's common rule is
				// immediately followed by their localpart rule before moving to
				// the next user. Tagged source nodes get a single combined
				// common rule after all per-user pairs.
				if hasLocalpart {
					matched := make([]bool, len(localpartRules))

					if hasCommonUsers {
						groups := groupPrincipalsByUser(nodes, srcIPs)
						for _, principals := range groups.perUser {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: principals,
								SSHUsers:   commonUserMap,
								Action:     &action,
								AcceptEnv:  acceptEnv,
							})

							// Interleave matching localpart rules for this user.
							for i, lpr := range localpartRules {
								if !matched[i] &&
									principalsOverlap(principals, lpr.Principals) {
									rules = append(rules, lpr)
									matched[i] = true
								}
							}
						}

						if len(groups.tagged) > 0 {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: groups.tagged,
								SSHUsers:   commonUserMap,
								Action:     &action,
								AcceptEnv:  acceptEnv,
							})
						}
					}

					// Append any localpart rules not matched to a per-user
					// common rule (e.g. when hasCommonUsers is false).
					for i, lpr := range localpartRules {
						if !matched[i] {
							rules = append(rules, lpr)
						}
					}
				} else if hasCommonUsers {
					var principals []*tailcfg.SSHPrincipal
					for addr := range util.IPSetAddrIter(srcIPs) {
						principals = append(principals, &tailcfg.SSHPrincipal{
							NodeIP: addr.String(),
						})
					}

					if len(principals) > 0 {
						rules = append(rules, &tailcfg.SSHRule{
							Principals: principals,
							SSHUsers:   commonUserMap,
							Action:     &action,
							AcceptEnv:  acceptEnv,
						})
					}
				}
			} else if hasLocalpart && node.InIPSet(srcIPs) {
				// Self-access distribution: when localpart entries are present,
				// source nodes that are NOT in the destination set still receive
				// rules scoped to their own user. This matches Tailscale SaaS behavior
				// where source nodes get self-access SSH rules.
				selfPrincipals := selfAccessPrincipals(node, nodes, srcIPs)
				if len(selfPrincipals) > 0 {
					if hasCommonUsers {
						rules = append(rules, &tailcfg.SSHRule{
							Principals: selfPrincipals,
							SSHUsers:   commonUserMap,
							Action:     &action,
							AcceptEnv:  acceptEnv,
						})
					}

					// Emit localpart rules matching this node's user only
					for _, lpRule := range localpartRules {
						if principalsOverlap(lpRule.Principals, selfPrincipals) {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: selfPrincipals,
								SSHUsers:   lpRule.SSHUsers,
								Action:     lpRule.Action,
								AcceptEnv:  acceptEnv,
							})
						}
					}
				}
			}
		}
	}

	// Tailscale SaaS reorders check (holdAndDelegate) rules before accept
	// rules. This ensures first-match-wins semantics give check precedence
	// over accept when both exist for the same destination.
	slices.SortStableFunc(rules, func(a, b *tailcfg.SSHRule) int {
		aIsCheck := a.Action != nil && a.Action.HoldAndDelegate != ""
		bIsCheck := b.Action != nil && b.Action.HoldAndDelegate != ""

		switch {
		case aIsCheck && !bIsCheck:
			return -1
		case !aIsCheck && bIsCheck:
			return 1
		default:
			return 0
		}
	})

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}, nil
}

// selfAccessPrincipals returns the SSH principals for self-access distribution.
// For user-owned nodes, it returns that user's source node IPs from the srcIPs set.
// For tagged nodes, it returns the node's own IPs if they're in the srcIPs set.
func selfAccessPrincipals(
	node types.NodeView,
	nodes views.Slice[types.NodeView],
	srcIPs *netipx.IPSet,
) []*tailcfg.SSHPrincipal {
	if node.IsTagged() {
		// Tagged node: use the node's own IPs if they're in the source set
		if !slices.ContainsFunc(node.IPs(), srcIPs.Contains) {
			return nil
		}

		var builder netipx.IPSetBuilder

		node.AppendToIPSet(&builder)

		ipSet, err := builder.IPSet()
		if err != nil || ipSet == nil {
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

	// User-owned node: find all source IPs belonging to the same user
	if !node.User().Valid() {
		return nil
	}

	uid := node.User().ID()

	var builder netipx.IPSetBuilder

	for _, n := range nodes.All() {
		if n.IsTagged() || !n.User().Valid() || n.User().ID() != uid {
			continue
		}

		if slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
			n.AppendToIPSet(&builder)
		}
	}

	ipSet, err := builder.IPSet()
	if err != nil || ipSet == nil {
		return nil
	}

	var principals []*tailcfg.SSHPrincipal
	for addr := range util.IPSetAddrIter(ipSet) {
		principals = append(principals, &tailcfg.SSHPrincipal{
			NodeIP: addr.String(),
		})
	}

	if len(principals) == 0 {
		return nil
	}

	return principals
}

// principalsOverlap returns true if any principal NodeIP in a appears in b.
func principalsOverlap(a, b []*tailcfg.SSHPrincipal) bool {
	bIPs := make(map[string]bool, len(b))
	for _, p := range b {
		bIPs[p.NodeIP] = true
	}

	for _, p := range a {
		if bIPs[p.NodeIP] {
			return true
		}
	}

	return false
}

// perUserPrincipalGroups holds the result of grouping source IPs by user ownership.
type perUserPrincipalGroups struct {
	// perUser contains per-user principal lists, one entry per source user,
	// ordered by user ID for deterministic output.
	perUser [][]*tailcfg.SSHPrincipal
	// tagged contains principals from tagged source nodes (not associated with any user).
	// These are combined into a single group since tagged nodes have no user identity.
	tagged []*tailcfg.SSHPrincipal
}

// groupPrincipalsByUser groups source IPs into per-user buckets based on node ownership.
// User-owned source nodes are grouped by user ID; tagged source nodes are collected into
// a separate "tagged" bucket. Only includes nodes whose IPs are in the given srcIPs set.
func groupPrincipalsByUser(
	nodes views.Slice[types.NodeView],
	srcIPs *netipx.IPSet,
) perUserPrincipalGroups {
	type userPrincipals struct {
		userID     uint
		principals []*tailcfg.SSHPrincipal
	}

	// Build per-user and tagged IP sets from source nodes.
	userIPSets := make(map[uint]*netipx.IPSetBuilder)

	var taggedIPSet netipx.IPSetBuilder

	hasTagged := false

	for _, n := range nodes.All() {
		if !slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
			continue
		}

		if n.IsTagged() {
			n.AppendToIPSet(&taggedIPSet)

			hasTagged = true

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

	var result perUserPrincipalGroups

	// Convert per-user IP sets to principals, sorted by user ID for deterministic output.
	var userResults []userPrincipals

	for uid, builder := range userIPSets {
		ipSet, err := builder.IPSet()
		if err != nil || ipSet == nil {
			continue
		}

		var principals []*tailcfg.SSHPrincipal
		for addr := range util.IPSetAddrIter(ipSet) {
			principals = append(principals, &tailcfg.SSHPrincipal{
				NodeIP: addr.String(),
			})
		}

		if len(principals) > 0 {
			userResults = append(userResults, userPrincipals{userID: uid, principals: principals})
		}
	}

	slices.SortFunc(userResults, func(a, b userPrincipals) int {
		if a.userID < b.userID {
			return -1
		}

		if a.userID > b.userID {
			return 1
		}

		return 0
	})

	result.perUser = make([][]*tailcfg.SSHPrincipal, len(userResults))
	for i, up := range userResults {
		result.perUser[i] = up.principals
	}

	// Convert tagged IP set to principals.
	if hasTagged {
		taggedSet, err := taggedIPSet.IPSet()
		if err == nil && taggedSet != nil {
			for addr := range util.IPSetAddrIter(taggedSet) {
				result.tagged = append(result.tagged, &tailcfg.SSHPrincipal{
					NodeIP: addr.String(),
				})
			}
		}
	}

	return result
}

// resolveLocalpartRules generates per-user SSH rules for localpart:*@<domain> entries.
// For each localpart entry, it finds all users whose email is in the specified domain,
// extracts their email local-part, and creates a tailcfg.SSHRule scoped to that user's
// node IPs with an SSHUsers map that only allows their local-part.
// Each localpart rule contains only the localpart mapping; common entries (root, nonroot,
// specific users) are emitted as separate per-user rules by the caller.
func resolveLocalpartRules(
	localpartEntries []SSHUser,
	users types.Users,
	nodes views.Slice[types.NodeView],
	srcIPs *netipx.IPSet,
	action *tailcfg.SSHAction,
	acceptEnv []string,
) []*tailcfg.SSHRule {
	if len(localpartEntries) == 0 {
		return nil
	}

	var rules []*tailcfg.SSHRule

	for _, entry := range localpartEntries {
		domain, err := entry.ParseLocalpart()
		if err != nil {
			// Should not happen if validation passed, but skip gracefully.
			log.Warn().Err(err).Msgf("skipping invalid localpart entry %q during SSH compilation", entry)

			continue
		}

		// Find users whose email matches *@<domain> and build per-user rules.
		for _, user := range users {
			if user.Email == "" {
				continue
			}

			atIdx := strings.LastIndex(user.Email, "@")
			if atIdx < 0 {
				continue
			}

			emailDomain := user.Email[atIdx+1:]
			if !strings.EqualFold(emailDomain, domain) {
				continue
			}

			localPart := user.Email[:atIdx]

			// Find this user's non-tagged nodes that are in the source IP set.
			var userSrcIPs netipx.IPSetBuilder

			for _, n := range nodes.All() {
				if n.IsTagged() {
					continue
				}

				if !n.User().Valid() || n.User().ID() != user.ID {
					continue
				}

				if slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
					n.AppendToIPSet(&userSrcIPs)
				}
			}

			userSrcSet, err := userSrcIPs.IPSet()
			if err != nil || userSrcSet == nil || len(userSrcSet.Prefixes()) == 0 {
				continue
			}

			var principals []*tailcfg.SSHPrincipal
			for addr := range util.IPSetAddrIter(userSrcSet) {
				principals = append(principals, &tailcfg.SSHPrincipal{
					NodeIP: addr.String(),
				})
			}

			if len(principals) == 0 {
				continue
			}

			// Build per-user SSHUsers map with only the localpart mapping.
			// Common entries (root, nonroot, specific users) are emitted as
			// separate per-user rules by the caller.
			userMap := map[string]string{
				localPart: localPart,
			}

			rules = append(rules, &tailcfg.SSHRule{
				Principals: principals,
				SSHUsers:   userMap,
				Action:     action,
				AcceptEnv:  acceptEnv,
			})
		}
	}

	return rules
}

func ipSetToPrefixStringList(ips *netipx.IPSet) []string {
	var out []string

	if ips == nil {
		return out
	}

	for _, pref := range ips.Prefixes() {
		out = append(out, pref.String())
	}

	return out
}

// filterRuleKey generates a unique key for merging based on SrcIPs and IPProto.
func filterRuleKey(rule tailcfg.FilterRule) string {
	srcKey := strings.Join(rule.SrcIPs, ",")

	protoStrs := make([]string, len(rule.IPProto))
	for i, p := range rule.IPProto {
		protoStrs[i] = strconv.Itoa(p)
	}

	return srcKey + "|" + strings.Join(protoStrs, ",")
}

// mergeFilterRules merges rules with identical SrcIPs and IPProto by combining
// their DstPorts. DstPorts are NOT deduplicated to match Tailscale behavior.
func mergeFilterRules(rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	if len(rules) <= 1 {
		return rules
	}

	keyToIdx := make(map[string]int)
	result := make([]tailcfg.FilterRule, 0, len(rules))

	for _, rule := range rules {
		key := filterRuleKey(rule)

		if idx, exists := keyToIdx[key]; exists {
			// Merge: append DstPorts to existing rule
			result[idx].DstPorts = append(result[idx].DstPorts, rule.DstPorts...)
		} else {
			// New unique combination
			keyToIdx[key] = len(result)
			result = append(result, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: slices.Clone(rule.DstPorts),
				IPProto:  rule.IPProto,
			})
		}
	}

	return result
}
