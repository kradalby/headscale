package policy

import (
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// PolicyManager is a policy compiled against fixed users and nodes. It is
// only read; a change to any of its inputs compiles a new one.
type PolicyManager interface {
	// Filter returns the current filter rules for the entire tailnet and the associated matchers.
	Filter() ([]tailcfg.FilterRule, []matcher.Match)
	// FilterForNode returns filter rules for a specific node, handling autogroup:self
	FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error)
	// MatchersForNode returns matchers for peer relationship determination (unreduced)
	MatchersForNode(node types.NodeView) ([]matcher.Match, error)
	// BuildPeerMap constructs peer relationship maps for the given nodes
	BuildPeerMap(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID
	// BuildPeerClasses works out who sees whom, grouping nodes that see
	// the same nodes.
	BuildPeerClasses(nodes views.Slice[types.NodeView], prev *policyv2.PeerClasses) *policyv2.PeerClasses
	SSHPolicy(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error)
	// SSHCheckParams resolves the SSH check period for src logging in to
	// dst as localUser from the current policy, avoiding trust of
	// client-provided URL params.
	SSHCheckParams(srcNodeID, dstNodeID types.NodeID, localUser string) (time.Duration, bool)
	// NodeCanHaveTag reports whether the given node can have the given tag.
	NodeCanHaveTag(node types.NodeView, tag string) bool

	// UserCanHaveTag reports whether the given user owns the given tag, i.e.
	// is listed (directly or via a group) in the tag's tagOwners. This is the
	// user half of NodeCanHaveTag, used to authorise re-auth tag changes
	// against the authenticating user rather than the node's stale ownership.
	UserCanHaveTag(user types.UserView, tag string) bool

	// TagExists reports whether the given tag is defined in the policy.
	TagExists(tag string) bool

	// TagOwnedByTags reports whether a credential holding ownerTags may apply
	// tag: true if tag is one of ownerTags, or tag's tag-to-tag ownership chain
	// transitively includes one of ownerTags. Authorises the tags an OAuth
	// access token may set on the auth keys it mints.
	TagOwnedByTags(tag string, ownerTags []string) bool

	// NodeCanApproveRoute reports whether the given node can approve the given route.
	NodeCanApproveRoute(node types.NodeView, route netip.Prefix) bool

	// ViaRoutesForPeer is static policy inspection. Live routing must use
	// the immutable result of ElectViaRoutes instead.
	ViaRoutesForPeer(viewer, peer types.NodeView) types.ViaRouteResult
	// ElectViaRoutes revisits only scopes a change can move: touched
	// prefixes, and on a recompile the scopes whose candidates moved. It
	// reports winner changes, not policy-binding changes; callers must
	// adopt the returned result even when the boolean is false.
	ElectViaRoutes(previous *policyv2.ViaRoutes, touched map[netip.Prefix]struct{}, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) (*policyv2.ViaRoutes, bool)

	// NodeCapMap returns compiled policy capabilities for the given node,
	// or nil when none target it. The map is a defensive clone; its values
	// are shared and read-only. It describes the node's own capabilities,
	// not a per-viewer view.
	NodeCapMap(id types.NodeID) tailcfg.NodeCapMap

	// NodeCapMaps returns the per-node policy CapMap. It is shared with
	// the manager, which never changes it, and must not be modified:
	// every map render reads it.
	NodeCapMaps() map[types.NodeID]tailcfg.NodeCapMap

	Version() int
	DebugString() string
}

// NewPolicyManagerFrom is [NewPolicyManager] reusing what prev compiled
// that the change of nodes since cannot have moved.
func NewPolicyManagerFrom(prev PolicyManager, pol []byte, users []types.User, nodes views.Slice[types.NodeView]) (PolicyManager, error) {
	last, _ := prev.(*policyv2.PolicyManager)

	pm, err := policyv2.NewPolicyManagerFrom(last, pol, users, nodes)
	if err != nil {
		return nil, err
	}

	return pm, nil
}

// NewPolicyManager returns a new [PolicyManager].
func NewPolicyManager(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) (PolicyManager, error) {
	var (
		polMan PolicyManager
		err    error
	)

	polMan, err = policyv2.NewPolicyManager(pol, users, nodes)
	if err != nil {
		return nil, err
	}

	return polMan, err
}

// PolicyManagersForTest returns all available [PolicyManager] implementations to
// be used in tests to validate them in tests that try to determine that they
// behave the same.
func PolicyManagersForTest(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) ([]PolicyManager, error) {
	var polMans []PolicyManager

	for _, pmf := range PolicyManagerFuncsForTest(pol) {
		pm, err := pmf(users, nodes)
		if err != nil {
			return nil, err
		}

		polMans = append(polMans, pm)
	}

	return polMans, nil
}

func PolicyManagerFuncsForTest(pol []byte) []func([]types.User, views.Slice[types.NodeView]) (PolicyManager, error) {
	polmanFuncs := make([]func([]types.User, views.Slice[types.NodeView]) (PolicyManager, error), 0, 1)

	polmanFuncs = append(polmanFuncs, func(u []types.User, n views.Slice[types.NodeView]) (PolicyManager, error) {
		return policyv2.NewPolicyManager(pol, u, n)
	})

	return polmanFuncs
}
