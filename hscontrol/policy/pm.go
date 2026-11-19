package policy

import (
	"net/netip"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// ErrPolicyEmpty reports an empty policy document.
var ErrPolicyEmpty = policyv2.ErrPolicyEmpty

// PolicyManager is a policy compiled against fixed users and nodes. It is
// only read; a change to any of its inputs compiles a new one. It serves
// what the graph's cells do not; packet filters, peers and via steering
// are served by the cells, and the v2 manager's address compile, which the
// audit holds them to, is deliberately not part of this interface.
type PolicyManager interface {
	DERPMap() *tailcfg.DERPMap
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

func ValidatePolicy(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) error {
	return policyv2.ValidatePolicy(pol, users, nodes)
}

// ValidatePolicyAgainst is [ValidatePolicy] with the tests run against the
// global filter global expands for the candidate, see
// [policyv2.ValidatePolicyAgainst].
func ValidatePolicyAgainst(
	pol []byte,
	users []types.User,
	nodes views.Slice[types.NodeView],
	global func(*policyv2.PolicyManager) ([]tailcfg.FilterRule, error),
) error {
	return policyv2.ValidatePolicyAgainst(pol, users, nodes, global)
}
