package types

// Regression tests for NodeView.HasPolicyChange.
//
// Two defects were present:
//
//  1. UserID compared views.ValuePointer wrappers with !=, which is
//     pointer identity, not value equality. Two distinct *uint holding
//     the same ID looked like a change.
//  2. Exit-route changes were not detected, so toggling an exit node
//     failed to invalidate the policy cache and rebuild adjacency.
//
// See https://github.com/juanfont/headscale/issues/3417.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func policyChangeTestNode() Node {
	ipv4 := netip.MustParseAddr("100.64.0.1")
	now := time.Now()

	return Node{
		ID:         1,
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		DiscoKey:   key.NewDisco().Public(),
		Hostname:   "node",
		GivenName:  "node",
		IPv4:       &ipv4,
		CreatedAt:  now,
		UpdatedAt:  now,
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "node"},
	}
}

// TestHasPolicyChangeUserIDPointerIdentity ensures two distinct *uint
// values holding the same user ID do not register as a policy change.
func TestHasPolicyChangeUserIDPointerIdentity(t *testing.T) {
	userID := uint(7)

	a := policyChangeTestNode()
	a.UserID = &userID

	b := policyChangeTestNode()
	otherPtr := new(uint)
	*otherPtr = 7
	b.UserID = otherPtr

	// Different pointers, same value.
	require.NotSame(t, a.UserID, b.UserID)
	require.False(t, a.View().HasPolicyChange(b.View()),
		"same UserID value via distinct pointers must not register as policy change")

	// And a real change must register.
	c := policyChangeTestNode()
	otherVal := uint(8)
	c.UserID = &otherVal
	require.True(t, a.View().HasPolicyChange(c.View()),
		"different UserID value must register as policy change")
}

// TestHasPolicyChangeUserIDValidity covers the nil vs non-nil transition.
func TestHasPolicyChangeUserIDValidity(t *testing.T) {
	a := policyChangeTestNode()
	// a.UserID nil
	b := policyChangeTestNode()
	v := uint(1)
	b.UserID = &v

	require.True(t, a.View().HasPolicyChange(b.View()),
		"nil -> non-nil UserID must register as policy change")
}

// TestHasPolicyChangeExitRoutes covers the missing ExitRoutes comparison.
func TestHasPolicyChangeExitRoutes(t *testing.T) {
	exitV4 := netip.MustParsePrefix("0.0.0.0/0")
	exitV6 := netip.MustParsePrefix("::/0")

	base := policyChangeTestNode()
	base.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	base.ApprovedRoutes = nil // not approved -> no exit routes

	b := policyChangeTestNode()
	b.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	b.ApprovedRoutes = []netip.Prefix{exitV4, exitV6} // approved -> exit routes live

	require.True(t, base.View().HasPolicyChange(b.View()),
		"enabling exit routes must register as policy change")

	// Reverse: approved on both, no change.
	c := policyChangeTestNode()
	c.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	c.ApprovedRoutes = []netip.Prefix{exitV4, exitV6}

	require.False(t, b.View().HasPolicyChange(c.View()),
		"identical exit-route state must not register as policy change")
}
