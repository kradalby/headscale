package statemodel

import (
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
)

// Level is the system at one depth below the policy, as a property drives
// it from the model's steps: what it offers the shared judges once it is
// settled. How it writes a step and how it knows it is settled stay its
// own: the State's entry points, steered to the model's IDs and
// addresses, are written in step with the hub; the server's front doors
// hand out their own and settle when its goroutines do. A write it cannot
// make it leaves out of [Level.Model], or stores behind production's
// back, and counts.
//
// [Stored] reads a Level; what its clients hold goes to
// [policymodel.NetmapDiff] against a fresh session, and to
// [policymodel.Held.Client] at the [policymodel.Moment] the level is at.
type Level interface {
	// Model is the world the level was driven to, in the IDs and
	// addresses it holds.
	Model() policymodel.World
	// State is the State the level writes through.
	State() *state.State
	// Joined is how node id last registered, as the level registered it.
	Joined(id types.NodeID) Joined
	// Elections is the election history the level was driven through.
	Elections() *policymodel.Elections
}

// Moment is the moment l is at, as the reference reads it; a level adds
// what only it knows (shared addresses, routes it left unheld).
func Moment(l Level) policymodel.Moment {
	return policymodel.Moment{World: l.Model(), Elections: l.Elections()}
}
