// Package propcheck contains independent reference models for property tests.
package propcheck

import (
	"cmp"
	"net/netip"
	"slices"
	"time"
)

// RouteNode is an immutable input record. IDs must be unique and nonzero.
// Expired is supplied by the caller so the reference never reads a clock.
type RouteNode struct {
	ID                         uint64
	Online, Expired, Unhealthy bool
	SessionStart               time.Time
	Announced, Approved        []netip.Prefix
	Tags                       []string
}

// ViaScope supplies policy resolution separately from route election. Key is
// a stable scope identity, independent of grant order. Candidates are the IDs
// allowed by that scope; absent nodes and unapproved routes cannot win.
type ViaScope struct {
	Key        string
	Prefix     netip.Prefix
	Candidates []uint64
}

// RouteResult owns its maps. Missing entries mean no elected router. Via maps
// contain supplied scope keys, including keys with no elected prefixes.
type RouteResult struct {
	Global                  map[netip.Prefix]uint64
	Via                     map[string]map[netip.Prefix]uint64
	GlobalOutage, ViaOutage bool
}

// ElectRoutes specifies route election without graph or policy implementation
// dependencies. It does not modify or retain mutable input collections.
//
// Available routers rank by oldest session, then lowest ID. Without one, global
// elections retain an approving incumbent, otherwise the lowest healthy ID;
// via elections choose the lowest approving ID regardless of health/history.
// Prefixes intersect exactly: overlapping networks do not approve each other.
// Exit routes never enter subnet elections. Public route rendering is a
// separate concern and does not affect these election results.
func ElectRoutes(nodes []RouteNode, previous map[netip.Prefix]uint64, scopes []ViaScope) RouteResult {
	result := RouteResult{
		Global: make(map[netip.Prefix]uint64),
		Via:    make(map[string]map[netip.Prefix]uint64),
	}
	byID := make(map[uint64]RouteNode, len(nodes))
	approvers := make(map[netip.Prefix][]RouteNode)

	for _, node := range nodes {
		byID[node.ID] = node

		seen := make(map[netip.Prefix]bool)
		for _, prefix := range node.Announced {
			if !prefix.IsValid() || prefix.Bits() == 0 || seen[prefix] || !slices.Contains(node.Approved, prefix) {
				continue
			}

			seen[prefix] = true
			approvers[prefix] = append(approvers[prefix], node)
		}
	}

	for prefix, candidates := range approvers {
		id := routeWinner(candidates, previous[prefix], false)
		if id != 0 {
			result.Global[prefix] = id
			result.GlobalOutage = result.GlobalOutage || byID[id].Unhealthy && !slices.ContainsFunc(candidates, routeAvailable)
		}
	}

	// Repeated descriptions of one scope contribute the same candidate set;
	// unioning them also makes equivalent grant reorderings immaterial.
	type scopeKey struct {
		key    string
		prefix netip.Prefix
	}

	grouped := make(map[scopeKey][]RouteNode)

	for _, scope := range scopes {
		if result.Via[scope.Key] == nil {
			result.Via[scope.Key] = make(map[netip.Prefix]uint64)
		}

		key := scopeKey{scope.Key, scope.Prefix}
		for _, candidate := range approvers[scope.Prefix] {
			if slices.Contains(scope.Candidates, candidate.ID) && !slices.ContainsFunc(grouped[key], func(n RouteNode) bool { return n.ID == candidate.ID }) {
				grouped[key] = append(grouped[key], candidate)
			}
		}
	}

	for key, candidates := range grouped {
		id := routeWinner(candidates, 0, true)
		if id != 0 {
			result.Via[key.key][key.prefix] = id
			result.ViaOutage = result.ViaOutage || !slices.ContainsFunc(candidates, routeAvailable)
		}
	}

	return result
}

func routeAvailable(n RouteNode) bool { return n.Online && !n.Expired && !n.Unhealthy }

// Sorting a copied list expresses the preference order directly; no incumbent
// or incremental election state is hidden in the reference.
func routeWinner(candidates []RouteNode, previous uint64, via bool) uint64 {
	ranked := slices.Clone(candidates)
	slices.SortFunc(ranked, func(a, b RouteNode) int {
		if routeAvailable(a) != routeAvailable(b) {
			if routeAvailable(a) {
				return -1
			}

			return 1
		}

		if routeAvailable(a) {
			if order := a.SessionStart.Compare(b.SessionStart); order != 0 {
				return order
			}
		} else if !via {
			if (a.ID == previous) != (b.ID == previous) {
				if a.ID == previous {
					return -1
				}

				return 1
			}

			if a.Unhealthy != b.Unhealthy {
				if !a.Unhealthy {
					return -1
				}

				return 1
			}
		}

		return cmp.Compare(a.ID, b.ID)
	})

	if len(ranked) == 0 {
		return 0
	}

	first := ranked[0]
	if via || routeAvailable(first) || first.ID == previous || !first.Unhealthy {
		return first.ID
	}

	return 0
}
