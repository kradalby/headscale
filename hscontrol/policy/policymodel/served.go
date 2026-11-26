package policymodel

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
)

// What a viewer's client is given of a peer's routes once the routers
// are elected: elections as docs/ref/routes.md ("High availability")
// states them, held afresh from the world alone. Where only history can
// say who holds a route, or via steering goes past the one case its
// documentation decides, the route is left unjudged and named as such.

// nodeRanges are the ranges headscale hands node addresses out of.
var nodeRanges = setOf(netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48"))

// NamesNode reports whether route q is a single address inside the node
// ranges: it names a node, not a subnet, and is never served, though it
// stays approved (CHANGELOG: #3603).
func NamesNode(q netip.Prefix) bool { return q.IsSingleIP() && nodeRanges.Contains(q.Addr()) }

// Node is the node with id as the reference reads it.
func (r *Ref) Node(id types.NodeID) (RefNode, bool) { return r.node(id) }

// routersOf are the nodes serving subnet route q, in ID order.
func (r *Ref) routersOf(q netip.Prefix) []RefNode {
	var out []RefNode

	for _, n := range r.nodes {
		if slices.Contains(n.subnets(), q) {
			out = append(out, n)
		}
	}

	return out
}

// Primary is the router the tailnet-wide election gives subnet route q,
// and whether the world decides it. The election is the documented
// session ordering ([Elections]): a world without a history connected at
// once and has no prober, so the lowest available ID; with no router
// available the route stays with the one that served it last while it
// approves it, or goes to the lowest-ID healthy approving router, which
// only a history can say.
func (r *Ref) Primary(q netip.Prefix) (types.NodeID, bool) {
	return r.elections.primary(r.routersOf(q), q)
}

// ViaPrimary is the router the election of a via grant with tags gives
// subnet route q: among routers carrying one of tags that serve q, the
// session ordering's choice, and with none available the lowest ID,
// "independently of the previous winner". Grants with the same tags share
// one election per route.
func (r *Ref) ViaPrimary(tags []string, q netip.Prefix) (types.NodeID, bool) {
	candidates := slices.DeleteFunc(r.routersOf(q), func(n RefNode) bool { return !n.hasTag(tags) })

	if id, ok := r.elections.elect(candidates); ok {
		return id, true
	}

	if len(candidates) > 0 {
		return candidates[0].ID, true
	}

	return 0, false
}

// viaRules are the via rules viewer v is a source of that reach route q:
// its traffic for q is steered. An exit route is steered by
// autogroup:internet alone, as the internet through exit nodes, never by a
// destination prefix it holds; [Ref.Steered] also counts a public subnet
// route under autogroup:internet, since it only says what to leave out.
func (r *Ref) viaRules(v RefNode, q netip.Prefix) []refRule {
	var out []refRule

	for _, rl := range r.rules {
		if len(rl.via) > 0 && on(v, rl.src) && (!isExitRoute(q) && rl.dst.OverlapsPrefix(q) || rl.internet && isExitRoute(q)) {
			out = append(out, rl)
		}
	}

	return out
}

// ServedRoutes are the routes of peer in viewer's AllowedIPs, sorted, and
// the routes of peer it leaves unjudged, which a comparison takes out of
// both sides:
//
//   - a route viewer is given ([Ref.Routes]) and not steered: an exit
//     route as given, a subnet route only from its primary ([Ref.Primary]);
//     unjudged where history elects;
//   - a single address inside the node ranges, or an exit route without
//     the other family's: never;
//   - a subnet route a via grant steers ([Ref.Steered]) that no rule
//     without via gives: only from the router its election picks
//     ([Ref.ViaPrimary]), when every such grant carries the same via tags
//     ("an overlapping grant without via uses the ordinary tailnet-wide
//     election instead" and grants with other tags combine elections,
//     which this does not follow: unjudged);
//   - an exit route a via grant steers: only from an exit node carrying a
//     via tag of such a grant, or from any where a rule without via lets
//     viewer reach the internet ("A user who matches several via grants
//     can use the exit nodes of all of them. A via grant does not hide
//     exit nodes from a user who also has a rule that allows access to
//     the internet without via");
//   - a route viewer serves itself that it is not given: unjudged
//     (headscale shows a standby its primary whatever the policy, which no
//     document states).
func (r *Ref) ServedRoutes(viewer, peer types.NodeID) ([]netip.Prefix, []netip.Prefix) {
	v, ok := r.node(viewer)
	p, okp := r.node(peer)

	if !ok || !okp {
		return nil, nil
	}

	given := r.Routes(viewer, peer)

	var want, unjudged []netip.Prefix

	for _, q := range p.routes() {
		has := slices.Contains(given, q)
		via := r.viaRules(v, q)

		switch {
		case NamesNode(q):
		case isExitRoute(q) && len(p.exitRoutes()) < 2:
		case !has && slices.Contains(v.subnets(), q):
			unjudged = append(unjudged, q)
		case len(via) == 0 && isExitRoute(q):
			if has {
				want = append(want, q)
			}
		case len(via) == 0:
			if !has {
				continue
			}

			if id, decided := r.Primary(q); !decided {
				unjudged = append(unjudged, q)
			} else if id == peer {
				want = append(want, q)
			}
		case isExitRoute(q):
			if slices.ContainsFunc(via, func(rl refRule) bool { return p.hasTag(rl.via) }) || r.internetWithoutVia(v) {
				want = append(want, q)
			}
		case has || !sameVia(via):
			unjudged = append(unjudged, q)
		default:
			if id, _ := r.ViaPrimary(via[0].via, q); p.hasTag(via[0].via) && id == peer {
				want = append(want, q)
			}
		}
	}

	slices.SortFunc(want, netip.Prefix.Compare)
	slices.SortFunc(unjudged, netip.Prefix.Compare)

	return want, unjudged
}

// internetWithoutVia reports whether a port rule without via lets v reach
// the internet, which gives it every exit route.
func (r *Ref) internetWithoutVia(v RefNode) bool {
	return slices.ContainsFunc(r.rules, func(rl refRule) bool {
		return len(rl.via) == 0 && len(rl.ip) > 0 && r.ownSelf(rl, v) && on(v, rl.src) && rl.reachesInternet()
	})
}

// sameVia reports whether rules all carry one set of via tags.
func sameVia(rules []refRule) bool {
	set := func(rl refRule) []string { return slices.Compact(slices.Sorted(slices.Values(rl.via))) }

	return !slices.ContainsFunc(rules[1:], func(rl refRule) bool { return !slices.Equal(set(rl), set(rules[0])) })
}

// ContestedServedRoutes reports whether headscale's reading gives viewer
// exactly got of peer's routes as served, but for the routes it leaves
// unjudged, and the clauses that make it (see [attribute]).
func ContestedServedRoutes(ref *Ref, viewer, peer types.NodeID, got []netip.Prefix) (Contested, bool) {
	return attribute(func(k Contested) bool {
		want, unjudged := ref.Without(k).ServedRoutes(viewer, peer)

		return slices.Equal(Judged(got, unjudged), want)
	})
}

// Judged is routes without the unjudged ones.
func Judged(routes, unjudged []netip.Prefix) []netip.Prefix {
	return slices.DeleteFunc(slices.Clone(routes), func(q netip.Prefix) bool { return slices.Contains(unjudged, q) })
}
