package policymodel

import (
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
)

// joined is the nodes steps join, in order.
func joined(steps []Step) []Node {
	var out []Node

	for _, st := range steps {
		for _, e := range st.Edits {
			if j, ok := e.(Join); ok {
				out = append(out, j.Node)
			}
		}
	}

	return out
}

// sessionReach is, for one script, the worlds it applies to and the steps
// after which what it moves for its viewer moved, as the reference reads
// it, with nothing else of the viewer moving.
type sessionReach struct{ applies, alone int }

// TestSessionScriptsReach holds each change-routing script to moving what
// it says for its viewer, in the reference, in most worlds it applies to:
// PeerSetScript the viewer's peers and not its rules; StampScript the
// member's stamps and not the viewer's peers, and in address form the
// viewer's rules; CoverScript the routes the viewer is given of the
// router, and not its peers or rules; RouteViewScript likewise for its
// viewer; FailoverScript sets up a viewer given the subnet from both
// routers. Worlds whose drawn rules give the script's nodes everything
// already are where the move is not alone.
func TestSessionScriptsReach(t *testing.T) {
	const worlds = 1000

	reach := map[string]*sessionReach{}
	count := func(name string, applies bool, alone ...bool) {
		r := reach[name]
		if r == nil {
			r = &sessionReach{}
			reach[name] = r
		}

		if applies {
			r.applies++
		}

		if applies && !slices.Contains(alone, false) {
			r.alone++
		}
	}

	for i := range worlds {
		w := Worlds().Example(i)

		// at returns the world before each step and after the last.
		at := func(steps []Step) []World {
			out := make([]World, 1, 1+len(steps))
			out[0] = w

			for _, st := range steps {
				out = append(out, out[len(out)-1].Apply(st.Edits...))
			}

			return out
		}

		same := func(a, b []World, f func(*Ref) any) bool {
			return slices.EqualFunc(a, b, func(x, y World) bool { return equalAny(f(RefOf(x)), f(RefOf(y))) })
		}

		if steps := PeerSetScript(w); steps != nil {
			ws, x := at(steps), joined(steps)[0].ID
			n := len(ws)
			moved := !equalAny(RefOf(ws[n-3]).Peers(x), RefOf(ws[n-4]).Peers(x))
			count("peer set", true, moved, same(ws[n-4:n-3], ws[n-3:n-2], func(r *Ref) any { return r.Rules(x) }))
		} else {
			count("peer set", false)
		}

		if steps := StampScript(w); steps != nil {
			ws, nodes := at(steps), joined(steps)
			v, m := nodes[0].ID, nodes[1].ID
			n := len(ws)
			moved := !equalAny(RefOf(ws[n-4]).Stamps(m), RefOf(ws[n-3]).Stamps(m))
			count("stamps", true, moved, same(ws[n-4:n-3], ws[n-3:n-2], func(r *Ref) any { return r.Peers(v) }))
		} else {
			count("stamps", false)
		}

		if steps := CoverScript(w); steps != nil {
			ws, nodes := at(steps), joined(steps)
			r, v := nodes[0].ID, nodes[1].ID
			n := len(ws)
			moved := !equalAny(RefOf(ws[n-6]).Routes(v, r), RefOf(ws[n-5]).Routes(v, r))
			count("cover", true, moved,
				same(ws[n-6:n-5], ws[n-5:n-4], func(r *Ref) any { return r.Peers(v) }),
				same(ws[n-6:n-5], ws[n-5:n-4], func(r *Ref) any { return r.Rules(v) }))
		} else {
			count("cover", false)
		}

		if steps := RouteViewScript(w); steps != nil {
			ws, nodes := at(steps), joined(steps)
			r, v := nodes[0].ID, nodes[1].ID
			n := len(ws)
			moved := !equalAny(RefOf(ws[n-4]).Routes(v, r), RefOf(ws[n-3]).Routes(v, r))
			count("route view", true, moved,
				same(ws[n-4:n-3], ws[n-3:n-2], func(r *Ref) any { return r.Peers(v) }),
				same(ws[n-4:n-3], ws[n-3:n-2], func(r *Ref) any { return r.Rules(v) }))
		} else {
			count("route view", false)
		}

		if f, ok := FailoverScript(w); ok {
			ref := RefOf(at(f.Steps)[len(f.Steps)])
			q := netip.MustParsePrefix("10.0.1.0/24")
			count("failover", true, slices.Contains(ref.Routes(f.Viewer, f.Routers[0]), q), slices.Contains(ref.Routes(f.Viewer, f.Routers[1]), q))
		} else {
			count("failover", false)
		}
	}

	// Far below what the draws give: other generator changes move them.
	for _, name := range []string{"peer set", "stamps", "cover", "route view", "failover"} {
		r := reach[name]
		t.Logf("%s: applies to %d of %d worlds, moves alone in %d", name, r.applies, worlds, r.alone)

		if r.applies < worlds/2 || r.alone < worlds/10 {
			t.Errorf("%s: applies to %d of %d worlds and moves alone in %d; want half and a tenth", name, r.applies, worlds, r.alone)
		}
	}
}

func equalAny(a, b any) bool {
	switch a := a.(type) {
	case []types.NodeID:
		o, _ := b.([]types.NodeID)

		return slices.Equal(a, o)
	case []netip.Prefix:
		o, _ := b.([]netip.Prefix)

		return slices.Equal(a, o)
	case []string:
		o, _ := b.([]string)

		return slices.Equal(a, o)
	}

	return reflect.DeepEqual(a, b)
}

// TestElectionsFollowTheirHistory pins the documented election
// (docs/ref/routes.md, "High availability") as Elections reads history:
// the router connected longest serves; one that reconnects becomes a
// standby; the prober's failure takes a router out; with none available
// the last holder keeps the route while it approves it, else the
// lowest-ID healthy router holds it.
func TestElectionsFollowTheirHistory(t *testing.T) {
	q := netip.MustParsePrefix("10.0.1.0/24")
	router := func(id types.NodeID, down bool) RefNode {
		return RefNode{ID: id, Announced: []netip.Prefix{q}, Approved: []netip.Prefix{q}, Unavailable: down}
	}

	for _, c := range []struct {
		name      string
		started   map[types.NodeID]uint64
		unhealthy map[types.NodeID]bool
		held      types.NodeID
		routers   []RefNode
		want      types.NodeID
		decided   bool
	}{
		{"connected longest", map[types.NodeID]uint64{1: 1, 2: 2}, nil, 0, []RefNode{router(1, false), router(2, false)}, 1, true},
		{"a reconnect is a standby", map[types.NodeID]uint64{1: 3, 2: 2}, nil, 1, []RefNode{router(1, false), router(2, false)}, 2, true},
		{"failed by the prober", map[types.NodeID]uint64{1: 1, 2: 2}, map[types.NodeID]bool{1: true}, 1, []RefNode{router(1, false), router(2, false)}, 2, true},
		{"none available, the holder keeps it", map[types.NodeID]uint64{1: 1, 2: 2}, nil, 2, []RefNode{router(1, true), router(2, true)}, 2, true},
		{"none available, the holder gone", map[types.NodeID]uint64{1: 1, 2: 2}, map[types.NodeID]bool{1: true}, 3, []RefNode{router(1, false), router(2, true)}, 2, true},
		{"none available, none healthy", nil, map[types.NodeID]bool{1: true}, 3, []RefNode{router(1, false)}, 0, false},
	} {
		e := NewElections()
		maps.Copy(e.Started, c.started)
		e.Unhealthy = c.unhealthy
		e.Held[q] = c.held

		if got, decided := e.primary(c.routers, q); got != c.want || decided != c.decided {
			t.Errorf("%s: n%d (%t), want n%d (%t)", c.name, got, decided, c.want, c.decided)
		}
	}

	if got, decided := (*Elections)(nil).primary([]RefNode{router(1, true), router(2, false)}, q); got != 2 || !decided {
		t.Errorf("without a history: n%d (%t), want the lowest available, n2", got, decided)
	}

	if _, decided := (*Elections)(nil).primary([]RefNode{router(1, true)}, q); decided {
		t.Errorf("without a history, none available: decided")
	}
}
