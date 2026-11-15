package propcheck

import (
	"maps"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestElectRoutesFallback(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/48")

	for _, tc := range []struct {
		name                                      string
		previous                                  uint64
		firstOnline, firstExpired, firstUnhealthy bool
		secondOnline, secondUnhealthy             bool
		global, via                               uint64
		globalOutage, viaOutage                   bool
	}{
		{name: "offline healthy incumbent", previous: 2, global: 2, via: 1, viaOutage: true},
		{name: "no incumbent", global: 1, via: 1, viaOutage: true},
		{name: "absent incumbent", previous: 99, global: 1, via: 1, viaOutage: true},
		{name: "unhealthy incumbent", previous: 2, secondUnhealthy: true, global: 2, via: 1, globalOutage: true, viaOutage: true},
		{name: "all unhealthy without incumbent", firstUnhealthy: true, secondUnhealthy: true, via: 1, viaOutage: true},
		{name: "healthy fallback", firstUnhealthy: true, global: 2, via: 1, viaOutage: true},
		{name: "available beats incumbent", previous: 2, firstOnline: true, global: 1, via: 1},
		{name: "zero session beats epoch", firstOnline: true, secondOnline: true, global: 2, via: 2},
		{name: "expired oldest unavailable", firstOnline: true, firstExpired: true, secondOnline: true, global: 2, via: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []RouteNode{
				{ID: 1, Online: tc.firstOnline, Expired: tc.firstExpired, Unhealthy: tc.firstUnhealthy, SessionStart: time.Unix(0, 0), Announced: []netip.Prefix{prefix}, Approved: []netip.Prefix{prefix}},
				{ID: 2, Online: tc.secondOnline, Unhealthy: tc.secondUnhealthy, Announced: []netip.Prefix{prefix}, Approved: []netip.Prefix{prefix}},
			}

			got := ElectRoutes(nodes, map[netip.Prefix]uint64{prefix: tc.previous}, []ViaScope{{Key: "tag:a", Prefix: prefix, Candidates: []uint64{2, 1, 2, 99}}})
			if got.Global[prefix] != tc.global || got.Via["tag:a"][prefix] != tc.via || got.GlobalOutage != tc.globalOutage || got.ViaOutage != tc.viaOutage {
				t.Fatalf("got %+v; want global=%d via=%d outages=%v/%v", got, tc.global, tc.via, tc.globalOutage, tc.viaOutage)
			}
		})
	}
}

func TestElectRoutesOwnsResults(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	overlap := netip.MustParsePrefix("10.0.0.0/16")
	exit4, exit6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	nodes := []RouteNode{
		{ID: 2, Online: true, Announced: []netip.Prefix{prefix, prefix, overlap, exit4, exit6}, Approved: []netip.Prefix{prefix, exit4, exit6}},
		{ID: 1, Online: true, Announced: []netip.Prefix{prefix}, Approved: []netip.Prefix{prefix, prefix}},
	}
	previous := map[netip.Prefix]uint64{overlap: 99}
	scopes := []ViaScope{
		{Key: "scoped", Prefix: prefix, Candidates: []uint64{2, 2, 99}},
		{Key: "scoped", Prefix: exit4, Candidates: []uint64{1, 2}},
		{Key: "empty", Prefix: prefix},
	}
	got := ElectRoutes(nodes, previous, scopes)

	want := RouteResult{
		Global: map[netip.Prefix]uint64{prefix: 1},
		Via:    map[string]map[netip.Prefix]uint64{"scoped": {prefix: 2}, "empty": {}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	if nodes[0].ID != 2 || len(nodes[0].Announced) != 5 || scopes[0].Candidates[0] != 2 || !maps.Equal(previous, map[netip.Prefix]uint64{overlap: 99}) {
		t.Fatal("reference mutated inputs")
	}

	nodes[0].Approved[0] = overlap
	scopes[0].Candidates[0] = 1
	previous[prefix] = 2

	if !reflect.DeepEqual(got, want) {
		t.Fatal("result retained mutable inputs")
	}

	got.Global[prefix] = 99

	got.Via["scoped"][prefix] = 99
	if previous[prefix] != 2 || scopes[0].Candidates[0] != 1 {
		t.Fatal("result aliases input collections")
	}
}
