package policymodel

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/wgengine/filter"
)

// TestReferenceLaws holds the reference to what its own statement implies,
// over generated worlds, with and without each contested clause: its
// rules parse in the client; visibility is symmetric but for an exit node
// seeing the sources of an app grant that reaches the internet; and stamps
// name only identity sources of the document or an owner.
func TestReferenceLaws(t *testing.T) {
	t.Parallel()

	for i := range 300 {
		w := Worlds().Example(i)

		for _, without := range append([]Contested{0}, ContestedClauses...) {
			ref := RefOf(w).Without(without)

			for _, n := range ref.nodes {
				_, err := filter.MatchesFromFilterRules(ref.Rules(n.ID))
				if err != nil {
					t.Fatalf("world %d n%d without %v: the client refuses the reference's rules: %v\n%#v", i, n.ID, without, err, w)
				}

				for _, id := range ref.Peers(n.ID) {
					m, _ := ref.node(id)
					if !slices.Contains(ref.Peers(id), n.ID) && !slices.ContainsFunc(ref.rules, func(rl refRule) bool { return ref.oneWay(rl, n, m) }) {
						t.Fatalf("world %d without %v: n%d sees n%d one way, by no app grant reaching the internet\n%#v", i, without, n.ID, id, w)
					}
				}

				for _, s := range ref.Stamps(n.ID) {
					if _, owner := strings.CutPrefix(s, "owner:"); !owner && !identity(s) {
						t.Fatalf("world %d n%d is stamped %q, no identity selector\n%#v", i, n.ID, s, w)
					}
				}
			}
		}
	}
}

// TestReferenceResolvesUsers pins the user references docs/ref/oidc.md
// describes: a provider identifier first, then one e-mail, then one name;
// a value without "@" written with one appended.
func TestReferenceResolvesUsers(t *testing.T) {
	t.Parallel()

	users := []User{
		{ID: 1, Name: "alice"},
		{ID: 2, Name: "bob", Email: "bob@example.com"},
		{ID: 3, Name: "carol", Email: "carol@example.org", Provider: "https://idp.example.com/3"},
		{ID: 4, Name: "bob@example.com", Provider: "https://idp.example.com/4"},
		{ID: 5, Name: "erin", Provider: "https://idp.example.com/5"},
		{ID: 6, Name: "erin", Provider: "https://idp.example.com/6"},
	}
	r := NewRef(Doc{}, users, nil)

	for tok, want := range map[string][]uint{
		"https://idp.example.com/3@": {3},
		"alice@":                     {1},
		"bob@example.com":            {2}, // the e-mail owner wins over the user so named
		"carol@example.org":          {3},
		"erin@":                      nil, // two users so named
		"nobody@":                    nil,
		"@":                          nil,
		"user:*@example.com":         {2},
		"user:*@EXAMPLE.org":         {3},
	} {
		if got := r.usersOf(tok); !slices.Equal(got, want) {
			t.Errorf("%s names %v, want %v", tok, got, want)
		}
	}
}

// TestServedRoutesFollowTheElections pins the elections ServedRoutes reads,
// as docs/ref/routes.md states them: the lowest-ID available router of a
// route serves it, history decides when none is, and a via grant's
// election falls back to its lowest-ID router; a single address inside
// the node ranges is never served.
func TestServedRoutesFollowTheElections(t *testing.T) {
	t.Parallel()

	subnet, node := netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("100.64.0.9/32")
	router := func(id types.NodeID, down bool, tags ...string) RefNode {
		return RefNode{
			ID: id, Tags: tags, Addrs: []netip.Addr{netip.AddrFrom4([4]byte{100, 64, 0, byte(id)})}, //nolint:gosec // small
			Announced: []netip.Prefix{subnet, node}, Approved: []netip.Prefix{subnet, node}, Unavailable: down,
		}
	}
	viewer := RefNode{ID: 1, User: 1, Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}
	users := []User{{ID: 1, Name: "alice"}}

	plain, err := ParseDoc([]byte(`{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["*:*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}

	via, err := ParseDoc([]byte(`{"tagOwners": {"tag:a": []}, "grants": [{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:a"]}]}`))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name           string
		doc            Doc
		routers        []RefNode
		want, unjudged map[types.NodeID][]netip.Prefix
	}{
		{
			"the lowest available", plain,
			[]RefNode{router(2, true), router(3, false), router(4, false)},
			map[types.NodeID][]netip.Prefix{3: {subnet}},
			nil,
		},
		{
			"none available", plain,
			[]RefNode{router(2, true), router(3, true)},
			nil,
			map[types.NodeID][]netip.Prefix{2: {subnet}, 3: {subnet}},
		},
		{
			"via, the lowest available", via,
			[]RefNode{router(2, true, "tag:a"), router(3, false, "tag:a"), router(4, false)},
			map[types.NodeID][]netip.Prefix{3: {subnet}},
			nil,
		},
		{
			"via, none available", via,
			[]RefNode{router(2, true, "tag:a"), router(3, true, "tag:a")},
			map[types.NodeID][]netip.Prefix{2: {subnet}},
			nil,
		},
	} {
		r := NewRef(c.doc, users, append([]RefNode{viewer}, c.routers...))

		for _, p := range c.routers {
			want, unjudged := r.ServedRoutes(viewer.ID, p.ID)
			if !slices.Equal(want, c.want[p.ID]) || !slices.Equal(unjudged, c.unjudged[p.ID]) {
				t.Errorf("%s: n%d gives %v (%v unjudged), want %v (%v unjudged)", c.name, p.ID, want, unjudged, c.want[p.ID], c.unjudged[p.ID])
			}
		}
	}
}
