package policymodel

import (
	"slices"
	"strings"
	"testing"

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
