package policymodel

import (
	"slices"
	"strings"
	"testing"

	"tailscale.com/wgengine/filter"
)

// TestReferenceLaws holds the reference to what its own statement implies,
// over generated worlds: its rules parse in the client; visibility is
// symmetric but for an exit node seeing an internet-reaching app grant's
// sources; leaving the contested clauses out never adds a route; and
// stamps name only identity sources of the document or an owner.
func TestReferenceLaws(t *testing.T) {
	t.Parallel()

	for i := range 300 {
		w := Worlds().Example(i)
		ref := RefOf(w)
		all := ref.Without(AllContested)

		for _, n := range ref.nodes {
			_, err := filter.MatchesFromFilterRules(ref.Rules(n.ID))
			if err != nil {
				t.Fatalf("world %d n%d: the client refuses the reference's rules: %v\n%#v", i, n.ID, err, w)
			}

			for _, m := range ref.Peers(n.ID) {
				if !slices.Contains(ref.Peers(m), n.ID) && !n.exit() {
					t.Fatalf("world %d: n%d sees n%d one way, and is no exit node\n%#v", i, n.ID, m, w)
				}
			}

			for _, s := range ref.Stamps(n.ID) {
				if _, owner := strings.CutPrefix(s, "owner:"); !owner && !identity(s) {
					t.Fatalf("world %d n%d is stamped %q, no identity selector\n%#v", i, n.ID, s, w)
				}
			}

			for _, p := range ref.Peers(n.ID) {
				for _, q := range all.Routes(n.ID, p) {
					if !slices.Contains(ref.Routes(n.ID, p), q) {
						t.Fatalf("world %d: without the contested clauses n%d gains n%d's route %v\n%#v", i, n.ID, p, q, w)
					}
				}
			}
		}
	}
}
