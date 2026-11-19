package policymodel

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestScale holds drawn cases to mostly small with a tail, from the side
// TestCoverage cannot: few scenarios take no step or start with one node,
// and few reads fall in a world the reference properties skip whole for a
// database-only address. The tail's floors are shapes in Required. Run
// with -v for the distributions.
func TestScale(t *testing.T) {
	t.Parallel()

	gen := Scenarios(coverageSteps)

	nodes, users := make([]int, 0, coverageSamples), make([]int, 0, coverageSamples)
	rules, steps := make([]int, 0, coverageSamples), make([]int, 0, coverageSamples)

	var quiet, alone, reads, skip int

	for i := range coverageSamples {
		s := gen.Example(i)

		nodes = append(nodes, len(s.Start.Topology.Nodes))
		users = append(users, len(s.Start.Topology.Users))
		rules = append(rules, len(s.Start.Policy.ACLs)+len(s.Start.Policy.Grants))
		steps = append(steps, len(s.Steps))

		if len(s.Steps) == 0 {
			quiet++
		}

		if len(s.Start.Topology.Nodes) == 1 {
			alone++
		}

		for k, w := range s.Worlds() {
			n := len(w.Topology.Nodes)
			if k > 0 {
				n = len(s.Steps[k-1].Reads)
			}

			reads += n

			if v := NewView(w); v.outsideAddr() || v.sharedAddr() {
				skip += n
			}
		}
	}

	t.Logf("start nodes %s", spread(nodes))
	t.Logf("start users %s", spread(users))
	t.Logf("start rules %s", spread(rules))
	t.Logf("steps %s", spread(steps))
	t.Logf("no step %d, one node %d, of %d; reads in skipped worlds %d of %d", quiet, alone, coverageSamples, skip, reads)

	for _, c := range []struct {
		what      string
		got, most float64
	}{
		{"scenarios without a step", share(quiet, coverageSamples), 0.1},
		{"starts with one node", share(alone, coverageSamples), 0.1},
		{"reads in a world holding a database-only address", share(skip, reads), 0.15},
	} {
		if c.got > c.most {
			t.Errorf("%s: %.3f, want at most %.2f", c.what, c.got, c.most)
		}
	}
}

func share(n, of int) float64 { return float64(n) / float64(max(1, of)) }

// spread is xs as its mean, quantiles and largest value.
func spread(xs []int) string {
	s := slices.Sorted(slices.Values(xs))
	sum := 0

	for _, x := range s {
		sum += x
	}

	var b strings.Builder

	fmt.Fprintf(&b, "mean %.2f", share(sum, len(s)))

	for _, q := range []int{50, 90, 99} {
		fmt.Fprintf(&b, " p%d %d", q, s[len(s)*q/100])
	}

	fmt.Fprintf(&b, " max %d", s[len(s)-1])

	return b.String()
}
