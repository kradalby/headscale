package policymodel

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// coverageSamples is how many drawn cases the coverage test classifies,
// at coverageSteps, the step count builders run.
const (
	coverageSamples = 1000
	coverageSteps   = 10
)

// TestCoverage classifies drawn cases and fails when a required shape
// falls below its floor: a generator that stops reaching a shape fails
// here, not in review. Run with -v for the table.
func TestCoverage(t *testing.T) {
	t.Parallel()

	worlds, scenarios := map[string]int{}, map[string]int{}
	gen := Scenarios(coverageSteps)

	for i := range coverageSamples {
		for _, name := range Classify(Scenario{Start: Worlds().Example(i)}, Required) {
			worlds[name]++
		}

		for _, name := range Classify(gen.Example(i), Required) {
			scenarios[name]++
		}
	}

	var table strings.Builder

	fmt.Fprintf(&table, "%-36s %8s %10s %6s  %s\n", "shape", "worlds", "scenarios", "floor", "why")

	for _, sh := range Required {
		w := "-"
		if sh.World != nil {
			w = strconv.Itoa(worlds[sh.Name])
		}

		fmt.Fprintf(&table, "%-36s %8s %10d %6.0f  %s\n", sh.Name, w, scenarios[sh.Name], sh.Min*coverageSamples, sh.Why)

		if floor := int(sh.Min * coverageSamples); scenarios[sh.Name] < floor {
			t.Errorf("%s in %d of %d scenarios, floor %d", sh.Name, scenarios[sh.Name], coverageSamples, floor)
		}
	}

	t.Logf("cases out of %d containing each shape:\n%s", coverageSamples, table.String())
}
