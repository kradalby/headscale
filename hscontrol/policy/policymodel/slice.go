package policymodel

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
)

// A slice of a property: some of its judges, over the cases that hold
// some shapes, run from the property's own code, at the cost of that
// slice alone: a judge left out is not run, and a case outside the shapes
// is drawn and dropped before the level is driven. The names come from
// the environment so any property is narrowed without code.
const (
	// JudgesEnv names, comma-separated, the judges a property runs; a
	// property that names none of its own runs whole.
	JudgesEnv = "HEADSCALE_PBT_JUDGES"
	// ShapesEnv names, comma-separated, the shapes of [Required] a case
	// must hold one of; "via-*" names every shape so prefixed.
	ShapesEnv = "HEADSCALE_PBT_SHAPES"
)

var errSlice = errors.New("no such part")

// Slice is what a run is narrowed to. The zero value is the whole
// property.
type Slice struct {
	judges map[string]bool
	shapes []Shape
}

// SliceOf reads the slice a property with the named judges runs,
// refusing a judge it does not have or a shape no table holds.
func SliceOf(judges ...string) (Slice, error) {
	var s Slice

	if v := os.Getenv(JudgesEnv); v != "" && len(judges) > 0 {
		s.judges = map[string]bool{}

		for name := range strings.SplitSeq(v, ",") {
			if !slices.Contains(judges, name) {
				return Slice{}, fmt.Errorf("%s: %w: judge %q (this property has %v)", JudgesEnv, errSlice, name, judges)
			}

			s.judges[name] = true
		}
	}

	if v := os.Getenv(ShapesEnv); v != "" {
		for name := range strings.SplitSeq(v, ",") {
			n := len(s.shapes)

			for _, sh := range Required {
				if prefix, ok := strings.CutSuffix(name, "*"); sh.Name == name || ok && strings.HasPrefix(sh.Name, prefix) {
					s.shapes = append(s.shapes, sh)
				}
			}

			if len(s.shapes) == n {
				return Slice{}, fmt.Errorf("%s: %w: shape %q", ShapesEnv, errSlice, name)
			}
		}
	}

	return s, nil
}

// Judges reports whether the run holds judge name.
func (s Slice) Judges(name string) bool { return s.judges == nil || s.judges[name] }

// Holds reports whether sc is in the slice: it holds one of its shapes,
// or the run names none. A level that draws its steps as it plays holds
// its start alone to them, which only shapes of a world can match.
func (s Slice) Holds(sc Scenario) bool {
	return len(s.shapes) == 0 || len(Classify(sc, s.shapes)) > 0
}

// Whole reports whether the run is the whole property: only then is what
// it reached held to the property's floors.
func (s Slice) Whole() bool { return s.judges == nil && len(s.shapes) == 0 }

func (s Slice) String() string {
	if s.Whole() {
		return "whole"
	}

	names := make([]string, 0, len(s.shapes))
	for _, sh := range s.shapes {
		names = append(names, sh.Name)
	}

	judges := "all"
	if s.judges != nil {
		judges = strings.Join(slices.Sorted(maps.Keys(s.judges)), ",")
	}

	return fmt.Sprintf("judges %s; shapes %v", judges, names)
}
