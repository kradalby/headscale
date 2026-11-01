//go:build headscale_debug

package graph

// CellInfo describes a cell without exposing its value. ChangedAt is the
// revision of its last value change, not its last computation.
type CellInfo struct {
	Name         string
	Kind         string
	ChangedAt    uint64
	Dependencies []string
}

// Inspect returns independent metadata for a published snapshot of g. It
// reads only what registration sets, which is frozen before publication, so
// it needs no writer lock; the writer's later release of initial values
// touches a field it does not read.
func (g *Graph) Inspect(s *Snapshot) []CellInfo {
	out := make([]CellInfo, 0, len(g.cells))
	for i, c := range g.cells {
		info := CellInfo{Name: c.name, Kind: "input", ChangedAt: s.changed[i], Dependencies: []string{}}
		if c.derived {
			info.Kind = "derived"
		}

		seen := make(map[int]bool)
		for _, dep := range s.deps[i] {
			if !seen[dep] {
				info.Dependencies = append(info.Dependencies, g.cells[dep].name)
				seen[dep] = true
			}
		}

		out = append(out, info)
	}

	return out
}
