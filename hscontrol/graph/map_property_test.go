package graph

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"pgregory.net/rapid"
)

// mapRef is one side of a comparison: a Map, what reading it gives, and,
// for a cursor, what the Map it stands for holds.
type mapRef struct {
	m        *Map[int, int]
	ident    int
	contents map[int]int
	of       map[int]int
	cursor   bool
}

func (r *mapRun) ref(v int) mapRef {
	ver := r.versions[v]
	c := r.idents[ver.ident].contents

	return mapRef{m: ver.m, ident: ver.ident, contents: c, of: c}
}

func (r *mapRun) identRef(id int) mapRef {
	c := r.idents[id].contents

	return mapRef{m: r.idents[id].m, ident: id, contents: c, of: c}
}

// cursorOf stands for ref as the old side of ChangedSince and reads as an
// empty Map.
func cursorOf(ref mapRef) mapRef {
	if ref.m == nil {
		return ref
	}

	return mapRef{m: ref.m.Cursor(), ident: ref.ident, contents: map[int]int{}, of: ref.of, cursor: true}
}

var nilRef = mapRef{ident: nilIdent, contents: map[int]int{}, of: map[int]int{}}

// eqFor is the equality Changes compares new and old by: new's, else old's,
// else none.
func (r *mapRun) eqFor(old, next mapRef) eqKind {
	switch {
	case next.m != nil && !next.cursor && r.idents[next.ident].hasEq:
		return r.eq
	case old.m != nil && !old.cursor && r.idents[old.ident].hasEq:
		return r.eq
	default:
		return eqNever
	}
}

// lineage is whether new's edit log reaches old, and the keys the edits
// between them changed and wrote.
func (r *mapRun) lineage(old, next mapRef) (bool, []int, []int) {
	switch {
	case old.m == next.m:
		return true, nil, nil
	case old.m == nil || next.m == nil:
		return false, nil, nil
	case old.ident == next.ident:
		return true, nil, nil
	}

	var changed, written [mapKeys]bool

	for cur, d := next.ident, 1; d <= r.idents[next.ident].logLen; d++ {
		id := r.idents[cur]
		for _, k := range id.changed {
			changed[k] = true
		}

		for _, k := range id.written {
			written[k] = true
		}

		if id.parent == old.ident {
			return true, keysOf(changed), keysOf(written)
		}

		cur = id.parent
	}

	return false, nil, nil
}

func keysOf(set [mapKeys]bool) []int {
	var keys []int

	for k, in := range set {
		if in {
			keys = append(keys, k)
		}
	}

	return keys
}

// compare holds Changes and ChangedSince between old and new to the model:
// Changes is the exact difference, each key once, and its result the
// caller's; from a cursor nothing is promised, it being a ChangedSince
// token alone. ChangedSince answers exactly when new's log reaches old,
// with every key that differs and only keys the edits between wrote, and
// counts a miss otherwise.
func (r *mapRun) compare(tl tally, old, next mapRef) string {
	eq := r.eqFor(old, next)
	reaches, through, written := r.lineage(old, next)

	// A cursor is a token for ChangedSince only, so what Changes would
	// answer from one is nothing the package promises.
	if !old.cursor {
		got := Changes(old.m, next.m)
		want := diffKeys(old.contents, next.contents, eq)

		// With no equality that decides changes, the log names the keys
		// the edits between wrote when it reaches old, and comparison
		// names every key either side holds.
		if eq == eqNever && reaches {
			want = slices.DeleteFunc(slices.Clone(through), func(k int) bool {
				_, held := next.contents[k]
				if !held {
					_, held = old.contents[k]
				}

				return !held
			})
		}

		if sorted := slices.Sorted(slices.Values(got)); !slices.Equal(sorted, want) {
			return fmt.Sprintf("Changes = %v, want %v", sorted, want)
		}

		// The result is the caller's: scribbling on it must not reach a log.
		for i := range got {
			got[i] = -1
		}
	}

	before := MapLogMisses()
	keys, ok := next.m.ChangedSince(old.m)
	missed := MapLogMisses() - before

	if ok != reaches {
		return fmt.Sprintf("ChangedSince answered %t, model %t", ok, reaches)
	}

	var wantMissed uint64
	if !ok && old.m != nil && next.m != nil {
		wantMissed = 1
	}

	if missed != wantMissed {
		return fmt.Sprintf("ChangedSince counted %d misses, want %d", missed, wantMissed)
	}

	if !ok {
		tl["log misses"]++

		return ""
	}

	tl["logged"]++

	for _, k := range diffKeys(old.of, next.contents, r.eqOf(next.ident).moved()) {
		if !slices.Contains(keys, k) {
			return fmt.Sprintf("ChangedSince = %v misses %d", keys, k)
		}
	}

	for _, k := range keys {
		if !slices.Contains(written, k) {
			return fmt.Sprintf("ChangedSince = %v names %d, which no edit between wrote", keys, k)
		}
	}

	return ""
}

// edges are the distances back an edit log's reach turns at: the log of L
// edits reaches back L, keeps mapLog and grows to twice that.
func edges(logLen int) []int {
	return []int{1, mapLog, mapLog + 1, logLen, logLen + 1, 2 * mapLog}
}

// queries compares every version with the one it was edited from, the
// drawn pairs, and every named version with its ancestors at the log's
// edges, each also through the old side's cursor.
func (r *mapRun) queries(h mapHistory, tl tally) string {
	both := func(old, next mapRef, what func() string) string {
		if d := r.compare(tl, old, next); d != "" {
			return what() + ": " + d
		}

		if d := r.compare(tl, cursorOf(old), next); d != "" {
			return what() + " from its cursor: " + d
		}

		return ""
	}

	for i, v := range r.versions {
		if v.base < 0 {
			continue
		}

		if d := both(r.ref(v.base), r.ref(i), func() string { return fmt.Sprintf("version %d from %d", i, v.base) }); d != "" {
			return d
		}
	}

	// Each named version and the one before, both ways: after a branch,
	// cousins.
	for i := 1; i < len(r.named); i++ {
		a, b := r.named[i-1], r.named[i]

		if d := both(r.ref(a), r.ref(b), func() string { return fmt.Sprintf("version %d from %d", b, a) }); d != "" {
			return d
		}

		if d := both(r.ref(b), r.ref(a), func() string { return fmt.Sprintf("version %d from %d", a, b) }); d != "" {
			return d
		}
	}

	for _, p := range h.Pairs {
		old, next := r.ref(r.versionAt(p.Old)), r.ref(r.versionAt(p.New))
		how := ""

		switch p.Kind {
		case pairCursor:
			old, how = cursorOf(old), " from a cursor"
		case pairNilOld:
			old, how = nilRef, " from nil"
		case pairNilNew:
			next, how = nilRef, " to nil"
		case pairPlain:
		}

		if d := r.compare(tl, old, next); d != "" {
			return fmt.Sprintf("named %d to %d%s: %s", p.Old, p.New, how, d)
		}
	}

	// The log's edges, through the Map only: its cursor reaches as far.
	for _, v := range r.named {
		id := r.versions[v].ident

		// A cursor holds none of its Map's entries.
		if c := r.versions[v].m.Cursor(); c != nil {
			for k := range mapKeys {
				if _, ok := c.Get(k); ok {
					return fmt.Sprintf("version %d: its cursor holds %d", v, k)
				}
			}

			if c.Len() != 0 || len(maps.Collect(c.All())) != 0 {
				return fmt.Sprintf("version %d: its cursor holds %d entries", v, c.Len())
			}
		}

		for _, d := range edges(r.idents[id].logLen) {
			a := id
			for range d {
				if a = r.idents[a].parent; a < 0 {
					break
				}
			}

			if a < 0 || d < 1 {
				continue
			}

			if d > mapLog {
				tl["past the kept log"]++
			}

			if msg := r.compare(tl, r.identRef(a), r.ref(v)); msg != "" {
				return fmt.Sprintf("version %d from %d edits back: %s", v, d, msg)
			}
		}
	}

	return ""
}

// TestMapHistoriesMatchPlainMaps replays drawn edit histories (edits of
// older versions, deletes and re-adds, same-value writes, net-zero edits,
// lineages from new, copied, zero and nil Maps, and runs of edits longer
// than the log keeps) alongside plain Go maps. Every version reads as its
// plain map after every edit, so no edit shows through an older one; an
// edit reads its staged changes; Done returns the Map it started from
// exactly when nothing changed by the Map's equality. Changes is the exact
// difference between any two versions, cursors and nil; ChangedSince
// answers exactly where the log reaches (modelled from mapLog's doc) and
// then names every changed key and only written ones.
func TestMapHistoriesMatchPlainMaps(t *testing.T) {
	tl := tally{}

	rapid.Check(t, func(t *rapid.T) {
		h := mapHistories(defaultMapSizes).Draw(t, "history")

		r := replayHistory(h, true)
		if r.problem != "" {
			t.Fatal(r.problem)
		}

		if d := r.queries(h, tl); d != "" {
			t.Fatal(d)
		}

		for k, n := range r.excepts {
			tl[k] += n
		}

		for _, v := range r.versions {
			if l := r.idents[v.ident].logLen; l > mapLog && v.filler {
				tl["log past mapLog"]++

				break
			}
		}
	})

	tl.require(t, "logged", "log misses", "past the kept log", "log past mapLog")
}

// rebuild is the grouping of contents from scratch.
func rebuild(contents map[int]int, groupsOf func(k, v int) []int) map[int][]int {
	out := map[int][]int{}

	for k, v := range contents {
		for _, g := range groupsOf(k, v) {
			out[g] = append(out[g], k)
		}
	}

	for g, keys := range out {
		slices.Sort(keys)
		out[g] = slices.Compact(keys)
	}

	return out
}

type groupResult struct {
	g Grouped[int, int, int]
	v int // the version grouped
}

// TestGroupByMatchesRebuildUnderHistories groups the versions of a drawn
// history in order, each from the latest result, from an older one (a
// branch), from nothing, or after skipping versions. Every result, and
// every one before it, equals grouping its input from scratch, in sorted
// lists of their length; the result's Groups is the Map it started from
// when no group changed, and Changes from it names the groups that did;
// groupsOf is called only for keys that changed, never for one sameGroups
// clears.
func TestGroupByMatchesRebuildUnderHistories(t *testing.T) {
	tl := tally{}

	rapid.Check(t, func(t *rapid.T) {
		gc := groupingCases(defaultMapSizes).Draw(t, "case")
		r := replayHistory(gc.History, false)
		groups, same := gc.Grouping.groups(r.eq), gc.Grouping.same(r.eq)

		results := make([]groupResult, 0, len(gc.Steps))

		var called []int

		counted := func(k, v int) []int {
			called = append(called, k)

			return groups(k, v)
		}

		for i, st := range gc.Steps {
			v := r.named[i]
			in := r.ref(v)
			prev, from := groupResult{v: -1}, -1

			switch st.Kind {
			case stepSkip:
				continue
			case stepOlder:
				if len(results) > 0 {
					from = len(results) - 1 - st.Back%len(results)
					tl["branched"]++
				}
			case stepNext:
				from = len(results) - 1
			case stepScratch:
			}

			if from >= 0 {
				prev = results[from]
			}

			called = called[:0]
			res := GroupBy(prev.g, in.m, counted, same)

			want := rebuild(in.contents, groups)
			if d := groupsDiffer(res, want); d != "" {
				t.Fatalf("step %d: %s", i, d)
			}

			if res.In != in.m {
				t.Fatalf("step %d: the result's input is not the Map grouped", i)
			}

			if d := callsBeyond(r, prev, in, called, same); d != "" {
				t.Fatalf("step %d: %s", i, d)
			}

			if prev.v >= 0 {
				before := rebuild(r.ref(prev.v).contents, groups)
				if maps.EqualFunc(before, want, slices.Equal[[]int]) {
					if res.Groups != prev.g.Groups {
						t.Fatalf("step %d: no group changed, but the groups are a new Map", i)
					}

					tl["groups kept"]++
				}

				var moved []int

				for g := range maps.Keys(before) {
					if !slices.Equal(before[g], want[g]) {
						moved = append(moved, g)
					}
				}

				for g := range maps.Keys(want) {
					if _, ok := before[g]; !ok {
						moved = append(moved, g)
					}
				}

				slices.Sort(moved)

				if got := slices.Sorted(slices.Values(Changes(prev.g.Groups, res.Groups))); !slices.Equal(got, moved) {
					t.Fatalf("step %d: Changes of the groups = %v, want %v", i, got, moved)
				}
			}

			results = append(results, groupResult{g: res, v: v})

			for j, old := range results {
				if d := groupsDiffer(old.g, rebuild(r.ref(old.v).contents, groups)); d != "" {
					t.Fatalf("after step %d, result %d: %s", i, j, d)
				}
			}
		}
	})

	tl.require(t, "branched", "groups kept")
}

// groupsDiffer describes how res differs from want, or "".
func groupsDiffer(res Grouped[int, int, int], want map[int][]int) string {
	if res.Groups == nil {
		return "no groups"
	}

	got := maps.Collect(res.Groups.All())
	if !maps.EqualFunc(got, want, slices.Equal[[]int]) {
		return fmt.Sprintf("groups %v, want %v", got, want)
	}

	for g, keys := range got {
		if cap(keys) != len(keys) {
			return fmt.Sprintf("group %d holds %d keys in an array of %d", g, len(keys), cap(keys))
		}
	}

	return ""
}

// callsBeyond checks groupsOf was called only as GroupBy's doc allows:
// once per entry from nothing, otherwise at most for each side of a key
// that changed, and never for a change sameGroups clears.
func callsBeyond(r *mapRun, prev groupResult, in mapRef, called []int, same func(a, b int) bool) string {
	count := map[int]int{}
	for _, k := range called {
		count[k]++
	}

	if prev.v < 0 {
		for k, n := range count {
			if _, ok := in.contents[k]; !ok || n > 1 {
				return fmt.Sprintf("grouping from nothing called groupsOf %d times for key %d", n, k)
			}
		}

		return ""
	}

	old := r.ref(prev.v)
	diff := diffKeys(old.contents, in.contents, r.eqFor(old, in))

	for k, n := range count {
		was, hadOld := old.contents[k]
		is, hasCur := in.contents[k]

		allowed := b2i(hadOld) + b2i(hasCur)
		if !slices.Contains(diff, k) || hadOld && hasCur && same != nil && same(was, is) {
			allowed = 0
		}

		if n > allowed {
			return fmt.Sprintf("groupsOf called %d times for key %d (%d=%t to %d=%t), allowed %d", n, k, was, hadOld, is, hasCur, allowed)
		}
	}

	return ""
}

// TestChangesFromACursorNamesLoggedKeys records what [Changes] answers
// from a [Cursor], a token [Map.ChangedSince] alone promises: with the
// log reaching it, the logged keys the new Map holds — [3] here, where
// the difference from the Map the cursor stands for is [1 3] and from an
// empty Map, which Cursor's doc says other reads see, [2 3].
func TestChangesFromACursorNamesLoggedKeys(t *testing.T) {
	base := NewMap(Same[int], map[int]int{1: 1, 2: 2})
	e := base.Edit()
	e.Delete(1)
	e.Set(3, 3)
	next := e.Done()

	if got := slices.Sorted(slices.Values(Changes(base.Cursor(), next))); !slices.Equal(got, []int{3}) {
		t.Fatalf("Changes from the cursor = %v", got)
	}
}

// TestEditOfANilMapReturnsNil pins Done's rule for a nil base: an edit
// that changes nothing returns the Map it started from, nil included, so
// a no-op edit keeps pointer identity where it began.
func TestEditOfANilMapReturnsNil(t *testing.T) {
	var m *Map[int, int]

	got := m.Edit().Done()
	if got != nil {
		t.Fatal("Done returned a new Map, want the nil it started from")
	}
}

// TestGroupByTrustsTheInputsEquality pins GroupBy's precondition: it
// moves only the keys the input's equality reports as changed, so a
// groupsOf that tells apart values the equality calls equal must not be
// given to it — a key it would regroup stays in its old group.
func TestGroupByTrustsTheInputsEquality(t *testing.T) {
	tens := func(a, b int) bool { return a/10 == b/10 }
	byValue := func(_, v int) []int { return []int{v} }

	in := NewMap(tens, map[int]int{1: 1})
	grouped := GroupBy(Grouped[int, int, int]{}, in, byValue, nil)

	e := in.Edit()
	e.Set(1, 2)
	e.Set(2, 20)
	next := e.Done()

	if v, _ := next.Get(1); v != 2 {
		t.Fatalf("key 1 holds %d", v)
	}

	got := maps.Collect(GroupBy(grouped, next, byValue, nil).Groups.All())
	if !maps.EqualFunc(got, map[int][]int{1: {1}, 20: {2}}, slices.Equal[[]int]) {
		t.Fatalf("groups %v: GroupBy now regroups keys its input calls unchanged", got)
	}
}

// TestChangesUnderNeverDependsOnTheLog pins Changes' rule for a Map with
// no usable equality: from the Map an edit started from, whose log the
// answer reads, it names what the edits wrote; from an equal Map of
// another lineage, compared key by key, every key.
func TestChangesUnderNeverDependsOnTheLog(t *testing.T) {
	base := NewMap(Never[int], map[int]int{1: 1, 2: 2})
	e := base.Edit()
	e.Set(3, 3)
	next := e.Done()

	if got := Changes(base, next); !slices.Equal(got, []int{3}) {
		t.Fatalf("Changes through the log = %v, want the keys the edit wrote", got)
	}

	twin := NewMap(Never[int], map[int]int{1: 1, 2: 2})
	if got := slices.Sorted(slices.Values(Changes(twin, next))); !slices.Equal(got, []int{1, 2, 3}) {
		t.Fatalf("Changes by comparison = %v, want every key either side holds", got)
	}
}
