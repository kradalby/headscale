package graph

import (
	"iter"
	"maps"
	"slices"
	"testing"

	"pgregory.net/rapid"
)

// mapHistory keeps the oracle independent of the persistent map and its log.
// Unchanged commits reuse the history node, just as Done promises identity.
type mapHistory struct {
	value   *Map[int, int]
	cursor  *Map[int, int]
	entries map[int]int
	parent  *mapHistory
}

func mapModelDiff(a, b map[int]int, modulus int) []int {
	if modulus == 0 {
		return fullDiff(a, b)
	}

	canonical := func(m map[int]int) map[int]int {
		out := make(map[int]int, len(m))
		for k, v := range m {
			out[k] = v % modulus
		}

		return out
	}

	return fullDiff(canonical(a), canonical(b))
}

func checkMapReads(t *rapid.T, m interface {
	Get(key int) (int, bool)
	Len() int
	All() iter.Seq2[int, int]
}, want map[int]int,
) {
	t.Helper()

	got := make(map[int]int)
	for k, v := range m.All() {
		if _, duplicate := got[k]; duplicate {
			t.Fatalf("All repeated key %d", k)
		}

		got[k] = v
	}

	if !maps.Equal(got, want) || m.Len() != len(want) {
		t.Fatalf("All = %v, Len = %d; want %v", got, m.Len(), want)
	}

	// Cover the entire generated key domain, including deleted keys.
	for k := -1; k <= 9; k++ {
		v, present := want[k]
		if actual, ok := m.Get(k); ok != present || actual != v {
			t.Fatalf("Get(%d) = %d, %t; want %d, %t", k, actual, ok, v, present)
		}
	}

	calls := 0

	m.All()(func(int, int) bool { calls++; return false })

	if calls != min(1, len(want)) {
		t.Fatalf("All ignored early stop: %d calls", calls)
	}
}

func checkMapHistoryPair(t *rapid.T, old, cur *mapHistory, modulus int) {
	t.Helper()

	want := mapModelDiff(old.entries, cur.entries, modulus)

	got := Changes(old.value, cur.value)
	if !slices.Equal(sortedUnique(got), want) || len(got) != len(want) {
		t.Fatalf("Changes(%v, %v) = %v; want %v", old.entries, cur.entries, got, want)
	}

	keys, ok := cur.value.ChangedSince(old.value)

	cursorKeys, cursorOK := cur.value.ChangedSince(old.cursor)
	if ok != cursorOK || !slices.Equal(keys, cursorKeys) {
		t.Fatalf("cursor = %v, %t; snapshot = %v, %t", cursorKeys, cursorOK, keys, ok)
	}

	ancestor, distance := cur, 0
	touched := make(map[int]bool)

	for ancestor != nil && ancestor != old {
		if ancestor.parent != nil {
			for _, k := range mapModelDiff(ancestor.parent.entries, ancestor.entries, modulus) {
				touched[k] = true
			}
		}

		ancestor = ancestor.parent
		distance++
	}

	if ancestor == nil && ok {
		t.Fatal("ChangedSince accepted a sibling or unrelated map")
	}

	if ancestor != nil && distance <= mapLog && !ok {
		t.Fatalf("ChangedSince missed an ancestor %d effective commits back", distance)
	}

	if ok {
		// ChangedSince may repeat keys and include reversions, but must retain
		// every effective touch, not merely the final net difference.
		for k := range touched {
			if !slices.Contains(keys, k) {
				t.Fatalf("ChangedSince = %v omits touched key %d", keys, k)
			}
		}

		for _, k := range keys {
			if !touched[k] {
				t.Fatalf("ChangedSince invented untouched key %d", k)
			}
		}
	}
}

func TestMapPropertyHistories(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modulus int
	}{{"exact", 0}, {"equivalence", 4}} {
		t.Run(tc.name, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				equal := func(a, b int) bool {
					if tc.modulus != 0 {
						return a%tc.modulus == b%tc.modulus
					}

					return a == b
				}
				entries := rapid.MapOfN(rapid.IntRange(0, 7), rapid.IntRange(0, 15), 0, 8).Draw(t, "initial")
				root := NewMap(equal, entries)
				history := []*mapHistory{{value: root, cursor: root.Cursor(), entries: maps.Clone(entries)}}
				// NewMap must not keep the caller's mutable native map.
				clear(entries)

				type heldEdit struct {
					edit    *MapEdit[int, int]
					entries map[int]int
				}

				var discarded []heldEdit

				edit := func(t *rapid.T, discard, restore bool) {
					base := history[rapid.IntRange(0, len(history)-1).Draw(t, "parent")]
					e := base.value.Edit()
					model := maps.Clone(base.entries)
					checkMapReads(t, e, model)

					for range rapid.IntRange(0, 8).Draw(t, "batch size") {
						k := rapid.IntRange(0, 7).Draw(t, "key")
						if rapid.Bool().Draw(t, "delete") {
							e.Delete(k)
							delete(model, k)
						} else {
							v := rapid.IntRange(0, 15).Draw(t, "value")
							e.Set(k, v)
							model[k] = v
						}

						checkMapReads(t, e, model)
						checkMapReads(t, base.value, base.entries)
					}

					if restore {
						for k := range 8 {
							if v, ok := base.entries[k]; ok {
								e.Set(k, v)
							} else {
								e.Delete(k)
							}
						}

						model = maps.Clone(base.entries)
						checkMapReads(t, e, model)
					}

					if discard {
						discarded = append(discarded, heldEdit{e, model})

						return
					}

					next := e.Done()
					if len(mapModelDiff(base.entries, model, tc.modulus)) == 0 {
						if next != base.value {
							t.Fatal("net-zero edit lost map identity")
						}

						// An equivalent replacement need not become the stored representative.
						checkMapReads(t, next, base.entries)

						return
					}

					node := &mapHistory{next, next.Cursor(), model, base}
					history = append(history, node)

					checkMapReads(t, next, model)
					checkMapHistoryPair(t, base, node, tc.modulus)
				}

				t.Repeat(map[string]func(*rapid.T){
					"edit":    func(t *rapid.T) { edit(t, false, false) },
					"discard": func(t *rapid.T) { edit(t, true, false) },
					"restore": func(t *rapid.T) { edit(t, false, true) },
					"unrelated": func(t *rapid.T) {
						model := rapid.MapOfN(rapid.IntRange(0, 7), rapid.IntRange(0, 15), 0, 8).Draw(t, "entries")
						m := NewMap(equal, model)
						history = append(history, &mapHistory{value: m, cursor: m.Cursor(), entries: model})
					},
				})

				for _, old := range history {
					checkMapReads(t, old.value, old.entries)

					for _, cur := range history {
						checkMapHistoryPair(t, old, cur, tc.modulus)
					}
				}

				for _, held := range discarded {
					checkMapReads(t, held.edit, held.entries)
				}
			})
		})
	}
}

func TestMapPropertyEmptyForms(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.IntRange(0, 7).Draw(t, "key")
		value := rapid.Int().Draw(t, "value")

		for _, empty := range []*Map[int, int]{nil, {}, NewMap[int, int](Same[int], nil), NewMap(Same[int], map[int]int{})} {
			checkMapReads(t, empty, nil)
			e := empty.Edit()
			e.Delete(key)
			e.Set(key, value)
			checkMapReads(t, e, map[int]int{key: value})
			e.Delete(key)
			checkMapReads(t, e, nil)

			zero := e.Done()
			checkMapReads(t, zero, nil)

			if empty != nil && zero != empty {
				t.Fatal("net-zero edit of an empty map lost identity")
			}

			e = empty.Edit()
			e.Set(key, value)
			next := e.Done()
			checkMapReads(t, next, map[int]int{key: value})
			checkMapReads(t, empty, nil)

			e = next.Edit()
			e.Set(key, value^1)
			updated := e.Done()
			checkMapReads(t, updated, map[int]int{key: value ^ 1})
			checkMapReads(t, next, map[int]int{key: value})

			e = updated.Edit()
			e.Delete(key)
			deleted := e.Done()
			checkMapReads(t, deleted, nil)

			for _, pair := range [][2]*Map[int, int]{
				{empty, zero},
				{zero, empty},
				{empty, next},
				{next, empty},
				{next, next},
				{nil, next},
				{next, nil},
				{next, updated},
				{updated, next},
				{updated, deleted},
				{deleted, updated},
			} {
				want := fullDiff(toNative(pair[0]), toNative(pair[1]))
				if got := Changes(pair[0], pair[1]); !slices.Equal(sortedUnique(got), want) || len(got) != len(want) {
					t.Fatalf("empty-form Changes = %v; want %v", got, want)
				}
			}

			for _, m := range []*Map[int, int]{empty, zero, next} {
				keys, ok := m.ChangedSince(empty)

				cursorKeys, cursorOK := m.ChangedSince(empty.Cursor())
				if ok != cursorOK || !slices.Equal(keys, cursorKeys) {
					t.Fatal("empty-form cursor differs from its snapshot")
				}
			}
		}
	})
}

// The long skeleton cannot shrink away the commits needed to trim the log.
// Generated churn still varies deletion, reinsertion and reverted keys.
func TestMapPropertyLogBoundaries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		initial := rapid.MapOfN(rapid.IntRange(1, 7), rapid.IntRange(0, 15), 0, 7).Draw(t, "initial")
		root := NewMap(Same[int], initial)
		history := []*mapHistory{{value: root, cursor: root.Cursor(), entries: maps.Clone(initial)}}
		churnKey := rapid.IntRange(1, 7).Draw(t, "churn key")
		churnValue := rapid.IntRange(0, 15).Draw(t, "churn value")

		for step := 1; step <= 513; step++ {
			base := history[len(history)-1]
			model := maps.Clone(base.entries)
			e := base.value.Edit()
			e.Set(0, step) // Every commit is effective, regardless of generated churn.
			model[0] = step

			if step%2 == 0 {
				e.Delete(churnKey)
				delete(model, churnKey)
			} else {
				e.Set(churnKey, churnValue)
				model[churnKey] = churnValue
			}

			next := e.Done()
			if next == base.value {
				t.Fatal("boundary skeleton failed to make an effective commit")
			}

			history = append(history, &mapHistory{next, next.Cursor(), model, base})
		}

		for _, step := range []int{255, 256, 257, 511, 512, 513} {
			cur := history[step]
			for _, age := range []int{0, 1, 255, 256, 257, 511, 512, 513} {
				if age > step {
					continue
				}

				old := history[step-age]
				checkMapHistoryPair(t, old, cur, 0)
				checkMapHistoryPair(t, cur, old, 0)
			}

			// Branch from a retained snapshot after the main chain has trimmed.
			base := history[step-1]
			e := base.value.Edit()
			e.Set(8, churnValue)
			sibling := e.Done()
			model := maps.Clone(base.entries)
			model[8] = churnValue
			branch := &mapHistory{sibling, sibling.Cursor(), model, base}
			checkMapHistoryPair(t, base, branch, 0)
			checkMapHistoryPair(t, branch, cur, 0)
			checkMapHistoryPair(t, cur, branch, 0)

			unrelated := NewMap(Same[int], cur.entries)
			other := &mapHistory{value: unrelated, cursor: unrelated.Cursor(), entries: maps.Clone(cur.entries)}
			checkMapHistoryPair(t, other, cur, 0)
			checkMapHistoryPair(t, cur, other, 0)
		}

		// Pin the documented 2*mapLog trimming threshold and the retained window.
		if _, ok := history[512].value.ChangedSince(history[0].cursor); !ok {
			t.Fatal("log trimmed before 512 effective commits")
		}

		if _, ok := history[513].value.ChangedSince(history[256].cursor); ok {
			t.Fatal("513th commit did not trim the oldest half")
		}

		for _, old := range history {
			checkMapReads(t, old.value, old.entries)
		}
	})
}

type groupPropertyValue struct {
	memberships []int
	payload     int
}

func groupPropertyEqual(a, b groupPropertyValue) bool {
	return a.payload == b.payload && slices.Equal(a.memberships, b.memberships)
}

func groupPropertySameGroups(a, b groupPropertyValue) bool {
	return slices.Equal(sortedUnique(a.memberships), sortedUnique(b.memberships))
}

// Rebuild from membership sets, without GroupBy, Changes or persistent maps.
func rebuildPropertyGroups(entries map[int]groupPropertyValue) map[int][]int {
	sets := make(map[int]map[int]bool)

	for key, value := range entries {
		for _, group := range value.memberships {
			if sets[group] == nil {
				sets[group] = make(map[int]bool)
			}

			sets[group][key] = true
		}
	}

	out := make(map[int][]int, len(sets))
	for group, members := range sets {
		out[group] = slices.Sorted(maps.Keys(members))
	}

	return out
}

func TestGroupByPropertyHistories(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		valueGen := rapid.Custom(func(t *rapid.T) groupPropertyValue {
			memberships := rapid.OneOf(
				rapid.SliceOfN(rapid.IntRange(0, 5), 0, 5),
				rapid.SliceOfN(rapid.IntRange(0, 19), 16, 20),
			).Draw(t, "memberships")

			return groupPropertyValue{memberships, rapid.IntRange(0, 5).Draw(t, "payload")}
		})

		type snapshot struct {
			in      *Map[int, groupPropertyValue]
			entries map[int]groupPropertyValue
		}

		inputs := []snapshot{{nil, map[int]groupPropertyValue{}}, {&Map[int, groupPropertyValue]{}, map[int]groupPropertyValue{}}}

		type heldGroups struct {
			result   Grouped[int, groupPropertyValue, int]
			retained map[int][]int
			want     map[int][]int
		}

		var outputs []heldGroups

		groupsOf := func(_ int, v groupPropertyValue) []int { return v.memberships }
		check := func(result Grouped[int, groupPropertyValue, int], in snapshot) {
			want := rebuildPropertyGroups(in.entries)

			got := toNative(result.Groups)
			if result.In != in.in || !maps.EqualFunc(got, want, slices.Equal[[]int]) {
				t.Fatalf("GroupBy = %v; rebuild = %v", got, want)
			}

			outputs = append(outputs, heldGroups{result, got, want})
		}
		publish := func(in snapshot) {
			var prev Grouped[int, groupPropertyValue, int]
			if len(outputs) > 0 {
				prev = outputs[rapid.IntRange(0, len(outputs)-1).Draw(t, "previous grouping")].result
			}

			check(GroupBy(prev, in.in, groupsOf, nil), in)
			check(GroupBy(prev, in.in, groupsOf, groupPropertySameGroups), in)
		}

		for _, in := range inputs {
			publish(in)
		}

		initial := rapid.MapOfN(rapid.IntRange(0, 7), valueGen, 0, 8).Draw(t, "initial")
		inputs = append(inputs, snapshot{NewMap(groupPropertyEqual, initial), maps.Clone(initial)})
		publish(inputs[len(inputs)-1])

		t.Repeat(map[string]func(*rapid.T){
			"edit": func(t *rapid.T) {
				// Nil/zero input forms are read-only: they carry no value equivalence.
				base := inputs[rapid.IntRange(2, len(inputs)-1).Draw(t, "input parent")]
				model := maps.Clone(base.entries)
				e := base.in.Edit()

				for range rapid.IntRange(0, 6).Draw(t, "batch size") {
					key := rapid.IntRange(0, 7).Draw(t, "key")
					value := model[key]

					switch rapid.IntRange(0, 4).Draw(t, "operation") {
					case 0:
						e.Delete(key)
						delete(model, key)

						continue
					case 1:
						value = valueGen.Draw(t, "value")
					case 2:
						value.payload++
					case 3:
						value.memberships = slices.Clone(value.memberships)
						slices.Reverse(value.memberships)
					case 4:
						value.memberships = append(slices.Clone(value.memberships), value.memberships...)
					}

					e.Set(key, value)
					model[key] = value
				}

				next := snapshot{e.Done(), model}
				inputs = append(inputs, next)
				publish(next)
			},
			"regroup": func(t *rapid.T) {
				publish(inputs[rapid.IntRange(0, len(inputs)-1).Draw(t, "input")])
			},
			"unrelated": func(t *rapid.T) {
				model := rapid.MapOfN(rapid.IntRange(0, 7), valueGen, 0, 8).Draw(t, "entries")
				next := snapshot{NewMap(groupPropertyEqual, model), model}
				inputs = append(inputs, next)
				publish(next)
			},
		})

		for _, in := range inputs {
			if !maps.EqualFunc(toNative(in.in), in.entries, groupPropertyEqual) {
				t.Fatal("old grouping input changed")
			}
		}

		for _, old := range outputs {
			if !maps.EqualFunc(toNative(old.result.Groups), old.want, slices.Equal[[]int]) ||
				!maps.EqualFunc(old.retained, old.want, slices.Equal[[]int]) {
				t.Fatal("published group membership slices changed")
			}
		}
	})
}

// Exercise both membership algorithms on every run, including all groups being
// removed and sameGroups skipping payload-only, duplicate and ordering changes.
func TestGroupByPropertyMembershipBoundaries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.IntRange(0, 7).Draw(t, "key")
		offset := rapid.IntRange(0, 5).Draw(t, "group offset")
		in := NewMap[int, groupPropertyValue](groupPropertyEqual, nil)

		var prev Grouped[int, groupPropertyValue, int]

		for _, size := range []int{0, 1, 16, 17, 20, 17, 16, 1, 0} {
			memberships := make([]int, size)
			for i := range memberships {
				memberships[i] = offset + i%17
			}

			value := groupPropertyValue{memberships: memberships}
			e := in.Edit()
			e.Set(key, value)
			in = e.Done()
			old := prev
			retained := toNative(old.Groups)
			oldWant := rebuildPropertyGroups(toNative(old.In))
			prev = GroupBy(prev, in, func(_ int, v groupPropertyValue) []int { return v.memberships }, nil)

			want := rebuildPropertyGroups(map[int]groupPropertyValue{key: value})
			if !maps.EqualFunc(toNative(prev.Groups), want, slices.Equal[[]int]) ||
				!maps.EqualFunc(retained, oldWant, slices.Equal[[]int]) {
				t.Fatalf("membership boundary %d: groups or retained snapshot differ", size)
			}

			value.memberships = append(slices.Clone(memberships), memberships...)
			slices.Reverse(value.memberships)
			value.payload++
			e = in.Edit()
			e.Set(key, value)
			in = e.Done()

			optimized := GroupBy(prev, in, func(int, groupPropertyValue) []int {
				t.Fatal("sameGroups must skip groupsOf for equivalent memberships")

				return nil
			}, groupPropertySameGroups)
			if optimized.In != in || optimized.Groups != prev.Groups {
				t.Fatal("sameGroups must advance input while preserving group identity")
			}

			prev = optimized
		}
	})
}
