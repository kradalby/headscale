package graph

import (
	"cmp"
	"hash/maphash"
	"iter"
	"slices"
	"sync/atomic"

	"github.com/benbjohnson/immutable"
)

// Map is an immutable map that remembers which keys its recent edits
// changed, so a reader holding an older Map it was edited from finds what
// moved without comparing every key. Edits share structure with the Map
// they start from: an edit of k keys costs O(k log n), and an older Map a
// reader still holds costs only what the edits after it replaced.
//
// The zero Map is empty.
type Map[K comparable, V any] struct {
	items *immutable.Map[K, V]
	eq    func(a, b V) bool

	// id identifies this Map in the edit logs of Maps edited from it.
	id uint64
	// log is the most recent edit that led here; earlier ones follow.
	log *mapEdit[K]
}

// mapEdit is one edit: the keys it changed on the Map with id from. The
// edits form a chain shared by every Map edited from the same one, so an
// edit adds an entry instead of copying the log.
type mapEdit[K comparable] struct {
	from  uint64
	keys  []K
	prev  *mapEdit[K]
	depth int // entries from here to the chain's end, this one included
}

// mapLog is how many edits back a Map's log always reaches; a reader
// further behind compares every key instead. A chain grows to twice this
// before its oldest half is dropped, so trimming costs O(1) per edit.
const mapLog = 256

var (
	mapIDs atomic.Uint64

	logMisses atomic.Uint64
)

// MapLogMisses counts the times [Map.ChangedSince] found an older Map
// outside the edit log, so its reader compared every key instead.
func MapLogMisses() uint64 { return logMisses.Load() }

// NewMap returns a Map holding entries. eq decides whether a value set by
// an edit is a change.
func NewMap[K comparable, V any](eq func(a, b V) bool, entries map[K]V) *Map[K, V] {
	b := immutable.NewMapBuilder[K, V](hasher[K]{})
	for k, v := range entries {
		b.Set(k, v)
	}

	return &Map[K, V]{items: b.Map(), eq: eq, id: mapIDs.Add(1)}
}

// Get returns the value for k.
func (m *Map[K, V]) Get(k K) (V, bool) {
	if m == nil || m.items == nil {
		var zero V

		return zero, false
	}

	return m.items.Get(k)
}

// Len returns the number of entries.
func (m *Map[K, V]) Len() int {
	if m == nil || m.items == nil {
		return 0
	}

	return m.items.Len()
}

// All returns the entries in no particular order.
func (m *Map[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		if m == nil || m.items == nil {
			return
		}

		for it := m.items.Iterator(); !it.Done(); {
			k, v, _ := it.Next()
			if !yield(k, v) {
				return
			}
		}
	}
}

// ChangedSince returns the keys the edits from old to m touched, possibly
// with repeats and keys that changed back, when old is a Map m was edited
// from within its edit log; otherwise it returns false. [Changes] is the
// exact form.
func (m *Map[K, V]) ChangedSince(old *Map[K, V]) ([]K, bool) {
	if m == old {
		return nil, true
	}

	if m == nil || old == nil {
		return nil, false
	}

	if m.id == old.id {
		return nil, true
	}

	// Find old in the log before collecting: a reader too far behind
	// must not pay for the whole log.
	n, found := 0, false

	for e := m.log; e != nil; e = e.prev {
		n += len(e.keys)
		if e.from == old.id {
			found = true

			break
		}
	}

	if !found {
		logMisses.Add(1)

		return nil, false
	}

	keys := make([]K, 0, n)

	for e := m.log; ; e = e.prev {
		keys = append(keys, e.keys...)
		if e.from == old.id {
			return keys, true
		}
	}
}

// Cursor returns a Map that stands for m only as the old side of
// [Map.ChangedSince]: it holds none of m's entries, so a reader keeping it
// to ask a later Map what changed pins nothing. Reading it any other way
// sees an empty Map.
func (m *Map[K, V]) Cursor() *Map[K, V] {
	if m == nil {
		return nil
	}

	return &Map[K, V]{id: m.id}
}

// Changes returns the keys whose entry differs between old and m, each
// once. It reads the edit log when it can and compares every key when it
// cannot, so it is always correct; old may be nil.
func Changes[K comparable, V any](old, m *Map[K, V]) []K {
	eq := m.eqOr(old)

	if logged, ok := m.ChangedSince(old); ok {
		// The log also names keys that changed back.
		seen := make(map[K]struct{}, len(logged))
		keys := logged[:0:0]

		for _, k := range logged {
			if _, dup := seen[k]; dup {
				continue
			}

			seen[k] = struct{}{}

			was, wasOK := old.Get(k)
			if is, isOK := m.Get(k); wasOK != isOK || isOK && !eq(was, is) {
				keys = append(keys, k)
			}
		}

		return keys
	}

	var keys []K

	for k, v := range m.All() {
		if ov, ok := old.Get(k); !ok || !eq(ov, v) {
			keys = append(keys, k)
		}
	}

	for k := range old.All() {
		if _, ok := m.Get(k); !ok {
			keys = append(keys, k)
		}
	}

	return keys
}

func (m *Map[K, V]) eqOr(other *Map[K, V]) func(a, b V) bool {
	switch {
	case m != nil && m.eq != nil:
		return m.eq
	case other != nil && other.eq != nil:
		return other.eq
	default:
		return func(V, V) bool { return false }
	}
}

// Edit starts an edit of m. m is unchanged by it.
func (m *Map[K, V]) Edit() *MapEdit[K, V] {
	e := &MapEdit[K, V]{base: m, touched: make(map[K]struct{})}
	if m != nil {
		e.items = m.items
	}

	if e.items == nil {
		e.items = immutable.NewMap[K, V](hasher[K]{})
	}

	return e
}

// MapEdit stages changes to a Map. It is not safe for concurrent use.
type MapEdit[K comparable, V any] struct {
	base    *Map[K, V]
	items   *immutable.Map[K, V]
	touched map[K]struct{}
	order   []K
}

// Get returns the value for k with the staged changes applied.
func (e *MapEdit[K, V]) Get(k K) (V, bool) { return e.items.Get(k) }

// Len returns the number of entries with the staged changes applied.
func (e *MapEdit[K, V]) Len() int { return e.items.Len() }

// All returns the entries with the staged changes applied.
func (e *MapEdit[K, V]) All() iter.Seq2[K, V] {
	return (&Map[K, V]{items: e.items}).All()
}

// Set stages k = v.
func (e *MapEdit[K, V]) Set(k K, v V) {
	e.touch(k)
	e.items = e.items.Set(k, v)
}

// Delete stages the removal of k.
func (e *MapEdit[K, V]) Delete(k K) {
	if _, ok := e.items.Get(k); !ok {
		return
	}

	e.touch(k)
	e.items = e.items.Delete(k)
}

func (e *MapEdit[K, V]) touch(k K) {
	if _, ok := e.touched[k]; !ok {
		e.touched[k] = struct{}{}
		e.order = append(e.order, k)
	}
}

// Done returns the edited Map, or the Map the edit started from when no
// entry ends up different from it.
func (e *MapEdit[K, V]) Done() *Map[K, V] {
	eq := e.base.eqOr(nil)

	var changed []K

	for _, k := range e.order {
		was, wasOK := e.base.Get(k)
		is, isOK := e.items.Get(k)

		if wasOK != isOK || isOK && !eq(was, is) {
			changed = append(changed, k)
		}
	}

	if len(changed) == 0 && e.base != nil {
		return e.base
	}

	next := &Map[K, V]{items: e.items, id: mapIDs.Add(1)}

	if e.base != nil {
		next.eq = e.base.eq

		next.log = &mapEdit[K]{from: e.base.id, keys: changed, prev: e.base.log, depth: 1}
		if e.base.log != nil {
			next.log.depth = e.base.log.depth + 1
		}

		if next.log.depth > 2*mapLog {
			next.log = trimLog(next.log, mapLog)
		}
	}

	return next
}

// trimLog returns a new chain of the n newest edits from head; the older
// ones are left to the Maps still holding them.
func trimLog[K comparable](head *mapEdit[K], n int) *mapEdit[K] {
	kept := make([]*mapEdit[K], 0, n)
	for e := head; e != nil && len(kept) < n; e = e.prev {
		kept = append(kept, e)
	}

	var chain *mapEdit[K]

	for i, e := range slices.Backward(kept) {
		chain = &mapEdit[K]{from: e.from, keys: e.keys, prev: chain, depth: len(kept) - i}
	}

	return chain
}

// hasher hashes any comparable key the way the runtime's maps do.
type hasher[K comparable] struct{}

var seed = maphash.MakeSeed()

func (hasher[K]) Hash(k K) uint32 {
	h := maphash.Comparable(seed, k)

	return uint32(h ^ h>>32) //nolint:gosec // folding a hash
}

func (hasher[K]) Equal(a, b K) bool { return a == b }

// Grouped is the result of [GroupBy]: the input it was computed from and
// the keys of each group, sorted.
type Grouped[K cmp.Ordered, V any, G comparable] struct {
	In     *Map[K, V]
	Groups *Map[G, []K]
}

// GroupBy groups the keys of in by groupsOf, which names every group an
// entry belongs to. Given its previous result, it moves only the keys that
// changed since prev.In.
func GroupBy[K cmp.Ordered, V any, G comparable](
	prev Grouped[K, V, G],
	in *Map[K, V],
	groupsOf func(K, V) []G,
) Grouped[K, V, G] {
	groups := prev.Groups
	if groups == nil {
		groups = NewMap[G, []K](slices.Equal[[]K], nil)
	}

	e := groups.Edit()

	for _, k := range Changes(prev.In, in) {
		var was, is []G
		if v, ok := prev.In.Get(k); ok {
			was = groupsOf(k, v)
		}

		if v, ok := in.Get(k); ok {
			is = groupsOf(k, v)
		}

		for _, g := range was {
			if slices.Contains(is, g) {
				continue
			}

			keys, _ := e.Get(g)
			if i, found := slices.BinarySearch(keys, k); found {
				keys = slices.Delete(slices.Clone(keys), i, i+1)
				if len(keys) == 0 {
					e.Delete(g)
				} else {
					e.Set(g, keys)
				}
			}
		}

		for _, g := range is {
			keys, _ := e.Get(g)
			if i, found := slices.BinarySearch(keys, k); !found {
				e.Set(g, slices.Insert(slices.Clone(keys), i, k))
			}
		}
	}

	return Grouped[K, V, G]{In: in, Groups: e.Done()}
}
