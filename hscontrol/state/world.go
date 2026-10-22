package state

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
)

// fallbackGivenName is the DNS label used when a node is written with
// an empty [types.Node.GivenName]. Matches Tailscale SaaS behaviour
// for empty sanitised labels.
const fallbackGivenName = "node"

// Errors returned by [world.SetGivenName].
var (
	ErrGivenNameTaken   = errors.New("given name already in use by another node")
	ErrGivenNameInvalid = errors.New("given name is not a valid DNS label")
)

const prometheusNamespace = "headscale"

var (
	worldCommits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "world_commits_total",
		Help:      "Committed control-plane graph transactions.",
	})
	worldNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "world_nodes",
		Help:      "Nodes in the control-plane graph.",
	})
	worldBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "world_write_batch_size",
		Help:      "Node writes committed together.",
		Buckets:   []float64{1, 2, 5, 10, 20, 50, 100, 200},
	})
	policyCompiles = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "policy_compiles_total",
		Help:      "Policy compilations by result.",
	}, []string{"result"})
)

// nodeMap is the set of nodes. A stored node is never mutated: a write
// stores a modified copy, so a [types.NodeView] taken from a snapshot stays
// valid and two snapshots holding the same pointer hold the same node.
type nodeMap = graph.Map[types.NodeID, *types.Node]

// nodeEdit stages a write to the nodes.
type nodeEdit = graph.MapEdit[types.NodeID, *types.Node]

// world is the control plane as a dataflow graph. Its inputs are what the
// server is told: nodes, users, the policy document, the DERP map and the
// extra DNS records. Everything else is derived and recomputed only when
// what it read changed:
//
//	nodes ──► index ──► policyNodes ─┬─► policy ──► peers
//	users ───────────────────────────┤
//	policySrc ───────────────────────┘
//	index ──► primaries
//
// The nodes, users and policySrc inputs are written only through the
// methods below, which serialise on the graph.
type world struct {
	g *graph.Graph

	// writeMu guards the group-commit queue of node writes.
	writeMu    sync.Mutex
	writes     []*nodeWrite
	committing bool

	// batchSize and batchTimeout are [types.Tuning.NodeStoreBatchSize] and
	// [types.Tuning.NodeStoreBatchTimeout]: a commit waits up to the timeout
	// for writes to batch, or until batchSize are queued. Zero waits for
	// nothing. full wakes a waiting commit once the batch is full.
	batchSize    int
	batchTimeout time.Duration
	full         chan struct{}

	nodes        graph.Input[*nodeMap]
	users        graph.Input[[]types.User]
	policySrc    graph.Input[[]byte]
	derpMap      graph.Input[*tailcfg.DERPMap]
	extraRecords graph.Input[[]tailcfg.DNSRecord]

	index       graph.Derived[*nodeIndex]
	policyNodes graph.Derived[policyNodes]
	policy      graph.Derived[*compiledPolicy]
	peers       graph.Derived[map[types.NodeID][]types.NodeID]
	primaries   graph.Derived[primaryRoutes]
}

// nodeIndex holds the lookups every reader needs. Each part moves only
// the nodes a commit changed.
type nodeIndex struct {
	from         *nodeMap         // the nodes this indexes
	all          []types.NodeView // sorted by ID
	byNodeKey    graph.Grouped[types.NodeID, *types.Node, key.NodePublic]
	byMachineKey graph.Grouped[types.NodeID, *types.Node, key.MachinePublic]
	// byUser holds user-owned nodes; tagged nodes are owned by their tags.
	byUser graph.Grouped[types.NodeID, *types.Node, types.UserID]
	// advertisers holds, per non-exit prefix, the online nodes approving
	// it: the candidates of its primary-route election.
	advertisers graph.Grouped[types.NodeID, *types.Node, netip.Prefix]
}

// policyNodes is the node list as the policy reads it. It changes only
// when a node joins, leaves or changes a field the policy reads
// ([types.NodeView.HasPolicyChange]); keeping the older views otherwise is
// what spares an endpoint update a policy compile. gen counts the lists,
// from the nodes it was last checked against.
type policyNodes struct {
	list views.Slice[types.NodeView]
	from *nodeMap
	gen  uint64
}

// compiledPolicy is the policy compiled against the users and nodes of a
// snapshot. When a later compile fails, the last good one keeps serving
// and err records why.
type compiledPolicy struct {
	pm  policy.PolicyManager
	err error
}

// newWorld builds the graph and publishes its first snapshot. It fails
// when the policy does not compile against users and nodes.
func newWorld(nodes types.Nodes, users []types.User, polSrc []byte) (*world, error) {
	g := graph.New()
	w := &world{g: g, full: make(chan struct{}, 1)}

	byID := make(map[types.NodeID]*types.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	table := graph.NewMap(graph.Same[*types.Node], byID)

	w.nodes = graph.NewInput(g, "nodes", table, graph.Same[*nodeMap])
	// Users are refreshed on every registration; an unchanged list must not
	// recompile the policy.
	w.users = graph.NewInput(g, "users", users, samePolicyUsers)
	w.policySrc = graph.NewInput(g, "policy-source", polSrc, graph.Never[[]byte])
	// Both are refreshed on a timer; an unchanged value must not wake
	// every session.
	w.derpMap = graph.NewInput(g, "derp-map", (*tailcfg.DERPMap)(nil), sameDERPMap)
	w.extraRecords = graph.NewInput(g, "extra-records", []tailcfg.DNSRecord(nil), slices.Equal[[]tailcfg.DNSRecord])

	w.index = graph.NewDerived(g, "index", graph.Same[*nodeIndex],
		func(s *graph.Snapshot, prev *nodeIndex) *nodeIndex {
			return updateIndex(prev, graph.Get(s, w.nodes))
		})

	w.policyNodes = graph.NewDerived(g, "policy-nodes", samePolicyNodes,
		func(s *graph.Snapshot, prev policyNodes) policyNodes {
			nodes := graph.Get(s, w.nodes)
			if prev.from != nil && !policyFactsChanged(prev.from, nodes) {
				return policyNodes{list: prev.list, from: nodes, gen: prev.gen}
			}

			return policyNodes{list: views.SliceOf(graph.Get(s, w.index).all), from: nodes, gen: prev.gen + 1}
		})

	w.policy = graph.NewDerived(g, "policy", graph.Same[*compiledPolicy],
		func(s *graph.Snapshot, prev *compiledPolicy) *compiledPolicy {
			src := graph.Get(s, w.policySrc)
			users := graph.Get(s, w.users)
			nodes := graph.Get(s, w.policyNodes).list

			pm, err := policy.NewPolicyManager(src, users, nodes)
			if err != nil {
				policyCompiles.WithLabelValues("error").Inc()
				log.Error().Err(err).Msg("compiling policy; keeping the last good policy")

				var last policy.PolicyManager
				if prev != nil {
					last = prev.pm
				}

				return &compiledPolicy{pm: last, err: err}
			}

			policyCompiles.WithLabelValues("ok").Inc()

			return &compiledPolicy{pm: pm}
		})

	w.peers = graph.NewDerived(g, "peers", samePeerMap,
		func(s *graph.Snapshot, _ map[types.NodeID][]types.NodeID) map[types.NodeID][]types.NodeID {
			pm := graph.Get(s, w.policy).pm
			peers := pm.BuildPeerMap(graph.Get(s, w.policyNodes).list)

			// Sorted once here, so readers can share the slices.
			for _, ids := range peers {
				slices.Sort(ids)
			}

			return peers
		})

	w.primaries = graph.NewDerived(g, "primaries", samePrimaries,
		func(s *graph.Snapshot, prev primaryRoutes) primaryRoutes {
			nodes := graph.Get(s, w.nodes)
			if prev.from == nil {
				return newPrimaryRoutes(electPrimaryRoutes(nodes, nil), nodes)
			}

			// Only the prefixes a changed router names can elect anew.
			touched := electionPrefixes(prev.from, nodes)
			if len(touched) == 0 {
				return primaryRoutes{routes: prev.routes, byNode: prev.byNode, from: nodes}
			}

			groups := graph.Get(s, w.index).advertisers.Groups
			routes := maps.Clone(prev.routes)

			for p := range touched {
				candidates, _ := groups.Get(p)
				if primary, ok := electPrimary(nodes, candidates, prev.routes, p); ok {
					routes[p] = primary
				} else {
					delete(routes, p)
				}
			}

			return newPrimaryRoutes(routes, nodes)
		})

	snap, err := g.Update(func(*graph.Tx) error { return nil })
	if err != nil {
		return nil, err
	}

	if cp := graph.Get(snap, w.policy); cp.pm == nil {
		return nil, fmt.Errorf("compiling policy: %w", cp.err)
	}

	worldNodes.Set(float64(table.Len()))

	return w, nil
}

// updateIndex returns the index of nodes, moving only the nodes changed
// since prev was built.
func updateIndex(prev *nodeIndex, nodes *nodeMap) *nodeIndex {
	var p nodeIndex
	if prev != nil {
		p = *prev
	}

	return &nodeIndex{
		from: nodes,
		all:  patchSorted(p.from, p.all, nodes),
		byNodeKey: graph.GroupBy(p.byNodeKey, nodes, func(_ types.NodeID, n *types.Node) []key.NodePublic {
			return []key.NodePublic{n.NodeKey}
		}),
		byMachineKey: graph.GroupBy(p.byMachineKey, nodes, func(_ types.NodeID, n *types.Node) []key.MachinePublic {
			return []key.MachinePublic{n.MachineKey}
		}),
		byUser: graph.GroupBy(p.byUser, nodes, func(_ types.NodeID, n *types.Node) []types.UserID {
			if n.IsTagged() {
				return nil
			}

			return []types.UserID{n.TypedUserID()}
		}),
		advertisers: graph.GroupBy(p.advertisers, nodes, func(_ types.NodeID, n *types.Node) []netip.Prefix {
			if !n.Online() {
				return nil
			}

			return electionRoutes(n)
		}),
	}
}

// electionRoutes are the prefixes a node is a primary-route candidate for
// when online: its approved, announced routes, exits aside.
func electionRoutes(n *types.Node) []netip.Prefix {
	return slices.DeleteFunc(n.AllApprovedRoutes(), tsaddr.IsExitRoute)
}

// patchSorted returns the views of to sorted by ID, given all, the sorted
// views of from.
func patchSorted(from *nodeMap, all []types.NodeView, to *nodeMap) []types.NodeView {
	byID := func(nv types.NodeView, id types.NodeID) int { return cmp.Compare(nv.ID(), id) }

	if from == nil {
		out := make([]types.NodeView, 0, to.Len())
		for _, n := range to.All() {
			out = append(out, n.View())
		}

		slices.SortFunc(out, func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })

		return out
	}

	changed := graph.Changes(from, to)
	if len(changed) == 0 {
		return all
	}

	out := slices.Clone(all)

	for _, id := range changed {
		i, found := slices.BinarySearchFunc(out, id, byID)
		n, ok := to.Get(id)

		switch {
		case found && ok:
			out[i] = n.View()
		case found:
			out = slices.Delete(out, i, i+1)
		case ok:
			out = slices.Insert(out, i, n.View())
		}
	}

	return out
}

func samePolicyNodes(a, b policyNodes) bool { return a.gen == b.gen }

// policyFactsChanged reports whether a node joined, left or changed a
// field the policy reads between from and to.
func policyFactsChanged(from, to *nodeMap) bool {
	for _, id := range graph.Changes(from, to) {
		old, wasOK := from.Get(id)
		n, isOK := to.Get(id)

		if wasOK != isOK || old.View().HasPolicyChange(n.View()) {
			return true
		}
	}

	return false
}

// samePolicyUsers reports whether the policy resolves both user lists the
// same way, so an unrelated user field (a login's UpdatedAt) costs no
// compile.
func samePolicyUsers(a, b []types.User) bool {
	return slices.EqualFunc(a, b, func(x, y types.User) bool { return x.PolicyEqual(&y) })
}

// primaryRoutes is the prefix→primary election and the nodes it was held
// against.
type primaryRoutes struct {
	routes map[netip.Prefix]types.NodeID
	// byNode is routes inverted, each node's prefixes sorted.
	byNode map[types.NodeID][]netip.Prefix
	from   *nodeMap
}

func newPrimaryRoutes(routes map[netip.Prefix]types.NodeID, from *nodeMap) primaryRoutes {
	byNode := make(map[types.NodeID][]netip.Prefix)
	for p, id := range routes {
		byNode[id] = append(byNode[id], p)
	}

	for _, ps := range byNode {
		slices.SortFunc(ps, netip.Prefix.Compare)
	}

	return primaryRoutes{routes: routes, byNode: byNode, from: from}
}

func samePrimaries(a, b primaryRoutes) bool { return maps.Equal(a.routes, b.routes) }

// electionPrefixes returns the prefixes whose election a change between
// from and to can move: those a node approves before or after a change to
// its online state, health or routes.
func electionPrefixes(from, to *nodeMap) map[netip.Prefix]struct{} {
	touched := map[netip.Prefix]struct{}{}

	for _, id := range graph.Changes(from, to) {
		old, wasOK := from.Get(id)
		n, isOK := to.Get(id)

		if wasOK && isOK && old.Online() == n.Online() && old.Unhealthy == n.Unhealthy &&
			slices.Equal(old.AllApprovedRoutes(), n.AllApprovedRoutes()) {
			continue
		}

		for _, side := range []*types.Node{old, n} {
			if side == nil {
				continue
			}

			for _, p := range electionRoutes(side) {
				touched[p] = struct{}{}
			}
		}
	}

	return touched
}

func samePeerMap(a, b map[types.NodeID][]types.NodeID) bool {
	return maps.EqualFunc(a, b, slices.Equal[[]types.NodeID])
}

// snapshot returns the latest consistent view of the world.
func (w *world) snapshot() *Snapshot {
	return &Snapshot{s: w.g.Snapshot(), w: w}
}

// nodeWrite is one queued change to the node table; see [world.update].
type nodeWrite struct {
	fn   func(nodes *nodeEdit)
	done chan *Snapshot
}

// update commits fn's edit of the nodes and returns the snapshot holding
// it.
//
// Writes that arrive while a commit runs share the next one (group
// commit): a burst of joins, deletes or endpoint updates costs one policy
// compile and one peer rebuild instead of one each, and an idle write pays
// no wait.
func (w *world) update(fn func(nodes *nodeEdit)) *Snapshot {
	nw := &nodeWrite{fn: fn, done: make(chan *Snapshot, 1)}

	w.writeMu.Lock()
	w.writes = append(w.writes, nw)
	lead := !w.committing
	w.committing = true

	if w.batchSize > 0 && len(w.writes) >= w.batchSize {
		select {
		case w.full <- struct{}{}:
		default:
		}
	}
	w.writeMu.Unlock()

	if lead {
		w.lingerForBatch()
		w.commitWrites()
	}

	return <-nw.done
}

// lingerForBatch waits for writes to batch, as the tuning asks. Writes
// that land together are also elected together: two HA routers coming back
// at once keep their healthy primary instead of handing the route to
// whichever reconnected first.
func (w *world) lingerForBatch() {
	if w.batchTimeout <= 0 {
		return
	}

	timer := time.NewTimer(w.batchTimeout)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-w.full:
	}
}

// commitWrites commits every queued write in one transaction, then hands
// any writes queued meanwhile to a new leader so no caller waits on others'
// batches.
func (w *world) commitWrites() {
	w.writeMu.Lock()
	batch := w.writes
	w.writes = nil

	// A full signal for the writes taken here must not cut the next
	// batch's wait short.
	select {
	case <-w.full:
	default:
	}
	w.writeMu.Unlock()

	snap, _ := w.g.Update(func(tx *graph.Tx) error {
		cur := graph.Peek(tx, w.nodes)
		e := cur.Edit()

		for _, nw := range batch {
			nw.fn(e)
		}

		next := e.Done()
		if next == cur {
			return nil
		}

		graph.Set(tx, w.nodes, next)
		worldNodes.Set(float64(next.Len()))
		worldCommits.Inc()

		return nil
	})

	worldBatchSize.Observe(float64(len(batch)))

	out := &Snapshot{s: snap, w: w}
	for _, nw := range batch {
		nw.done <- out
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if len(w.writes) == 0 {
		w.committing = false

		return
	}

	go w.commitWrites()
}

// UpdateNodeFunc modifies a node in place. It runs on a copy of the stored
// node, inside the writer, so it sees every write committed before it.
type UpdateNodeFunc func(n *types.Node)

// PutNode stores n, replacing any node with its ID. Its GivenName is made
// unique first. It returns the stored node.
func (w *world) PutNode(n types.Node) types.NodeView {
	snap := w.update(func(nodes *nodeEdit) {
		stored := n
		stored.GivenName = uniqueGivenName(nodes, n.ID, n.GivenName)
		nodes.Set(n.ID, &stored)
	})

	nv, _ := snap.GetNode(n.ID)

	return nv
}

// UpdateNode applies fn to the node with id and returns the result and
// whether the node exists.
func (w *world) UpdateNode(id types.NodeID, fn UpdateNodeFunc) (types.NodeView, bool) {
	_, after, ok := w.UpdateNodeDiff(id, fn)

	return after, ok
}

// UpdateNodeDiff is [world.UpdateNode] that also returns the node as it
// was before fn ran.
func (w *world) UpdateNodeDiff(id types.NodeID, fn UpdateNodeFunc) (types.NodeView, types.NodeView, bool) {
	pre := make(map[types.NodeID]types.NodeView, 1)
	snap := w.updateNodes(map[types.NodeID]UpdateNodeFunc{id: fn}, pre)
	after, ok := snap.GetNode(id)

	return pre[id], after, ok
}

// UpdateNodes applies every update in one commit, so no reader sees some of
// them without the others.
func (w *world) UpdateNodes(updates map[types.NodeID]UpdateNodeFunc) {
	w.updateNodes(updates, nil)
}

func (w *world) updateNodes(
	updates map[types.NodeID]UpdateNodeFunc,
	pre map[types.NodeID]types.NodeView,
) *Snapshot {
	if len(updates) == 0 {
		return w.snapshot()
	}

	return w.update(func(nodes *nodeEdit) {
		for id, fn := range updates {
			cur, ok := nodes.Get(id)
			if !ok {
				continue
			}

			if pre != nil {
				pre[id] = cur.View()
			}

			next := cur.Clone()
			fn(next)

			if next.GivenName != cur.GivenName {
				next.GivenName = uniqueGivenName(nodes, id, next.GivenName)
			}

			nodes.Set(id, next)
		}
	})
}

// DeleteNode removes the node with id.
func (w *world) DeleteNode(id types.NodeID) {
	w.update(func(nodes *nodeEdit) { nodes.Delete(id) })
}

// SetGivenName renames a node to exactly name, rejecting an invalid label
// and one another node holds (case-insensitively).
func (w *world) SetGivenName(id types.NodeID, name string) (types.NodeView, error) {
	var err error

	snap := w.update(func(nodes *nodeEdit) {
		cur, ok := nodes.Get(id)
		if !ok {
			err = ErrNodeNotFound

			return
		}

		if dnsname.ValidLabel(name) != nil {
			err = ErrGivenNameInvalid

			return
		}

		for oid, other := range nodes.All() {
			if oid != id && strings.EqualFold(other.GivenName, name) {
				err = ErrGivenNameTaken

				return
			}
		}

		next := cur.Clone()
		next.GivenName = name
		nodes.Set(id, next)
	})

	if err != nil {
		return types.NodeView{}, err
	}

	nv, _ := snap.GetNode(id)

	return nv, nil
}

// SetUsers replaces the user list and refreshes the user every node
// carries, so a renamed user is shown renamed.
func (w *world) SetUsers(users []types.User) {
	byID := make(map[uint]*types.User, len(users))
	for i := range users {
		byID[users[i].ID] = &users[i]
	}

	_, _ = w.g.Update(func(tx *graph.Tx) error {
		graph.Set(tx, w.users, users)

		cur := graph.Peek(tx, w.nodes)
		e := cur.Edit()

		for id, n := range cur.All() {
			if n.User == nil {
				continue
			}

			u, ok := byID[n.User.ID]
			if !ok || *u == *n.User {
				continue
			}

			c := n.Clone()
			uc := *u
			c.User = &uc
			e.Set(id, c)
		}

		if next := e.Done(); next != cur {
			graph.Set(tx, w.nodes, next)
		}

		worldCommits.Inc()

		return nil
	})
}

// SetPolicy replaces the policy document. The caller has compiled it
// against the current users and nodes already.
func (w *world) SetPolicy(src []byte) {
	_, _ = w.g.Update(func(tx *graph.Tx) error {
		graph.Set(tx, w.policySrc, src)
		worldCommits.Inc()

		return nil
	})
}

// SetDERPMap replaces the DERP map.
func (w *world) SetDERPMap(dm *tailcfg.DERPMap) {
	_, _ = w.g.Update(func(tx *graph.Tx) error {
		graph.Set(tx, w.derpMap, dm)

		return nil
	})
}

// sameDERPMap compares DERP maps by content; a fetch returns a new map
// even when nothing changed.
func sameDERPMap(a, b *tailcfg.DERPMap) bool {
	return reflect.DeepEqual(a, b)
}

// SetExtraRecords replaces the extra DNS records.
func (w *world) SetExtraRecords(records []tailcfg.DNSRecord) {
	_, _ = w.g.Update(func(tx *graph.Tx) error {
		graph.Set(tx, w.extraRecords, records)

		return nil
	})
}

// uniqueGivenName returns a DNS label for self based on base that no other
// node holds: base, base-1, base-2, … An empty base becomes
// [fallbackGivenName]. DNS is case-insensitive, so "Laptop" holds "laptop".
func uniqueGivenName(nodes *nodeEdit, self types.NodeID, base string) string {
	if base == "" {
		base = fallbackGivenName
	}

	taken := make(map[string]struct{}, nodes.Len())

	for id, n := range nodes.All() {
		if id != self {
			taken[strings.ToLower(n.GivenName)] = struct{}{}
		}
	}

	candidate := base
	for i := 1; ; i++ {
		if _, busy := taken[strings.ToLower(candidate)]; !busy {
			return candidate
		}

		candidate = base + "-" + strconv.Itoa(i)
	}
}

// onlineAdvertisers maps each non-exit prefix to the IDs of online nodes
// that approve it, in ID order.
func onlineAdvertisers(nodes *nodeMap) map[netip.Prefix][]types.NodeID {
	advertisers := make(map[netip.Prefix][]types.NodeID)

	for id, n := range nodes.All() {
		if n.Online() {
			for _, p := range electionRoutes(n) {
				advertisers[p] = append(advertisers[p], id)
			}
		}
	}

	for _, ids := range advertisers {
		slices.Sort(ids)
	}

	return advertisers
}

// electPrimaryRoutes elects every prefix from scratch, keeping prev's
// primaries where they still hold.
func electPrimaryRoutes(
	nodes *nodeMap,
	prev map[netip.Prefix]types.NodeID,
) map[netip.Prefix]types.NodeID {
	advertisers := onlineAdvertisers(nodes)
	routes := make(map[netip.Prefix]types.NodeID, len(advertisers))

	for prefix, candidates := range advertisers {
		if primary, ok := electPrimary(nodes, candidates, prev, prefix); ok {
			routes[prefix] = primary
		}
	}

	return routes
}

// electPrimary picks the primary for prefix among candidates, its online
// advertisers in ID order: a healthy incumbent keeps it, otherwise the
// lowest healthy candidate takes it; when none is healthy, the incumbent
// keeps it rather than flap.
func electPrimary(
	nodes *nodeMap,
	candidates []types.NodeID,
	prev map[netip.Prefix]types.NodeID,
	prefix netip.Prefix,
) (types.NodeID, bool) {
	healthy := func(id types.NodeID) bool {
		n, _ := nodes.Get(id)

		return !n.Unhealthy
	}

	cur, hadPrimary := prev[prefix]
	incumbent := hadPrimary && slices.Contains(candidates, cur)

	if incumbent && healthy(cur) {
		return cur, true
	}

	if i := slices.IndexFunc(candidates, healthy); i >= 0 {
		return candidates[i], true
	}

	return cur, incumbent
}

// Snapshot is one consistent view of the control plane: nodes, users,
// compiled policy, peer visibility and primary routes all belong to the
// same commit. Everything rendered for a client should come from one
// Snapshot.
type Snapshot struct {
	s *graph.Snapshot
	w *world
}

func (s *Snapshot) index() *nodeIndex { return graph.Get(s.s, s.w.index) }

// Rev identifies the commit this snapshot shows.
func (s *Snapshot) Rev() uint64 { return s.s.Rev() }

func (s *Snapshot) nodes() *nodeMap { return graph.Get(s.s, s.w.nodes) }

// GetNode returns the node with id.
func (s *Snapshot) GetNode(id types.NodeID) (types.NodeView, bool) {
	n, ok := s.nodes().Get(id)
	if !ok {
		return types.NodeView{}, false
	}

	return n.View(), true
}

// GetNodeByNodeKey returns the node holding nodeKey.
func (s *Snapshot) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	ids, _ := s.index().byNodeKey.Groups.Get(nodeKey)
	if len(ids) == 0 {
		return types.NodeView{}, false
	}

	return s.GetNode(ids[0])
}

// GetNodesByMachineKeyAllUsers returns every node sharing machineKey,
// keyed by owning UserID; tagged nodes are under UserID(0).
func (s *Snapshot) GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView {
	ids, _ := s.index().byMachineKey.Groups.Get(machineKey)
	if len(ids) == 0 {
		return nil
	}

	out := make(map[types.UserID]types.NodeView, len(ids))
	for _, nv := range s.gather(ids) {
		out[nv.TypedUserID()] = nv
	}

	return out
}

// gather returns the views of ids, skipping any no longer stored.
func (s *Snapshot) gather(ids []types.NodeID) []types.NodeView {
	nodes := s.nodes()
	out := make([]types.NodeView, 0, len(ids))

	for _, id := range ids {
		if n, ok := nodes.Get(id); ok {
			out = append(out, n.View())
		}
	}

	return out
}

// ListNodes returns every node, sorted by ID.
func (s *Snapshot) ListNodes() views.Slice[types.NodeView] {
	return views.SliceOf(s.index().all)
}

// ListNodesByUser returns the user-owned nodes of uid.
func (s *Snapshot) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	ids, _ := s.index().byUser.Groups.Get(uid)

	return views.SliceOf(s.gather(ids))
}

// ListPeerIDs returns the sorted IDs of the nodes id can see, as a copy
// the caller may keep and modify.
func (s *Snapshot) ListPeerIDs(id types.NodeID) []types.NodeID {
	return slices.Clone(s.PeerIDs(id))
}

// PeerIDs returns the sorted IDs of the nodes id can see. The slice is
// shared with the snapshot and must not be modified.
func (s *Snapshot) PeerIDs(id types.NodeID) []types.NodeID {
	return graph.Get(s.s, s.w.peers)[id]
}

// ListPeers returns the nodes id can see, sorted by ID.
func (s *Snapshot) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	return views.SliceOf(s.gather(s.PeerIDs(id)))
}

// Policy returns the compiled policy.
func (s *Snapshot) Policy() policy.PolicyManager { return graph.Get(s.s, s.w.policy).pm }

// PolicyErr is the error of the latest failed policy compile, or nil when
// the served policy is current.
func (s *Snapshot) PolicyErr() error { return graph.Get(s.s, s.w.policy).err }

// PolicySource returns the policy document. It is shared and must not be
// modified.
func (s *Snapshot) PolicySource() []byte { return graph.Get(s.s, s.w.policySrc) }

// Users returns the user list.
func (s *Snapshot) Users() []types.User { return graph.Get(s.s, s.w.users) }

// DERPMap returns the DERP map.
func (s *Snapshot) DERPMap() *tailcfg.DERPMap { return graph.Get(s.s, s.w.derpMap) }

// PrimaryRoutes returns the prefix→primary assignment. It is shared and
// must not be modified.
func (s *Snapshot) PrimaryRoutes() map[netip.Prefix]types.NodeID {
	return graph.Get(s.s, s.w.primaries).routes
}

// PrimaryRouteFor returns the primary advertiser of prefix.
func (s *Snapshot) PrimaryRouteFor(prefix netip.Prefix) (types.NodeID, bool) {
	id, ok := s.PrimaryRoutes()[prefix]

	return id, ok
}

// PrimaryRoutesForNode returns the prefixes id is primary for, sorted.
func (s *Snapshot) PrimaryRoutesForNode(id types.NodeID) []netip.Prefix {
	return slices.Clone(graph.Get(s.s, s.w.primaries).byNode[id])
}

// HANodes returns the prefixes with two or more online advertisers.
func (s *Snapshot) HANodes() map[netip.Prefix][]types.NodeID {
	out := make(map[netip.Prefix][]types.NodeID)

	for p, ids := range s.index().advertisers.Groups.All() {
		if len(ids) >= 2 {
			out[p] = slices.Clone(ids)
		}
	}

	return out
}

// IsNodeHealthy reports the HA prober's view of id; unknown nodes are
// healthy.
func (s *Snapshot) IsNodeHealthy(id types.NodeID) bool {
	n, ok := graph.Get(s.s, s.w.nodes).Get(id)

	return !ok || !n.Unhealthy
}

// PrimaryRoutesString renders the primary assignment for diagnostics.
func (s *Snapshot) PrimaryRoutesString() string {
	routes := s.PrimaryRoutes()

	var b strings.Builder
	for _, p := range slices.SortedFunc(maps.Keys(routes), netip.Prefix.Compare) {
		fmt.Fprintf(&b, "%s: %d\n", p, routes[p])
	}

	return b.String()
}

// RoutesForPeer returns the routes peer carries in viewer's AllowedIPs:
// the primary routes it holds and its approved exit routes that viewer's
// matchers allow, adjusted by via grants. A viewer advertising a prefix
// the peer is primary for always sees it, so HA secondaries know the
// primary.
func (s *Snapshot) RoutesForPeer(viewer, peer types.NodeView, matchers []matcher.Match) []netip.Prefix {
	via := s.Policy().ViaRoutesForPeer(viewer, peer)
	primaries := s.PrimaryRoutesForNode(peer.ID())
	candidates := slices.Concat(primaries, peer.ExitRoutes())

	var reduced []netip.Prefix

	if len(via.Include) == 0 && len(via.Exclude) == 0 {
		reduced = policy.ReduceRoutes(viewer, candidates, matchers)
	} else {
		candidates = slices.DeleteFunc(candidates, func(p netip.Prefix) bool {
			return slices.Contains(via.Exclude, p)
		})
		reduced = policy.ReduceRoutes(viewer, candidates, matchers)

		// The via grant is the authorization. Where a regular grant also
		// covers the prefix, HA election decides: only the primary keeps it.
		for _, p := range via.Include {
			if slices.Contains(reduced, p) {
				continue
			}

			if slices.Contains(primaries, p) || !slices.Contains(via.UsePrimary, p) {
				reduced = append(reduced, p)
			}
		}
	}

	viewerSubnets := viewer.SubnetRoutes()
	for _, p := range primaries {
		if slices.Contains(viewerSubnets, p) && !slices.Contains(reduced, p) {
			reduced = append(reduced, p)
		}
	}

	return reduced
}

// SelfRoutes returns the routes node carries in its own AllowedIPs: the
// primary routes the global matchers allow, and its approved exit routes.
func (s *Snapshot) SelfRoutes(node types.NodeView) []netip.Prefix {
	_, matchers := s.Policy().Filter()
	primaries := policy.ReduceRoutes(node, s.PrimaryRoutesForNode(node.ID()), matchers)

	return slices.Concat(primaries, node.ExitRoutes())
}

// Revisions report the commit at which a part of the world last changed,
// so a renderer can skip work whose inputs are unchanged.

// Change is what differs between two snapshots, for telling which map
// sessions an update can reach.
type Change struct {
	// Global is set when something every map reads changed: the compiled
	// policy, the DERP map or the extra DNS records.
	Global bool
	// Nodes are the nodes whose stored node differs, added and deleted
	// ones included.
	Nodes []types.NodeID
	// Primaries are the nodes that gained or lost a primary route.
	Primaries []types.NodeID
	// PeerSets are the nodes whose set of peers differs.
	PeerSets []types.NodeID
}

// Since returns what changed from old to s. A nil old is everything.
func (s *Snapshot) Since(old *Snapshot) Change {
	if old == nil {
		return Change{Global: true}
	}

	c := Change{
		Global: s.PolicyRev() != old.PolicyRev() ||
			graph.ChangedAt(s.s, s.w.derpMap) != graph.ChangedAt(old.s, old.w.derpMap) ||
			s.DNSRev() != old.DNSRev(),
		Nodes: graph.Changes(old.nodes(), s.nodes()),
	}

	if s.PrimariesRev() != old.PrimariesRev() {
		c.Primaries = changedKeys(
			graph.Get(old.s, old.w.primaries).byNode,
			graph.Get(s.s, s.w.primaries).byNode,
			slices.Equal[[]netip.Prefix],
		)
	}

	if s.PeersRev() != old.PeersRev() {
		c.PeerSets = changedKeys(graph.Get(old.s, old.w.peers), graph.Get(s.s, s.w.peers), slices.Equal[[]types.NodeID])
	}

	return c
}

// changedKeys returns the keys whose value differs between a and b.
func changedKeys[K comparable, V any](a, b map[K]V, eq func(x, y V) bool) []K {
	var keys []K

	for k, v := range b {
		if old, ok := a[k]; !ok || !eq(old, v) {
			keys = append(keys, k)
		}
	}

	for k := range a {
		if _, ok := b[k]; !ok {
			keys = append(keys, k)
		}
	}

	return keys
}

// NodesVersion is the nodes of a snapshot, which a reader keeps to ask a
// later snapshot what changed since. Holding one costs only what later
// writes replaced.
type NodesVersion struct{ m *nodeMap }

// NodesVersion returns the nodes of s.
func (s *Snapshot) NodesVersion() NodesVersion { return NodesVersion{m: s.nodes()} }

// NodesChangedSince returns the nodes that differ between v and s, each
// once; added and deleted nodes included.
func (s *Snapshot) NodesChangedSince(v NodesVersion) []types.NodeID {
	return graph.Changes(v.m, s.nodes())
}

// NodesRev is the revision of the latest node change.
func (s *Snapshot) NodesRev() uint64 { return graph.ChangedAt(s.s, s.w.nodes) }

// PolicyRev is the revision of the latest policy compile.
func (s *Snapshot) PolicyRev() uint64 { return graph.ChangedAt(s.s, s.w.policy) }

// PolicyNodesRev is the revision of the latest change to what the policy
// reads of nodes.
func (s *Snapshot) PolicyNodesRev() uint64 { return graph.ChangedAt(s.s, s.w.policyNodes) }

// PeersRev is the revision of the latest change to peer visibility.
func (s *Snapshot) PeersRev() uint64 { return graph.ChangedAt(s.s, s.w.peers) }

// PrimariesRev is the revision of the latest primary route change.
func (s *Snapshot) PrimariesRev() uint64 { return graph.ChangedAt(s.s, s.w.primaries) }

// DNSRev is the revision of the latest extra DNS records change.
func (s *Snapshot) DNSRev() uint64 { return graph.ChangedAt(s.s, s.w.extraRecords) }
