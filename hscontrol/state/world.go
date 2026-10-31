package state

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"tailscale.com/envknob"
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

// worldCommitPanics counts node write commits that panicked.
var worldCommitPanics atomic.Uint64

var (
	worldCommits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "world_commits_total",
		Help:      "Control-plane graph transactions publishing a new snapshot after the initial snapshot, including node, user, policy, DNS and DERP changes. Transactions that stage no edit — an unknown node, unchanged users, a byte-identical policy, equal DNS records or DERP maps — and refused and panicking ones are excluded; a panicking node batch is retried write by write, each surviving publication counting separately. A node write that stages an identical copy of the node still counts, as does a commit whose policy recompile fails. This does not count database persistence or client delivery.",
	})
	_ = promauto.NewCounterFunc(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "world_commit_panics_total",
		Help:      "Node write commits that panicked; a batch's writers are retried individually, so only the writers that panic again fail. The graph kept serving.",
	}, func() float64 { return float64(worldCommitPanics.Load()) })
	worldNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "world_nodes",
		Help:      "Nodes in the control-plane graph.",
	})
	worldBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "world_write_batch_size",
		Help:      "Node writes in completed batches, including no-op batches. Panicking batches are excluded; successful individual retries are observed separately.",
		Buckets:   []float64{1, 2, 5, 10, 20, 50, 100, 200},
	})
	policyCompiles = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "policy_compiles_total",
		Help:      "Policy compilations in the graph by result: at boot and on each change to the document, the users, or a node field the policy reads, published or refused; one write compiles up to three times when users or nodes move during its tests. A document refused before it reaches the graph, a write's own test candidate and the audit's compile are not counted.",
	}, []string{"result"})

	// policyAudit compiles every policy from scratch as well and reports
	// where the incremental compile differs.
	policyAudit         = envknob.RegisterBool("HEADSCALE_DEBUG_POLICY_AUDIT")
	policyAuditFailures atomic.Uint64
	policyAuditRuns     atomic.Uint64
)

// PolicyAuditFailures counts the compiles the policy audit found to
// differ from a compile from scratch.
func PolicyAuditFailures() uint64 { return policyAuditFailures.Load() }

// PolicyAuditRuns counts the from-scratch via election audits that ran,
// so a test can prove the audit is wired, not merely quiet.
func PolicyAuditRuns() uint64 { return policyAuditRuns.Load() }

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
//	index, nodes, policy ──► primaries
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
	// [types.Tuning.NodeStoreBatchTimeout]: during an HA outage a commit
	// waits up to the timeout for writes to batch, or until batchSize are
	// queued. Zero waits for nothing. full wakes a waiting commit once the
	// batch is full. inOutage is refreshed when batching is enabled and
	// election inputs change, see [hasOutage].
	batchSize    int
	batchTimeout time.Duration
	full         chan struct{}
	inOutage     atomic.Bool

	// servesRoute is [types.Config.ServesRoute]; nil serves every route.
	servesRoute func(netip.Prefix) bool

	// outageMu and outageRev order the outage stores: a state computed
	// from an older snapshot than the one already stored must not win,
	// whichever of two concurrent writers finished first.
	outageMu  sync.Mutex
	outageRev uint64

	// outageStores and routesClones are test oracles, world-owned so a
	// test reads exact deltas from its own synchronous writes and no
	// other test's world can interfere.
	outageStores atomic.Uint64
	routesClones atomic.Uint64

	// beforePolicyCommit, for tests, runs just before [world.SetPolicy]
	// takes the graph's lock: the last point a write can land between a
	// caller's checks and the commit.
	beforePolicyCommit func()

	nodes       graph.Input[*nodeMap]
	users       graph.Input[[]types.User]
	policyUsers graph.Derived[[]types.User]
	policySrc   graph.Input[[]byte]
	derpMap     graph.Input[*tailcfg.DERPMap]
	dns         graph.Input[types.DNSView]

	index       graph.Derived[*nodeIndex]
	policyNodes graph.Derived[policyNodes]
	policy      graph.Derived[*compiledPolicy]
	// peerPolicy counts the compiled policies that render nodes as peers
	// differently; see [policyv2.PolicyManager.SameForPeers].
	peerPolicy graph.Derived[peerPolicy]
	// nodeCaps is the policy's capability map per node, kept as a Map so
	// a reader finds whose caps a recompile changed.
	nodeCaps  graph.Derived[*capsMap]
	peers     graph.Derived[*policyv2.PeerClasses]
	primaries graph.Derived[primaryRoutes]
}

// nodeIndex holds the lookups every reader needs. Each part moves only
// the nodes a commit changed.
type nodeIndex struct {
	from         *nodeMap     // the nodes this indexes
	all          *sortedNodes // sorted by ID, built on first read
	byNodeKey    graph.Grouped[types.NodeID, *types.Node, key.NodePublic]
	byMachineKey graph.Grouped[types.NodeID, *types.Node, key.MachinePublic]
	// byUser holds user-owned nodes; tagged nodes are owned by their tags.
	byUser graph.Grouped[types.NodeID, *types.Node, types.UserID]
	// advertisers holds, per non-exit prefix, the online nodes approving
	// it: the candidates of its primary-route election.
	advertisers graph.Grouped[types.NodeID, *types.Node, netip.Prefix]
	// routed holds, under true, the nodes serving any approved route.
	routed graph.Grouped[types.NodeID, *types.Node, bool]
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

// capsMap holds each node's policy capabilities.
type capsMap = graph.Map[types.NodeID, tailcfg.NodeCapMap]

func sameCaps(a, b tailcfg.NodeCapMap) bool { return reflect.DeepEqual(a, b) }

// peerPolicy is a generation number that moves only when a compiled
// policy renders peers differently, with the policy it was taken at.
type peerPolicy struct {
	pm  policy.PolicyManager
	gen uint64
}

// compiledPolicy is the policy compiled against the users and nodes of a
// snapshot. When a later compile fails, the last good one keeps serving
// and err records why.
type compiledPolicy struct {
	pm  policy.PolicyManager
	err error

	// src, users and nodes (a policy-nodes generation) are what pm was
	// compiled from.
	src   []byte
	users []types.User
	nodes uint64
}

// newWorld builds the graph and publishes its first snapshot. It fails
// when the policy does not compile against users and nodes.
func newWorld(nodes types.Nodes, users []types.User, polSrc []byte, dns types.DNSView) (*world, error) {
	g := graph.New()
	w := &world{g: g, full: make(chan struct{}, 1), beforePolicyCommit: func() {}}

	byID := make(map[types.NodeID]*types.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	table := graph.NewMap(graph.Same[*types.Node], byID)

	w.nodes = g.NewInput("nodes", table, graph.Same[*nodeMap])
	// Users are refreshed on every registration; an unchanged list must not
	// recompile the policy.
	w.users = g.NewInput("users", slices.Clone(users), slices.Equal[[]types.User])

	// The policy reads users only through fields a compile resolves, so a
	// display name or picture change does not recompile it.
	w.policyUsers = graph.NewDerived(g, "policy-users", types.SamePolicyUsers,
		func(s *graph.Snapshot, _ []types.User) []types.User { return s.Get(w.users) })
	w.policySrc = g.NewInput("policy-source", polSrc, graph.Never[[]byte])
	// The DERP map is refreshed on a timer and DNS by the extra-records
	// watcher; an unchanged value must not wake every session.
	w.derpMap = g.NewInput("derp-map", (*tailcfg.DERPMap)(nil), sameDERPMap)
	w.dns = g.NewInput("dns", dns, types.DNSView.Equal)

	w.index = graph.NewDerived(g, "index", graph.Same[*nodeIndex],
		func(s *graph.Snapshot, prev *nodeIndex) *nodeIndex {
			return updateIndex(prev, s.Get(w.nodes))
		})

	w.policyNodes = graph.NewDerived(g, "policy-nodes", samePolicyNodes,
		func(s *graph.Snapshot, prev policyNodes) policyNodes {
			nodes := s.Get(w.nodes)
			if prev.from != nil && !policyFactsChanged(prev.from, nodes) {
				return policyNodes{list: prev.list, from: nodes, gen: prev.gen}
			}

			return policyNodes{list: views.SliceOf(s.Get(w.index).all.get()), from: nodes, gen: prev.gen + 1}
		})

	w.policy = graph.NewDerived(g, "policy", graph.Same[*compiledPolicy],
		func(s *graph.Snapshot, prev *compiledPolicy) *compiledPolicy {
			src := s.Get(w.policySrc)
			users := s.Get(w.policyUsers)
			pn := s.Get(w.policyNodes)
			nodes := pn.list

			var last policy.PolicyManager
			if prev != nil {
				last = prev.pm
			}

			pm, err := policy.NewPolicyManagerFrom(last, src, users, nodes)
			if err != nil {
				policyCompiles.WithLabelValues("error").Inc()

				// A user change that breaks the unchanged document (such as
				// a second user with a name it lists) keeps the last good
				// users, as a refused policy write would, but the nodes must
				// still move: a re-tag or delete has to revoke access.
				if prev != nil && prev.pm != nil && bytes.Equal(prev.src, src) && prev.nodes != pn.gen {
					retry, retryErr := policy.NewPolicyManagerFrom(last, src, prev.users, nodes)
					if retryErr == nil {
						log.Error().Err(err).Msg("compiling policy; keeping the last good users")

						return &compiledPolicy{pm: retry, err: err, src: src, users: prev.users, nodes: pn.gen}
					}
				}

				log.Error().Err(err).Msg("compiling policy; keeping the last good policy")

				kept := &compiledPolicy{pm: last, err: err}
				if prev != nil {
					kept.src, kept.users, kept.nodes = prev.src, prev.users, prev.nodes
				}

				return kept
			}

			policyCompiles.WithLabelValues("ok").Inc()

			if pmv2, ok := pm.(*policyv2.PolicyManager); ok && last != nil && policyAudit() {
				err := pmv2.Audit(src, users, nodes)
				if err != nil {
					policyAuditFailures.Add(1)
					log.Error().Err(err).Msg("policy audit")
				}
			}

			return &compiledPolicy{pm: pm, src: src, users: users, nodes: pn.gen}
		})

	w.peerPolicy = graph.NewDerived(g, "peer-policy", func(a, b peerPolicy) bool { return a.gen == b.gen },
		func(s *graph.Snapshot, prev peerPolicy) peerPolicy {
			cur := s.Get(w.policy)
			next, _ := cur.pm.(*policyv2.PolicyManager)
			last, _ := prev.pm.(*policyv2.PolicyManager)

			if next != nil && next.SameForPeers(last) {
				return peerPolicy{pm: cur.pm, gen: prev.gen}
			}

			return peerPolicy{pm: cur.pm, gen: prev.gen + 1}
		})

	w.nodeCaps = graph.NewDerived(g, "node-caps", graph.Same[*capsMap],
		func(s *graph.Snapshot, prev *capsMap) *capsMap {
			// A first compile that failed has no policy; newWorld
			// returns its error.
			pm := s.Get(w.policy).pm
			if pm == nil {
				return prev
			}

			caps := pm.NodeCapMaps()
			if prev == nil {
				return graph.NewMap(sameCaps, caps)
			}

			e := prev.Edit()
			for id, c := range caps {
				if old, ok := prev.Get(id); !ok || !sameCaps(old, c) {
					e.Set(id, c)
				}
			}

			for id := range prev.All() {
				if _, ok := caps[id]; !ok {
					e.Delete(id)
				}
			}

			return e.Done()
		})

	w.peers = graph.NewDerived(g, "peers", (*policyv2.PeerClasses).Same,
		func(s *graph.Snapshot, prev *policyv2.PeerClasses) *policyv2.PeerClasses {
			pm := s.Get(w.policy).pm
			if pm == nil {
				return prev
			}

			nodes := s.Get(w.policyNodes).list
			next := pm.BuildPeerClasses(nodes, prev)

			// Classes built from prev reuse its per-node sides, a path no
			// compile from scratch takes.
			if pmv2, ok := pm.(*policyv2.PolicyManager); ok && prev != nil && policyAudit() {
				err := pmv2.AuditPeers(next, nodes)
				if err != nil {
					policyAuditFailures.Add(1)
					log.Error().Err(err).Msg("policy audit")
				}
			}

			// Views that did not change keep their identity, so sessions
			// and shared peer maps keyed on them carry over.
			next.Reuse(prev)

			return next
		})

	w.primaries = graph.NewDerived(g, "primaries", samePrimaries, w.electPrimaries)

	snap, err := g.Update(func(*graph.Tx) error { return nil })
	if err != nil {
		return nil, err
	}

	if cp := snap.Get(w.policy); cp.pm == nil {
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
		all:  p.all.next(nodes),
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
		routed: graph.GroupBy(p.routed, nodes, func(_ types.NodeID, n *types.Node) []bool {
			if len(n.AllApprovedRoutes()) == 0 {
				return nil
			}

			return []bool{true}
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
// sortedNodes is an index's nodes sorted by ID, built on first read: most
// commits change nodes nobody lists, and keeping the list current copied
// every node per commit. An unbuilt list patches from the last built one,
// so it holds at most one older list.
type sortedNodes struct {
	from *nodeMap

	mu    sync.Mutex
	built bool
	list  []types.NodeView
	base  *sortedNodes // a built list to patch from; nil once built
}

// next returns the unbuilt list of nodes, patching from s or from the list
// s itself patches from. s may be nil.
func (s *sortedNodes) next(nodes *nodeMap) *sortedNodes {
	n := &sortedNodes{from: nodes}

	if s != nil {
		s.mu.Lock()
		if s.built {
			n.base = s
		} else {
			n.base = s.base
		}
		s.mu.Unlock()
	}

	return n
}

// get returns the nodes sorted by ID.
func (s *sortedNodes) get() []types.NodeView {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.built {
		var (
			from *nodeMap
			all  []types.NodeView
		)

		if s.base != nil {
			from, all = s.base.from, s.base.get()
		}

		s.list, s.built, s.base = patchSorted(from, all, s.from), true, nil
	}

	return s.list
}

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

// electionInputChanged reports whether a change between from and to can
// move an election: a router's availability moves the prefixes it names,
// and a policy fact — a join, a leave, tags, addresses, routes — can move
// more. One walk decides exactly what [electionPrefixes] and
// [policyFactsChanged] decide separately. The arms run cheapest first:
// presence, then availability guarded by routes, then the policy facts.
func electionInputChanged(from, to *nodeMap) bool {
	for _, id := range graph.Changes(from, to) {
		old, wasOK := from.Get(id)
		n, isOK := to.Get(id)

		if wasOK != isOK {
			// A join or a leave is a policy fact change.
			return true
		}

		// Availability moves only the prefixes a changed router names: a
		// node without election routes — a plain client, an exit-only
		// router — moves none.
		if old.Online() != n.Online() ||
			old.Unhealthy != n.Unhealthy ||
			!slices.Equal(old.AllApprovedRoutes(), n.AllApprovedRoutes()) {
			if len(electionRoutes(old))+len(electionRoutes(n)) > 0 {
				return true
			}
		}

		if old.View().HasPolicyChange(n.View()) {
			return true
		}
	}

	return false
}

// sameUserForNodes reports whether a node holding user a needs no copy of
// b: they differ at most in timestamps, which no map or policy reads. A
// login bumping UpdatedAt then rewrites none of the user's nodes.
func sameUserForNodes(a, b types.User) bool {
	a.CreatedAt, a.UpdatedAt, a.DeletedAt = b.CreatedAt, b.UpdatedAt, b.DeletedAt

	return a == b
}

// electPrimaries re-elects the prefixes a change can move. prev is a
// per-commit copy of the cell's boxed value, so fields may be reassigned
// here, but maps shared with published snapshots (routes, byNode) must
// never be mutated in place.
func (w *world) electPrimaries(s *graph.Snapshot, prev primaryRoutes) primaryRoutes {
	nodes := s.Get(w.nodes)
	pm := s.Get(w.policy).pm

	var (
		touched map[netip.Prefix]struct{}
		routes  map[netip.Prefix]types.NodeID
	)

	if prev.from == nil {
		routes = electPrimaryRoutes(nodes, nil)
	} else {
		// Only the prefixes a changed router names can elect anew.
		touched = electionPrefixes(prev.from, nodes)
		if len(touched) == 0 && pm == prev.policy {
			prev.from = nodes

			return prev
		}

		routes = prev.routes

		if len(touched) > 0 {
			// The touched prefixes elect anew; the rest keep their winners.
			// The map is cloned only when a winner actually moves, so a
			// touched commit that re-elects everyone allocates nothing.
			groups := s.Get(w.index).advertisers.Groups

			var moved bool

			for p := range touched {
				candidates, _ := groups.Get(p)
				primary, ok := electPrimary(nodes, views.SliceOf(candidates), prev.routes[p])

				cur, had := prev.routes[p]
				if (ok && (!had || cur != primary)) || (!ok && had) {
					if !moved {
						moved = true
						routes = maps.Clone(prev.routes)

						w.routesClones.Add(1)
					}

					if ok {
						routes[p] = primary
					} else {
						delete(routes, p)
					}
				}
			}
		}
	}

	var via *policyv2.ViaRoutes

	// The seed only survives the pm == nil path: no policy means the last
	// via binding must be dropped.
	changed := pm == nil && prev.via != nil
	if pm != nil {
		electRoute := func(candidates views.Slice[types.NodeID], incumbent types.NodeID) (types.NodeID, bool) {
			return electPrimary(nodes, candidates, incumbent)
		}

		via, changed = pm.ElectViaRoutes(prev.via, touched, electRoute)

		// The from-scratch reference for the incremental election above:
		// seeded with the same incumbents, it must agree with what the
		// world adopted.
		if policyAudit() {
			if pmv2, ok := pm.(*policyv2.PolicyManager); ok {
				policyAuditRuns.Add(1)

				if !pmv2.AuditViaElections(prev.via, via, electRoute) {
					policyAuditFailures.Add(1)
					log.Error().Msg("policy audit: via election differs from a full one")
				}
			}
		}
	}

	next := newPrimaryRoutes(routes, nodes, prev)
	if changed {
		next.gen++
	}

	next.via, next.policy = via, pm

	return next
}

// primaryRoutes holds global and via-scoped elections from the same snapshot.
type primaryRoutes struct {
	routes map[netip.Prefix]types.NodeID
	via    *policyv2.ViaRoutes
	policy policy.PolicyManager
	// byNode is routes inverted, each node's prefixes sorted.
	byNode map[types.NodeID][]netip.Prefix
	from   *nodeMap
	// gen changes only when the election result changes, so endpoint
	// writes reach the equality cutoff without comparing every prefix.
	gen uint64
}

func newPrimaryRoutes(routes map[netip.Prefix]types.NodeID, from *nodeMap, prev primaryRoutes) primaryRoutes {
	if prev.from != nil && maps.Equal(prev.routes, routes) {
		prev.from = from

		return prev
	}

	byNode := make(map[types.NodeID][]netip.Prefix)
	for p, id := range routes {
		byNode[id] = append(byNode[id], p)
	}

	for _, ps := range byNode {
		slices.SortFunc(ps, netip.Prefix.Compare)
	}

	return primaryRoutes{routes: routes, byNode: byNode, from: from, gen: prev.gen + 1}
}

func samePrimaries(a, b primaryRoutes) bool { return a.gen == b.gen }

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

// snapshot returns the latest consistent view of the world.
func (w *world) snapshot() *Snapshot {
	return &Snapshot{s: w.g.Snapshot(), w: w}
}

// nodeWrite is one queued change to the node table; see [world.update].
type nodeWrite struct {
	fn   func(nodes *nodeEdit)
	done chan writeResult
}

// writeResult is a committed write's snapshot, or the panic its commit
// raised, which the writer re-raises in its own goroutine.
type writeResult struct {
	snap  *Snapshot
	panic any
}

// update commits fn's edit of the nodes and returns the snapshot holding
// it.
//
// Writes that arrive while a commit runs share the next one (group
// commit): a burst of joins, deletes or endpoint updates costs one policy
// compile and one peer rebuild instead of one each, and an idle write pays
// no wait.
func (w *world) update(fn func(nodes *nodeEdit)) *Snapshot {
	nw := &nodeWrite{fn: fn, done: make(chan writeResult, 1)}

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
		w.lead()
	}

	r := <-nw.done
	if r.panic != nil {
		panic(r.panic)
	}

	return r.snap
}

// lingerForBatch waits for writes to batch, as the tuning asks. It runs
// only during an HA outage: writes that land together are elected
// together, so two routers coming back at once keep their primary instead
// of handing the route to whichever reconnected first. Any other write
// commits at once.
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

	// Hand the commit on whatever happens below, or a panic would leave
	// committing set and every later write waiting for nothing.
	defer w.handOff()

	out, p, stack := w.commitBatch(batch)
	if p == nil {
		for _, nw := range batch {
			nw.done <- writeResult{snap: out}
		}

		return
	}

	worldCommitPanics.Add(1)
	log.Error().Interface("panic", p).Bytes("stack", stack).Int("batch", len(batch)).Msg("node write panicked")

	if len(batch) == 1 {
		batch[0].done <- writeResult{snap: out, panic: p}

		return
	}

	// One write's panic must not fail the others it was batched with:
	// commit each alone, so only the writes that panic again fail.
	for _, nw := range batch {
		out, p, _ := w.commitBatch([]*nodeWrite{nw})
		nw.done <- writeResult{snap: out, panic: p}
	}
}

// commitBatch commits batch's writes together, returning the panic one of
// them or a cell raised, with its stack, instead of letting it unwind the
// commit loop.
//
//nolint:nonamedreturns // the deferred recover sets the panic result
func (w *world) commitBatch(batch []*nodeWrite) (out *Snapshot, p any, stack []byte) {
	defer func() {
		if p = recover(); p != nil {
			stack = debug.Stack()
		}
	}()

	var checkOutage, changed bool

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

		if w.batchTimeout > 0 {
			// Health can change without moving the primary, and policy
			// facts — tags, routes — can move elections without touching
			// anything the availability diff sees. One walk decides.
			checkOutage = electionInputChanged(cur, next)
		}

		graph.Set(tx, w.nodes, next)

		changed = true

		return nil
	})

	if changed {
		worldNodes.Set(float64(snap.Get(w.nodes).Len()))
		worldCommits.Inc()
	}

	worldBatchSize.Observe(float64(len(batch)))

	out = &Snapshot{s: snap, w: w}
	if checkOutage {
		w.storeOutage(out)
	}

	return out, nil, nil
}

// storeOutage records the outage state of snap, refusing a state computed
// from an older snapshot than the one already stored: whichever of two
// concurrent writers finished first, the newer snapshot's state wins.
func (w *world) storeOutage(snap *Snapshot) {
	// The state is a pure function of an immutable snapshot: compute it
	// outside the lock and hold the lock only to order the stores.
	rev, out := snap.Rev(), hasOutage(snap)

	w.outageMu.Lock()
	defer w.outageMu.Unlock()

	if rev < w.outageRev {
		return
	}

	w.outageRev = rev
	w.inOutage.Store(out)
	w.outageStores.Add(1)
}

// handOff ends the commit loop when no writes are queued, or starts the
// next commit for those that arrived during this one.
func (w *world) handOff() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if len(w.writes) == 0 {
		w.committing = false

		return
	}

	go w.lead()
}

// lead runs the next commit, waiting first for writes to batch during an HA
// outage. Every commit goes through it, including those started for writes
// that arrived during the one before.
func (w *world) lead() {
	if w.inOutage.Load() {
		w.lingerForBatch()
	}

	w.commitWrites()
}

// UpdateNodeFunc modifies a node in place. It runs on a copy of the stored
// node, inside the writer, so it sees every write committed before it. If
// another write in its batch panics it runs again, alone, so it must only
// edit n and set what its caller reads afterwards.
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
func (w *world) SetUsers(users []types.User) error {
	// Most refreshes, one per registration, change nothing; they must not
	// queue behind a commit.
	before := w.g.Snapshot()
	if slices.Equal(before.Get(w.users), users) {
		return before.Get(w.policy).err
	}

	byID := make(map[uint]*types.User, len(users))
	for i := range users {
		byID[users[i].ID] = &users[i]
	}

	var changed bool

	snap, err := w.g.Update(func(tx *graph.Tx) error {
		changed = !slices.Equal(graph.Peek(tx, w.users), users)
		if !changed {
			return nil
		}

		graph.Set(tx, w.users, slices.Clone(users))

		cur := graph.Peek(tx, w.nodes)
		e := cur.Edit()

		for id, n := range cur.All() {
			if n.User == nil {
				continue
			}

			u, ok := byID[n.User.ID]
			if !ok || sameUserForNodes(*u, *n.User) {
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

		return nil
	})
	if err != nil {
		return err
	}

	if changed {
		worldCommits.Inc()

		// A user change can move elections like a policy change can,
		// without any node availability changing.
		if w.batchTimeout > 0 {
			w.storeOutage(w.snapshot())
		}
	}

	return snap.Get(w.policy).err
}

// SetPolicy replaces the policy document and reports whether it differed
// from the live one. The commit is published only if check accepts it.
// It compiles incrementally, from the last good policy, while a caller
// checks a candidate compiled from scratch; the policy audit compares the
// two.
func (w *world) SetPolicy(src []byte, check func(*Snapshot) error) (bool, error) {
	var changed bool

	w.beforePolicyCommit()

	_, err := w.g.UpdateChecked(
		func(tx *graph.Tx) error {
			// Compared under the lock, so a document set twice at once is
			// compiled and published once.
			changed = !bytes.Equal(graph.Peek(tx, w.policySrc), src)
			if changed {
				graph.Set(tx, w.policySrc, src)
			}

			return nil
		},
		func(s *graph.Snapshot) error { return check(&Snapshot{s: s, w: w}) },
	)
	if err != nil || !changed {
		return false, err
	}

	worldCommits.Inc()

	// A policy change can move elections without any node availability
	// changing; the outage state follows it.
	if w.batchTimeout > 0 {
		w.storeOutage(w.snapshot())
	}

	return true, nil
}

// SetDERPMap replaces the DERP map.
func (w *world) SetDERPMap(dm *tailcfg.DERPMap) {
	var changed bool

	_, _ = w.g.Update(func(tx *graph.Tx) error {
		changed = !sameDERPMap(graph.Peek(tx, w.derpMap), dm)
		if changed {
			graph.Set(tx, w.derpMap, dm)
		}

		return nil
	})

	if changed {
		worldCommits.Inc()
	}
}

// sameDERPMap compares DERP maps by content; a fetch returns a new map
// even when nothing changed.
func sameDERPMap(a, b *tailcfg.DERPMap) bool {
	return reflect.DeepEqual(a, b)
}

// SetExtraRecords replaces the extra DNS records.
func (w *world) SetExtraRecords(records []tailcfg.DNSRecord) {
	var changed bool

	_, _ = w.g.Update(func(tx *graph.Tx) error {
		cur := graph.Peek(tx, w.dns)
		dns := cur.WithExtraRecords(records)

		changed = !cur.Equal(dns)
		if changed {
			graph.Set(tx, w.dns, dns)
		}

		return nil
	})

	if changed {
		worldCommits.Inc()
	}
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

// hasOutage reports whether s has an HA outage: a prefix whose primary is
// unhealthy while no router for it is healthy. The primary keeps the
// route then, and the routers coming back should be elected together.
func hasOutage(s *Snapshot) bool {
	nodes := s.nodes()
	groups := s.s.Get(s.w.index).advertisers.Groups

	healthy := func(id types.NodeID) bool {
		n, ok := nodes.Get(id)

		return ok && !n.Unhealthy
	}

	for p, id := range s.s.Get(s.w.primaries).routes {
		if healthy(id) {
			continue
		}

		candidates, _ := groups.Get(p)
		if !slices.ContainsFunc(candidates, healthy) {
			return true
		}
	}

	// Via scopes count too: their candidates are not the global advertisers,
	// so a scope can lose every router while the global election stays
	// healthy through an untagged one.
	available := func(id types.NodeID) bool {
		n, ok := nodes.Get(id)

		return ok && n.Online() && !n.Unhealthy
	}

	return s.s.Get(s.w.primaries).via.HasOutage(available)
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
		if primary, ok := electPrimary(nodes, views.SliceOf(candidates), prev[prefix]); ok {
			routes[prefix] = primary
		}
	}

	return routes
}

// electPrimary picks among candidates in ID order: a healthy online
// incumbent keeps the route, otherwise the lowest healthy candidate takes
// it. With no healthy candidate an online incumbent retains the route
// rather than flap; an offline one drops it.
func electPrimary(
	nodes *nodeMap,
	candidates views.Slice[types.NodeID],
	cur types.NodeID,
) (types.NodeID, bool) {
	var firstHealthy types.NodeID

	incumbent := false

	for _, id := range candidates.All() {
		n, ok := nodes.Get(id)
		if !ok || !n.Online() {
			continue
		}

		if id == cur {
			incumbent = true

			if !n.Unhealthy {
				return cur, true
			}
		}

		if !n.Unhealthy && firstHealthy == 0 {
			firstHealthy = id
		}
	}

	if firstHealthy != 0 {
		return firstHealthy, true
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

func (s *Snapshot) index() *nodeIndex { return s.s.Get(s.w.index) }

// Rev identifies the commit this snapshot shows.
func (s *Snapshot) Rev() uint64 { return s.s.Rev() }

// Time is when the commit this snapshot shows was made.
func (s *Snapshot) Time() time.Time { return s.s.Time() }

func (s *Snapshot) nodes() *nodeMap { return s.s.Get(s.w.nodes) }

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

	// A machine re-registered under another user keeps its node key on
	// both nodes; the client speaks for the newer one, the highest ID.
	return s.GetNode(ids[len(ids)-1])
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
		// A tagged node may still record the user who created it; tags,
		// not that user, own it.
		owner := nv.TypedUserID()
		if nv.IsTagged() {
			owner = 0
		}

		out[owner] = nv
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
	return views.SliceOf(s.index().all.get())
}

// ListNodesByUser returns the user-owned nodes of uid.
func (s *Snapshot) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	ids, _ := s.index().byUser.Groups.Get(uid)

	return views.SliceOf(s.gather(ids))
}

// ListPeerIDs returns the sorted IDs of the nodes id can see, as a copy
// the caller may keep and modify.
func (s *Snapshot) ListPeerIDs(id types.NodeID) []types.NodeID {
	return s.s.Get(s.w.peers).Peers(id)
}

// PeerView returns the sorted IDs of the nodes id can see, possibly
// including id itself: nodes that see the same nodes share one view. It
// is shared with the snapshot and must not be modified.
func (s *Snapshot) PeerView(id types.NodeID) []types.NodeID {
	return s.s.Get(s.w.peers).View(id)
}

// PeerViews returns every distinct view; see [Snapshot.PeerView].
func (s *Snapshot) PeerViews() [][]types.NodeID { return s.s.Get(s.w.peers).Views() }

// ListPeers returns the nodes id can see, sorted by ID.
func (s *Snapshot) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	return views.SliceOf(s.gather(s.ListPeerIDs(id)))
}

// Policy returns the compiled policy.
func (s *Snapshot) Policy() policy.PolicyManager { return s.s.Get(s.w.policy).pm }

// PolicyErr is the error of the latest failed policy compile, or nil when
// the served policy is current.
func (s *Snapshot) PolicyErr() error { return s.s.Get(s.w.policy).err }

// policyInputs returns the users and nodes the policy compiles against,
// and the revision they last changed at.
func (s *Snapshot) policyInputs() ([]types.User, views.Slice[types.NodeView], uint64) {
	rev := max(graph.ChangedAt(s.s, s.w.policyUsers), graph.ChangedAt(s.s, s.w.policyNodes))

	return s.s.Get(s.w.policyUsers), s.s.Get(s.w.policyNodes).list, rev
}

// PolicySource returns the policy document. It is shared and must not be
// modified.
func (s *Snapshot) PolicySource() []byte { return s.s.Get(s.w.policySrc) }

// Users returns the user list.
func (s *Snapshot) Users() []types.User { return s.s.Get(s.w.users) }

// DERPMap returns the DERP map.
func (s *Snapshot) DERPMap() *tailcfg.DERPMap { return s.s.Get(s.w.derpMap) }

// DNS returns the immutable DNS settings and records of this snapshot.
func (s *Snapshot) DNS() types.DNSView { return s.s.Get(s.w.dns) }

// PrimaryRoutes returns the prefix→primary assignment. It is shared and
// must not be modified.
func (s *Snapshot) PrimaryRoutes() map[netip.Prefix]types.NodeID {
	return s.s.Get(s.w.primaries).routes
}

// PrimaryRouteFor returns the primary advertiser of prefix.
func (s *Snapshot) PrimaryRouteFor(prefix netip.Prefix) (types.NodeID, bool) {
	id, ok := s.PrimaryRoutes()[prefix]

	return id, ok
}

// PrimaryRoutesForNode returns the prefixes id is primary for, sorted.
func (s *Snapshot) PrimaryRoutesForNode(id types.NodeID) []netip.Prefix {
	return slices.Clone(s.s.Get(s.w.primaries).byNode[id])
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
	n, ok := s.s.Get(s.w.nodes).Get(id)

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
	via := s.s.Get(s.w.primaries).via.ForPeer(viewer, peer)
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

	// A single address inside the node ranges names a node, not a subnet: it
	// stays approved and in the router's own entry, but no viewer is served
	// it. Via inclusions skip the election, so the rule applies here, to
	// everything the viewer gets.
	if s.w.servesRoute != nil {
		reduced = slices.DeleteFunc(reduced, func(p netip.Prefix) bool { return !s.w.servesRoute(p) })
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
	// Resync means the node edit history was exceeded; consumers must
	// check retained node state against the current snapshot.
	Resync bool
	// Nodes includes nodes changed back or deleted between snapshots
	// when commits coalesced: a session may have rendered them meanwhile.
	Nodes []types.NodeID
	// Primaries are the nodes that gained or lost a global or via-scoped route.
	Primaries []types.NodeID
	// PeerSets are the nodes whose set of peers differs.
	PeerSets []types.NodeID
	// Filters are the nodes whose packet filter a recompile of the
	// policy after a node change can have changed; Caps those whose
	// policy capabilities changed, which their viewers render too.
	Filters, Caps []types.NodeID
}

// Since returns what changed from old to s. A nil old is everything.
func (s *Snapshot) Since(old *Snapshot) Change {
	if old == nil {
		return Change{Global: true}
	}

	c := Change{
		Global: graph.ChangedAt(s.s, s.w.derpMap) != graph.ChangedAt(old.s, old.w.derpMap) ||
			s.DNSRev() != old.DNSRev(),
	}
	if s.Rev() > old.Rev()+1 {
		var complete bool

		c.Nodes, complete = s.NodesTouchedSince(old.NodesVersion())
		c.Resync = !complete

		c.Global = c.Global || c.Resync || s.PolicyRev() != old.PolicyRev() ||
			s.PeersRev() != old.PeersRev() || s.PrimariesRev() != old.PrimariesRev()
		if c.Global {
			return c
		}
	} else {
		c.Nodes = graph.Changes(old.nodes(), s.nodes())
	}

	if s.PolicyRev() != old.PolicyRev() {
		next, _ := s.Policy().(*policyv2.PolicyManager)
		last, _ := old.Policy().(*policyv2.PolicyManager)

		filters, all := next.FilterChangedNodes(last)
		if all {
			c.Global = true
		} else {
			c.Filters = filters
			c.Caps = graph.Changes(old.s.Get(old.w.nodeCaps), s.s.Get(s.w.nodeCaps))
		}
	}

	if s.PrimariesRev() != old.PrimariesRev() {
		c.Primaries = changedKeys(
			old.s.Get(old.w.primaries).byNode,
			s.s.Get(s.w.primaries).byNode,
			slices.Equal[[]netip.Prefix],
		)

		was, now := old.s.Get(old.w.primaries).via, s.s.Get(s.w.primaries).via
		c.Primaries = append(c.Primaries, now.ChangedNodes(was)...)

		slices.Sort(c.Primaries)
		c.Primaries = slices.Compact(c.Primaries)
	}

	if s.PeersRev() != old.PeersRev() {
		c.PeerSets = s.s.Get(s.w.peers).Changed(old.s.Get(old.w.peers))
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

// RoutedNodes returns the nodes serving an approved route, sorted. It is
// shared and must not be modified.
func (s *Snapshot) RoutedNodes() []types.NodeID {
	ids, _ := s.index().routed.Groups.Get(true)

	return ids
}

// CapsVersion is the policy's node capabilities in a snapshot, which a
// reader keeps to ask a later snapshot whose caps changed.
type CapsVersion struct{ m *capsMap }

// CapsVersion returns the node capabilities of s.
func (s *Snapshot) CapsVersion() CapsVersion { return CapsVersion{m: s.s.Get(s.w.nodeCaps)} }

// CapsChangedSince returns the nodes whose policy capabilities differ
// between v and s.
func (s *Snapshot) CapsChangedSince(v CapsVersion) []types.NodeID {
	return graph.Changes(v.m, s.s.Get(s.w.nodeCaps))
}

// NodesVersion is the nodes of a snapshot, which a reader keeps to ask a
// later snapshot what changed since. Holding one costs only what later
// writes replaced.
type NodesVersion struct{ m *nodeMap }

// NodesVersion returns the nodes of s.
func (s *Snapshot) NodesVersion() NodesVersion { return NodesVersion{m: s.nodes()} }

// NodesTouchedSince returns the nodes the writes from v to s touched,
// possibly with repeats and nodes that changed back, while v is within
// the nodes' edit log; otherwise false, and the caller should not compare
// every node when a smaller set covers what it needs.
func (s *Snapshot) NodesTouchedSince(v NodesVersion) ([]types.NodeID, bool) {
	return s.nodes().ChangedSince(v.m)
}

// PeerPolicyRev is the revision of the latest policy compile that
// renders nodes as peers differently.
func (s *Snapshot) PeerPolicyRev() uint64 { return graph.ChangedAt(s.s, s.w.peerPolicy) }

// PolicyRev is the revision of the latest policy compile.
func (s *Snapshot) PolicyRev() uint64 { return graph.ChangedAt(s.s, s.w.policy) }

// PeersRev is the revision of the latest change to peer visibility.
func (s *Snapshot) PeersRev() uint64 { return graph.ChangedAt(s.s, s.w.peers) }

// PrimariesRev is the revision of the latest global or via-scoped route change.
func (s *Snapshot) PrimariesRev() uint64 { return graph.ChangedAt(s.s, s.w.primaries) }

// DNSRev is the revision of the latest extra DNS records change.
func (s *Snapshot) DNSRev() uint64 { return graph.ChangedAt(s.s, s.w.dns) }
