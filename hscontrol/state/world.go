package state

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

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
	policyCompiles = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "policy_compiles_total",
		Help:      "Policy compilations by result.",
	}, []string{"result"})
)

// nodeTable is the set of nodes. A stored node is never mutated: a write
// stores a modified copy, so a [types.NodeView] taken from a snapshot stays
// valid and two snapshots holding the same pointer hold the same node.
type nodeTable struct {
	byID map[types.NodeID]*types.Node
}

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

	nodes        graph.Input[*nodeTable]
	users        graph.Input[[]types.User]
	policySrc    graph.Input[[]byte]
	derpMap      graph.Input[*tailcfg.DERPMap]
	extraRecords graph.Input[[]tailcfg.DNSRecord]

	index       graph.Derived[*nodeIndex]
	policyNodes graph.Derived[policyNodes]
	policy      graph.Derived[*compiledPolicy]
	peers       graph.Derived[map[types.NodeID][]types.NodeID]
	primaries   graph.Derived[map[netip.Prefix]types.NodeID]
}

// nodeIndex holds the lookups every reader needs, rebuilt when a node
// changes.
type nodeIndex struct {
	all          []types.NodeView // sorted by ID
	byID         map[types.NodeID]types.NodeView
	byNodeKey    map[key.NodePublic]types.NodeView
	byMachineKey map[key.MachinePublic]map[types.UserID]types.NodeView
	byUser       map[types.UserID][]types.NodeView
}

// policyNodes is the node list as the policy reads it. It changes only
// when a node joins, leaves or changes a field the policy reads
// ([types.NodeView.HasPolicyChange]); keeping the older views otherwise is
// what spares an endpoint update a policy compile.
type policyNodes struct {
	list views.Slice[types.NodeView]
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
	w := &world{g: g}

	table := &nodeTable{byID: make(map[types.NodeID]*types.Node, len(nodes))}
	for _, n := range nodes {
		table.byID[n.ID] = n
	}

	w.nodes = graph.NewInput(g, "nodes", table, graph.Same[*nodeTable])
	// Users are refreshed on every registration; an unchanged list must not
	// recompile the policy.
	w.users = graph.NewInput(g, "users", users, samePolicyUsers)
	w.policySrc = graph.NewInput(g, "policy-source", polSrc, graph.Never[[]byte])
	w.derpMap = graph.NewInput(g, "derp-map", (*tailcfg.DERPMap)(nil), graph.Same[*tailcfg.DERPMap])
	w.extraRecords = graph.NewInput(g, "extra-records", []tailcfg.DNSRecord(nil), graph.Never[[]tailcfg.DNSRecord])

	w.index = graph.NewDerived(g, "index", graph.Same[*nodeIndex],
		func(s *graph.Snapshot, _ *nodeIndex) *nodeIndex {
			return buildIndex(graph.Get(s, w.nodes))
		})

	w.policyNodes = graph.NewDerived(g, "policy-nodes", samePolicyNodes,
		func(s *graph.Snapshot, _ policyNodes) policyNodes {
			return policyNodes{list: views.SliceOf(graph.Get(s, w.index).all)}
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

			return pm.BuildPeerMap(graph.Get(s, w.policyNodes).list)
		})

	w.primaries = graph.NewDerived(g, "primaries", samePrimaries,
		func(s *graph.Snapshot, prev map[netip.Prefix]types.NodeID) map[netip.Prefix]types.NodeID {
			return electPrimaryRoutes(graph.Get(s, w.nodes).byID, prev)
		})

	snap, err := g.Update(func(*graph.Tx) error { return nil })
	if err != nil {
		return nil, err
	}

	if cp := graph.Get(snap, w.policy); cp.pm == nil {
		return nil, fmt.Errorf("compiling policy: %w", cp.err)
	}

	worldNodes.Set(float64(len(table.byID)))

	return w, nil
}

func buildIndex(t *nodeTable) *nodeIndex {
	idx := &nodeIndex{
		all:          make([]types.NodeView, 0, len(t.byID)),
		byID:         make(map[types.NodeID]types.NodeView, len(t.byID)),
		byNodeKey:    make(map[key.NodePublic]types.NodeView, len(t.byID)),
		byMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView),
		byUser:       make(map[types.UserID][]types.NodeView),
	}

	for _, id := range slices.Sorted(maps.Keys(t.byID)) {
		n := t.byID[id]
		nv := n.View()
		idx.all = append(idx.all, nv)
		idx.byID[id] = nv
		idx.byNodeKey[n.NodeKey] = nv

		uid := n.TypedUserID()
		// Tagged nodes are owned by their tags, not a user.
		if !n.IsTagged() {
			idx.byUser[uid] = append(idx.byUser[uid], nv)
		}

		if idx.byMachineKey[n.MachineKey] == nil {
			idx.byMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}

		idx.byMachineKey[n.MachineKey][uid] = nv
	}

	return idx
}

func samePolicyNodes(a, b policyNodes) bool {
	if a.list.Len() != b.list.Len() {
		return false
	}

	for i := range a.list.Len() {
		x, y := a.list.At(i), b.list.At(i)
		if x.ID() != y.ID() || x.HasPolicyChange(y) {
			return false
		}
	}

	return true
}

// samePolicyUsers reports whether the policy resolves both user lists the
// same way, so an unrelated user field (a login's UpdatedAt) costs no
// compile.
func samePolicyUsers(a, b []types.User) bool {
	return slices.EqualFunc(a, b, func(x, y types.User) bool { return x.PolicyEqual(&y) })
}

func samePrimaries(a, b map[netip.Prefix]types.NodeID) bool { return maps.Equal(a, b) }

func samePeerMap(a, b map[types.NodeID][]types.NodeID) bool {
	return maps.EqualFunc(a, b, slices.Equal[[]types.NodeID])
}

// snapshot returns the latest consistent view of the world.
func (w *world) snapshot() *Snapshot {
	return &Snapshot{s: w.g.Snapshot(), w: w}
}

// update commits the result of fn applied to a copy of the node table.
// fn reports whether it changed anything; an unchanged table publishes
// nothing.
func (w *world) update(fn func(nodes map[types.NodeID]*types.Node) bool) *Snapshot {
	snap, _ := w.g.Update(func(tx *graph.Tx) error {
		cur := graph.Peek(tx, w.nodes)

		next := maps.Clone(cur.byID)
		if !fn(next) {
			return nil
		}

		graph.Set(tx, w.nodes, &nodeTable{byID: next})
		worldNodes.Set(float64(len(next)))
		worldCommits.Inc()

		return nil
	})

	return &Snapshot{s: snap, w: w}
}

// UpdateNodeFunc modifies a node in place. It runs on a copy of the stored
// node, inside the writer, so it sees every write committed before it.
type UpdateNodeFunc func(n *types.Node)

// PutNode stores n, replacing any node with its ID. Its GivenName is made
// unique first. It returns the stored node.
func (w *world) PutNode(n types.Node) types.NodeView {
	snap := w.update(func(nodes map[types.NodeID]*types.Node) bool {
		stored := n
		stored.GivenName = uniqueGivenName(nodes, n.ID, n.GivenName)
		nodes[n.ID] = &stored

		return true
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

	return w.update(func(nodes map[types.NodeID]*types.Node) bool {
		changed := false

		for id, fn := range updates {
			cur, ok := nodes[id]
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

			nodes[id] = next
			changed = true
		}

		return changed
	})
}

// DeleteNode removes the node with id.
func (w *world) DeleteNode(id types.NodeID) {
	w.update(func(nodes map[types.NodeID]*types.Node) bool {
		if _, ok := nodes[id]; !ok {
			return false
		}

		delete(nodes, id)

		return true
	})
}

// SetGivenName renames a node to exactly name, rejecting an invalid label
// and one another node holds (case-insensitively).
func (w *world) SetGivenName(id types.NodeID, name string) (types.NodeView, error) {
	var err error

	snap := w.update(func(nodes map[types.NodeID]*types.Node) bool {
		cur, ok := nodes[id]
		if !ok {
			err = ErrNodeNotFound

			return false
		}

		if dnsname.ValidLabel(name) != nil {
			err = ErrGivenNameInvalid

			return false
		}

		for oid, other := range nodes {
			if oid != id && strings.EqualFold(other.GivenName, name) {
				err = ErrGivenNameTaken

				return false
			}
		}

		next := cur.Clone()
		next.GivenName = name
		nodes[id] = next

		return true
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

		var next map[types.NodeID]*types.Node

		for id, n := range cur.byID {
			if n.User == nil {
				continue
			}

			u, ok := byID[n.User.ID]
			if !ok || *u == *n.User {
				continue
			}

			if next == nil {
				next = maps.Clone(cur.byID)
			}

			c := n.Clone()
			uc := *u
			c.User = &uc
			next[id] = c
		}

		if next != nil {
			graph.Set(tx, w.nodes, &nodeTable{byID: next})
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
func uniqueGivenName(nodes map[types.NodeID]*types.Node, self types.NodeID, base string) string {
	if base == "" {
		base = fallbackGivenName
	}

	taken := make(map[string]struct{}, len(nodes))

	for id, n := range nodes {
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
func onlineAdvertisers(nodes map[types.NodeID]*types.Node) map[netip.Prefix][]types.NodeID {
	advertisers := make(map[netip.Prefix][]types.NodeID)

	for _, id := range slices.Sorted(maps.Keys(nodes)) {
		n := nodes[id]
		if n.IsOnline == nil || !*n.IsOnline {
			continue
		}

		for _, p := range n.AllApprovedRoutes() {
			if tsaddr.IsExitRoute(p) {
				continue
			}

			advertisers[p] = append(advertisers[p], id)
		}
	}

	return advertisers
}

// electPrimaryRoutes picks the primary advertiser for each non-exit
// prefix among online nodes approving it. A previous primary that is still
// a healthy candidate keeps the prefix (no flapping); otherwise the lowest
// healthy NodeID wins. When every candidate is unhealthy, only a previous
// primary that is still a candidate keeps it: pointing peers at another
// node the prober declared unreachable is worse than leaving it unmapped.
func electPrimaryRoutes(
	nodes map[types.NodeID]*types.Node,
	prev map[netip.Prefix]types.NodeID,
) map[netip.Prefix]types.NodeID {
	advertisers := onlineAdvertisers(nodes)
	routes := make(map[netip.Prefix]types.NodeID, len(advertisers))

	for prefix, candidates := range advertisers {
		cur, hadPrimary := prev[prefix]
		incumbent := hadPrimary && slices.Contains(candidates, cur)

		if incumbent && !nodes[cur].Unhealthy {
			routes[prefix] = cur
			continue
		}

		idx := slices.IndexFunc(candidates, func(c types.NodeID) bool { return !nodes[c].Unhealthy })

		switch {
		case idx >= 0:
			routes[prefix] = candidates[idx]
		case incumbent:
			routes[prefix] = cur
		}
	}

	return routes
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

// GetNode returns the node with id.
func (s *Snapshot) GetNode(id types.NodeID) (types.NodeView, bool) {
	nv, ok := s.index().byID[id]

	return nv, ok
}

// GetNodeByNodeKey returns the node holding nodeKey.
func (s *Snapshot) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	nv, ok := s.index().byNodeKey[nodeKey]

	return nv, ok
}

// GetNodesByMachineKeyAllUsers returns every node sharing machineKey,
// keyed by owning UserID; tagged nodes are under UserID(0).
func (s *Snapshot) GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView {
	return maps.Clone(s.index().byMachineKey[machineKey])
}

// ListNodes returns every node, sorted by ID.
func (s *Snapshot) ListNodes() views.Slice[types.NodeView] {
	return views.SliceOf(s.index().all)
}

// ListNodesByUser returns the user-owned nodes of uid.
func (s *Snapshot) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	return views.SliceOf(s.index().byUser[uid])
}

// ListPeerIDs returns the sorted IDs of the nodes id can see.
func (s *Snapshot) ListPeerIDs(id types.NodeID) []types.NodeID {
	return slices.Sorted(slices.Values(graph.Get(s.s, s.w.peers)[id]))
}

// ListPeers returns the nodes id can see, sorted by ID.
func (s *Snapshot) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	byID := s.index().byID
	ids := s.ListPeerIDs(id)
	peers := make([]types.NodeView, 0, len(ids))

	for _, pid := range ids {
		if nv, ok := byID[pid]; ok {
			peers = append(peers, nv)
		}
	}

	return views.SliceOf(peers)
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
	return graph.Get(s.s, s.w.primaries)
}

// PrimaryRouteFor returns the primary advertiser of prefix.
func (s *Snapshot) PrimaryRouteFor(prefix netip.Prefix) (types.NodeID, bool) {
	id, ok := s.PrimaryRoutes()[prefix]

	return id, ok
}

// PrimaryRoutesForNode returns the prefixes id is primary for, sorted.
func (s *Snapshot) PrimaryRoutesForNode(id types.NodeID) []netip.Prefix {
	var out []netip.Prefix

	for p, nid := range s.PrimaryRoutes() {
		if nid == id {
			out = append(out, p)
		}
	}

	slices.SortFunc(out, netip.Prefix.Compare)

	return out
}

// HANodes returns the prefixes with two or more online advertisers.
func (s *Snapshot) HANodes() map[netip.Prefix][]types.NodeID {
	out := make(map[netip.Prefix][]types.NodeID)

	for p, ids := range onlineAdvertisers(graph.Get(s.s, s.w.nodes).byID) {
		if len(ids) >= 2 {
			out[p] = ids
		}
	}

	return out
}

// IsNodeHealthy reports the HA prober's view of id; unknown nodes are
// healthy.
func (s *Snapshot) IsNodeHealthy(id types.NodeID) bool {
	n, ok := graph.Get(s.s, s.w.nodes).byID[id]

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
