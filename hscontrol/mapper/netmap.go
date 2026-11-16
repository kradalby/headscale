package mapper

import (
	"cmp"
	"errors"
	"iter"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/graph"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// peer returns the peer with id; the node itself is not its own peer.
func (nm *netMap) peer(id tailcfg.NodeID) (*tailcfg.Node, bool) {
	if nm.self != nil && id == nm.self.ID {
		return nil, false
	}

	return nm.peers.Get(id)
}

// allPeers returns the peers, the node itself left out.
func (nm *netMap) allPeers() iter.Seq2[tailcfg.NodeID, *tailcfg.Node] {
	return func(yield func(tailcfg.NodeID, *tailcfg.Node) bool) {
		for id, p := range nm.peers.All() {
			if nm.self != nil && id == nm.self.ID {
				continue
			}

			if !yield(id, p) {
				return
			}
		}
	}
}

// peerMap holds the rendered peers of a netMap by ID.
type peerMap = graph.Map[tailcfg.NodeID, *tailcfg.Node]

func newPeerMap() *peerMap {
	return graph.NewMap[tailcfg.NodeID, *tailcfg.Node](graph.Same[*tailcfg.Node], nil)
}

// profileMap is the profiles of a class's owners, shared by the sessions of
// the class like its peers.
type profileMap = graph.Map[tailcfg.UserID, tailcfg.UserProfile]

func newProfileMap() *profileMap {
	return graph.NewMap[tailcfg.UserID, tailcfg.UserProfile](sameProfile, nil)
}

// ErrNodeGone is returned when the node a map is rendered for is no
// longer in the world.
var ErrNodeGone = errors.New("node no longer exists")

// netMap is everything a node is told about its tailnet, rendered from one
// [state.Snapshot]. A client holds exactly the last netMap it was sent;
// what to send next is the difference to a fresh one, see [diff].
type netMap struct {
	// at is when the snapshot rendered was committed: the ControlTime of
	// the updates it is diffed into, the same for every session rendering
	// it, so their identical updates encode to identical bytes. Sessions
	// render on commits, so it is recent.
	at   time.Time
	self *tailcfg.Node
	// peers is usually the map its class shares (see [classMaps]), which
	// holds the node itself when it sees its own class; read it through
	// [netMap.peer] and [netMap.allPeers], which leave the node out.
	peers *peerMap
	// profiles are the owners of the class's nodes, shared like peers;
	// selfProfile is the node's own owner's, when it has one.
	profiles    *profileMap
	selfProfile *tailcfg.UserProfile
	filter      []tailcfg.FilterRule
	ssh         *tailcfg.SSHPolicy
	dns         *tailcfg.DNSConfig
	derpMap     *tailcfg.DERPMap

	// base is the render this one follows. changed lists the peers added or
	// rendered again since base and removed the peers gone, so a diff
	// against base touches only them. sameProfiles reports profiles equal to
	// base's.
	base         *netMap
	changed      []tailcfg.NodeID
	removed      []tailcfg.NodeID
	sameProfiles bool
	// ownerless is set when self had no owner, so no profiles were sent
	// though peers were.
	ownerless bool
}

// renderer renders one node's netMap. After the first render it renders a
// peer again only when the peer or what its rendering reads (its policy
// caps, its routes) changed; the common endpoint and online updates cost
// one peer each.
type renderer struct {
	cfg    *types.Config
	nodeID types.NodeID
	capVer tailcfg.CapabilityVersion
	// peerCapVer is the version peers are rendered for, see [peerCapVer].
	peerCapVer tailcfg.CapabilityVersion

	last *netMap
	// renders and classes are the caches of the renderer's version; they
	// keep it alive, see [versionCache].
	renders *peerRenders
	classes *classMaps

	// The shared peers, peer inputs and peer set of the previous render, for
	// telling which peers a later snapshot can have changed.
	lastClass   *peerMap
	lastKey     renderKey
	lastPeerIDs []types.NodeID // the snapshot's shared view, see [state.Snapshot.PeerView]
	lastSelf    types.NodeView
	lastNodes   state.NodesVersion
	lastCaps    state.CapsVersion
	// overlaid holds the peers this viewer has its own copy of, with its
	// routes or without the IPv4 identity, so losing the last restores the
	// shared class map. It is kept by ID, not told from the last class
	// map: a rebuilt class can render an unchanged peer anew, an equal
	// render under another pointer than this viewer holds.
	overlaid         map[tailcfg.NodeID]struct{}
	lastIPv4Disabled bool
	// routedPrimaries are the primary routes each routed peer's routes were
	// rendered with, and routedVia the via elections: a primary move that
	// keeps the elections renders again only the routers whose primaries
	// moved.
	// Weak identity lets idle streams release obsolete compiled policies.
	routedPrimaries map[tailcfg.NodeID][]netip.Prefix
	routedVia       weak.Pointer[policyv2.ViaRoutes]
	routedWinners   *policyv2.ViaRoutes

	// dns is reused while its inputs, the node and the policy's capability
	// map and the extra records, are unchanged.
	dns    *tailcfg.DNSConfig
	dnsKey dnsKey

	// self is reused while the node, its policy caps and the primary routes,
	// which its own routes come from, are unchanged.
	self    *tailcfg.Node
	selfKey selfKey
	// selfCaps is the policy's immutable map, never the rendered CapMap.
	selfCaps tailcfg.NodeCapMap

	// rendered counts peer renders, for tests that bound per-write work.
	rendered int
}

// renderKey is what a peer's rendering reads besides the peer and the
// viewer: how the policy renders peers, and the primary routes.
type renderKey struct {
	policy, primaries uint64
}

type dnsKey struct {
	self        types.NodeView
	policy, dns uint64
}

// selfKey holds what the node's own entry renders from. dns is there for
// the HTTPS capability: an extra record at the node's name takes it away.
type selfKey struct {
	self           types.NodeView
	primaries, dns uint64
}

func newRenderer(cfg *types.Config, hub *Hub, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *renderer {
	pcv := peerCapVer(capVer)
	vc := hub.cache(pcv)

	return &renderer{
		cfg:        cfg,
		nodeID:     nodeID,
		capVer:     capVer,
		peerCapVer: pcv,
		renders:    &vc.renders,
		classes:    &vc.classes,
	}
}

// peerCapVer is the version a client speaking capVer is sent peers for.
// Peer renders are cached per version, and a client newer than the server
// can be told nothing a current one is not; rendering for its own version
// would keep a second render set alive for every newer version connected,
// the common case for an auto-updating fleet.
func peerCapVer(capVer tailcfg.CapabilityVersion) tailcfg.CapabilityVersion {
	return min(max(capVer, capver.MinSupportedCapabilityVersion), tailcfg.CurrentCapabilityVersion)
}

// versionCache holds what the sessions speaking one capability version
// share. Their renderers own it and the hub indexes it only weakly, so it
// lives exactly as long as a session speaking its version: a client
// cycling through versions leaves behind nothing its live sessions do not
// render.
type versionCache struct {
	renders peerRenders
	classes classMaps
}

// peerRenders shares, across sessions, the part of a peer's rendering that
// does not depend on who views it: everything but its routes. Each stored
// node is rendered once per policy, not once per viewer.
type peerRenders struct {
	m sync.Map // types.NodeID -> *atomic.Pointer[peerRender]
	// mu serialises admission with deletion; floor rejects misses from
	// older snapshots without keeping a tombstone for every deleted node.
	mu    sync.Mutex
	floor uint64
}

// advance publishes the newest snapshot observed. The watcher must call
// it before deletion cleanup, even when a resync finds no retained IDs.
func (pr *peerRenders) advance(rev uint64) {
	pr.mu.Lock()
	pr.floor = max(pr.floor, rev)
	pr.mu.Unlock()
}

// forget drops the render of a deleted node after advance publishes the
// deleting snapshot. Stores through an already admitted slot remain safe:
// they write the detached slot, never reinsert it.
func (pr *peerRenders) forget(id types.NodeID) {
	pr.mu.Lock()
	pr.m.Delete(id)
	pr.mu.Unlock()
}

// of returns node's render slot.
func (pr *peerRenders) of(node types.NodeID, rev uint64) *atomic.Pointer[peerRender] {
	if v, ok := pr.m.Load(node); ok {
		return v.(*atomic.Pointer[peerRender]) //nolint:forcetypeassert // only slots are stored
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if rev < pr.floor {
		return &atomic.Pointer[peerRender]{}
	}

	v, _ := pr.m.LoadOrStore(node, &atomic.Pointer[peerRender]{})

	return v.(*atomic.Pointer[peerRender]) //nolint:forcetypeassert // only slots are stored
}

type peerRender struct {
	node   types.NodeView
	policy uint64
	caps   tailcfg.NodeCapMap // the policy's caps for node, all it reads of the policy
	tn     *tailcfg.Node
}

// render returns peer rendered without routes. The result is shared and
// must not be modified; see [withRoutes].
func (pr *peerRenders) render(
	cfg *types.Config,
	dns types.DNSView,
	capVer tailcfg.CapabilityVersion,
	rev, policy uint64,
	peer types.NodeView,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
) (*tailcfg.Node, error) {
	slot := pr.of(peer.ID(), rev)
	caps := capMaps[peer.ID()]

	prev := slot.Load()
	if prev != nil {
		if prev.node == peer && prev.policy == policy {
			return prev.tn, nil
		}

		// A new policy that gives the peer the same caps renders it the
		// same: keep the render, so sessions see nothing to send.
		if prev.node == peer && reflect.DeepEqual(prev.caps, caps) {
			slot.Store(&peerRender{node: peer, policy: policy, caps: caps, tn: prev.tn})

			return prev.tn, nil
		}
	}

	// Peers must not read DNS records: the class cache reuses peer renders
	// across DNS revisions, and the peer CapMap is replaced below. Names come
	// from the frozen base domain, so a records-free view keeps peer renders
	// independent of record changes by construction.
	tn, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return nil }, cfg, dns.WithExtraRecords(nil), caps)
	if err != nil {
		return nil, err
	}

	// A peer's CapMap carries only the caps clients read from the peer
	// view; see [policyv2.PeerCapMap].
	tn.CapMap = policyv2.PeerCapMap(peer, caps)

	tn.Hostinfo = types.PeerHostinfo(tn.Hostinfo)

	if peer.IsExpired() {
		if peer.ActiveSessions() > 0 {
			tn.Online, tn.LastSeen = new(true), nil
		}

		tn.Endpoints, tn.HomeDERP = nil, 0
	}

	// Hostinfo is not patchable, so any change resends the whole peer.
	// Keep the Hostinfo clients hold while the fields they read are equal;
	// doing it here, once, keeps the render shared.
	if prev != nil && peerHostinfoEqual(prev.tn.Hostinfo, tn.Hostinfo) {
		tn.Hostinfo = prev.tn.Hostinfo
	}

	slot.Store(&peerRender{node: peer, policy: policy, caps: caps, tn: tn})

	return tn, nil
}

// withRoutes returns the shared render base carrying the routes one viewer
// sees, as [types.NodeView.TailNode] would have rendered them. A peer with
// no routes for the viewer, most of them, is the shared base itself, so a
// viewer holds a copy only of the peers that route for it.
func withRoutes(base *tailcfg.Node, routes []netip.Prefix) *tailcfg.Node {
	if len(routes) == 0 {
		return base
	}

	tn := *base
	tn.AllowedIPs = slices.Concat(base.Addresses, slices.SortedFunc(slices.Values(routes), netip.Prefix.Compare))

	tn.PrimaryRoutes = nil

	for _, r := range routes {
		if !tsaddr.IsExitRoute(r) {
			tn.PrimaryRoutes = append(tn.PrimaryRoutes, r)
		}
	}

	return &tn
}

// withoutIPv4Identity makes a viewer-specific overlay without mutating the shared peer.
func withoutIPv4Identity(base *tailcfg.Node) *tailcfg.Node {
	if !slices.ContainsFunc(base.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() }) {
		return base
	}

	tn := *base
	tn.AllowedIPs = slices.DeleteFunc(slices.Clone(base.AllowedIPs), func(p netip.Prefix) bool {
		return p.Addr().Is4() && slices.Contains(base.Addresses, p)
	})
	tn.Addresses = slices.DeleteFunc(slices.Clone(base.Addresses), func(p netip.Prefix) bool { return p.Addr().Is4() })

	return &tn
}

// taggedSelfUserID isolates a tagged node's self identity from tagged peers.
func taggedSelfUserID(id types.NodeID) tailcfg.UserID {
	return tailcfg.UserID(types.TaggedDevicesUserID) + 1 + tailcfg.UserID(id) //nolint:gosec // node IDs fit in int64
}

// render renders the node's netMap from snap.
func (r *renderer) render(snap *state.Snapshot) (*netMap, error) {
	self, ok := snap.GetNode(r.nodeID)
	if !ok {
		return nil, ErrNodeGone
	}

	pm := snap.Policy()
	capMaps := pm.NodeCapMaps()

	dns := snap.DNS()
	selfCaps := capMaps[self.ID()]

	if k := (selfKey{self: self, primaries: snap.PrimariesRev(), dns: snap.DNSRev()}); r.self == nil || k != r.selfKey || !r.selfCaps.Equal(selfCaps) {
		tn, err := self.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
			return self.AllApprovedRoutes()
		}, r.cfg, dns, selfCaps)
		if err != nil {
			return nil, err
		}

		if self.IsTagged() {
			tn.User = taggedSelfUserID(self.ID())
		}

		tn.PrimaryRoutes = slices.DeleteFunc(slices.Clone(snap.PrimaryRoutesForNode(self.ID())), func(p netip.Prefix) bool {
			return !r.cfg.ServesRoute(p)
		})
		tn.MachineAuthorized, tn.Expired = true, false
		tn.Cap, tn.Online, tn.LastSeen = 0, nil, nil
		tn.Hostinfo = types.SelfHostinfo(tn.Hostinfo)

		r.self, r.selfKey, r.selfCaps = tn, k, selfCaps
	}

	tn := r.self

	filter, err := pm.FilterForNode(self)
	if err != nil {
		return nil, err
	}

	ssh, err := pm.SSHPolicy(r.cfg.ServerURL, self)
	if err != nil {
		// Fail closed: a nil SSHPolicy would leave the client's previous
		// rules in force.
		log.Error().Caller().Err(err).EmbedObject(self).
			Msg("compiling SSH policy failed; sending empty SSH policy")

		ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}
	}

	if k := (dnsKey{self: self, policy: snap.PolicyRev(), dns: snap.DNSRev()}); r.dns == nil || k != r.dnsKey {
		r.dns, r.dnsKey = generateDNSConfig(dns, self, capMaps[self.ID()]), k
	}

	nm := &netMap{
		at:      snap.Time(),
		self:    tn,
		filter:  filter,
		ssh:     ssh,
		dns:     r.dns,
		derpMap: snap.DERPMap(),
		base:    r.last,
	}

	err = r.renderPeers(snap, self, capMaps, nm)
	if err != nil {
		return nil, err
	}

	r.renderProfiles(self, nm)
	r.last = nm

	return nm, nil
}

// renderPeers fills nm.peers: the shared peer map of the node's class (see
// [classMaps]) without the node itself and with its own routes on the
// routed peers. After the first render it records in nm.changed and
// nm.removed the peers that can differ from the base, so a diff looks at
// only them: those added to or gone from the view, those whose node
// changed, and those whose render reads something that moved without
// their node changing (their policy caps, or their routes, which come from
// the policy, the primary routes and the node's own routes).
func (r *renderer) renderPeers(
	snap *state.Snapshot,
	self types.NodeView,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
	nm *netMap,
) error {
	key := renderKey{
		policy:    snap.PeerPolicyRev(),
		primaries: snap.PrimariesRev(),
	}

	view := snap.PeerView(r.nodeID)
	class, profiles, nodes := r.classes.get(r.cfg, r.renders, snap, view, r.peerCapVer, key.policy, capMaps)
	nm.peers, nm.profiles = class, profiles

	base := nm.base

	var candidates []tailcfg.NodeID

	if base != nil {
		// The class map remembers changed renders, including view changes;
		// falling beyond its edit log compares only this class's peers.
		candidates = r.peerCandidates(snap, class, view)
		if base.peers != r.lastClass {
			// Keep this viewer's route overlays while applying class edits.
			nm.peers = base.peers
		}
	}

	candidates = append(candidates, r.routedCandidates(snap, self, key, base == nil)...)

	_, ipv4Disabled := capMaps[self.ID()][types.NodeAttrDisableIPv4]
	if (base == nil && ipv4Disabled) || (base != nil && ipv4Disabled != r.lastIPv4Disabled) {
		for id := range class.All() {
			candidates = append(candidates, id)
		}
	}

	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	peers := nm.peers.Edit()

	var (
		routed []types.NodeID
		// overlaid are the candidates this render gives an overlay; the
		// other peers keep what they had.
		overlaid []tailcfg.NodeID
	)

	for _, id := range candidates {
		tn, ok := class.Get(id)
		if !ok {
			peers.Delete(id)
			delete(r.routedPrimaries, id)

			continue
		}

		peer, _ := snap.GetNode(types.NodeID(id)) //nolint:gosec // NodeID types are the same value
		if id != r.nodeID.NodeID() && peer.ApprovedRoutes().Len() > 0 {
			routed = append(routed, peer.ID())
		} else {
			// Not a routed peer any more: its routes need no record.
			delete(r.routedPrimaries, id)

			if ipv4Disabled && id != r.nodeID.NodeID() {
				tn = withoutIPv4Identity(tn)
				if plain, _ := class.Get(id); tn != plain {
					overlaid = append(overlaid, id)
				}
			}

			if old, _ := peers.Get(id); old != tn {
				peers.Set(id, tn)
			}
		}
	}

	if len(routed) > 0 {
		// RoutesForPeer needs the unreduced matchers: every rule where
		// the node is source or destination.
		matchers, err := snap.Policy().MatchersForNode(self)
		if err != nil {
			return err
		}

		if r.routedPrimaries == nil {
			r.routedPrimaries = make(map[tailcfg.NodeID][]netip.Prefix, len(routed))
		}

		for _, id := range routed {
			base, _ := class.Get(id.NodeID())
			peer, _ := snap.GetNode(id)

			r.routedPrimaries[id.NodeID()] = snap.PrimaryRoutesForNode(id)

			tn := withRoutes(base, snap.RoutesForPeer(self, peer, matchers))
			if ipv4Disabled {
				tn = withoutIPv4Identity(tn)
			}

			if tn != base {
				overlaid = append(overlaid, id.NodeID())
			}

			if old, _ := peers.Get(id.NodeID()); old != tn {
				peers.Set(id.NodeID(), tn)
			}
		}
	}

	for _, id := range candidates {
		delete(r.overlaid, id)
	}

	if len(overlaid) > 0 && r.overlaid == nil {
		r.overlaid = make(map[tailcfg.NodeID]struct{}, len(overlaid))
	}

	for _, id := range overlaid {
		r.overlaid[id] = struct{}{}
	}

	// Only routed peers differ per viewer; a session without them
	// shares its class's map outright.
	nm.peers = peers.Done()
	if len(r.overlaid) == 0 {
		nm.peers = class
	}

	r.lastIPv4Disabled = ipv4Disabled

	nm.recordPeerChanges(base, candidates, r.nodeID.NodeID())
	r.rendered += len(nm.changed)

	// Only a render that completed moves the cursor; a failed one is
	// retried from the same place.
	r.markRendered(snap, key, self, class, nodes)

	return nil
}

// peerCandidates keeps membership churn from comparing unrelated class maps:
// their sorted views name membership edits; node and cap edits cover survivors.
func (r *renderer) peerCandidates(snap *state.Snapshot, class *peerMap, view []types.NodeID) []tailcfg.NodeID {
	old := r.lastPeerIDs
	if len(old) == len(view) && (len(view) == 0 || &old[0] == &view[0]) {
		return graph.Changes(r.lastClass, class)
	}

	touched, ok := snap.NodesTouchedSince(r.lastNodes)
	// A tiny view can cost less to compare than a coalesced global edit log.
	if !ok || len(touched) > len(old)+len(view) {
		return graph.Changes(r.lastClass, class)
	}

	var candidates []tailcfg.NodeID

	for _, id := range append(touched, snap.CapsChangedSince(r.lastCaps)...) {
		if inView(old, id) || inView(view, id) {
			candidates = append(candidates, id.NodeID())
		}
	}

	// Both views are sorted; walk their symmetric difference without map reads.
	for i, j := 0, 0; i < len(old) || j < len(view); {
		switch {
		case j == len(view) || i < len(old) && old[i] < view[j]:
			candidates = append(candidates, old[i].NodeID())
			i++
		case i == len(old) || view[j] < old[i]:
			candidates = append(candidates, view[j].NodeID())
			j++
		default:
			i++
			j++
		}
	}

	return candidates
}

func (nm *netMap) recordPeerChanges(base *netMap, candidates []tailcfg.NodeID, self tailcfg.NodeID) {
	if base == nil {
		for id := range nm.allPeers() {
			nm.changed = append(nm.changed, id)
		}

		slices.Sort(nm.changed)

		return
	}

	for _, id := range candidates {
		if id == self {
			continue
		}

		was, sent := base.peer(id)
		is, ok := nm.peer(id)

		switch {
		case ok && (!sent || was != is):
			nm.changed = append(nm.changed, id)
		case sent && !ok:
			nm.removed = append(nm.removed, id)
		}
	}
}

// routedCandidates returns the routed peers whose routes snap can render
// differently from the last render: every one after a policy or viewer
// change, those whose primaries moved after a primary move.
func (r *renderer) routedCandidates(snap *state.Snapshot, self types.NodeView, key renderKey, first bool) []tailcfg.NodeID {
	var out []tailcfg.NodeID

	via := weak.Make(snap.ViaElection())

	switch {
	case first || key.policy != r.lastKey.policy || !sameRouteFacts(r.lastSelf, self):
		// A policy or viewer change can steer any router's routes for this
		// viewer.
		r.routedPrimaries = nil

		for _, id := range snap.RoutedNodes() {
			out = append(out, id.NodeID())
		}

		return out
	case key.primaries != r.lastKey.primaries:
		// A peer's routes read the policy, the viewer, the via elections
		// and the peer's own primaries; check the latter independently
		// of the via election changes below.
		for _, id := range snap.RoutedNodes() {
			if was, ok := r.routedPrimaries[id.NodeID()]; !ok || !slices.Equal(was, snap.PrimaryRoutesForNode(id)) {
				out = append(out, id.NodeID())
			}
		}
	}

	if via != r.routedVia {
		// With the same policy and viewer, a via election changes only
		// whether the peer is its winner: revisit both losing and gaining
		// routers, independently of the global primary moves above.
		for _, id := range snap.ViaElection().ChangedNodes(r.routedWinners) {
			out = append(out, id.NodeID())
		}
	}

	return out
}

// sameRouteFacts reports whether a and b are the same viewer to the routes
// its peers are rendered with: its addresses and the routes it serves.
func sameRouteFacts(a, b types.NodeView) bool {
	return a == b || a.Valid() && b.Valid() &&
		slices.Equal(a.IPs(), b.IPs()) &&
		slices.Equal(a.AllApprovedRoutes(), b.AllApprovedRoutes())
}

func (r *renderer) markRendered(snap *state.Snapshot, key renderKey, self types.NodeView, class *peerMap, nodes state.NodesVersion) {
	r.lastClass, r.lastKey = class, key
	r.lastPeerIDs, r.lastSelf = snap.PeerView(r.nodeID), self
	r.lastNodes, r.lastCaps = nodes, snap.CapsVersion()

	via := weak.Make(snap.ViaElection())
	if via != r.routedVia {
		r.routedWinners = snap.ViaElection().WithoutPolicy()
		r.routedVia = via
	}
}

// classMaps holds the peer maps shared by the sessions of a class: nodes
// that see the same nodes are sent the same peers but for themselves and
// their own routes, so the class's view is rendered once, without routes,
// and each session edits in only what is its own. A session's map then
// costs its own edits, not a copy of every peer.
type classMaps struct {
	mu sync.Mutex
	m  map[classKey]*classEntry
	// pruned is the peer-classes revision maps were last pruned against.
	pruned uint64
}

// classEntry is one class's latest map; mu serialises its update, so
// classes update in parallel.
type classEntry struct {
	mu  sync.Mutex
	cur *classPeers
}

// classKey names a class by its view, which the snapshot shares and never
// changes.
type classKey struct {
	view *types.NodeID
	n    int
}

// classPeers is the peer map of a class's view at one snapshot, with the
// profiles of the nodes' owners.
type classPeers struct {
	rev    uint64
	nodes  state.NodesVersion
	caps   state.CapsVersion
	peers  *peerMap
	owners classOwners
}

// classOwners tracks who owns a class's nodes, so a node change edits the
// profiles without a walk over the class.
type classOwners struct {
	profiles *profileMap
	of       *graph.Map[tailcfg.NodeID, tailcfg.UserID]
	nodes    *graph.Map[tailcfg.UserID, int]
}

func newClassOwners() classOwners {
	return classOwners{
		profiles: newProfileMap(),
		of:       graph.NewMap[tailcfg.NodeID, tailcfg.UserID](func(a, b tailcfg.UserID) bool { return a == b }, nil),
		nodes:    graph.NewMap[tailcfg.UserID, int](func(a, b int) bool { return a == b }, nil),
	}
}

type classOwnersEdit struct {
	profiles *graph.MapEdit[tailcfg.UserID, tailcfg.UserProfile]
	of       *graph.MapEdit[tailcfg.NodeID, tailcfg.UserID]
	nodes    *graph.MapEdit[tailcfg.UserID, int]
}

func (o classOwners) edit() classOwnersEdit {
	return classOwnersEdit{profiles: o.profiles.Edit(), of: o.of.Edit(), nodes: o.nodes.Edit()}
}

func (e classOwnersEdit) done() classOwners {
	return classOwners{profiles: e.profiles.Done(), of: e.of.Done(), nodes: e.nodes.Done()}
}

// drop removes node id, and its owner's profile with the owner's last node.
func (e classOwnersEdit) drop(id tailcfg.NodeID) {
	uid, ok := e.of.Get(id)
	if !ok {
		return
	}

	e.of.Delete(id)

	if n, _ := e.nodes.Get(uid); n > 1 {
		e.nodes.Set(uid, n-1)
	} else {
		e.nodes.Delete(uid)
		e.profiles.Delete(uid)
	}
}

// set records node id as owned by owner.
func (e classOwnersEdit) set(id tailcfg.NodeID, owner types.UserView) {
	if !owner.Valid() {
		e.drop(id)

		return
	}

	p := owner.TailscaleUserProfile()

	if was, ok := e.of.Get(id); !ok || was != p.ID {
		e.drop(id)
		e.of.Set(id, p.ID)

		n, _ := e.nodes.Get(p.ID)
		e.nodes.Set(p.ID, n+1)
	}

	if was, ok := e.profiles.Get(p.ID); !ok || !sameProfile(was, p) {
		e.profiles.Set(p.ID, p)
	}
}

// get returns the peer map of view at snap: every node of view rendered
// for capVer without routes, but those that cannot be rendered, and the
// profiles of their owners. It updates the class's latest maps by the
// nodes and caps changed since, or rebuilds them from the view when that is
// too far back to tell.
// The node version is shared with the class, so sessions need no new cursor.
func (cm *classMaps) get(
	cfg *types.Config,
	renders *peerRenders,
	snap *state.Snapshot,
	view []types.NodeID,
	capVer tailcfg.CapabilityVersion,
	policy uint64,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
) (*peerMap, *profileMap, state.NodesVersion) {
	renders.advance(snap.Rev())

	cm.mu.Lock()
	if cm.m == nil {
		cm.m = make(map[classKey]*classEntry)
	}

	cm.prune(snap)

	if len(view) == 0 {
		cm.mu.Unlock()
		return newPeerMap(), newProfileMap(), state.NodesVersion{}
	}

	key := classKey{view: &view[0], n: len(view)}

	entry, ok := cm.m[key]
	if !ok {
		entry = &classEntry{}
		// A render overtaken by pruning keeps a vanished class local.
		if snap.PeersRev() >= cm.pruned {
			cm.m[key] = entry
		}
	}
	cm.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	cur := entry.cur
	if cur != nil && cur.rev == snap.Rev() {
		return cur.peers, cur.owners.profiles, cur.nodes
	}

	var (
		e      *graph.MapEdit[tailcfg.NodeID, *tailcfg.Node]
		owners classOwnersEdit
	)

	changed := view

	dns := snap.DNS()

	if cur != nil {
		if touched, ok := snap.NodesTouchedSince(cur.nodes); ok {
			e, owners = cur.peers.Edit(), cur.owners.edit()
			changed = slices.Concat(touched, snap.CapsChangedSince(cur.caps))
		}
	}

	var (
		peers    map[tailcfg.NodeID]*tailcfg.Node
		profiles map[tailcfg.UserID]tailcfg.UserProfile
		of       map[tailcfg.NodeID]tailcfg.UserID
		nodes    map[tailcfg.UserID]int
	)
	if e == nil {
		peers = make(map[tailcfg.NodeID]*tailcfg.Node, len(view))
		profiles = make(map[tailcfg.UserID]tailcfg.UserProfile)
		of = make(map[tailcfg.NodeID]tailcfg.UserID, len(view))
		nodes = make(map[tailcfg.UserID]int)
	}

	for _, id := range changed {
		// The view is immutable, so an ID outside it was never in this map.
		if !inView(view, id) {
			continue
		}

		peer, ok := snap.GetNode(id)
		if !ok {
			if e != nil {
				e.Delete(id.NodeID())
				owners.drop(id.NodeID())
			}

			continue
		}

		tn, err := renders.render(cfg, dns, capVer, snap.Rev(), policy, peer, capMaps)
		if err != nil {
			// One peer with invalid data must not blank out the map for
			// every node that can see it.
			log.Warn().Caller().Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Msgf("dropping peer %d from map responses: invalid node data; fix with `%s`", peer.ID(), types.StoredDataFixHint(peer.ID(), err))

			if e != nil {
				e.Delete(id.NodeID())
				owners.drop(id.NodeID())
			}

			continue
		}

		if e != nil {
			e.Set(id.NodeID(), tn)
			owners.set(id.NodeID(), peer.Owner())
		} else {
			peers[id.NodeID()] = tn

			if owner := peer.Owner(); owner.Valid() {
				p := owner.TailscaleUserProfile()
				profiles[p.ID] = p
				of[id.NodeID()] = p.ID
				nodes[p.ID]++
			}
		}
	}

	next := &classPeers{
		rev: snap.Rev(), nodes: snap.NodesVersion(), caps: snap.CapsVersion(),
	}
	if e != nil {
		next.peers, next.owners = e.Done(), owners.done()
	} else {
		next.peers = graph.NewMap(graph.Same[*tailcfg.Node], peers)
		next.owners = classOwners{
			profiles: graph.NewMap(sameProfile, profiles),
			of:       graph.NewMap(graph.Same[tailcfg.UserID], of),
			nodes:    graph.NewMap(graph.Same[int], nodes),
		}
	}

	// A session rendering an older snapshot than the class's latest keeps
	// its map to itself.
	if cur == nil || cur.rev < snap.Rev() {
		entry.cur = next
	}

	return next.peers, next.owners.profiles, next.nodes
}

// advance drops obsolete classes even when no session renders the new
// snapshot. The watcher calls it before deletion cleanup.
func (cm *classMaps) advance(snap *state.Snapshot) {
	cm.mu.Lock()
	cm.prune(snap)
	cm.mu.Unlock()
}

// prune drops the maps of views snap no longer holds. The caller holds mu.
func (cm *classMaps) prune(snap *state.Snapshot) {
	// Views vanish only when the peer classes change; prune then, so a
	// class gone for good does not pin its map until a new one appears.
	if rev := snap.PeersRev(); rev > cm.pruned {
		cm.pruned = rev
	} else {
		return
	}

	current := map[*types.NodeID]struct{}{}

	for _, v := range snap.PeerViews() {
		if len(v) > 0 {
			current[&v[0]] = struct{}{}
		}
	}

	for k := range cm.m {
		if _, ok := current[k.view]; !ok {
			delete(cm.m, k)
		}
	}
}

// renderProfiles completes nm's profiles with the node's own owner's. The
// peers' owners come shared with the class (see [classMaps]), so a session
// holds one profile of its own, not one per peer owner. Without an owner no
// profiles go out.
func (r *renderer) renderProfiles(self types.NodeView, nm *netMap) {
	owner := self.Owner()

	nm.ownerless = !owner.Valid()
	if nm.ownerless {
		nm.profiles = newProfileMap()
	} else {
		p := owner.TailscaleUserProfile()
		if self.IsTagged() {
			if _, ok := nm.profiles.Get(p.ID); !ok {
				profiles := nm.profiles.Edit()
				profiles.Set(p.ID, p)
				nm.profiles = profiles.Done()
			}

			p = tailcfg.UserProfile{
				ID:          taggedSelfUserID(self.ID()),
				LoginName:   strings.TrimSuffix(nm.self.Name, "."),
				DisplayName: self.GivenName(),
			}
		}

		nm.selfProfile = &p
	}

	base := nm.base
	nm.sameProfiles = base != nil && base.ownerless == nm.ownerless && base.profiles == nm.profiles &&
		(base.selfProfile == nil) == (nm.selfProfile == nil) &&
		(nm.selfProfile == nil || sameProfile(*base.selfProfile, *nm.selfProfile))
}

// profile returns the profile nm holds for user id.
func (nm *netMap) profile(id tailcfg.UserID) (tailcfg.UserProfile, bool) {
	if nm.selfProfile != nil && nm.selfProfile.ID == id {
		return *nm.selfProfile, true
	}

	return nm.profiles.Get(id)
}

// profileIDs returns the users nm holds a profile of, sorted.
func (nm *netMap) profileIDs() []tailcfg.UserID {
	ids := make([]tailcfg.UserID, 0, nm.profiles.Len()+1)
	for id := range nm.profiles.All() {
		ids = append(ids, id)
	}

	if nm.selfProfile != nil {
		ids = append(ids, nm.selfProfile.ID)
	}

	slices.Sort(ids)

	return slices.Compact(ids)
}

// userProfiles returns nm's profiles sorted by user.
func (nm *netMap) userProfiles() []tailcfg.UserProfile {
	ids := nm.profileIDs()
	out := make([]tailcfg.UserProfile, 0, len(ids))

	for _, id := range ids {
		p, _ := nm.profile(id)
		out = append(out, p)
	}

	return out
}

func sortedPeers(nm *netMap) []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, nm.peers.Len())
	for _, p := range nm.allPeers() {
		out = append(out, p)
	}

	slices.SortFunc(out, func(a, b *tailcfg.Node) int { return cmp.Compare(a.ID, b.ID) })

	return out
}

// sameProfile compares field by field; [tailcfg.UserProfile] holds a
// slice, and this runs for every update.
func sameProfile(a, b tailcfg.UserProfile) bool {
	return a.ID == b.ID && a.LoginName == b.LoginName && a.DisplayName == b.DisplayName &&
		a.ProfilePicURL == b.ProfilePicURL && slices.Equal(a.Groups, b.Groups)
}

// peerHostinfoEqual reports whether a and b agree on the Hostinfo fields a
// client reads from a peer: what tailscale status shows, PeerAPI services,
// SSH known hosts, exit-node location, app-connector eligibility and the
// announced routes.
func peerHostinfoEqual(a, b tailcfg.HostinfoView) bool {
	if !a.Valid() || !b.Valid() {
		return a.Valid() == b.Valid()
	}

	return a.Hostname() == b.Hostname() &&
		a.OS() == b.OS() &&
		servicesEqual(a.Services(), b.Services()) &&
		views.SliceEqual(a.SSH_HostKeys(), b.SSH_HostKeys()) &&
		locationEqual(a.Location(), b.Location()) &&
		a.AppConnector() == b.AppConnector() &&
		views.SliceEqual(a.RoutableIPs(), b.RoutableIPs())
}

// servicesEqual compares field by field, as [tailcfg.Service] is
// incomparable.
func servicesEqual(a, b views.Slice[tailcfg.Service]) bool {
	if a.Len() != b.Len() {
		return false
	}

	for i := range a.Len() {
		x, y := a.At(i), b.At(i)
		if x.Proto != y.Proto || x.Port != y.Port || x.Description != y.Description {
			return false
		}
	}

	return true
}

// locationEqual compares field by field, as [tailcfg.LocationView] has no
// Equal.
func locationEqual(a, b tailcfg.LocationView) bool {
	if !a.Valid() || !b.Valid() {
		return a.Valid() == b.Valid()
	}

	return a.Country() == b.Country() &&
		a.CountryCode() == b.CountryCode() &&
		a.City() == b.City() &&
		a.CityCode() == b.CityCode() &&
		a.Latitude() == b.Latitude() &&
		a.Longitude() == b.Longitude() &&
		a.Priority() == b.Priority()
}

// inView reports whether the sorted view holds id.
func inView(view []types.NodeID, id types.NodeID) bool {
	_, found := slices.BinarySearch(view, id)

	return found
}
