package mapper

import (
	"cmp"
	"errors"
	"maps"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// ErrNodeGone is returned when the node a map is rendered for is no
// longer in the world.
var ErrNodeGone = errors.New("node no longer exists")

// netMap is everything a node is told about its tailnet, rendered from one
// [state.Snapshot]. A client holds exactly the last netMap it was sent;
// what to send next is the difference to a fresh one, see [diff].
type netMap struct {
	self     *tailcfg.Node
	peers    map[tailcfg.NodeID]*tailcfg.Node
	profiles map[tailcfg.UserID]tailcfg.UserProfile
	filter   []tailcfg.FilterRule
	ssh      *tailcfg.SSHPolicy
	dns      *tailcfg.DNSConfig
	derpMap  *tailcfg.DERPMap
}

// renderer renders one node's netMap. It keeps every peer it rendered and
// renders a peer again only when the peer or what its rendering reads
// (policy, policy-relevant node facts, primary routes) changed; other
// writes, the common endpoint and online updates, cost one peer each.
type renderer struct {
	cfg    *types.Config
	nodeID types.NodeID
	capVer tailcfg.CapabilityVersion

	peers map[types.NodeID]renderedPeer
}

type renderedPeer struct {
	node types.NodeView // the stored node; stored nodes are immutable
	key  renderKey
	tn   *tailcfg.Node
}

// renderKey is what a peer's rendering reads besides the peer itself.
type renderKey struct {
	policy, policyNodes, primaries uint64
}

func newRenderer(cfg *types.Config, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *renderer {
	return &renderer{
		cfg:    cfg,
		nodeID: nodeID,
		capVer: capVer,
		peers:  make(map[types.NodeID]renderedPeer),
	}
}

// render renders the node's netMap from snap.
func (r *renderer) render(snap *state.Snapshot) (*netMap, error) {
	self, ok := snap.GetNode(r.nodeID)
	if !ok {
		return nil, ErrNodeGone
	}

	pm := snap.Policy()
	capMaps := pm.NodeCapMaps()

	tn, err := self.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
		return snap.SelfRoutes(self)
	}, r.cfg, capMaps[self.ID()])
	if err != nil {
		return nil, err
	}

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

	peers := snap.ListPeers(r.nodeID)

	nm := &netMap{
		self:     tn,
		peers:    make(map[tailcfg.NodeID]*tailcfg.Node, peers.Len()),
		profiles: make(map[tailcfg.UserID]tailcfg.UserProfile),
		filter:   filter,
		ssh:      ssh,
		dns:      generateDNSConfig(r.cfg, self, capMaps[self.ID()]),
		derpMap:  snap.DERPMap(),
	}

	for _, p := range generateUserProfiles(self, peers) {
		nm.profiles[p.ID] = p
	}

	key := renderKey{
		policy:      snap.PolicyRev(),
		policyNodes: snap.PolicyNodesRev(),
		primaries:   snap.PrimariesRev(),
	}

	var (
		matchers       []matcher.Match
		matchersLoaded bool
	)

	seen := make(map[types.NodeID]bool, peers.Len())

	for _, peer := range peers.All() {
		seen[peer.ID()] = true

		if cached, ok := r.peers[peer.ID()]; ok && cached.node == peer && cached.key == key {
			nm.peers[cached.tn.ID] = cached.tn
			continue
		}

		// RoutesForPeer needs the unreduced matchers: every rule where
		// the node is source or destination.
		if !matchersLoaded {
			matchers, err = pm.MatchersForNode(self)
			if err != nil {
				return nil, err
			}

			matchersLoaded = true
		}

		ptn, err := peer.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
			return snap.RoutesForPeer(self, peer, matchers)
		}, r.cfg, capMaps[peer.ID()])
		if err != nil {
			// One peer with invalid data must not blank out the map for
			// every node that can see it.
			log.Warn().Caller().Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Uint64("map.viewer.node.id", r.nodeID.Uint64()).
				Msgf("dropping peer %d from map response: invalid node data; fix with `headscale nodes rename %d <name>`", peer.ID(), peer.ID())
			delete(r.peers, peer.ID())

			continue
		}

		// A peer's CapMap carries only the caps clients read from the
		// peer view; see [policyv2.PeerCapMap].
		ptn.CapMap = policyv2.PeerCapMap(peer, capMaps[peer.ID()])

		// Clients never read a peer's NetInfo, and its home DERP reaches
		// them as HomeDERP; leaving it in would turn every DERP move into
		// a whole-peer update.
		if ptn.Hostinfo.Valid() && ptn.Hostinfo.NetInfo().Valid() {
			hi := ptn.Hostinfo.AsStruct()
			hi.NetInfo = nil
			ptn.Hostinfo = hi.View()
		}

		r.peers[peer.ID()] = renderedPeer{node: peer, key: key, tn: ptn}
		nm.peers[ptn.ID] = ptn
	}

	for id := range r.peers {
		if !seen[id] {
			delete(r.peers, id)
		}
	}

	return nm, nil
}

func sortedPeers(peers map[tailcfg.NodeID]*tailcfg.Node) []*tailcfg.Node {
	out := slices.Collect(maps.Values(peers))
	slices.SortFunc(out, func(a, b *tailcfg.Node) int { return cmp.Compare(a.ID, b.ID) })

	return out
}

func sortedProfiles(profiles map[tailcfg.UserID]tailcfg.UserProfile) []tailcfg.UserProfile {
	out := slices.Collect(maps.Values(profiles))
	slices.SortFunc(out, func(a, b tailcfg.UserProfile) int { return cmp.Compare(a.ID, b.ID) })

	return out
}
