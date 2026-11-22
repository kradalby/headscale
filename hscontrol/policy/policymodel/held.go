package policymodel

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// What a client holds, judged: the netmap a client assembled against the
// one a fresh session gives ([NetmapDiff]), and against the reference
// ([HeldJudge]). Every level of the system whose nodes run clients holds
// them with these, so a fix lands at every level at once.

// JSON is v as the wire has it, for comparisons where nil and empty are
// the same, and for messages.
func JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unencodable: " + err.Error()
	}

	return string(b)
}

// ClientPeer is a peer as the client acts on it. A patch cannot clear
// LastSeen when a peer comes online, and the client acts on Online then,
// so an online peer's LastSeen is left out.
func ClientPeer(n tailcfg.NodeView) string {
	p := n.AsStruct()
	if p.Online != nil && *p.Online {
		p.LastSeen = nil
	}

	// TODO(kradalby): render/addresses-nil: a peer with no address is
	// rendered as nil or as an empty list; the client reads both alike.
	if p.Addresses == nil {
		p.Addresses = []netip.Prefix{}
	}

	if p.AllowedIPs == nil {
		p.AllowedIPs = p.Addresses
	}

	return JSON(p)
}

// SameNode reports whether a and b are the same node to the client; on
// the wire when [tailcfg.NodeView.Equal], which is stricter about nil and
// empty, cannot tell.
func SameNode(a, b tailcfg.NodeView) bool {
	// Equal leaves out two fields the wire carries.
	if a.Equal(b) && a.DataPlaneAuditLogID() == b.DataPlaneAuditLogID() && a.ExitNodeDNSResolvers().Len() == 0 && b.ExitNodeDNSResolvers().Len() == 0 {
		return true
	}

	return ClientPeer(a) == ClientPeer(b)
}

// RuleCounts is a filter as a multiset of rules.
func RuleCounts(rules []tailcfg.FilterRule) map[string]int {
	out := map[string]int{}
	for _, r := range rules {
		out[JSON(r)]++
	}

	return out
}

// CountsDiff names the rules a has more of than b, sorted.
func CountsDiff(a, b map[string]int) []string {
	var out []string

	for _, r := range slices.Sorted(maps.Keys(a)) {
		if a[r] > b[r] {
			out = append(out, fmt.Sprintf("%dx %s", a[r]-b[r], r))
		}
	}

	return out
}

// RuleList is rules as the wire has them, an empty list as none.
func RuleList(rules []tailcfg.FilterRule) string {
	if len(rules) == 0 {
		return "[]"
	}

	return JSON(rules)
}

// FilterDiff compares two filters a client holds: the same rules as a
// multiset, and when their order differs, the same verdicts and app
// capabilities, in order, through the client's own filter under view.
func FilterDiff(have, want []tailcfg.FilterRule, view func() ClientView) string {
	if slices.EqualFunc(have, want, func(a, b tailcfg.FilterRule) bool { return reflect.DeepEqual(a, b) }) {
		return ""
	}

	hc, wc := RuleCounts(have), RuleCounts(want)
	if !maps.Equal(hc, wc) {
		return fmt.Sprintf("filter: only held %v; only fresh %v", CountsDiff(hc, wc), CountsDiff(wc, hc))
	}

	if RuleList(have) == RuleList(want) {
		return ""
	}

	if rep := Compare(want, have, view()); !rep.Equivalent() {
		return "filter reordered so that it answers otherwise: " + rep.String()
	}

	return ""
}

// peerIDs is nm's peers, in the client's order (by ID).
func peerIDs(nm *netmap.NetworkMap) []tailcfg.NodeID {
	out := make([]tailcfg.NodeID, len(nm.Peers))
	for i, p := range nm.Peers {
		out[i] = p.ID()
	}

	return out
}

// NetmapDiff reports how the netmap a client assembled differs from the
// one a fresh session gives, field by field, or "". Keys the client holds
// of itself and the parsed filter (compared as rules) are not compared;
// unseen is called for each offline peer held without its LastSeen.
func NetmapDiff(have, want *netmap.NetworkMap, unseen func()) string {
	if !SameNode(have.SelfNode, want.SelfNode) {
		return fmt.Sprintf("self: have %s, want %s", JSON(have.SelfNode), JSON(want.SelfNode))
	}

	if h, w := peerIDs(have), peerIDs(want); !slices.Equal(h, w) {
		return fmt.Sprintf("peers: have %v, want %v", h, w)
	}

	for i, w := range want.Peers {
		h := have.Peers[i]
		if SameNode(h, w) {
			continue
		}

		// TODO(kradalby): render/lastseen-patchify: a peer going offline
		// in a change no patch carries (its CapMap or endpoints emptied) is
		// sent whole; Tailscale's client patchifies it and keeps no
		// LastSeen it did not hold, so its session shows the peer offline
		// without the LastSeen a fresh one does. Counted, not judged.
		if hs := h.AsStruct(); hs.LastSeen == nil && w.LastSeen().Valid() && !w.Online().GetOr(true) && !h.Online().GetOr(true) {
			hs.LastSeen = new(w.LastSeen().Get())
			if SameNode(hs.View(), w) {
				unseen()

				continue
			}
		}

		return fmt.Sprintf("peer %d: have %s, want %s", w.ID(), ClientPeer(h), ClientPeer(w))
	}

	if d := FilterDiff(have.PacketFilterRules.AsSlice(), want.PacketFilterRules.AsSlice(), func() ClientView {
		return ViewFromNetmap(want)
	}); d != "" {
		return d
	}

	for _, f := range []struct {
		name       string
		have, want any
	}{
		{"ssh", have.SSHPolicy, want.SSHPolicy},
		{"dns", have.DNS, want.DNS},
		{"derp", have.DERPMap, want.DERPMap},
		{"domain", have.Domain, want.Domain},
		{"collect-services", have.CollectServices, want.CollectServices},
		{"profiles", have.UserProfiles, want.UserProfiles},
		{"display-messages", have.DisplayMessages, want.DisplayMessages},
		{"tka", []any{have.TKAEnabled, have.TKAHead}, []any{want.TKAEnabled, want.TKAHead}},
		{"caps", have.AllCaps, want.AllCaps},
	} {
		if reflect.DeepEqual(f.have, f.want) {
			continue
		}

		if h, w := JSON(f.have), JSON(f.want); h != w {
			return fmt.Sprintf("%s: have %s, want %s", f.name, h, w)
		}
	}

	return ""
}

// ModelView is what node n's client knows when it filters, by the model:
// local nets from what it announces and runs as, every node's addresses
// as sources worth probing, its own addresses less hidden, and
// capabilities from caps for a client that looks them up. A client not
// known to match capability sources (one reporting no versions,
// tailscale-rs) matches none: it parses a cap: source and finds nobody
// holding it.
func ModelView(n Node, w World, caps *NetmapCaps, hidden []netip.Addr) ClientView {
	addrs := slices.DeleteFunc(n.Addrs(), func(a netip.Addr) bool { return slices.Contains(hidden, a) })
	own := make([]netip.Prefix, 0, len(addrs))
	announced := make([]netip.Prefix, 0, len(n.Announced))

	for _, a := range addrs {
		own = append(own, netip.PrefixFrom(a, a.BitLen()))
	}

	for _, r := range n.Announced {
		announced = append(announced, Prefixes[r])
	}

	v := ClientView{Self: addrs, LocalNets: LocalNets(own, announced, n.Client == AppConnector, nil), Hidden: hidden}

	for _, m := range w.Topology.Nodes {
		v.Known = append(v.Known, m.Addrs()...)
	}

	if caps != nil && (n.Client == Official || n.Client == AppConnector) {
		v.HasCap = caps.HasCap
	}

	return v
}

// NetmapView is [ModelView] for a client holding nm: capabilities from
// nm, and hidden the addresses disable-ipv4 keeps from it, its own among
// them; whether rightly, the shown addresses' check says.
func NetmapView(n Node, w World, nm *netmap.NetworkMap) ClientView {
	caps := NewNetmapCaps(nm.SelfNode, nm.Peers)

	return ModelView(n, w, &caps, NotShown(w, slices.Concat(nm.Peers, []tailcfg.NodeView{nm.SelfNode})))
}

// netmapViewKey is what [NetmapView] reads of nm.
func netmapViewKey(nm *netmap.NetworkMap) string {
	type node struct {
		Addresses []netip.Prefix
		CapMap    tailcfg.NodeCapMap
		Unsigned  bool
	}

	nodes := make([]node, 0, len(nm.Peers)+1)
	for _, n := range append([]tailcfg.NodeView{nm.SelfNode}, nm.Peers...) {
		if n.Valid() {
			nodes = append(nodes, node{n.Addresses().AsSlice(), n.AsStruct().CapMap, n.UnsignedPeerAPIOnly()})
		}
	}

	return JSON(nodes)
}

// HeldJudge holds what clients hold to the reference, read for the model
// world their level was driven to, and counts what it held across a run.
// The zero value is ready.
type HeldJudge struct {
	Verdicts Verdicts
	Form     FormJudge

	// Clients counts the clients held, Filters the filters compared (one
	// compared before against all it reads is not again), PeerSets and
	// RoutePairs the peer lists and the viewer-peer pairs with routes on
	// either side, Primaries the routes a client's own primaries were
	// held on.
	Clients, Filters, PeerSets, RoutePairs, Primaries int
	SSHDecisions                                      int
	// Steered counts the route pairs via steering decides, Unjudged the
	// routes left unjudged, ByHistory those only the election history
	// decides.
	Steered, Unjudged, ByHistory int
	// Addressless counts the peers whose via-steered routes a viewer
	// holding no address is given fewer of than the reference gives.
	Addressless int
	// ContestedPeers and ContestedRoutes count what a named clause
	// forgave, Skipped the moments out of the reference's domain, by why.
	ContestedPeers, ContestedRoutes map[Contested]int
	Skipped                         map[string]int

	// passed holds the filters held already, by everything the
	// comparison reads.
	passed map[string]bool
}

func (j *HeldJudge) String() string {
	return fmt.Sprintf("reference: clients %d, filters compared %d, peer sets %d, route pairs %d (steered %d, routes left unjudged %d, "+
		"decided by the election history %d, steered short to a viewer without addresses %d), self primaries %d, SSH decisions %d; skipped %v; "+
		"peers contested %v, routes contested %v; filters: %v; form: %v",
		j.Clients, j.Filters, j.PeerSets, j.RoutePairs, j.Steered, j.Unjudged, j.ByHistory, j.Addressless, j.Primaries, j.SSHDecisions, j.Skipped,
		ContestedCounts(j.ContestedPeers), ContestedCounts(j.ContestedRoutes), &j.Verdicts, &j.Form)
}

// Moment is the world a level of the system was driven to, as the
// reference reads it: the model, in the IDs and addresses the level
// holds, and the election history it was driven through.
type Moment struct {
	World     World
	Elections *Elections
	// Shared is set once two nodes of the case shared an address
	// (database only): node attributes may be stale (TODO(kradalby):
	// policy/stale-under-shared-address), so the addresses a client is
	// shown go unjudged and the form allows for it.
	Shared bool
	// Unheld are subnet routes whose last holder is history the election
	// history missed: unjudged.
	Unheld map[netip.Prefix]bool
}

// Held is one moment's reference, for every client a level holds then.
type Held struct {
	j          *HeldJudge
	m          Moment
	ref, plain *Ref
	// world and known key what a filter comparison reads of the world:
	// the whole of it where a contested clause decided, else every node's
	// addresses.
	world, known string
	sshKnown     map[netip.Addr]bool
}

// At is the reference for m, or nil, counted, when m is out of its
// domain.
func (j *HeldJudge) At(m Moment) *Held {
	plain := RefOf(m.World)
	ref := plain.WithElections(m.Elections)

	if why := ref.OutOfDomain(); why != "" {
		if j.Skipped == nil {
			j.Skipped = map[string]int{}
		}

		j.Skipped[why]++

		return nil
	}

	if j.passed == nil {
		j.passed = map[string]bool{}
		j.ContestedPeers, j.ContestedRoutes = map[Contested]int{}, map[Contested]int{}
	}

	var known []netip.Addr
	for _, n := range m.World.Topology.Nodes {
		known = append(known, n.Addrs()...)
	}

	return &Held{j: j, m: m, ref: ref, plain: plain, world: JSON(m.World.Topology) + string(m.World.Policy.HuJSON()), known: fmt.Sprint(known)}
}

// Client holds what node id's client holds, nm, to the reference, or says
// how it differs: its peers and the addresses it is shown of them; what
// each peer carries in its AllowedIPs once routers are elected
// ([Ref.ServedRoutes]), and the routes the node is primary for; its
// packet filter, through its own client ([Verdicts], with the allowances
// and contested clauses of the reference properties) and in the form
// capSources says; and the stamps it and its peers carry, none in address
// mode. It also checks bounded SSH login decisions against the policy inputs.
func (h *Held) Client(id types.NodeID, nm *netmap.NetworkMap, capSources bool) string {
	h.j.Clients++

	for _, judge := range []func(types.NodeID, *netmap.NetworkMap, bool) string{h.peers, h.routes, h.filter, h.stamps, h.ssh} {
		if d := judge(id, nm, capSources); d != "" {
			return d
		}
	}

	return ""
}

// peers holds the client's peers and the addresses it is shown of them,
// and the routes the node is primary for to the election.
func (h *Held) peers(id types.NodeID, nm *netmap.NetworkMap, _ bool) string {
	got := make([]types.NodeID, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		got = append(got, types.NodeID(p.ID())) //nolint:gosec // small
	}

	for _, nv := range append([]tailcfg.NodeView{nm.SelfNode}, nm.Peers...) {
		var addrs []netip.Addr

		for _, p := range nv.Addresses().All() {
			addrs = append(addrs, p.Addr())
		}

		if want := ShownAddrs(h.m.World, id, types.NodeID(nv.ID())); !h.m.Shared && !slices.Equal(addrs, want) { //nolint:gosec // small
			return fmt.Sprintf("its client is shown n%d at %v, the model at %v", nv.ID(), addrs, want)
		}
	}

	h.j.PeerSets++

	if want := h.ref.Peers(id); !slices.Equal(got, want) {
		k, ok := ContestedPeers(h.ref, id, got)
		if !ok {
			return fmt.Sprintf("its client is shown %v, the reference shows it %v", got, want)
		}

		h.j.ContestedPeers[k]++
	}

	self, ok := h.ref.Node(id)
	if !ok {
		return ""
	}

	for _, q := range self.ServedRoutes() {
		primary, decided := h.ref.Primary(q)
		if q.Bits() == 0 || !decided || h.m.Unheld[q] {
			continue
		}

		h.j.Primaries++

		if want, has := primary == id && !NamesNode(q), slices.Contains(nm.SelfNode.PrimaryRoutes().AsSlice(), q); want != has {
			return fmt.Sprintf("its client is primary for %s: %t, the election gives it to n%d", q, has, primary)
		}
	}

	return ""
}

// routes holds what each peer carries in the client's AllowedIPs beyond
// its addresses to [Ref.ServedRoutes].
func (h *Held) routes(id types.NodeID, nm *netmap.NetworkMap, _ bool) string {
	viewer, _ := h.m.World.Topology.Node(id)

	for _, p := range nm.Peers {
		pid := types.NodeID(p.ID()) //nolint:gosec // small
		routes := slices.DeleteFunc(p.AllowedIPs().AsSlice(), func(q netip.Prefix) bool { return slices.Contains(p.Addresses().AsSlice(), q) })
		slices.SortFunc(routes, netip.Prefix.Compare)

		want, unjudged := h.ref.ServedRoutes(id, pid)
		if _, without := h.plain.ServedRoutes(id, pid); len(without) > len(unjudged) {
			h.j.ByHistory += len(without) - len(unjudged)
		}

		want = slices.DeleteFunc(want, func(q netip.Prefix) bool { return h.m.Unheld[q] })

		unjudged = append(unjudged, slices.SortedFunc(maps.Keys(h.m.Unheld), netip.Prefix.Compare)...)

		judged := Judged(routes, unjudged)
		h.j.Unjudged += len(unjudged)

		if h.ref.Steered(id, pid) && len(judged)+len(want) > 0 {
			h.j.Steered++
		}

		if len(routes)+len(want) > 0 {
			h.j.RoutePairs++
		}

		if slices.Equal(judged, want) {
			continue
		}

		k, ok := ContestedServedRoutes(h.ref, id, pid, routes)

		switch {
		case ok:
			h.j.ContestedRoutes[k]++
		case h.ref.Steered(id, pid) && len(viewer.Addrs()) == 0 && !slices.ContainsFunc(judged, func(q netip.Prefix) bool { return !slices.Contains(want, q) }):
			// TODO(kradalby): policy/via-addressless-viewer: a viewer
			// holding no address (database only) is on a via grant's
			// sources by the routes it serves under *, so the reference
			// steers it the routers' routes; headscale steers it none.
			// It can send nothing either way. Counted, not judged.
			h.j.Addressless++
		default:
			return fmt.Sprintf("its client is given %v of n%d's routes, the reference %v (%v unjudged)", routes, pid, want, unjudged)
		}
	}

	return ""
}

// filter holds the client's packet filter to the reference's rules
// through its own filter. A comparison that holds without a contested
// clause reads only the reference's rules for the node and what it
// serves, the view and the filter; one that needs a clause reads the
// whole world.
func (h *Held) filter(id types.NodeID, nm *netmap.NetworkMap, capSources bool) string {
	n, _ := h.m.World.Topology.Node(id)
	rules := nm.PacketFilterRules.AsSlice()

	if msg := h.j.Form.Check(h.m.World, h.ref, id, rules, capSources, h.m.Shared); msg != "" {
		return fmt.Sprintf("its client's filter is in the wrong form: %s\nheadscale %v", msg, rules)
	}

	k := fmt.Sprint(n, capSources, h.ref.Served(id).Prefixes()) + RuleList(h.ref.Rules(id)) + h.known + RuleList(rules) + netmapViewKey(nm)
	if h.j.passed[k] || h.j.passed[h.world+k] {
		return ""
	}

	h.j.Filters++

	contested := 0
	for _, c := range h.j.Verdicts.Contested {
		contested += c
	}

	rep := h.j.Verdicts.CompareAt(h.ref, id, rules, NetmapView(n, h.m.World, nm), capSources)
	if !rep.Equivalent() {
		return fmt.Sprintf("its client's filter differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v", rep, h.ref.Rules(id), rules)
	}

	for _, c := range h.j.Verdicts.Contested {
		contested -= c
	}

	if contested == 0 {
		h.j.passed[k] = true
	} else {
		h.j.passed[h.world+k] = true
	}

	return ""
}

// stamps holds the stamps the client holds of itself and its peers to the
// reference's, none in address mode.
func (h *Held) stamps(_ types.NodeID, nm *netmap.NetworkMap, capSources bool) string {
	for _, nv := range append([]tailcfg.NodeView{nm.SelfNode}, nm.Peers...) {
		of := types.NodeID(nv.ID()) //nolint:gosec // small

		var has, want []string

		for k := range nv.CapMap().All() {
			if strings.Contains(string(k), strings.TrimPrefix(StampPrefix, "https://")) {
				has = append(has, string(k))
			}
		}

		slices.Sort(has)

		for _, s := range h.ref.Stamps(of) {
			if capSources {
				want = append(want, StampPrefix+s)
			}
		}

		if !slices.Equal(has, want) {
			return fmt.Sprintf("its client holds n%d with stamps %v, the reference stamps it %v", of, has, want)
		}
	}

	return ""
}

type sshAction uint8

const (
	sshDeny sshAction = iota
	sshAccept
	sshCheck
)

func (a sshAction) String() string { return [...]string{"deny", "accept", "check"}[a] }

// ssh compares decisions, including those for sources that SSH alone doesn't make peers.
func (h *Held) ssh(id types.NodeID, nm *netmap.NetworkMap, _ bool) string {
	// See TODO(kradalby): policy/stale-under-shared-address in the delivery judge.
	if h.m.Shared {
		return ""
	}

	w := h.m.World

	dst, ok := w.Topology.Node(id)
	if !ok {
		return ""
	}

	var rules []*tailcfg.SSHRule
	if nm.SSHPolicy != nil {
		rules = nm.SSHPolicy.Rules
	}

	if len(w.Policy.SSH) == 0 && len(rules) == 0 {
		return ""
	}

	now := time.Now()

	for _, source := range h.sshSources(rules) {
		src, addr := source.node, source.addr
		user, _ := w.Topology.User(src.User)

		userLogin := cmp.Or(user.Email, user.Name, user.Provider)
		if src.Tagged() {
			userLogin = types.TaggedDevices.Name
		}

		for _, login := range []string{"root", "alice", "headscale-ssh-probe"} {
			want, possible := h.sshIntent(src, dst, login)
			if want != possible {
				continue
			}

			h.j.SSHDecisions++

			got, local := sshWireDecision(rules, now, src.ID, addr, userLogin, login)
			if got != want || (got != sshDeny && local != login) {
				return fmt.Sprintf("SSH decision from %s for %q: got %s as %q, want %s", addr, login, got, local, want)
			}
		}
	}

	return ""
}

type sshSource struct {
	node Node
	addr netip.Addr
}

// sshSources samples large worlds across IDs and reserves probes for stale principals.
func (h *Held) sshSources(rules []*tailcfg.SSHRule) []sshSource {
	const maxSources = 8

	nodes := h.m.World.Topology.Nodes
	if h.sshKnown == nil {
		h.sshKnown = make(map[netip.Addr]bool, len(nodes))

		for _, src := range nodes {
			for _, addr := range src.Addrs() {
				h.sshKnown[addr] = true
			}
		}
	}

	var sources []sshSource

	count := min(len(nodes), maxSources)
	for i := range count {
		src := nodes[i*(len(nodes)-1)/max(1, count-1)]
		for _, addr := range src.Addrs() {
			sources = append(sources, sshSource{src, addr})
		}
	}

	stale := make(map[netip.Addr]bool)

	for _, rule := range rules {
		if rule == nil {
			continue
		}

		for _, p := range rule.Principals {
			if p == nil {
				continue
			}

			addr, err := netip.ParseAddr(p.NodeIP)
			if err != nil || h.sshKnown[addr] || stale[addr] {
				continue
			}

			sources = append(sources, sshSource{addr: addr})
			stale[addr] = true

			if len(stale) == maxSources {
				return sources
			}
		}
	}

	return sources
}

// sshIntent bounds the decision when an unsupported selector or login might
// overlap this probe. A possible check can shadow an explicit accept.
func (h *Held) sshIntent(src, dst Node, login string) (sshAction, sshAction) {
	if src.ID == 0 {
		return sshDeny, sshDeny
	}

	var certain, possible sshAction

	for _, r := range h.m.World.Policy.SSH {
		srcMatch, srcPossible := h.sshSelectors(r.Src, src, Node{})
		if !srcPossible {
			continue
		}

		dstMatch, dstPossible := h.sshSelectors(r.Dst, dst, src)

		action := sshAccept
		if r.Check {
			action = sshCheck
		}

		var explicit, nonroot, localpart bool

		for _, u := range r.Users {
			switch name := SSHUsers[u]; {
			case name == login:
				explicit = true
			case name == "autogroup:nonroot":
				nonroot = login != "root"
			case strings.HasPrefix(name, "localpart:"):
				localpart = true
			}
		}

		if srcMatch && dstMatch && explicit {
			certain = max(certain, action)
		}

		// Localpart rules can also grant self access outside their destinations.
		if (dstPossible && (explicit || nonroot || localpart)) ||
			(localpart && (sshSameOwner(src, dst) || src.ID == dst.ID)) {
			possible = max(possible, action)
		}
	}

	return certain, possible
}

func sshSameOwner(a, b Node) bool {
	return a.User != 0 && a.User == b.User && !a.Tagged() && !b.Tagged()
}

func (h *Held) sshSelectors(sels []Sel, n, src Node) (bool, bool) {
	hasAddress := n.V4.IsValid() || n.V6.IsValid()

	var certain, possible bool

	for _, sel := range sels {
		switch sel.Kind {
		case SelSelf:
			certain = certain || sshSameOwner(src, n)
		case SelUser:
			certain = certain || (hasAddress && !n.Tagged() && slices.Contains(h.plain.usersOf(sel.String()), n.User))
		case SelTag:
			certain = certain || (hasAddress && slices.Contains(n.Tags, sel.I))
		case SelGroup, SelMember:
			possible = possible || (hasAddress && !n.Tagged())
		case SelTagged:
			possible = possible || (hasAddress && n.Tagged())
		case SelAll, SelHost, SelPrefix, SelInternet, SelDangerAll:
			possible = possible || hasAddress
		}
	}

	return certain, certain || possible
}

// sshWireDecision reads first-match wire rules for a probe with a local
// account. The model supplies the SSH source identity even without a peer.
func sshWireDecision(rules []*tailcfg.SSHRule, now time.Time, src types.NodeID, addr netip.Addr, userLogin, login string) (sshAction, string) {
	for _, r := range rules {
		if r == nil || r.Action == nil || (r.RuleExpires != nil && !now.Before(*r.RuleExpires)) {
			continue
		}

		if !slices.ContainsFunc(r.Principals, func(p *tailcfg.SSHPrincipal) bool {
			return p != nil && (p.Any || p.NodeIP == addr.String() ||
				(!p.Node.IsZero() && src != 0 && p.Node == src.StableID()) ||
				(p.UserLogin != "" && p.UserLogin == userLogin))
		}) {
			continue
		}

		if r.Action.Reject {
			break
		}

		local, ok := r.SSHUsers[login]
		if !ok {
			local = r.SSHUsers["*"]
		}

		if local == "=" && login != "root" {
			local = login
		}

		if local == "" || local == "=" {
			continue
		}

		switch {
		case r.Action.Accept:
			return sshAccept, local
		case r.Action.HoldAndDelegate != "":
			return sshCheck, local
		default:
			return sshDeny, ""
		}
	}

	return sshDeny, ""
}
