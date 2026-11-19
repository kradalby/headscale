package mapper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/mem"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

// wakeFields are the parts of a [state.Change] Route reads, each with how
// to take it out.
var wakeFields = []struct {
	name string
	drop func(*state.Change)
}{
	{"Nodes", func(c *state.Change) { c.Nodes = nil }},
	{"Primaries", func(c *state.Change) { c.Primaries = nil }},
	{"PeerSets", func(c *state.Change) { c.PeerSets = nil }},
	{"Filters", func(c *state.Change) { c.Filters = nil }},
	{"Caps", func(c *state.Change) { c.Caps = nil }},
	{"RouteViewers", func(c *state.Change) { c.RouteViewers = nil }},
	{"Routers", func(c *state.Change) { c.Routers = nil }},
	{"AllRouters", func(c *state.Change) { c.AllRouters = false }},
}

// wakeTally counts, for the stale pairs a routing property judges (a
// session holding x's render, a commit c whose fresh render would send it
// something), what made Route wake it: everyone, or which one field of
// the change alone, the rest naming nobody for it. A field that is never
// alone is one a routing could drop and no stale pair would show.
type wakeTally struct {
	stale, global int
	// globalDocuments counts everyone woken across a policy write.
	globalDocuments int
	// selective counts stale pairs Route answered without waking
	// everyone, coalesced those across more than one commit, and
	// documents those across a policy write.
	selective, coalesced, documents int
	// sole counts by field, and soleCoalesced and soleDocuments as above.
	sole, soleCoalesced, soleDocuments map[string]int
	// shared counts selective pairs two fields or more woke.
	shared int
	// by counts, per field, the commits that made it alone, by kind.
	by map[string]map[string]int
}

func newWakeTally() *wakeTally {
	return &wakeTally{sole: map[string]int{}, soleCoalesced: map[string]int{}, soleDocuments: map[string]int{}, by: map[string]map[string]int{}}
}

// droppedWakes holds, per pair of one State's snapshots, the sessions
// Route wakes with each of [wakeFields] taken out, in order: they are the
// pair's, whichever session asks.
type droppedWakes map[[2]uint64][]map[types.NodeID]struct{}

func (d droppedWakes) of(x, cur *state.Snapshot, c state.Change) []map[types.NodeID]struct{} {
	k := [2]uint64{x.Rev(), cur.Rev()}
	if w, ok := d[k]; ok {
		return w
	}

	out := make([]map[types.NodeID]struct{}, len(wakeFields))

	for i, f := range wakeFields {
		dropped := c
		f.drop(&dropped)
		_, out[i] = Route(x, cur, dropped)
	}

	d[k] = out

	return out
}

// soleWake returns the field of c without which Route(x, cur, c) would not
// wake id, or "" when another field wakes it too.
func soleWake(d droppedWakes, x, cur *state.Snapshot, c state.Change, id types.NodeID) string {
	for i, wake := range d.of(x, cur, c) {
		if !hasWake(wake, id) {
			return wakeFields[i].name
		}
	}

	return ""
}

func hasWake(wake map[types.NodeID]struct{}, id types.NodeID) bool {
	_, ok := wake[id]

	return ok
}

// add counts one stale pair Route woke id for: all, or c's fields; between
// when x is before c's neighbour, document when a policy write lies
// between them; kind names what made cur. d is the State's.
func (w *wakeTally) add(d droppedWakes, x, cur *state.Snapshot, all bool, c state.Change, id types.NodeID, between, document bool, kind string) {
	w.stale++

	if all {
		w.global++

		if document {
			w.globalDocuments++
		}

		return
	}

	w.selective++

	if between {
		w.coalesced++
	}

	if document {
		w.documents++
	}

	f := soleWake(d, x, cur, c, id)
	if f == "" {
		w.shared++

		return
	}

	w.sole[f]++

	if w.by[f] == nil {
		w.by[f] = map[string]int{}
	}

	w.by[f][kind]++

	if between {
		w.soleCoalesced[f]++
	}

	if document {
		w.soleDocuments[f]++
	}
}

func (w *wakeTally) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "stale pairs %d: everyone woken %d (across a policy write %d), selectively %d (coalesced %d, across a policy write %d), by two fields or more %d; alone:",
		w.stale, w.global, w.globalDocuments, w.selective, w.coalesced, w.documents, w.shared)

	for _, f := range wakeFields {
		fmt.Fprintf(&sb, " %s %d (coalesced %d, policy %d)", f.name, w.sole[f.name], w.soleCoalesced[f.name], w.soleDocuments[f.name])
	}

	for _, f := range wakeFields {
		if len(w.by[f.name]) > 0 {
			fmt.Fprintf(&sb, "; %s alone after %v", f.name, w.by[f.name])
		}
	}

	return sb.String()
}

// putNode writes n, built as tn, as production would come to hold it:
// what the model does not hold (keys, endpoints, names, DERP, sessions,
// health) stays as the State holds it, and a node connects and
// disconnects through [state.State.Connect] and [state.State.Disconnect],
// after any other write: a registration writes the node offline, its
// first session connects it. Connection state alone moving writes nothing
// else.
func (p *pbtWorld) putNode(was policymodel.Node, existed bool, n policymodel.Node, tn *types.Node) {
	if cur, ok := p.s.Snapshot().GetNode(n.ID); ok {
		c := cur.AsStruct()
		tn.NodeKey, tn.DiscoKey, tn.Endpoints = c.NodeKey, c.DiscoKey, c.Endpoints
		tn.Hostname, tn.GivenName = c.Hostname, c.GivenName

		if c.Hostinfo != nil {
			tn.Hostinfo.Hostname, tn.Hostinfo.NetInfo = c.Hostinfo.Hostname, c.Hostinfo.NetInfo
		}

		tn.SessionStart, tn.ActiveSessions, tn.SessionEpoch, tn.LastSeen = c.SessionStart, c.ActiveSessions, c.SessionEpoch, c.LastSeen
		tn.Unhealthy = c.Unhealthy
	}

	// The State's gates: an expired key is not online, and the prober's
	// mark holds only on an online node serving routes.
	tn.IsOnline = new(tn.ShouldBeOnline())
	tn.Unhealthy = tn.Unhealthy && tn.Online() && len(tn.AllApprovedRoutes()) > 0

	body := was
	body.Offline = n.Offline

	if !existed || !reflect.DeepEqual(body, n) {
		p.call(func() { p.s.PutNodeInStoreForTest(*tn) })
	}

	switch {
	case !n.Offline && len(p.conns[n.ID]) == 0:
		p.connect(n.ID)
	case n.Offline:
		for len(p.conns[n.ID]) > 0 {
			p.disconnect(n.ID)
		}
	}
}

// connect opens a connection of id, as a map session's start does; one
// with none open begins a run.
func (p *pbtWorld) connect(id types.NodeID) {
	p.t.Helper()

	run := len(p.conns[id]) == 0
	if run {
		p.runs++
		p.elections.Started[id] = p.runs

		// A run starts when the State's clock says: one starting at the
		// instant the last did would tie, which the election breaks by ID,
		// not by the order the runs began in. The clock only waits here.
		for !time.Now().After(p.started) {
			runtime.Gosched()
		}
	}

	p.call(func() {
		epoch := p.s.Connect(id)
		if epoch == 0 {
			p.t.Fatalf("n%d does not connect", id)
		}

		p.conns[id] = append(p.conns[id], epoch)
	})

	if n, ok := p.s.Snapshot().GetNode(id); ok && run {
		p.started = n.SessionStart()
	}
}

// disconnect closes id's oldest connection, as a map session's end does.
func (p *pbtWorld) disconnect(id types.NodeID) {
	p.t.Helper()

	epoch := p.conns[id][0]
	p.conns[id] = p.conns[id][1:]

	p.call(func() {
		err := p.s.Disconnect(id, epoch)
		if err != nil {
			p.t.Fatalf("n%d disconnects: %v", id, err)
		}
	})
}

// elect advances the election history to the latest commit, reading of
// each node what the election reads: its routes, whether it is online and
// unexpired, and the prober's mark.
func (p *pbtWorld) elect() {
	var (
		nodes     []policymodel.RefNode
		unhealthy = map[types.NodeID]bool{}
	)

	for _, nv := range p.s.Snapshot().ListNodes().All() {
		n := nv.AsStruct()
		nodes = append(nodes, policymodel.RefNode{
			ID: n.ID, Tags: n.Tags, Announced: n.AnnouncedRoutes(), Approved: n.ApprovedRoutes,
			Unavailable: !n.Online() || n.IsExpired(),
		})

		if n.Unhealthy {
			unhealthy[n.ID] = true
		}
	}

	p.elections.Commit(nodes, unhealthy)
}

// sessionKind is a write a node's client, the HA prober or an operator
// makes through its production entry point, beside the model's edits.
type sessionKind int

const (
	// writeReconnect: a connection ends and a new one opens, a new run.
	writeReconnect sessionKind = iota
	// writeOverlap: a new connection opens before the old one ends, the
	// same run.
	writeOverlap
	// writeHomeDERP: a map request setting the node's home DERP, or
	// clearing it.
	writeHomeDERP
	// writeHostname: a map request reporting another hostname.
	writeHostname
	// writeDiscoKey: a map request with a new disco key.
	writeDiscoKey
	// writeGivenName: an operator renaming the node.
	writeGivenName
	// writeExpiry: an operator expiring the node's key, or renewing it.
	writeExpiry
	// writeHealth: the HA prober failing a router, or passing it again.
	writeHealth
	// writeExtraRecords: the extra DNS records changing.
	writeExtraRecords
	// writeDERPMap: the DERP map changing.
	writeDERPMap
	numSessionKinds
)

var sessionKindNames = [numSessionKinds]string{
	"reconnect", "overlap", "home DERP", "hostname", "disco key", "given name", "expiry", "health", "extra records", "DERP map",
}

func (k sessionKind) String() string { return sessionKindNames[k] }

// sessionWrite is one such write: its kind, the node it goes to (an index
// into the nodes it can go to) and a value it writes.
type sessionWrite struct {
	Kind       sessionKind
	Who, Value int
}

func (w sessionWrite) GoString() string { return fmt.Sprintf("%s #%d =%d", w.Kind, w.Who, w.Value) }

var sessionWrites = rapid.Custom(func(t *rapid.T) sessionWrite {
	return sessionWrite{
		Kind:  sessionKind(rapid.IntRange(0, int(numSessionKinds)-1).Draw(t, "kind")),
		Who:   rapid.IntRange(0, 15).Draw(t, "who"),
		Value: rapid.IntRange(0, 2).Draw(t, "value"),
	}
})

// expiredAt is when a node expired: in the past, as the model writes it.
var expiredAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// session makes sw and returns what it did, or "" when no node can take
// it: a map request comes only from a connected node, the prober probes
// only a connected router serving routes.
func (p *pbtWorld) session(sw sessionWrite) string {
	p.t.Helper()

	snap := p.s.Snapshot()

	if sw.Kind == writeExtraRecords || sw.Kind == writeDERPMap {
		p.count(sw.Kind)
	}

	if sw.Kind == writeExtraRecords {
		var records []tailcfg.DNSRecord
		if snap.DNS().ExtraRecords().Len() == 0 {
			records = []tailcfg.DNSRecord{{Name: fmt.Sprintf("r%d.headscale.test", sw.Value), Type: "A", Value: "100.64.0.1"}}
		}

		p.call(func() { p.s.SetExtraRecords(records) })

		return fmt.Sprintf("extra records %v", records)
	}

	if sw.Kind == writeDERPMap {
		regions := map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}}
		if len(snap.DERPMap().Regions) == 1 {
			regions[900] = &tailcfg.DERPRegion{RegionID: 900}
		}

		p.call(func() { p.s.SetDERPMap(&tailcfg.DERPMap{Regions: regions}) })

		return fmt.Sprintf("DERP map of %d regions", len(regions))
	}

	var from []*types.Node

	for _, nv := range snap.ListNodes().All() {
		if n := nv.AsStruct(); p.takes(sw.Kind, n) {
			from = append(from, n)
		}
	}

	if len(from) == 0 {
		return ""
	}

	n := from[sw.Who%len(from)]

	return fmt.Sprintf("n%d: %s", n.ID, p.sessionAt(n, sw))
}

// count notes a write of kind made.
func (p *pbtWorld) count(k sessionKind) { p.made[k.String()]++ }

// takes reports whether n can take a write of kind k: a map request comes
// only from a connected node, the prober probes only a connected router
// serving routes.
func (p *pbtWorld) takes(k sessionKind, n *types.Node) bool {
	switch k {
	case writeReconnect, writeOverlap, writeHomeDERP, writeHostname, writeDiscoKey:
		return len(p.conns[n.ID]) > 0
	case writeHealth:
		return n.Online() && len(n.AllApprovedRoutes()) > 0
	case writeGivenName, writeExpiry, writeExtraRecords, writeDERPMap, numSessionKinds:
	}

	return true
}

// sessionAt makes sw on n.
func (p *pbtWorld) sessionAt(n *types.Node, sw sessionWrite) string {
	id := n.ID

	p.count(sw.Kind)

	switch sw.Kind {
	case writeReconnect:
		p.disconnect(id)
		p.connect(id)

		return "reconnects"
	case writeOverlap:
		p.connect(id)
		p.disconnect(id)

		return "reconnects before its old connection ends"
	case writeHomeDERP:
		// Set when unset, cleared when set: a clear is what no patch says.
		derp := 450 * tailcfg.DERPRegionID(sw.Value+1) //nolint:gosec // small
		if n.Hostinfo != nil && n.Hostinfo.NetInfo != nil && n.Hostinfo.NetInfo.PreferredDERP != 0 {
			derp = 0
		}

		p.mapRequest(n, func(hi *tailcfg.Hostinfo, _ *tailcfg.MapRequest) {
			hi.NetInfo = &tailcfg.NetInfo{PreferredDERP: derp}
		})

		return fmt.Sprintf("home DERP %d", derp)
	case writeHostname:
		name := fmt.Sprintf("h%d-%d", id, sw.Value)

		p.mapRequest(n, func(hi *tailcfg.Hostinfo, _ *tailcfg.MapRequest) { hi.Hostname = name })

		return "hostname " + name
	case writeDiscoKey:
		raw := make([]byte, 32)
		raw[0], raw[1] = 3, byte(sw.Value+1) //nolint:gosec // small
		binary.BigEndian.PutUint64(raw[24:], uint64(id))
		disco := key.DiscoPublicFromRaw32(mem.B(raw))

		p.mapRequest(n, func(_ *tailcfg.Hostinfo, req *tailcfg.MapRequest) { req.DiscoKey = disco })

		return "disco key " + disco.ShortString()
	case writeGivenName:
		name := fmt.Sprintf("g%d-%d", id, sw.Value)

		p.call(func() {
			_, err := p.s.RenameNode(id, name)
			if err != nil && !errors.Is(err, state.ErrNodeNotInNodeStore) {
				p.t.Fatalf("n%d renamed %s: %v", id, name, err)
			}
		})

		return "given name " + name
	case writeExpiry:
		expired := !n.IsExpired()

		var at *time.Time
		if expired {
			at = &expiredAt
		}

		p.call(func() {
			_, err := p.s.SetNodeExpiry(id, at)
			if err != nil && !errors.Is(err, state.ErrNodeNotInNodeStore) {
				p.t.Fatalf("n%d's expiry: %v", id, err)
			}
		})

		p.w = p.w.Apply(policymodel.SetExpired{ID: id, Expired: expired})

		if expired {
			return "key expired"
		}

		return "key renewed"
	case writeHealth:
		healthy := n.Unhealthy

		p.call(func() { p.s.SetNodeHealth(id, healthy) })

		if healthy {
			return "the prober passes it"
		}

		return "the prober fails it"
	case writeExtraRecords, writeDERPMap, numSessionKinds:
	}

	return ""
}

// mapRequest has n's client send a map request: what it holds, as edit
// changes it.
func (p *pbtWorld) mapRequest(n *types.Node, edit func(*tailcfg.Hostinfo, *tailcfg.MapRequest)) {
	p.t.Helper()

	hi := n.Hostinfo.Clone()
	if hi == nil {
		hi = &tailcfg.Hostinfo{}
	}

	req := tailcfg.MapRequest{NodeKey: n.NodeKey, DiscoKey: n.DiscoKey, Endpoints: n.Endpoints, Hostinfo: hi}
	edit(hi, &req)

	p.call(func() {
		// The node is in the world alone: what it reports lands in
		// memory, and the database write after finds no row.
		err := p.s.UpdateNodeFromMapRequest(n.ID, req)
		if err != nil && !errors.Is(err, state.ErrNodeNotInNodeStore) {
			p.t.Fatalf("n%d's map request: %v", n.ID, err)
		}
	})
}

// sessionTo makes a write of kind on node id with value, if the node can
// take it (see [pbtWorld.session]).
func (p *pbtWorld) sessionTo(id types.NodeID, kind sessionKind, value int) string {
	nv, ok := p.s.Snapshot().GetNode(id)
	if !ok {
		return ""
	}

	n := nv.AsStruct()
	if !p.takes(kind, n) {
		return ""
	}

	return fmt.Sprintf("n%d: %s", id, p.sessionAt(n, sessionWrite{Kind: kind, Value: value}))
}

// scriptAct is one act of a drawn script: a model step, or a write of a
// kind to one node. A key act is one of the moves the script is for; the
// acts before the first set it up.
type scriptAct struct {
	step *policymodel.Step
	node types.NodeID
	kind sessionKind
	key  bool
}

// accepted reports whether a is still a write headscale accepts in w,
// which other writes may have moved since the script was drawn: its edits
// still apply (a rule it inserts lands in the list), and a policy write is
// refused while a token it holds names two users.
func (a scriptAct) accepted(w policymodel.World) bool {
	if a.step == nil {
		return true
	}

	var (
		next    policymodel.World
		applies bool
	)

	func() {
		defer func() { _ = recover() }()

		next, applies = w.Apply(a.step.Edits...), true
	}()

	if !applies {
		return false
	}

	return string(next.Policy.HuJSON()) == string(w.Policy.HuJSON()) || len(policymodel.NewView(next).AmbiguousRefs()) == 0
}

// play makes a on p, a step's edits a commit each, and says what it did.
func (a scriptAct) play(p *pbtWorld) string {
	if a.step != nil {
		for _, e := range a.step.Edits {
			p.edit(e)
		}

		return a.step.String()
	}

	return p.sessionTo(a.node, a.kind, 0)
}

// sessionScripts are the change-routing scripts of policymodel, each
// moving one part of what a viewer is sent alone.
var sessionScripts = []struct {
	name  string
	steps func(policymodel.World) []policymodel.Step
}{
	{"peer set", policymodel.PeerSetScript},
	{"stamps", policymodel.StampScript},
	{"cover", policymodel.CoverScript},
	{"route view", policymodel.RouteViewScript},
}

// failoverActs are what can happen to an HA router once a failover is
// set up: it goes down or comes back, the prober fails or passes it, it
// reconnects, or reconnects before its old connection ends.
var failoverActs = []string{"down", "up", "health", "reconnect", "overlap"}

// drawScript draws a script to play from w: one of [sessionScripts], or a
// failover and what then happens to its routers. Nothing when it does not
// apply to w.
func drawScript(t *rapid.T, w policymodel.World) (string, []scriptAct) {
	k := rapid.IntRange(0, len(sessionScripts)).Draw(t, "script")

	steps := func(sts []policymodel.Step) []scriptAct {
		out := make([]scriptAct, len(sts))
		for i := range sts {
			out[i] = scriptAct{step: &sts[i]}
		}

		return out
	}

	if k < len(sessionScripts) {
		acts := steps(sessionScripts[k].steps(w))

		// Each ends with its moves: a member in and out, twice, and back.
		for i := max(0, len(acts)-5); i < len(acts); i++ {
			acts[i].key = true
		}

		return sessionScripts[k].name, acts
	}

	f, ok := policymodel.FailoverScript(w)
	if !ok {
		return "failover", nil
	}

	acts := steps(f.Steps)

	for _, act := range rapid.SliceOfN(rapid.SampledFrom(failoverActs), 1, 6).Draw(t, "failovers") {
		id := f.Routers[rapid.IntRange(0, 1).Draw(t, "router")]

		switch act {
		case "down", "up":
			acts = append(acts, scriptAct{step: &policymodel.Step{Edits: []policymodel.Edit{policymodel.SetOnline{ID: id, Online: act == "up"}}}, key: true})
		case "health":
			acts = append(acts, scriptAct{node: id, kind: writeHealth, key: true})
		case "reconnect":
			acts = append(acts, scriptAct{node: id, kind: writeReconnect, key: true})
		case "overlap":
			acts = append(acts, scriptAct{node: id, kind: writeOverlap, key: true})
		}
	}

	return "failover", acts
}

// addrIndex is the client's index of nodes by address, kept across
// responses as tailscaled keeps it (nodeBackend.UpdateNetmapDelta,
// TestCanaryCapLookupForgetsAddressOnRemoval): a response the client
// applies as mutations ([netmap.MutationsFromMapResponse]) moves it entry
// by entry, a removed or changed peer taking out the entries of its old
// addresses that are still its own, whoever else holds them; any other
// response rebuilds it from the netmap, the last node listed holding an
// address. A peer changed in place is taken as replaced, which keeps more
// entries than patching it can: what that misses, it misses soundly.
type addrIndex map[netip.Addr]tailcfg.NodeID

// apply moves ix over resp, which took the client from before to after.
func (ix addrIndex) apply(before, after *netmap.NetworkMap, resp *tailcfg.MapResponse) addrIndex {
	muts, delta := netmap.MutationsFromMapResponse(resp, time.Unix(0, 0))
	if ix == nil || before == nil || !delta {
		out := addrIndex{}

		for _, n := range append([]tailcfg.NodeView{after.SelfNode}, after.Peers...) {
			out.add(n)
		}

		return out
	}

	held := map[tailcfg.NodeID]tailcfg.NodeView{}
	for _, p := range before.Peers {
		held[p.ID()] = p
	}

	for _, m := range muts {
		switch m := m.(type) {
		case netmap.NodeMutationUpsert:
			ix.evict(held[m.Node.ID()], m.Node.ID())
			ix.add(m.Node)
		case netmap.NodeMutationRemove:
			ix.evict(held[m.NodeIDBeingMutated()], m.NodeIDBeingMutated())
		}
	}

	return ix
}

func (ix addrIndex) add(n tailcfg.NodeView) {
	if !n.Valid() {
		return
	}

	for _, p := range n.Addresses().All() {
		if p.IsSingleIP() {
			ix[p.Addr()] = n.ID()
		}
	}
}

func (ix addrIndex) evict(n tailcfg.NodeView, id tailcfg.NodeID) {
	if !n.Valid() {
		return
	}

	for _, p := range n.Addresses().All() {
		if p.IsSingleIP() && ix[p.Addr()] == id {
			delete(ix, p.Addr())
		}
	}
}

// forgotten returns an address a node of nm holds that ix indexes no
// node for, and that node: the client would match a capability source
// from that address against nobody.
func (ix addrIndex) forgotten(nm *netmap.NetworkMap) (netip.Addr, tailcfg.NodeID, bool) {
	for _, n := range append([]tailcfg.NodeView{nm.SelfNode}, nm.Peers...) {
		for _, p := range n.Addresses().All() {
			if _, ok := ix[p.Addr()]; p.IsSingleIP() && !ok {
				return p.Addr(), n.ID(), true
			}
		}
	}

	return netip.Addr{}, 0, false
}
