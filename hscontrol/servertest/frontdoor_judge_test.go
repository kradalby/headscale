package servertest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/control/controlclient"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
)

// Quiet is read off the goroutines, as testing/synctest's Wait reads them,
// which the database driver and net/http keep this test from using: the
// server has nothing pending when every goroutine is parked on a channel,
// a condition or a select, with the hub's watcher at its select, every map
// session at the select it waits at between updates, and no session's
// end waiting out its reconnect grace; and no commit landed while the
// goroutines were read. A commit wakes the watcher, a wake its session, a
// write the client's reader, and each of them runs until it parks, so a
// change in flight always shows as a goroutine that is not parked.
// Timers that fire later (keep-alives, the hub's history sweep, the
// ephemeral collector's hour) change no map.

// parkedStates are the goroutine states of a goroutine waiting for
// another one; any other state is work in progress.
var parkedStates = map[string]bool{
	"select": true, "select (no cases)": true, "chan receive": true, "chan send": true,
	"chan receive (nil chan)": true, "chan send (nil chan)": true, "sync.Cond.Wait": true,
	"sync.WaitGroup.Wait": true, "IO wait": true, "finalizer wait": true, "force gc (idle)": true,
	"GC worker (idle)": true, "GC sweep wait": true, "GC scavenge wait": true,
}

const (
	pollFunc  = "github.com/juanfont/headscale/hscontrol.(*mapSession).serveLongPoll"
	watchFunc = "github.com/juanfont/headscale/hscontrol/mapper.(*Hub).watch"
	// followupFunc waits for an interactive login's verdict.
	followupFunc = "github.com/juanfont/headscale/hscontrol.(*Headscale).waitForFollowup"
)

// pollLoopLine is the line of hscontrol/poll.go at which serveLongPoll
// waits between updates: the select of its loop, not the one that
// coalesces a burst after a wake.
func pollLoopLine() (int, error) {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, filepath.Join("..", "poll.go"), nil, 0)
	if err != nil {
		return 0, err
	}

	line := 0

	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serveLongPoll" {
			continue
		}

		for _, s := range fn.Body.List {
			loop, ok := s.(*ast.ForStmt)
			if !ok || loop.Cond != nil {
				continue
			}

			for _, s := range loop.Body.List {
				if sel, ok := s.(*ast.SelectStmt); ok {
					line = fset.Position(sel.Pos()).Line
				}
			}
		}
	}

	if line == 0 {
		return 0, errors.New("serveLongPoll waits at no select of its loop in hscontrol/poll.go") //nolint:err113
	}

	return line, nil
}

// quiet waits until the server has nothing pending; see above.
func (fd *frontDoor) quiet(at string) {
	start := time.Now()

	// The goroutines are read again at every tick until they are quiet.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	for {
		before := fd.srv.State().Snapshot().Rev()
		busy := fd.busy()

		if len(busy) == 0 && fd.srv.State().Snapshot().Rev() == before {
			took := time.Since(start)
			fd.run.tally.quiets++
			fd.run.tally.quietAll += took
			fd.run.tally.quietMax = max(fd.run.tally.quietMax, took)

			return
		}

		if time.Since(start) > fdQuietLimit {
			fd.t.Fatalf("%s: the server is not quiet after %v; still at work:\n%s", at, fdQuietLimit, strings.Join(busy, "\n\n"))
		}

		<-tick.C
	}
}

// dump is every goroutine's stack, the caller's first.
func (fd *frontDoor) dump() string {
	for {
		n := runtime.Stack(fd.stacks, true)
		if n < len(fd.stacks) {
			return string(fd.stacks[:n])
		}

		fd.stacks = make([]byte, 2*len(fd.stacks))
	}
}

// busy lists the goroutines at work, each with why.
func (fd *frontDoor) busy() []string {
	return pending(goroutines(fd.dump()), fd.run.loopLine)
}

// goroutine is one goroutine of a dump: its state, the first function
// outside the runtime and where in it, and its whole stack.
type goroutine struct {
	state, top, at, stack string
}

// goroutines reads dump, but for its first goroutine, the caller.
func goroutines(dump string) []goroutine {
	var out []goroutine

	for i, g := range strings.Split(dump, "\n\n") {
		if i == 0 {
			continue
		}

		header, body, _ := strings.Cut(g, "\n")

		state := header
		if a, b := strings.Index(header, "["), strings.LastIndex(header, "]"); a >= 0 && b > a {
			state = header[a+1 : b]
		}

		state, _, _ = strings.Cut(state, ",")
		gr := goroutine{state: state, stack: g}

		// Frames alternate a call and its file:line; the first outside
		// the runtime is where the goroutine waits.
		lines := strings.Split(body, "\n")

		for j := 0; j+1 < len(lines); j += 2 {
			call := lines[j]
			if strings.HasPrefix(call, "runtime.") || strings.HasPrefix(call, "created by ") {
				continue
			}

			fn, _, _ := strings.Cut(call, "(0x")
			gr.top = strings.TrimSuffix(strings.TrimSuffix(fn, "(...)"), "()")
			gr.at = strings.TrimSpace(lines[j+1])

			break
		}

		out = append(out, gr)
	}

	return out
}

// pending lists the goroutines at work, each with why.
func pending(gs []goroutine, loopLine int) []string {
	var out []string

	for _, g := range gs {
		var why string

		switch {
		case strings.Contains(g.stack, pollFunc+".func"):
			why = "a map session ending"
		case strings.Contains(g.stack, pollFunc+"("):
			if g.state != "select" || g.top != pollFunc || !strings.Contains(g.at, "/poll.go:"+strconv.Itoa(loopLine)+" ") {
				why = "a map session between a wake and its write"
			}
		case strings.Contains(g.stack, watchFunc+"("):
			if g.state != "select" || g.top != watchFunc {
				why = "the hub routing a commit"
			}
		case !parkedStates[g.state]:
			why = g.state
		}

		if why != "" {
			out = append(out, why+": "+g.stack)
		}
	}

	return out
}

// judgeClients holds every client that polls, as the model says it must,
// to a fresh session of its node, then to the reference.
func (fd *frontDoor) judgeClients(at string) {
	snap := fd.srv.State().Snapshot()
	w := fd.w

	for _, n := range w.Topology.Nodes {
		nd := fd.nodes[n.ID]
		if polling := nd.tc.Polling(); polling == n.Offline {
			fd.t.Fatalf("%s: n%d's client polls: %t; the model has it offline: %t", at, n.ID, polling, n.Offline)
		}
	}

	ref := policymodel.RefOf(w).WithElections(fd.elections)
	why := ref.OutOfDomain()

	if why != "" {
		fd.run.tally.skipped[why]++
	}

	var known []netip.Addr
	for _, n := range w.Topology.Nodes {
		known = append(known, n.Addrs()...)
	}

	key := fmt.Sprint(known)
	world := fmt.Sprint(w.Topology) + string(w.Policy.HuJSON())

	for _, n := range w.Topology.Nodes {
		if n.Offline {
			continue
		}

		nd := fd.nodes[n.ID]

		nm := nd.tc.Netmap()
		if nm == nil {
			fd.t.Fatalf("%s: n%d's client polls, and holds no map", at, n.ID)
		}

		fresh := freshNetmap(fd, snap, n.ID, nd.tc.Persist())

		fd.run.tally.clients++

		if d := netmapDiff(nm, fresh, func() { fd.run.tally.unseen++ }); d != "" {
			fd.t.Fatalf("%s: n%d's client, the server quiet, holds other than a fresh session of r%d is given: %s", at, n.ID, snap.Rev(), d)
		}

		if why != "" {
			continue
		}

		c := heldClient{fd: fd, at: at, ref: ref, w: w, id: n.ID, nm: nm}
		c.peers()
		c.routes()
		c.filter(world, key)
		c.stamps()

		fd.run.tally.refClients++
	}
}

// freshNetmap is what a fresh session of id is given at snap, as its
// client builds it off the wire.
func freshNetmap(fd *frontDoor, snap *state.Snapshot, id types.NodeID, p persist.Persist) *netmap.NetworkMap {
	st := mapper.NewStream(fd.srv.cfg, mapper.NewHub(), id, tailcfg.CurrentCapabilityVersion)

	resps, err := st.Initial(snap)
	if err != nil || len(resps) != 1 {
		fd.t.Fatalf("n%d: a fresh session of r%d: %d responses, %v", id, snap.Rev(), len(resps), err)
	}

	// The time it is sent at is the one field two sessions of a snapshot
	// do not share.
	resp := *resps[0]
	resp.ControlTime = nil

	b, err := mapper.Marshal(&resp)
	if err != nil {
		fd.t.Fatalf("encoding a first map: %v", err)
	}

	var wire tailcfg.MapResponse

	err = json.Unmarshal(b, &wire)
	if err != nil {
		fd.t.Fatalf("decoding a first map: %v", err)
	}

	nm, err := controlclient.NetmapFromMapResponseForDebug(context.Background(), p.View(), &wire)
	if err != nil {
		fd.t.Fatalf("n%d: the client refuses a fresh first map: %v", id, err)
	}

	return nm
}

func jsonOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unencodable: " + err.Error()
	}

	return string(b)
}

// clientPeer is a peer as the client acts on it. A patch cannot clear
// LastSeen when a peer comes online, and the client acts on Online then,
// so an online peer's LastSeen is left out.
func clientPeer(n tailcfg.NodeView) string {
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

	return jsonOf(p)
}

// sameNode reports whether a and b are the same node to the client.
func sameNode(a, b tailcfg.NodeView) bool {
	// Equal leaves out two fields the wire carries.
	if a.Equal(b) && a.DataPlaneAuditLogID() == b.DataPlaneAuditLogID() && a.ExitNodeDNSResolvers().Len() == 0 && b.ExitNodeDNSResolvers().Len() == 0 {
		return true
	}

	return clientPeer(a) == clientPeer(b)
}

// ruleCounts is a filter as a multiset of rules.
func ruleCounts(rules []tailcfg.FilterRule) map[string]int {
	out := map[string]int{}
	for _, r := range rules {
		out[jsonOf(r)]++
	}

	return out
}

// countsDiff names the rules a has more of than b, sorted.
func countsDiff(a, b map[string]int) []string {
	var out []string

	for _, r := range slices.Sorted(maps.Keys(a)) {
		if a[r] > b[r] {
			out = append(out, fmt.Sprintf("%dx %s", a[r]-b[r], r))
		}
	}

	return out
}

func ruleList(rules []tailcfg.FilterRule) string {
	parts := make([]string, len(rules))
	for i, r := range rules {
		parts[i] = jsonOf(r)
	}

	return strings.Join(parts, "\n")
}

// filterDiff compares two filters a client holds: the same rules as a
// multiset, and when their order differs, the same verdicts and app
// capabilities, in order, through the client's own filter under view.
func filterDiff(have, want []tailcfg.FilterRule, view func() policymodel.ClientView) string {
	if slices.EqualFunc(have, want, func(a, b tailcfg.FilterRule) bool { return reflect.DeepEqual(a, b) }) {
		return ""
	}

	hc, wc := ruleCounts(have), ruleCounts(want)
	if !maps.Equal(hc, wc) {
		return fmt.Sprintf("filter: only held %v; only fresh %v", countsDiff(hc, wc), countsDiff(wc, hc))
	}

	if ruleList(have) == ruleList(want) {
		return ""
	}

	if rep := policymodel.Compare(want, have, view()); !rep.Equivalent() {
		return "filter reordered so that it answers otherwise: " + rep.String()
	}

	return ""
}

// peerIDsOfNetmap is nm's peers, in the client's order (by ID).
func peerIDsOfNetmap(nm *netmap.NetworkMap) []tailcfg.NodeID {
	out := make([]tailcfg.NodeID, len(nm.Peers))
	for i, p := range nm.Peers {
		out[i] = p.ID()
	}

	return out
}

// netmapDiff reports how the netmap a client assembled differs from the
// one a fresh session gives, field by field, or "". Keys the client holds
// of itself and the parsed filter (compared as rules) are not compared;
// unseen is called for each offline peer held without its LastSeen.
func netmapDiff(have, want *netmap.NetworkMap, unseen func()) string {
	if !sameNode(have.SelfNode, want.SelfNode) {
		return fmt.Sprintf("self: have %s, want %s", jsonOf(have.SelfNode), jsonOf(want.SelfNode))
	}

	if h, w := peerIDsOfNetmap(have), peerIDsOfNetmap(want); !slices.Equal(h, w) {
		return fmt.Sprintf("peers: have %v, want %v", h, w)
	}

	for i, w := range want.Peers {
		h := have.Peers[i]
		if sameNode(h, w) {
			continue
		}

		// TODO(kradalby): render/lastseen-patchify: a peer going offline
		// in a change no patch carries is sent whole; the client patchifies
		// it and keeps no LastSeen it did not hold. Counted, not judged.
		if hs := h.AsStruct(); hs.LastSeen == nil && w.LastSeen().Valid() && !w.Online().GetOr(true) && !h.Online().GetOr(true) {
			hs.LastSeen = new(w.LastSeen().Get())
			if sameNode(hs.View(), w) {
				unseen()

				continue
			}
		}

		return fmt.Sprintf("peer %d: have %s, want %s", w.ID(), clientPeer(h), clientPeer(w))
	}

	if d := filterDiff(have.PacketFilterRules.AsSlice(), want.PacketFilterRules.AsSlice(), func() policymodel.ClientView {
		return policymodel.ViewFromNetmap(want)
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

		if h, w := jsonOf(f.have), jsonOf(f.want); h != w {
			return fmt.Sprintf("%s: have %s, want %s", f.name, h, w)
		}
	}

	return ""
}

// durable is what of a netmap a restart must keep. A restart ends every
// session, so peers' online state and last-seen times move, and the new
// server elects HA routers in the order their clients reconnect, keeping
// no history: which router is primary, and which peer carries a subnet
// route in AllowedIPs, may change. Everything else must not.
func durable(nm *netmap.NetworkMap) string {
	strip := func(n tailcfg.NodeView) string {
		if !n.Valid() {
			return "none"
		}

		c := n.AsStruct()
		c.Online, c.LastSeen, c.PrimaryRoutes = nil, nil, nil
		c.AllowedIPs = slices.DeleteFunc(slices.Clone(c.AllowedIPs), func(q netip.Prefix) bool {
			return !slices.Contains(c.Addresses, q) && !tsaddr.IsExitRoute(q)
		})

		return clientPeer(c.View())
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "self %s;", strip(nm.SelfNode))

	for _, p := range nm.Peers {
		fmt.Fprintf(&sb, "\n peer %s;", strip(p))
	}

	fmt.Fprintf(&sb, "\n filter %v;\n ssh %s;\n dns %s;\n profiles %s;\n caps %s",
		countsDiff(ruleCounts(nm.PacketFilterRules.AsSlice()), nil), jsonOf(nm.SSHPolicy), jsonOf(nm.DNS), jsonOf(nm.UserProfiles), jsonOf(nm.AllCaps))

	return sb.String()
}

// heldClient is one client held to the reference.
type heldClient struct {
	fd  *frontDoor
	at  string
	ref *policymodel.Ref
	w   policymodel.World
	id  types.NodeID
	nm  *netmap.NetworkMap
}

func (c heldClient) failf(format string, args ...any) {
	c.fd.t.Fatalf("%s: n%d: reference: "+format, append([]any{c.at, c.id}, args...)...)
}

// peers holds the client's peers, and the addresses it is shown, to the
// reference, and the routes the node is primary for to the election.
func (c heldClient) peers() {
	got := make([]types.NodeID, 0, len(c.nm.Peers))
	for _, p := range c.nm.Peers {
		got = append(got, types.NodeID(p.ID())) //nolint:gosec // small
	}

	for _, nv := range append([]tailcfg.NodeView{c.nm.SelfNode}, c.nm.Peers...) {
		var addrs []netip.Addr

		for _, p := range nv.Addresses().All() {
			addrs = append(addrs, p.Addr())
		}

		if want := policymodel.ShownAddrs(c.w, c.id, types.NodeID(nv.ID())); !slices.Equal(addrs, want) { //nolint:gosec // small
			c.failf("its client is shown n%d at %v, the model at %v", nv.ID(), addrs, want)
		}
	}

	c.fd.run.tally.peerSets++

	if want := c.ref.Peers(c.id); !slices.Equal(got, want) {
		k, ok := policymodel.ContestedPeers(c.ref, c.id, got)
		if !ok {
			c.failf("its client is shown %v, the reference shows it %v", got, want)
		}

		c.fd.run.tally.contested["peers "+k.String()]++
	}

	self, ok := c.ref.Node(c.id)
	if !ok {
		return
	}

	for _, q := range self.ServedRoutes() {
		primary, decided := c.ref.Primary(q)
		if q.Bits() == 0 || !decided || c.fd.unheld[q] {
			continue
		}

		c.fd.run.tally.primaries++

		if want, has := primary == c.id && !policymodel.NamesNode(q), slices.Contains(c.nm.SelfNode.PrimaryRoutes().AsSlice(), q); want != has {
			c.failf("its client is primary for %s: %t, the election gives it to n%d", q, has, primary)
		}
	}
}

// routes holds what each peer carries in the client's AllowedIPs beyond
// its addresses to [policymodel.Ref.ServedRoutes].
func (c heldClient) routes() {
	for _, p := range c.nm.Peers {
		pid := types.NodeID(p.ID()) //nolint:gosec // small
		routes := slices.DeleteFunc(p.AllowedIPs().AsSlice(), func(q netip.Prefix) bool { return slices.Contains(p.Addresses().AsSlice(), q) })
		slices.SortFunc(routes, netip.Prefix.Compare)

		want, unjudged := c.ref.ServedRoutes(c.id, pid)
		want = slices.DeleteFunc(want, func(q netip.Prefix) bool { return c.fd.unheld[q] })

		for q := range c.fd.unheld {
			unjudged = append(unjudged, q)
		}

		judged := policymodel.Judged(routes, unjudged)

		if len(routes)+len(want) > 0 {
			c.fd.run.tally.routePairs++
		}

		if !slices.Equal(judged, want) {
			k, ok := policymodel.ContestedServedRoutes(c.ref, c.id, pid, routes)

			switch {
			case ok:
				c.fd.run.tally.contested["routes "+k.String()]++
			case viaExitSourceRoutes(c.w, c.id, pid, judged, want):
				// TODO(kradalby): policy/via-exit-source-routes: FOLLOWUPS
				// A33. A via exit router on the source side of its own via
				// grant to autogroup:internet is given a peer's public
				// subnet routes, though that peer is no via router of the
				// grant. The reference has no clause for it. Counted, not
				// judged.
				c.fd.run.tally.contested["routes via exit source (A33)"]++
			default:
				c.failf("its client is given %v of n%d's routes, the reference %v (%v unjudged)", routes, pid, want, unjudged)
			}
		}
	}
}

// viaExitSourceRoutes reports whether judged is want and public subnet
// routes of peer that FOLLOWUPS A33 gives viewer: viewer is an exit node
// carrying the via tags of a grant to autogroup:internet whose sources
// it is among, and peer carries none of them.
func viaExitSourceRoutes(w policymodel.World, viewer, peer types.NodeID, judged, want []netip.Prefix) bool {
	v, _ := w.Topology.Node(viewer)
	p, _ := w.Topology.Node(peer)

	extra := slices.DeleteFunc(slices.Clone(judged), func(q netip.Prefix) bool { return slices.Contains(want, q) })
	if !v.Exit() || len(extra) == 0 || slices.ContainsFunc(want, func(q netip.Prefix) bool { return !slices.Contains(judged, q) }) {
		return false
	}

	for _, q := range extra {
		r := slices.Index(policymodel.Prefixes, q)
		if q.Bits() == 0 || !util.TheInternet().ContainsPrefix(q) || !slices.Contains(p.Announced, r) || !slices.Contains(p.Approved, r) {
			return false
		}
	}

	view := policymodel.NewView(w)
	carries := func(n policymodel.Node, via []int) bool {
		return slices.ContainsFunc(n.Tags, func(t int) bool { return slices.Contains(via, t) })
	}

	for _, g := range w.Policy.Grants {
		internet := slices.ContainsFunc(g.Dst, func(d policymodel.Dest) bool { return d.Sel.Kind == policymodel.SelInternet })
		source := slices.ContainsFunc(view.MembersOf(g.Src...), func(n policymodel.Node) bool { return n.ID == viewer })

		if internet && len(g.Via) > 0 && carries(v, g.Via) && !carries(p, g.Via) && source {
			return true
		}
	}

	return false
}

// filter holds the client's packet filter to the reference's rules
// through its own filter. A comparison that holds without a contested
// clause reads only the reference's rules for the node and what it
// serves, the view and the filter; one that needs a clause reads the
// whole world.
func (c heldClient) filter(world, key string) {
	n, _ := c.w.Topology.Node(c.id)
	rules := c.nm.PacketFilterRules.AsSlice()
	capSources := c.fd.capSources

	if msg := c.fd.run.form.Check(c.w, c.ref, c.id, rules, capSources, false); msg != "" {
		c.failf("its client's filter is in the wrong form: %s\nheadscale %v", msg, rules)
	}

	k := fmt.Sprint(n, capSources, c.ref.Served(c.id).Prefixes()) + ruleList(c.ref.Rules(c.id)) + key + ruleList(rules) + jsonOf(c.nm.SelfNode.CapMap()) + jsonOf(peerCaps(c.nm))
	if c.fd.run.passed[k] || c.fd.run.passed[world+k] {
		return
	}

	c.fd.run.tally.filters++

	contested := 0
	for _, n := range c.fd.run.verdicts.Contested {
		contested += n
	}

	rep := c.fd.run.verdicts.CompareAt(c.ref, c.id, rules, refView(n, c.w, c.nm), capSources)
	if !rep.Equivalent() {
		c.failf("its client's filter differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v", rep, c.ref.Rules(c.id), rules)
	}

	for _, n := range c.fd.run.verdicts.Contested {
		contested -= n
	}

	if contested == 0 {
		c.fd.run.passed[k] = true
	} else {
		c.fd.run.passed[world+k] = true
	}
}

// peerCaps is what the client's view reads of its peers: their
// capabilities, by address.
func peerCaps(nm *netmap.NetworkMap) []string {
	out := make([]string, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		out = append(out, fmt.Sprint(p.Addresses().AsSlice())+jsonOf(p.CapMap()))
	}

	return out
}

// stamps holds the stamps the client holds of itself and its peers to the
// reference's, none in address mode.
func (c heldClient) stamps() {
	for _, nv := range append([]tailcfg.NodeView{c.nm.SelfNode}, c.nm.Peers...) {
		of := types.NodeID(nv.ID()) //nolint:gosec // small

		var has, want []string

		for k := range nv.CapMap().All() {
			if strings.Contains(string(k), strings.TrimPrefix(policymodel.StampPrefix, "https://")) {
				has = append(has, string(k))
			}
		}

		slices.Sort(has)

		for _, s := range c.ref.Stamps(of) {
			if c.fd.capSources {
				want = append(want, policymodel.StampPrefix+s)
			}
		}

		if !slices.Equal(has, want) {
			c.failf("its client holds n%d with stamps %v, the reference stamps it %v", of, has, want)
		}
	}
}

// refView is what node n's client knows when it filters, holding nm: local
// nets from what it announces and runs as, every node's addresses as
// sources worth probing, capabilities from nm, for a client that looks
// them up.
func refView(n policymodel.Node, w policymodel.World, nm *netmap.NetworkMap) policymodel.ClientView {
	own := make([]netip.Prefix, 0, 2)
	announced := make([]netip.Prefix, 0, len(n.Announced))

	// disable-ipv4 keeps addresses from the netmap, its own among them;
	// whether rightly the shown addresses' check says.
	hidden := policymodel.NotShown(w, slices.Concat(nm.Peers, []tailcfg.NodeView{nm.SelfNode}))
	addrs := slices.DeleteFunc(n.Addrs(), func(a netip.Addr) bool { return slices.Contains(hidden, a) })

	for _, a := range addrs {
		own = append(own, netip.PrefixFrom(a, a.BitLen()))
	}

	for _, r := range n.Announced {
		announced = append(announced, policymodel.Prefixes[r])
	}

	v := policymodel.ClientView{Self: addrs, LocalNets: policymodel.LocalNets(own, announced, n.Client == policymodel.AppConnector, nil), Hidden: hidden}

	for _, m := range w.Topology.Nodes {
		v.Known = append(v.Known, m.Addrs()...)
	}

	if n.Client == policymodel.Official || n.Client == policymodel.AppConnector {
		caps := policymodel.NewNetmapCaps(nm.SelfNode, nm.Peers)
		v.HasCap = caps.HasCap
	}

	return v
}

// requireStored holds what the server stored to the model: every node
// equals the model's on what the model holds and on how it joined, and
// every row equals its node in memory.
func (fd *frontDoor) requireStored(after string) {
	snap := fd.srv.State().Snapshot()
	w := fd.w
	_, nodes := w.Topology.Build()

	held, want := make([]types.NodeID, 0, len(nodes)), make([]types.NodeID, 0, len(nodes))

	for _, nv := range snap.ListNodes().All() {
		held = append(held, nv.ID())
	}

	for _, tn := range nodes {
		want = append(want, tn.ID)
	}

	if !slices.Equal(held, want) {
		fd.t.Fatalf("stored: after %s, the server holds nodes %v, the model %v", after, held, want)
	}

	for i, tn := range nodes {
		nv, _ := snap.GetNode(tn.ID)

		if d := storedDiff(nv.AsStruct(), tn, w.Topology.Nodes[i], fd.nodes[tn.ID]); d != "" {
			fd.t.Fatalf("stored: after %s, n%d: %s", after, tn.ID, d)
		}
	}

	users, err := fd.srv.State().ListAllUsers()
	if err != nil {
		fd.t.Fatalf("stored: after %s: users: %v", after, err)
	}

	modelUsers, _ := w.Topology.Build()

	if h, m := usersOf(users), usersOf(modelUsers); h != m {
		fd.t.Fatalf("stored: after %s, the server holds users\n%s\nthe model\n%s", after, h, m)
	}

	rows, err := fd.srv.State().DB().ListNodes()
	if err != nil {
		fd.t.Fatalf("persisted: after %s: %v", after, err)
	}

	stored := make([]types.NodeID, 0, len(rows))
	for _, row := range rows {
		stored = append(stored, row.ID)
	}

	if !slices.Equal(stored, want) {
		fd.t.Fatalf("persisted: after %s, the database holds nodes %v, the model %v", after, stored, want)
	}

	for _, row := range rows {
		nv, _ := snap.GetNode(row.ID)

		if d := rowDiff(row, nv.AsStruct()); d != "" {
			fd.t.Fatalf("persisted: after %s, n%d's row differs from the node in memory: %s", after, row.ID, d)
		}
	}
}

// usersOf is users as the policy reads them, in ID order.
func usersOf(users []types.User) string {
	users = slices.Clone(users)
	slices.SortFunc(users, func(a, b types.User) int { return int(a.ID) - int(b.ID) }) //nolint:gosec // small

	var sb strings.Builder

	for _, u := range users {
		fmt.Fprintf(&sb, "u%d %q <%s> %s\n", u.ID, u.Name, u.Email, u.ProviderIdentifier.String)
	}

	return sb.String()
}

// storedDiff is how got, as the server holds it, differs from tn, model
// node n built, and from how its client joined.
func storedDiff(got, tn *types.Node, n policymodel.Node, nd *fdNode) string {
	var out []string

	differ := func(what string, have, want any) {
		out = append(out, fmt.Sprintf("%s %v, the model %v", what, have, want))
	}

	addr := func(a *netip.Addr) netip.Addr {
		if a == nil {
			return netip.Addr{}
		}

		return *a
	}

	if addr(got.IPv4) != n.V4 || addr(got.IPv6) != n.V6 {
		differ("addresses", []netip.Addr{addr(got.IPv4), addr(got.IPv6)}, []netip.Addr{n.V4, n.V6})
	}

	if tags := slices.Sorted(slices.Values(got.Tags)); !slices.Equal(tags, tn.Tags) {
		differ("tags", tags, tn.Tags)
	}

	user := func(u *uint) uint {
		if u == nil {
			return 0
		}

		return *u
	}

	if user(got.UserID) != n.User {
		differ("user", user(got.UserID), n.User)
	}

	sorted := func(ps []netip.Prefix) []netip.Prefix {
		return slices.SortedFunc(slices.Values(ps), netip.Prefix.Compare)
	}

	if a, b := sorted(got.AnnouncedRoutes()), sorted(tn.Hostinfo.RoutableIPs); !slices.Equal(a, b) {
		differ("announced", a, b)
	}

	if a, b := sorted(got.ApprovedRoutes), sorted(tn.ApprovedRoutes); !slices.Equal(a, b) {
		differ("approved", a, b)
	}

	if a, b := sorted(got.AutoApprovedRoutes), sorted(tn.AutoApprovedRoutes); !slices.Equal(a, b) {
		differ("auto-approved", a, b)
	}

	client := func(hi *tailcfg.Hostinfo) string {
		if hi == nil {
			return "none"
		}

		return fmt.Sprintf("go=%q ipn=%q app=%q connector=%v", hi.GoVersion, hi.IPNVersion, hi.App, hi.AppConnector)
	}

	if a, b := client(got.Hostinfo), client(tn.Hostinfo); a != b {
		differ("client", a, b)
	}

	if got.IsExpired() != n.Expired {
		differ("expired", got.IsExpired(), n.Expired)
	}

	if online := !n.Offline && !n.Expired; got.Online() != online {
		differ("online", got.Online(), online)
	}

	if got.RegisterMethod != nd.method || got.Ephemeral != nd.ephemeral {
		differ("registration", fmt.Sprintf("%s ephemeral=%t", got.RegisterMethod, got.Ephemeral), fmt.Sprintf("%s ephemeral=%t (its client's)", nd.method, nd.ephemeral))
	}

	return strings.Join(out, "; ")
}

// rowDiff is how row, as the database holds it, differs from n in memory
// on the columns a write persists; when it was last seen rides along with
// the next write that persists anything.
func rowDiff(row, n *types.Node) string {
	var out []string

	differ := func(what string, have, want any) {
		out = append(out, fmt.Sprintf("%s %v, in memory %v", what, have, want))
	}

	str := func(a *netip.Addr) string {
		if a == nil {
			return "none"
		}

		return a.String()
	}

	at := func(t *time.Time) string {
		if t == nil {
			return "never"
		}

		return t.UTC().Format(time.RFC3339Nano)
	}

	user := func(u *uint) string {
		if u == nil {
			return "none"
		}

		return strconv.FormatUint(uint64(*u), 10)
	}

	cols := []struct {
		name       string
		have, want string
	}{
		{"machine key", row.MachineKey.String(), n.MachineKey.String()},
		{"node key", row.NodeKey.String(), n.NodeKey.String()},
		{"disco key", row.DiscoKey.String(), n.DiscoKey.String()},
		{"endpoints", fmt.Sprint(row.Endpoints), fmt.Sprint(n.Endpoints)},
		{"addresses", str(row.IPv4) + " " + str(row.IPv6), str(n.IPv4) + " " + str(n.IPv6)},
		{"hostname", row.Hostname, n.Hostname},
		{"given name", row.GivenName, n.GivenName},
		{"user", user(row.UserID), user(n.UserID)},
		{"register method", row.RegisterMethod, n.RegisterMethod},
		{"tags", fmt.Sprint([]string(row.Tags)), fmt.Sprint([]string(n.Tags))},
		{"expiry", at(row.Expiry), at(n.Expiry)},
		{"approved", fmt.Sprint([]netip.Prefix(row.ApprovedRoutes)), fmt.Sprint([]netip.Prefix(n.ApprovedRoutes))},
		{"auto-approved", fmt.Sprint([]netip.Prefix(row.AutoApprovedRoutes)), fmt.Sprint([]netip.Prefix(n.AutoApprovedRoutes))},
		{"ephemeral", strconv.FormatBool(row.Ephemeral), strconv.FormatBool(n.Ephemeral)},
	}

	for _, c := range cols {
		if c.have != c.want {
			differ(c.name, c.have, c.want)
		}
	}

	if !row.Hostinfo.Equal(n.Hostinfo) {
		differ("hostinfo", jsonOf(row.Hostinfo), jsonOf(n.Hostinfo))
	}

	return strings.Join(out, "; ")
}
