package servertest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/state/statemodel"
	"github.com/juanfont/headscale/hscontrol/types"
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
	client := fd.run.slice.Judges("client")

	for _, n := range w.Topology.Nodes {
		nd := fd.nodes[n.ID]
		if polling := nd.tc.Polling(); client && polling == n.Offline {
			fd.t.Fatalf("%s: n%d's client polls: %t; the model has it offline: %t", at, n.ID, polling, n.Offline)
		}
	}

	var ref *policymodel.Held

	if fd.run.slice.Judges("reference") {
		m := statemodel.Moment(fd)
		m.Unheld = fd.unheld
		ref = fd.run.held.At(m)
	}

	for _, n := range w.Topology.Nodes {
		if n.Offline {
			continue
		}

		nd := fd.nodes[n.ID]

		nm := nd.tc.Netmap()
		if nm == nil {
			fd.t.Fatalf("%s: n%d's client polls, and holds no map", at, n.ID)
		}

		if client {
			fresh := freshNetmap(fd, snap, n.ID, nd.tc.Persist())

			fd.run.tally.clients++

			if d := policymodel.NetmapDiff(nm, fresh, func() { fd.run.tally.unseen++ }); d != "" {
				fd.t.Fatalf("%s: n%d's client, the server quiet, holds other than a fresh session of r%d is given: %s", at, n.ID, snap.Rev(), d)
			}
		}

		if ref == nil {
			continue
		}

		if d := ref.Client(n.ID, nm, fd.capSources); d != "" {
			fd.t.Fatalf("%s: n%d: reference: %s", at, n.ID, d)
		}
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

		return policymodel.ClientPeer(c.View())
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "self %s;", strip(nm.SelfNode))

	for _, p := range nm.Peers {
		fmt.Fprintf(&sb, "\n peer %s;", strip(p))
	}

	fmt.Fprintf(&sb, "\n filter %v;\n ssh %s;\n dns %s;\n profiles %s;\n caps %s",
		policymodel.CountsDiff(policymodel.RuleCounts(nm.PacketFilterRules.AsSlice()), nil), policymodel.JSON(nm.SSHPolicy), policymodel.JSON(nm.DNS), policymodel.JSON(nm.UserProfiles), policymodel.JSON(nm.AllCaps))

	return sb.String()
}

// requireStored holds what the server stored to the model
// ([statemodel.Stored]).
func (fd *frontDoor) requireStored(after string) {
	if !fd.run.slice.Judges("stored") {
		return
	}

	if d := statemodel.Stored(fd); d != "" {
		fd.t.Fatalf("after %s: %s", after, d)
	}
}

// The front door is a level the shared judges read.
var _ statemodel.Level = (*frontDoor)(nil)

func (fd *frontDoor) Model() policymodel.World                 { return fd.w }
func (fd *frontDoor) State() *state.State                      { return fd.srv.State() }
func (fd *frontDoor) Joined(id types.NodeID) statemodel.Joined { return fd.nodes[id].Joined }
func (fd *frontDoor) Elections() *policymodel.Elections        { return fd.elections }
