package mapper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"pgregory.net/rapid"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/zstdframe"
)

// realClient is one map session of the Tailscale client: the long poll
// [controlclient.Direct] runs, reading a response body the test writes
// instead of a network. Each response goes as poll writes it (JSON, zstd,
// a length prefix) and the client decodes and applies it as off the wire,
// so what it assembles across responses is the client's own answer, not a
// model of it. A reconnect is a new realClient, as a new long poll is a
// new map session.
type realClient struct {
	direct *controlclient.Direct
	body   *io.PipeWriter
	nms    chan *netmap.NetworkMap
	done   chan error
	nm     *netmap.NetworkMap
	closed bool
}

// clientHost is what every realClient's Direct is built on: nothing of it
// reaches a map session, so the clients of a test binary share it, and
// their keys, which no comparison reads.
var clientHost = sync.OnceValue(func() struct {
	bus     *eventbus.Bus
	tracker *health.Tracker
	dialer  *tsdial.Dialer
	machine key.MachinePrivate
	node    key.NodePrivate
} {
	bus := eventbus.New()

	return struct {
		bus     *eventbus.Bus
		tracker *health.Tracker
		dialer  *tsdial.Dialer
		machine key.MachinePrivate
		node    key.NodePrivate
	}{bus, health.NewTracker(bus), tsdial.NewDialer(netmon.NewStatic()), key.NewMachine(), key.NewNode()}
})

// fullNetmaps hands every netmap the session builds to the test. Not being
// a delta updater, it has the session build one for every response.
type fullNetmaps chan *netmap.NetworkMap

func (u fullNetmaps) UpdateFullNetmap(nm *netmap.NetworkMap) { u <- nm }

// bodyTransport answers the long poll's one request with body.
type bodyTransport struct{ body io.ReadCloser }

func (b bodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}

	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: b.body, Request: req}, nil
}

var (
	errClientStopped  = errors.New("the client's map session ended")
	errClientPanicked = errors.New("the client panicked")
)

func newRealClient(t pbtT) *realClient {
	t.Helper()

	host := clientHost()
	r, w := io.Pipe()

	d, err := controlclient.NewDirect(controlclient.Options{
		Persist:              persist.Persist{PrivateNodeKey: host.node},
		GetMachinePrivateKey: func() (key.MachinePrivate, error) { return host.machine, nil },
		ServerURL:            "https://headscale.test",
		Hostinfo:             &tailcfg.Hostinfo{BackendLogID: "pbt"},
		Logf:                 logger.Discard,
		HealthTracker:        host.tracker,
		Dialer:               host.dialer,
		Bus:                  host.bus,
		NoiseTestClient:      &http.Client{Transport: bodyTransport{body: r}},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	c := &realClient{direct: d, body: w, nms: make(fullNetmaps), done: make(chan error, 1)}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				c.done <- fmt.Errorf("%w: %v", errClientPanicked, p)
			}
		}()

		c.done <- d.PollNetMap(context.Background(), fullNetmaps(c.nms))
	}()

	t.Cleanup(c.close)

	return c
}

// apply has the client read resp and returns the netmap it then holds.
func (c *realClient) apply(t pbtT, resp *tailcfg.MapResponse) *netmap.NetworkMap {
	t.Helper()

	b, err := Marshal(resp)
	if err != nil {
		t.Fatalf("encoding a response: %v", err)
	}

	z := zstdframe.AppendEncode(nil, b, zstdframe.FastestCompression)
	frame := binary.LittleEndian.AppendUint32(make([]byte, 0, 4+len(z)), uint32(len(z))) //nolint:gosec // small
	frame = append(frame, z...)

	_, err = c.body.Write(frame)
	if err != nil {
		err := <-c.done
		c.done <- err

		t.Fatalf("the client stopped reading: %v", err)
	}

	select {
	case c.nm = <-c.nms:
	case err := <-c.done:
		c.done <- err

		t.Fatalf("the client refused a response: %v", err)
	case <-time.After(time.Minute):
		// A guard against a hang, never a decision.
		t.Fatalf("the client applied no response")
	}

	return c.nm
}

// ended waits for the client's long poll to return, and returns why.
func (c *realClient) ended() error { return <-c.done }

func (c *realClient) close() {
	if c.closed {
		return
	}

	c.closed = true

	_ = c.body.CloseWithError(errClientStopped)
	_ = c.ended()

	_ = c.direct.Close()
}

// debugPersist is the identity the client's one-response map sessions
// read: only its node key, which no comparison reads.
var debugPersist = sync.OnceValue(func() persist.PersistView {
	return (&persist.Persist{PrivateNodeKey: clientHost().node}).View()
})

// freshSession is a fresh session's first map of a snapshot: as the wire
// has it, and what the server cut for it.
type freshSession struct {
	wire   []byte
	served []tailcfg.FilterRule
}

func newFreshSession(t pbtT, cfg *types.Config, snap *state.Snapshot, id types.NodeID, cv tailcfg.CapabilityVersion) freshSession {
	t.Helper()

	st := NewStream(cfg, NewHub(), id, cv)

	resps, err := st.Initial(snap)
	if err != nil {
		t.Fatalf("n%d: a fresh session of r%d: %v", id, snap.Rev(), err)
	}

	if len(resps) != 1 {
		t.Fatalf("n%d: a fresh session of r%d opens with %d responses", id, snap.Rev(), len(resps))
	}

	// The time it is sent at is the one field two sessions of a snapshot
	// do not share.
	resp := *resps[0]
	resp.ControlTime = nil

	b, err := Marshal(&resp)
	if err != nil {
		t.Fatalf("encoding a first map: %v", err)
	}

	return freshSession{wire: b, served: st.sent.filter}
}

// client is what the client holds after the first map: the netmap its own
// map session builds from it, read off the bytes, and the chunks it names.
func (f freshSession) client(t pbtT) (*netmap.NetworkMap, policyv2.FilterChunks) {
	t.Helper()

	var resp tailcfg.MapResponse

	err := json.Unmarshal(f.wire, &resp)
	if err != nil {
		t.Fatalf("decoding a first map: %v", err)
	}

	chunks := policyv2.FilterChunks{}.ApplyResponse(&resp)

	nm, err := controlclient.NetmapFromMapResponseForDebug(context.Background(), debugPersist(), &resp)
	if err != nil {
		t.Fatalf("the client refuses a fresh first map: %v", err)
	}

	return nm, chunks
}

// TestCanaryClientMapSessionAcrossResponses pins, through [realClient],
// what the client's map session does with responses in turn that the
// stream's diff is written around; a failure means the client changed and
// names the part of the diff that can then be reconsidered.
func TestCanaryClientMapSessionAcrossResponses(t *testing.T) {
	t.Parallel()

	self := &tailcfg.Node{ID: 1, Name: "n1.headscale.test.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}
	ep := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	peer := func(eps []netip.AddrPort, caps tailcfg.NodeCapMap) *tailcfg.Node {
		return &tailcfg.Node{
			ID: 2, Name: "n2.headscale.test.", Key: key.NewNode().Public(), DiscoKey: key.NewDisco().Public(),
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Endpoints: eps, CapMap: caps,
		}
	}

	held := func(nm *netmap.NetworkMap) tailcfg.NodeView {
		if len(nm.Peers) != 1 {
			t.Fatalf("the client holds %d peers, want 1", len(nm.Peers))
		}

		return nm.Peers[0]
	}

	t.Run("peers-changed-endpoints-clear", func(t *testing.T) {
		t.Parallel()

		c := newRealClient(t)
		was := peer(ep, nil)
		c.apply(t, &tailcfg.MapResponse{Node: self, Peers: []*tailcfg.Node{was}})

		now := was.Clone()
		now.Endpoints = nil

		if got := held(c.apply(t, &tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{now}})).Endpoints(); got.Len() == 0 {
			t.Errorf("the client now takes an Endpoints clear from a PeersChanged entry; needsPeerListRefresh need not send a whole peer list for it")
		}
	})

	t.Run("patch-empty-capmap", func(t *testing.T) {
		t.Parallel()

		c := newRealClient(t)
		c.apply(t, &tailcfg.MapResponse{Node: self, Peers: []*tailcfg.Node{peer(ep, tailcfg.NodeCapMap{"example.com/cap/x": nil})}})

		nm := c.apply(t, &tailcfg.MapResponse{PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 2, CapMap: tailcfg.NodeCapMap{}}}})
		if held(nm).CapMap().Len() == 0 {
			t.Errorf("an empty patch CapMap now reaches the client; peerPatch need not send a whole peer to empty one")
		}
	})

	t.Run("chunks-in-turn", func(t *testing.T) {
		t.Parallel()

		rule := func(port uint16) tailcfg.FilterRule {
			return tailcfg.FilterRule{SrcIPs: []string{"100.64.0.2"}, DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1", Ports: tailcfg.PortRange{First: port, Last: port}}}}
		}

		a, b, d := rule(1), rule(2), rule(3)
		c := newRealClient(t)

		var model policyv2.FilterChunks

		for i, step := range []struct {
			chunks map[string][]tailcfg.FilterRule
			want   []tailcfg.FilterRule
		}{
			{map[string][]tailcfg.FilterRule{"*": nil, "r/a": {a}}, []tailcfg.FilterRule{a}},
			{map[string][]tailcfg.FilterRule{"r/b": {b}}, []tailcfg.FilterRule{a, b}},
			{map[string][]tailcfg.FilterRule{"r/a": nil}, []tailcfg.FilterRule{b}},
			{map[string][]tailcfg.FilterRule{"*": nil, "r/d": {d}}, []tailcfg.FilterRule{d}},
			{map[string][]tailcfg.FilterRule{"base": {a}}, []tailcfg.FilterRule{a, d}},
		} {
			resp := &tailcfg.MapResponse{PacketFilters: step.chunks}
			if i == 0 {
				resp.Node = self
			}

			model = model.ApplyResponse(resp)
			got := c.apply(t, resp).PacketFilterRules.AsSlice()

			if !reflect.DeepEqual(got, step.want) {
				t.Errorf("response %d: the client holds %s, want %s; FilterChunks, the model of it, must follow", i, jsonOf(got), jsonOf(step.want))
			}

			if m := model.Rules(); !reflect.DeepEqual(got, m) {
				t.Errorf("response %d: the client holds %s, the model of it %s", i, jsonOf(got), jsonOf(m))
			}
		}
	})
}

// jsonOf is v as the wire has it, for comparisons where nil and empty are
// the same and messages.
func jsonOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unencodable: " + err.Error()
	}

	return string(b)
}

// clientPeer is a peer as the client acts on it. A patch cannot clear
// LastSeen when a peer comes online, and the client acts on Online then
// (see [peerPatch]), so an online peer's LastSeen is left out.
func clientPeer(n tailcfg.NodeView) string {
	p := n.AsStruct()
	if p.Online != nil && *p.Online {
		p.LastSeen = nil
	}

	// TODO(kradalby): render/addresses-nil: see clientAddresses.
	if p.Addresses == nil {
		p.Addresses = []netip.Prefix{}
	}

	if p.AllowedIPs == nil {
		p.AllowedIPs = p.Addresses
	}

	return jsonOf(p)
}

// sameNode reports whether a and b are the same node to the client; on the
// wire when [tailcfg.NodeView.Equal], which is stricter about nil and
// empty, cannot tell.
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
		// in a change no patch carries (its CapMap or endpoints emptied) is
		// sent whole; Tailscale's client patchifies it and keeps no
		// LastSeen it did not hold, so its session shows the peer offline
		// without the LastSeen a fresh one does. Counted, not judged.
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

// peerIDsOfNetmap is nm's peers, in the client's order (by ID).
func peerIDsOfNetmap(nm *netmap.NetworkMap) []tailcfg.NodeID {
	out := make([]tailcfg.NodeID, len(nm.Peers))
	for i, p := range nm.Peers {
		out[i] = p.ID()
	}

	return out
}

// deliveryCombo is one setting of policy.capability_sources and
// policy.filter_chunks.
type deliveryCombo struct{ capSources, chunks bool }

func (c deliveryCombo) String() string {
	return fmt.Sprintf("capability_sources=%t/filter_chunks=%t", c.capSources, c.chunks)
}

// deliveryCombos are all four; the first, both off, is what the others
// are held to.
var deliveryCombos = []deliveryCombo{{false, false}, {false, true}, {true, false}, {true, true}}

// chunkedFor is the per-client decision as the model states it: chunks go
// only to Tailscale's own client, and only with the option on.
func chunkedFor(on bool, c policymodel.Client) bool {
	return on && (c == policymodel.Official || c == policymodel.AppConnector)
}

// stepPlan is what happens to sessions at the end of a step, drawn once
// and played in every world: which lag (leave their wake for a later
// step), whose write fails (and after how many responses), which come
// back only at the next step, which reconnect cleanly, which reconnect
// before their old session ends (it lives on through the next step).
type stepPlan struct {
	lag, fail, later, reconnect, overlap []int
	failAt                               int
}

var stepPlans = rapid.Custom(func(t *rapid.T) stepPlan {
	pick := func(label string) []int { return rapid.SliceOfN(rapid.IntRange(0, 15), 0, 2).Draw(t, label) }

	return stepPlan{
		lag: pick("lag"), fail: pick("fail"), later: pick("later"), reconnect: pick("reconnect"),
		failAt: rapid.IntRange(0, 2).Draw(t, "fail-at"), overlap: pick("overlap"),
	}
})

// names maps a plan's indices to the nodes of ids.
func (p stepPlan) names(picks []int, ids []types.NodeID, id types.NodeID) bool {
	return len(ids) > 0 && slices.ContainsFunc(picks, func(i int) bool { return ids[i%len(ids)] == id })
}

// chunkRegistry holds every chunk any session was sent, by name and by
// content, across the worlds of one case.
type chunkRegistry struct {
	byName, byContent map[string]string
}

// see holds one chunk sent under name to the naming contract: a name is
// one content, one content is one name; an r/ chunk is one rule without a
// CapGrant, a c/ chunk only rules with one.
func (cr *chunkRegistry) see(name string, rules []tailcfg.FilterRule) string {
	switch {
	case name == "base":
		return ""
	case strings.HasPrefix(name, "r/"):
		if len(rules) != 1 || len(rules[0].CapGrant) > 0 {
			return fmt.Sprintf("chunk %s holds %d rules, CapGrant %t", name, len(rules), len(rules) > 0 && len(rules[0].CapGrant) > 0)
		}
	case strings.HasPrefix(name, "c/"):
		if len(rules) == 0 || slices.ContainsFunc(rules, func(r tailcfg.FilterRule) bool { return len(r.CapGrant) == 0 }) {
			return fmt.Sprintf("chunk %s holds a rule without a CapGrant, or none", name)
		}
	default:
		return fmt.Sprintf("chunk name %q has no known prefix", name)
	}

	content := jsonOf(rules)

	if was, ok := cr.byName[name]; ok && was != content {
		return fmt.Sprintf("chunk %s named %s before, now %s", name, was, content)
	}

	if was, ok := cr.byContent[content]; ok && was != name {
		return fmt.Sprintf("%s went as %s before, now as %s", content, was, name)
	}

	cr.byName[name], cr.byContent[content] = content, name

	return ""
}

// deliveryReach counts what the cases reached.
type deliveryReach struct {
	compared, lagged, failed, reconnected, flips, clears, added, deleted, wholeSent int
	churnJudged, crossFamily, combosCompared, keptCleared                           int
	overlapped, indexed                                                             int
	// unseen counts offline peers a client holds without the LastSeen a
	// fresh session shows (see [netmapDiff]), and unindexed the clients
	// whose index lost their own address after a shared one.
	unseen, unindexed int
	// laggedFlips counts lagged renders across a delivery flip, and
	// laggedForms across a flip of the form the node is served.
	laggedFlips, laggedForms int
	// writes counts the writes made through production entry points, and
	// scripts the scripts played, by kind, in one world of each case.
	writes, scripts map[string]int
	// wakes counts what woke each render that sent something.
	wakes *wakeTally
}

func (r deliveryReach) String() string {
	return fmt.Sprintf("sessions held to a fresh one %d, lagged renders %d, failed writes %d, reconnects %d, delivery flips %d, "+
		"clears %d, chunks added %d and deleted %d, whole filters sent %d, membership-churn receivers judged %d, "+
		"nodes held across the four combinations %d (cross-family ICMP refused %d), kept chunks cleared %d, overlapping reconnects %d, "+
		"address indexes held %d (own address lost after a shared one %d), offline peers held without LastSeen %d, "+
		"lagged renders across a delivery flip %d and across a form flip %d; writes through production entry points %v, "+
		"scripts %v; renders that sent something: %s",
		r.compared, r.lagged, r.failed, r.reconnected, r.flips, r.clears, r.added, r.deleted, r.wholeSent,
		r.churnJudged, r.combosCompared, r.crossFamily, r.keptCleared, r.overlapped, r.indexed, r.unindexed, r.unseen,
		r.laggedFlips, r.laggedForms, r.writes, r.scripts, r.wakes)
}

// deliveryJudge is one part of what [TestDeliveryConvergesThroughTheClient]
// holds; each failure names its part.
type deliveryJudge int

const (
	// judgeClient: a session's client equals a fresh session's, and its
	// assembled filter the one served.
	judgeClient deliveryJudge = iota
	// judgeModel: the model of the client's chunks assembles what the
	// client does, response by response.
	judgeModel
	// judgeWire: every response follows the chunk scheme.
	judgeWire
	// judgeChurn: membership churn sends capability-form receivers no
	// filter.
	judgeChurn
	// judgeKept: a client keeping chunks across sessions is reset by the
	// next first map.
	judgeKept
	// judgeCombos: the four combinations enforce alike.
	judgeCombos
	// judgeReference: what a client holds is what the reference gives its
	// node (see [deliveryRun.holdToReference]).
	judgeReference
	// judgeIndex: the client's index of nodes by address, kept across
	// responses as tailscaled keeps it, indexes every address its netmap
	// holds (see [addrIndex]).
	judgeIndex
	numJudges
)

var judgeNames = [numJudges]string{"client", "model", "wire", "churn", "kept", "combos", "reference", "index"}

func (j deliveryJudge) String() string { return judgeNames[j] }

// deliveryJudgesEnv, a comma-separated list of [judgeNames], narrows a run
// to those parts, so a mutation run can tell which part kills what.
const deliveryJudgesEnv = "HEADSCALE_PBT_DELIVERY_JUDGES"

func deliveryJudges(t *testing.T) [numJudges]bool {
	t.Helper()

	var on [numJudges]bool

	v := os.Getenv(deliveryJudgesEnv)
	for j := range numJudges {
		on[j] = v == ""
	}

	for name := range strings.SplitSeq(v, ",") {
		if i := slices.Index(judgeNames[:], name); i >= 0 {
			on[i] = true
		} else if name != "" {
			t.Fatalf("%s: no part %q", deliveryJudgesEnv, name)
		}
	}

	return on
}

// deliverySess is one map session of a node and the client it writes to.
type deliverySess struct {
	id     types.NodeID
	st     *Stream
	sess   *Session
	capVer tailcfg.CapabilityVersion
	client *realClient
	// held is what the session's client holds in chunks, as the model of
	// the client applies what it was sent; every response holds it to the
	// filter the real client assembled.
	held policyv2.FilterChunks
	// chunked is the delivery the model decided at its last render, and
	// rev that render's revision.
	chunked bool
	rev     uint64
	// last is the snapshot it last rendered.
	last  *state.Snapshot
	ended atomic.Bool
	// skipped is set while it leaves a wake for a later step.
	skipped bool
	// index is the client's index of nodes by address; superseded the
	// step a newer session of the node opened beside it.
	index      addrIndex
	superseded int
	// judged is the netmap last held to a fresh first map, and that map.
	judged struct {
		nm   *netmap.NetworkMap
		wire []byte
	}
}

// deliveryWorld is one State in one combination, its hub routing in step,
// with a session per node.
type deliveryWorld struct {
	t        *rapid.T
	combo    deliveryCombo
	p        *pbtWorld
	h        *Hub
	w        *steppedWatcher
	coalesce bool
	mixed    bool
	sess     map[types.NodeID]*deliverySess
	// old holds the sessions a reconnect overlapped, which still render
	// for a step; steps counts the steps played.
	old   map[types.NodeID]*deliverySess
	steps int
	// down holds the nodes whose session a failed write ended, until they
	// reconnect.
	down map[types.NodeID]bool
	// kept is what a client keeping its chunks across map sessions holds
	// (tailscale-rs does; the Tailscale client cannot be made to): it
	// applies every response that arrived, including those before a
	// failed write.
	kept   map[types.NodeID]policyv2.FilterChunks
	names  *chunkRegistry
	probes probeCache
	judges *[numJudges]bool
	reach  *deliveryReach
	// shared is whether the start or any commit had two nodes share an
	// address: a write of several nodes commits them one at a time.
	shared bool
	// kind names the step being delivered, for what woke its renders.
	kind string
	// dropped is Route's answers with each part taken out, by pair.
	dropped droppedWakes
}

func newDeliveryWorld(t *rapid.T, r *deliveryRun, c deliveryCombo, w policymodel.World, coalesce, mixed bool, names *chunkRegistry) *deliveryWorld {
	dw := &deliveryWorld{
		t: t, combo: c, coalesce: coalesce, mixed: mixed, names: names, probes: r.probes, judges: &r.judges, reach: &r.reach,
		dropped: droppedWakes{},
		sess:    map[types.NodeID]*deliverySess{}, old: map[types.NodeID]*deliverySess{}, down: map[types.NodeID]bool{}, kept: map[types.NodeID]policyv2.FilterChunks{},
	}

	dw.p = newPBTWorld(t, w, func(cfg *types.Config) {
		cfg.Policy.CapabilitySources, cfg.Policy.FilterChunks = c.capSources, c.chunks
	})

	if snap := dw.p.s.Snapshot(); snap.CapabilitySources() != c.capSources || snap.FilterChunks() != c.chunks {
		t.Fatalf("test sanity: %s built a world with capability_sources=%t/filter_chunks=%t", c, snap.CapabilitySources(), snap.FilterChunks())
	}

	dw.shared, _ = heldAddresses(dw.p.s.Snapshot())

	dw.h = NewHub()
	dw.w = newSteppedWatcher(t, dw.h, dw.p.s)
	dw.p.committed = func(before uint64) {
		dw.w.committed(before)

		shared, _ := heldAddresses(dw.p.s.Snapshot())
		dw.shared = dw.shared || shared

		if !dw.coalesce && dw.p.s.Snapshot().Rev() != before {
			dw.w.settle()
		}
	}

	return dw
}

func (dw *deliveryWorld) logf(format string, args ...any) {
	dw.t.Logf("[%s] "+format, append([]any{dw.combo}, args...)...)
}

func (dw *deliveryWorld) fatalf(format string, args ...any) {
	dw.t.Fatalf("[%s] "+format, append([]any{dw.combo}, args...)...)
}

// failf fails the case for part j, when the run holds it.
func (dw *deliveryWorld) failf(j deliveryJudge, format string, args ...any) {
	if dw.judges[j] {
		dw.t.Fatalf("[%s] %s: "+format, append([]any{dw.combo, j}, args...)...)
	}
}

// client is the client the model's latest world says id runs.
func (dw *deliveryWorld) client(id types.NodeID) policymodel.Client {
	n, _ := dw.p.w.Topology.Node(id)

	return n.Client
}

// admit opens a session of id and writes its first map.
func (dw *deliveryWorld) admit(id types.NodeID) {
	s := &deliverySess{id: id, capVer: capVer}
	if dw.mixed && id%2 == 1 {
		s.capVer = capver.MinSupportedCapabilityVersion
	}

	s.sess = dw.h.Join(id, func() { s.ended.Store(true) })
	s.st = NewStream(dw.p.cfg, dw.h, id, s.capVer)
	s.st.Attach(s.sess)
	s.client = newRealClient(dw.t)
	dw.sess[id] = s

	snap := dw.p.s.Snapshot()

	resps, err := s.st.Initial(snap)
	if err != nil {
		dw.fatalf("n%d's first map of r%d: %v", id, snap.Rev(), err)
	}

	if dw.kept[id].Len() > 0 {
		dw.reach.keptCleared++
	}

	s.chunked = chunkedFor(dw.combo.chunks, dw.client(id))
	dw.checkWire(s, resps, true)
	dw.write(s, resps)
	s.st.Delivered()
	s.rev, s.last = snap.Rev(), snap

	if k := dw.kept[id]; !k.Equal(s.held) {
		dw.failf(judgeKept, "n%d reconnected: a client keeping chunks across sessions holds %v, a new session %v", id, k.Names(), s.held.Names())
	}

	dw.logf("n%d opens a session at r%d: %s", id, snap.Rev(), describeResponses(resps))
}

// checkWire holds the PacketFilters of responses a session returns to the
// chunk scheme, before its client applies them: the clear in a stream's
// first response and in the response of a delivery flip, and in no other;
// only "base" to a client sent the whole filter, never "base" to one sent
// chunks; an update naming only chunks its client lacks and deleting only
// chunks it holds; every chunk under the name of its content alone.
func (dw *deliveryWorld) checkWire(s *deliverySess, resps []*tailcfg.MapResponse, first bool) {
	want := chunkedFor(dw.combo.chunks, dw.client(s.id))
	flip := !first && want != s.chunked
	clears := 0

	// Where the clear goes first: a missing one is what makes the entries
	// below look wrong.
	for _, r := range resps {
		if _, ok := r.PacketFilters["*"]; ok {
			clears++
		}
	}

	switch {
	case first && (len(resps) == 0 || resps[0].PacketFilters == nil || clears != 1):
		dw.failf(judgeWire, "n%d's first map clears %d times, not in its first response", s.id, clears)
	case flip && clears != 1:
		dw.failf(judgeWire, "n%d's delivery flipped to chunked=%t; its update clears %d times", s.id, want, clears)
	case !first && !flip && clears != 0:
		dw.failf(judgeWire, "n%d's delivery stayed chunked=%t; its update clears %d times", s.id, want, clears)
	}

	held := s.held

	for i, r := range resps {
		if r.PacketFilter != nil {
			dw.failf(judgeWire, "n%d response %d sets the singular PacketFilter", s.id, i)
		}

		pf := r.PacketFilters
		if pf == nil {
			continue
		}

		v, cleared := pf["*"]
		if cleared {
			if v != nil {
				dw.failf(judgeWire, "n%d response %d: \"*\" is not null", s.id, i)
			}

			held = policyv2.FilterChunks{}
		}

		for _, name := range slices.Sorted(maps.Keys(pf)) {
			dw.checkChunk(s, held, name, pf[name], want, cleared)
		}

		before := held.Rules()
		held = held.Apply(pf)

		// The whole filter goes again only when what it holds would move.
		if _, ok := pf["base"]; ok && !cleared && ruleList(before) == ruleList(held.Rules()) {
			dw.failf(judgeWire, "n%d is sent its whole filter again, unchanged: %s", s.id, ruleList(before))
		}
	}

	if flip {
		dw.reach.flips++
	}

	dw.reach.clears += clears
	s.chunked = want
}

// checkChunk holds one entry of an update's PacketFilters, sent to s's
// client holding held, to the chunk scheme; want is the delivery the model
// decides and cleared whether the update clears first.
func (dw *deliveryWorld) checkChunk(s *deliverySess, held policyv2.FilterChunks, name string, rules []tailcfg.FilterRule, want, cleared bool) {
	switch {
	case name == "*":
	case want == (name == "base"):
		dw.failf(judgeWire, "n%d (client %s, chunks %t) is sent %q", s.id, dw.client(s.id), dw.combo.chunks, name)
	case name == "base":
		if rules != nil {
			dw.reach.wholeSent++
		}
	case rules == nil:
		if _, ok := held.Chunk(name); !ok || cleared {
			dw.failf(judgeWire, "n%d is sent a null for %s, which it does not hold", s.id, name)
		}

		dw.reach.deleted++
	default:
		if had, ok := held.Chunk(name); ok && reflect.DeepEqual(had, rules) {
			dw.failf(judgeWire, "n%d is sent %s, which it holds already", s.id, name)
		}

		dw.reach.added++

		if d := dw.names.see(name, rules); d != "" {
			dw.failf(judgeWire, "n%d: %s", s.id, d)
		}
	}
}

// write has s's client read resps, as a client keeping chunks across
// sessions does too. Each response holds the model of the client's chunks
// to the filter the real client then assembles, in order.
func (dw *deliveryWorld) write(s *deliverySess, resps []*tailcfg.MapResponse) {
	for i, r := range resps {
		dw.kept[s.id] = dw.kept[s.id].ApplyResponse(r)
		s.held = s.held.ApplyResponse(r)
		before := s.client.nm
		nm := s.client.apply(dw.t, r)
		s.index = s.index.apply(before, nm, r)

		if have, model := ruleList(nm.PacketFilterRules.AsSlice()), ruleList(s.held.Rules()); have != model {
			dw.failf(judgeModel, "n%d response %d: the client assembled %s, the model of it %s", s.id, i, have, model)
		}
	}
}

// lose is a write that failed once resps arrived: a client keeping chunks
// across sessions applied them; the Tailscale client's map session ends
// with the connection.
func (dw *deliveryWorld) lose(s *deliverySess, resps []*tailcfg.MapResponse) {
	for _, r := range resps {
		dw.kept[s.id] = dw.kept[s.id].ApplyResponse(r)
	}
}

// probeCache remembers the client's answers to comparisons already made:
// each is a function of the two filters and of what each view reads of
// its netmap, and the same filters come back step after step and in every
// world.
type probeCache map[string]policymodel.Report

func (pc probeCache) compare(ref []tailcfg.FilterRule, refNM *netmap.NetworkMap, cand []tailcfg.FilterRule, candNM *netmap.NetworkMap) policymodel.Report {
	k := ruleList(ref) + clientViewKey(refNM) + "\x00" + ruleList(cand) + clientViewKey(candNM)
	if rep, ok := pc[k]; ok {
		return rep
	}

	if len(pc) > 1<<14 {
		clear(pc)
	}

	rep := policymodel.CompareUnder(ref, policymodel.ViewFromNetmap(refNM), cand, policymodel.ViewFromNetmap(candNM))
	pc[k] = rep

	return rep
}

// clientViewKey is what [policymodel.ViewFromNetmap] reads of nm.
func clientViewKey(nm *netmap.NetworkMap) string {
	type peer struct {
		Addresses []netip.Prefix
		CapMap    tailcfg.NodeCapMap
		Unsigned  bool
	}

	peers := make([]peer, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		peers = append(peers, peer{p.Addresses().AsSlice(), p.AsStruct().CapMap, p.UnsignedPeerAPIOnly()})
	}

	return jsonOf(nm.SelfNode) + jsonOf(peers)
}

// ruleList is rules as the wire has them, an empty list as none.
func ruleList(rules []tailcfg.FilterRule) string {
	if len(rules) == 0 {
		return "[]"
	}

	return jsonOf(rules)
}

// render has s take its wake and render the latest snapshot; its write
// fails after failAt responses when fail is set.
func (dw *deliveryWorld) render(s *deliverySess, fail bool, failAt int) {
	<-s.sess.wakes

	snap := dw.p.s.Snapshot()

	resps, err := s.st.Update(snap)
	if errors.Is(err, ErrNodeGone) {
		dw.drop(s)

		return
	}

	if err != nil {
		dw.fatalf("n%d renders r%d: %v", s.id, snap.Rev(), err)
	}

	if s.skipped {
		dw.reach.lagged++
		s.skipped = false

		if chunkedFor(dw.combo.chunks, dw.client(s.id)) != s.chunked {
			dw.reach.laggedFlips++
		}

		if s.last != nil && capabilityForm(s.last.ReceiverFacts(s.id)) != capabilityForm(snap.ReceiverFacts(s.id)) {
			dw.reach.laggedForms++
		}
	}

	dw.checkWire(s, resps, false)

	if fail && len(resps) > 0 {
		at := min(failAt, len(resps)-1)
		dw.lose(s, resps[:at])
		dw.logf("n%d renders r%d: %s; the write fails after %d", s.id, snap.Rev(), describeResponses(resps), at)
		dw.drop(s)
		dw.down[s.id] = true
		dw.reach.failed++

		return
	}

	dw.write(s, resps)
	s.st.Delivered()
	dw.wokeFor(s, snap, resps)
	s.rev, s.last = snap.Rev(), snap
	dw.logf("n%d renders r%d: %s", s.id, snap.Rev(), describeResponses(resps))
}

// wokeFor counts what woke s for a render of snap that sent resps.
func (dw *deliveryWorld) wokeFor(s *deliverySess, snap *state.Snapshot, resps []*tailcfg.MapResponse) {
	if len(resps) == 0 || s.last == nil {
		return
	}

	c := snap.Since(s.last)
	all, _ := Route(s.last, snap, c)
	dw.reach.wakes.add(dw.dropped, s.last, snap, all, c, s.id, s.last.Rev()+1 < snap.Rev(), false, dw.kind)
}

func (dw *deliveryWorld) drop(s *deliverySess) {
	dw.h.Leave(s.sess)
	s.client.close()

	if dw.sess[s.id] == s {
		delete(dw.sess, s.id)
	}

	if dw.old[s.id] == s {
		delete(dw.old, s.id)
	}
}

// step commits st's edits, a commit each, and maybe a node's endpoint,
// set or cleared; the watcher routes after each commit, or once at the
// end when commits coalesce.
func (dw *deliveryWorld) step(st policymodel.Step, touch, clearEndpoint bool, who, i int, writes ...func(*pbtWorld) string) {
	dw.steps++

	for _, e := range st.Edits {
		dw.p.edit(e)
	}

	if nodes := dw.p.s.Snapshot().ListNodes(); touch && nodes.Len() > 0 {
		pick := nodes.At(who % nodes.Len())

		// A clear goes to a node that has endpoints when one does: a peer
		// losing its endpoints is what no patch can say.
		if clearEndpoint {
			var with []types.NodeView

			for _, n := range nodes.All() {
				if n.Endpoints().Len() > 0 {
					with = append(with, n)
				}
			}

			if len(with) > 0 {
				pick = with[who%len(with)]
			}
		}

		n := pick.AsStruct()

		n.Endpoints = nil
		if !clearEndpoint {
			n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1))} //nolint:gosec // small
		}

		dw.p.call(func() { dw.p.s.PutNodeInStoreForTest(*n) })
	}

	for _, w := range writes {
		if did := w(dw.p); did != "" {
			dw.logf("%s", did)
		}
	}

	dw.w.settle()

	for _, set := range []map[types.NodeID]*deliverySess{dw.sess, dw.old} {
		for _, id := range slices.Sorted(maps.Keys(set)) {
			if s := set[id]; s.ended.Load() {
				dw.logf("n%d's session ended by the hub", id)
				dw.drop(s)
			}
		}
	}

	for id := range dw.down {
		if _, ok := dw.p.w.Topology.Node(id); !ok {
			delete(dw.down, id)
		}
	}
}

// deliver has every session render what it was woken for, as the plan
// says, until nothing is pending but the lagging sessions' wakes; and
// opens sessions for nodes that have none, but those down until later.
func (dw *deliveryWorld) deliver(plan stepPlan, ids []types.NodeID) {
	// A session a reconnect overlapped two steps back ends now: it was
	// woken and judged beside the newer one for a whole step.
	for _, id := range slices.Sorted(maps.Keys(dw.old)) {
		if s := dw.old[id]; s.superseded < dw.steps-1 {
			dw.logf("n%d's overlapped session ends", id)
			dw.drop(s)
		}
	}

	for _, id := range ids {
		if s := dw.sess[id]; s != nil && plan.names(plan.reconnect, ids, id) {
			dw.logf("n%d reconnects", id)
			dw.drop(s)
			dw.reach.reconnected++
		}

		if s := dw.sess[id]; s != nil && dw.old[id] == nil && plan.names(plan.overlap, ids, id) {
			dw.logf("n%d reconnects before its session ends", id)
			s.superseded = dw.steps
			dw.old[id] = s
			delete(dw.sess, id)
			dw.reach.overlapped++
		}

		if dw.down[id] && !plan.names(plan.later, ids, id) {
			delete(dw.down, id)
			dw.reach.reconnected++
		}
	}

	failed := map[types.NodeID]bool{}

	for progress := true; progress; {
		progress = false

		for _, id := range ids {
			s := dw.sess[id]

			if o := dw.old[id]; o != nil && len(o.sess.wakes) > 0 {
				dw.render(o, false, 0)

				progress = true
			}

			switch {
			case s == nil && !dw.down[id]:
				dw.admit(id)

				progress = true
			case s == nil || len(s.sess.wakes) == 0:
			case plan.names(plan.lag, ids, id):
				s.skipped = true
			default:
				fail := plan.names(plan.fail, ids, id) && !failed[id]
				failed[id] = fail || failed[id]

				dw.render(s, fail, plan.failAt)

				if fail && dw.down[id] && !plan.names(plan.later, ids, id) {
					delete(dw.down, id)
					dw.reach.reconnected++
				}

				progress = true
			}
		}
	}
}

// fresh holds every session with no wake pending to a fresh session of the
// latest snapshot, through the client: what its client assembled equals
// what a fresh session's client does, the chunks it holds are those a
// fresh session names, and the filter it assembled answers as the filter
// served, in one list. A session a reconnect overlapped is held alike; the
// newest session of each node is what it returns. In capability mode, the
// client's index of nodes by address must hold every address its netmap
// does.
func (dw *deliveryWorld) fresh(at string) map[types.NodeID]*netmap.NetworkMap {
	snap := dw.p.s.Snapshot().Uncached()
	out := map[types.NodeID]*netmap.NetworkMap{}

	var all []*deliverySess

	for _, set := range []map[types.NodeID]*deliverySess{dw.sess, dw.old} {
		for _, id := range slices.Sorted(maps.Keys(set)) {
			all = append(all, set[id])
		}
	}

	for _, s := range all {
		id := s.id
		if len(s.sess.wakes) > 0 {
			continue
		}

		fresh := newFreshSession(dw.t, dw.p.cfg, snap, id, s.capVer)
		have := s.client.nm

		if dw.sess[id] == s {
			out[id] = have
		}

		if dw.combo.capSources {
			dw.reach.indexed++

			// TODO(kradalby): render/self-address-evicted: once an address
			// was shared (database only), a peer holding the viewer's own
			// address that leaves its peers goes as a removal, which takes
			// that address out of the client's index. Counted, not judged.
			var own tailcfg.NodeID
			if dw.shared || policymodel.SharesAddress(dw.p.w) {
				own = id.NodeID()
			}

			if a, holder, ok := s.index.forgotten(have, own); ok {
				dw.failf(judgeIndex, "%s: n%d's client, last rendered r%d, indexes nobody at %s, which n%d holds", at, id, s.rev, a, holder)
			} else if _, _, ok := s.index.forgotten(have, 0); ok {
				dw.reach.unindexed++
			}
		}

		// The client is a function of what it read: the same netmap held
		// against the same first map was judged already.
		if s.judged.nm == have && string(s.judged.wire) == string(fresh.wire) {
			continue
		}

		want, chunks := fresh.client(dw.t)

		if d := netmapDiff(have, want, func() { dw.reach.unseen++ }); d != "" {
			dw.failf(judgeClient, "%s: n%d's client, last rendered r%d, differs from a fresh session's of r%d: %s", at, id, s.rev, snap.Rev(), d)
		}

		if !s.held.Equal(chunks) {
			dw.failf(judgeClient, "%s: n%d's client holds chunks %v, a fresh session's %v", at, id, s.held.Names(), chunks.Names())
		}

		if d := servedDiff(dw.probes, have, fresh.served); d != "" {
			dw.failf(judgeClient, "%s: n%d's assembled filter is not the one served: %s", at, id, d)
		}

		s.judged.nm, s.judged.wire = have, fresh.wire
		dw.reach.compared++
	}

	return out
}

// servedDiff holds the filter a client assembled from chunks to the list
// served: the same rules, but for a rule served twice, which goes in one
// chunk; the rules carrying app capabilities in the order served, which is
// the order an application reads their values in; and the same verdicts
// and app capabilities through the client's filter.
func servedDiff(pc probeCache, nm *netmap.NetworkMap, served []tailcfg.FilterRule) string {
	assembled := nm.PacketFilterRules.AsSlice()
	if slices.EqualFunc(assembled, served, func(a, b tailcfg.FilterRule) bool { return reflect.DeepEqual(a, b) }) {
		return ""
	}

	if a, s := slices.Sorted(maps.Keys(ruleCounts(assembled))), slices.Sorted(maps.Keys(ruleCounts(served))); !slices.Equal(a, s) {
		return fmt.Sprintf("assembled %v, served %v", a, s)
	}

	capRules := func(rules []tailcfg.FilterRule) string {
		return ruleList(slices.DeleteFunc(slices.Clone(rules), func(r tailcfg.FilterRule) bool { return len(r.CapGrant) == 0 }))
	}

	if a, s := capRules(assembled), capRules(served); a != s {
		return fmt.Sprintf("app capability rules assembled %s, served %s", a, s)
	}

	// Past the two checks above no view can tell them apart, so each pair
	// is put through the client once, under the first view it comes with.
	k := "served " + ruleList(served) + ruleList(assembled)
	rep, ok := pc[k]

	if !ok {
		view := policymodel.ViewFromNetmap(nm)
		rep = policymodel.CompareUnder(served, view, assembled, view)
		pc[k] = rep
	}

	if !rep.Equivalent() {
		return rep.String()
	}

	return ""
}

// combosAgree holds, for every node all four worlds hold to a fresh
// session, what its client enforces to the same across the combinations:
// its peers and their routes, the CapMaps but the stamps capability mode
// adds, SSH and DNS, and the verdicts and app capabilities of its filter
// through the client under its own netmap. Capability form may refuse
// what address form accepts in one class only (TODO(kradalby):
// capsrc/portless: an ICMP protocol number carried in the other family's
// packet), counted.
func combosAgree(t *rapid.T, at string, r *deliveryRun, worlds []*deliveryWorld, held []map[types.NodeID]*netmap.NetworkMap, agreed map[[2]*netmap.NetworkMap]bool) {
	if !r.judges[judgeCombos] {
		return
	}

	seen := map[*netmap.NetworkMap]string{}
	enforcedOf := func(nm *netmap.NetworkMap) string {
		if e, ok := seen[nm]; ok {
			return e
		}

		seen[nm] = enforced(nm)

		return seen[nm]
	}

	for _, id := range slices.Sorted(maps.Keys(held[0])) {
		ref := held[0][id]

		for i, dw := range worlds[1:] {
			cand, ok := held[i+1][id]
			if !ok || agreed[[2]*netmap.NetworkMap{ref, cand}] {
				continue
			}

			if want, got := enforcedOf(ref), enforcedOf(cand); want != got {
				t.Fatalf("combos: %s: n%d's client holds under %s %s, under %s %s", at, id, worlds[0].combo, want, dw.combo, got)
			}

			rep := r.probes.compare(ref.PacketFilterRules.AsSlice(), ref, cand.PacketFilterRules.AsSlice(), cand)

			if dw.combo.capSources {
				var crossed int

				crossed, rep = rep.SplitCrossFamilyICMP()
				r.reach.crossFamily += crossed
			}

			_, rep = rep.SplitHidden(policymodel.NotShown(dw.p.w, slices.Concat(cand.Peers, []tailcfg.NodeView{cand.SelfNode}), slices.Concat(ref.Peers, []tailcfg.NodeView{ref.SelfNode})))

			if !rep.Equivalent() {
				t.Fatalf("combos: %s: n%d's client enforces otherwise under %s than under %s: %s", at, id, dw.combo, worlds[0].combo, rep)
			}

			agreed[[2]*netmap.NetworkMap{ref, cand}] = true

			r.reach.combosCompared++
		}
	}
}

// referenceTally is what [deliveryRun.holdToReference] met.
type referenceTally struct {
	verdicts policymodel.Verdicts
	form     policymodel.FormJudge
	// passed holds the filters held to the reference already, by
	// everything the comparison reads.
	passed map[string]bool

	clients, filters, peerSets, routePairs, ssh int
	steered, unjudgedRoutes, primaries          int
	contestedPeers, contestedRoutes             map[policymodel.Contested]int
	skipped                                     map[string]int

	// byHistory counts the routes only the election history decides:
	// unjudged without it, judged with it.
	byHistory int
	// addressless counts the peers whose via-steered routes a viewer
	// holding no address is given fewer of than the reference gives
	// (see [heldClient.routes]).
	addressless int
}

func (rt *referenceTally) skip(why string) {
	if rt.skipped == nil {
		rt.skipped = map[string]int{}
	}

	rt.skipped[why]++
}

func (rt *referenceTally) String() string {
	return fmt.Sprintf("reference: clients judged %d, filters compared %d, peer sets %d, route pairs %d (steered pairs judged %d, routes left unjudged %d, "+
		"decided by the election history %d, steered short to a viewer without addresses %d), self primaries %d, SSH policies %d; skipped %v; "+
		"peers contested %v, routes contested %v; filters: %v; form: %v",
		rt.clients, rt.filters, rt.peerSets, rt.routePairs, rt.steered, rt.unjudgedRoutes, rt.byHistory, rt.addressless, rt.primaries, rt.ssh, rt.skipped,
		rt.contestedPeers, rt.contestedRoutes, &rt.verdicts, &rt.form)
}

// require fails a run that held nothing of some kind to the reference.
// Steered pairs and routes the election history decides come from few
// worlds, so a run of the default length can meet none; deep runs alone
// are asked for them.
func (rt *referenceTally) require(t *testing.T, deep bool) {
	t.Helper()

	floors := map[string]int{
		"filters": rt.filters, "peer sets": rt.peerSets, "route pairs": rt.routePairs,
		"self primaries": rt.primaries, "SSH policies": rt.ssh, "filters with a cap: source": rt.form.WithCaps,
	}

	if deep {
		floors["steered route pairs"], floors["routes the election history decides"] = rt.steered, rt.byHistory
	}

	for name, n := range floors {
		if n == 0 {
			t.Errorf("reference: no case held %s to the reference", name)
		}
	}
}

// holdToReference holds what the client of every session held to a fresh
// one holds to the reference, read for the latest world, in each of the
// four worlds: its peers are the reference's; each peer carries in its
// AllowedIPs what the reference gives once the routers are elected
// ([policymodel.Ref.ServedRoutes]), and the node itself is primary for
// what the election gives it; its packet filter answers as the
// reference's rules through its own client ([policymodel.Verdicts], the
// allowances and contested clauses of the reference properties); it and
// its peers carry the reference's stamps in capability mode and none in
// address mode; and its SSH policy is a compile from scratch's. Oracle:
// the reference and the client's filter, and for SSH a compile that
// inherits nothing. Worlds out of the reference's domain are skipped, as
// the reference properties skip them.
func (r *deliveryRun) holdToReference(t *rapid.T, at string, worlds []*deliveryWorld, held []map[types.NodeID]*netmap.NetworkMap, shared bool) {
	if !r.judges[judgeReference] {
		return
	}

	// Elections read the history the State was driven through: when each
	// node connected, the prober's marks, who held each route last.
	w := worlds[0].p.w
	plain := policymodel.RefOf(w)
	ref := plain.WithElections(worlds[0].p.elections)

	if why := ref.OutOfDomain(); why != "" {
		r.ref.skip(why)

		return
	}

	if r.ref.passed == nil {
		r.ref.passed = map[string]bool{}
		r.ref.contestedPeers, r.ref.contestedRoutes = map[policymodel.Contested]int{}, map[policymodel.Contested]int{}
	}

	// TODO(kradalby): policy/stale-under-shared-address: SSH policies
	// carried across a commit keep an address another node shared, until a
	// document edit (TestSSHPolicyForgetsALeaverWhoSharedAnAddress in
	// state); once a case shared one, its SSH goes unjudged.
	var fresh *policyv2.PolicyManager

	if !shared {
		users, err := worlds[0].p.s.ListAllUsers()
		if err != nil {
			t.Fatalf("reference: %s: users: %v", at, err)
		}

		fresh, err = policyv2.NewPolicyManager(w.Policy.HuJSON(), users, worlds[0].p.s.Snapshot().ListNodes())
		if err != nil {
			t.Fatalf("reference: %s: the policy compiled from scratch: %v", at, err)
		}
	} else {
		r.ref.skip("SSH after a shared address")
	}

	// What a client's view reads of the world besides its own node: every
	// node's addresses, as sources worth probing.
	var known []netip.Addr
	for _, n := range w.Topology.Nodes {
		known = append(known, n.Addrs()...)
	}

	world, key := jsonOf(w.Topology)+string(w.Policy.HuJSON()), fmt.Sprint(known)

	for i, dw := range worlds {
		for _, id := range slices.Sorted(maps.Keys(held[i])) {
			r.ref.clients++
			dw.holdClient(t, at, ref, plain, world, key, id, held[i][id], fresh, shared, &r.ref)
		}
	}
}

// heldClient is one client held to the reference: node id's, holding nm.
type heldClient struct {
	dw  *deliveryWorld
	at  string
	ref *policymodel.Ref
	// plain is ref without the election history.
	plain *policymodel.Ref
	id    types.NodeID
	nm    *netmap.NetworkMap
	rt    *referenceTally
	fail  func(format string, args ...any)
	// shared: an address was shared in the case, so node attributes may
	// be stale (TODO(kradalby): policy/stale-under-shared-address).
	shared bool
}

// holdClient holds node id's client, holding nm, to ref; see
// [deliveryRun.holdToReference].
func (dw *deliveryWorld) holdClient(t *rapid.T, at string, ref, plain *policymodel.Ref, world, key string, id types.NodeID, nm *netmap.NetworkMap,
	fresh *policyv2.PolicyManager, shared bool, rt *referenceTally,
) {
	c := heldClient{dw: dw, at: at, ref: ref, plain: plain, id: id, nm: nm, rt: rt, shared: shared}
	c.fail = func(format string, args ...any) {
		dw.failf(judgeReference, "%s: n%d: "+format, append([]any{at, id}, args...)...)
	}

	c.peers()
	c.routes()
	c.filter(world, key)
	c.stamps()

	if fresh != nil {
		c.ssh(t, fresh)
	}
}

// peers holds the client's peers, and what each carries in its
// AllowedIPs, to the reference, and the routes the node is primary for to
// the election.
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

		if want := policymodel.ShownAddrs(c.dw.p.w, c.id, types.NodeID(nv.ID())); !c.shared && !slices.Equal(addrs, want) { //nolint:gosec // small
			c.fail("its client is shown n%d at %v, the model at %v", nv.ID(), addrs, want)
		}
	}

	c.rt.peerSets++

	if want := c.ref.Peers(c.id); !slices.Equal(got, want) {
		k, ok := policymodel.ContestedPeers(c.ref, c.id, got)
		if !ok {
			c.fail("its client is shown %v, the reference shows it %v", got, want)
		}

		c.rt.contestedPeers[k]++
	}

	self, ok := c.ref.Node(c.id)
	if !ok {
		return
	}

	for _, q := range self.ServedRoutes() {
		primary, decided := c.ref.Primary(q)
		if q.Bits() == 0 || !decided {
			continue
		}

		c.rt.primaries++

		if want, has := primary == c.id && !policymodel.NamesNode(q), slices.Contains(c.nm.SelfNode.PrimaryRoutes().AsSlice(), q); want != has {
			c.fail("its client is primary for %s: %t, the election gives it to n%d", q, has, primary)
		}
	}
}

// routes holds what each peer carries in the client's AllowedIPs beyond
// its addresses to [policymodel.Ref.ServedRoutes].
func (c heldClient) routes() {
	viewer, _ := c.dw.p.w.Topology.Node(c.id)

	for _, p := range c.nm.Peers {
		pid := types.NodeID(p.ID()) //nolint:gosec // small
		routes := slices.DeleteFunc(p.AllowedIPs().AsSlice(), func(q netip.Prefix) bool { return slices.Contains(p.Addresses().AsSlice(), q) })
		slices.SortFunc(routes, netip.Prefix.Compare)

		want, unjudged := c.ref.ServedRoutes(c.id, pid)
		judged := policymodel.Judged(routes, unjudged)
		c.rt.unjudgedRoutes += len(unjudged)

		if _, without := c.plain.ServedRoutes(c.id, pid); len(without) > len(unjudged) {
			c.rt.byHistory += len(without) - len(unjudged)
		}

		if c.ref.Steered(c.id, pid) && len(judged)+len(want) > 0 {
			c.rt.steered++
		}

		if len(routes)+len(want) > 0 {
			c.rt.routePairs++
		}

		if !slices.Equal(judged, want) {
			k, ok := policymodel.ContestedServedRoutes(c.ref, c.id, pid, routes)

			switch {
			case ok:
				c.rt.contestedRoutes[k]++
			case c.ref.Steered(c.id, pid) && len(viewer.Addrs()) == 0 && !slices.ContainsFunc(judged, func(q netip.Prefix) bool { return !slices.Contains(want, q) }):
				// TODO(kradalby): policy/via-addressless-viewer: a viewer
				// holding no address (database only) is on a via grant's
				// sources by the routes it serves under *, so the reference
				// steers it the routers' routes; headscale steers it none.
				// It can send nothing either way. Counted, not judged.
				c.rt.addressless++
			default:
				c.fail("its client is given %v of n%d's routes, the reference %v (%v unjudged)", routes, pid, want, unjudged)
			}
		}
	}
}

// filter holds the client's packet filter to the reference's rules
// through its own filter. A comparison that holds without a contested
// clause reads only the reference's rules for the node and what it
// serves, the view and the filter; one that needs a clause reads the
// whole world.
func (c heldClient) filter(world, key string) {
	n, _ := c.dw.p.w.Topology.Node(c.id)
	rules := c.nm.PacketFilterRules.AsSlice()

	if msg := c.rt.form.Check(c.dw.p.w, c.ref, c.id, rules, c.dw.combo.capSources, c.shared); msg != "" {
		c.fail("its client's filter is in the wrong form: %s\nheadscale %v", msg, rules)
	}

	k := fmt.Sprint(n, c.dw.combo.capSources, c.ref.Served(c.id).Prefixes()) + ruleList(c.ref.Rules(c.id)) + key + ruleList(rules) + clientViewKey(c.nm)
	if c.rt.passed[k] || c.rt.passed[world+k] {
		return
	}

	c.rt.filters++

	contested := 0
	for _, n := range c.rt.verdicts.Contested {
		contested += n
	}

	rep := c.rt.verdicts.CompareAt(c.ref, c.id, rules, refView(n, c.dw.p.w, c.nm), c.dw.combo.capSources)
	if !rep.Equivalent() {
		c.fail("its client's filter differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v", rep, c.ref.Rules(c.id), rules)
	}

	for _, n := range c.rt.verdicts.Contested {
		contested -= n
	}

	if contested == 0 {
		c.rt.passed[k] = true
	} else {
		c.rt.passed[world+k] = true
	}
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
			if c.dw.combo.capSources {
				want = append(want, policymodel.StampPrefix+s)
			}
		}

		if !slices.Equal(has, want) {
			c.fail("its client holds n%d with stamps %v, the reference stamps it %v", of, has, want)
		}
	}
}

// ssh holds the client's SSH policy to fresh's, a compile from scratch.
func (c heldClient) ssh(t *rapid.T, fresh *policyv2.PolicyManager) {
	nv, ok := c.dw.p.s.Snapshot().GetNode(c.id)
	if !ok {
		return
	}

	want, err := fresh.SSHPolicy(c.dw.p.cfg.ServerURL, nv)
	if err != nil {
		t.Fatalf("reference: %s: n%d's SSH policy from scratch: %v", c.at, c.id, err)
	}

	if want == nil {
		want = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}
	}

	c.rt.ssh++

	if h, w := jsonOf(c.nm.SSHPolicy), jsonOf(want); h != w {
		c.fail("its client's SSH policy is %s, a compile from scratch gives %s", h, w)
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

// enforced is what of a netmap no delivery option may move: the node and
// its peers without the stamps capability mode adds, SSH and DNS. When a
// node last disconnected is each world's own clock's, so LastSeen is left
// out.
func enforced(nm *netmap.NetworkMap) string {
	strip := func(n tailcfg.NodeView) string {
		if !n.Valid() {
			return "none"
		}

		c := n.AsStruct()
		c.LastSeen = nil
		maps.DeleteFunc(c.CapMap, func(k nodecap.Cap, _ []tailcfg.RawMessage) bool {
			return strings.HasPrefix(string(k), policymodel.StampPrefix)
		})

		if len(c.CapMap) == 0 {
			c.CapMap = nil
		}

		return clientPeer(c.View())
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "self %s;", strip(nm.SelfNode))

	for _, p := range nm.Peers {
		fmt.Fprintf(&sb, " peer %s;", strip(p))
	}

	fmt.Fprintf(&sb, " ssh %s; dns %s", jsonOf(nm.SSHPolicy), jsonOf(nm.DNS))

	return sb.String()
}

// membershipChurn reports whether st only joins, deletes or retags nodes
// under a policy whose capability-form receivers no such change may send a
// filter (see [ruleClass]), and which nodes it changes. A node serving a
// subnet route is no such change: * as a source names every approved
// route (TODO(kradalby): policy/star-approved-routes), so it moves what *
// writes in every form.
func membershipChurn(before policymodel.World, st policymodel.Step) (map[types.NodeID]bool, bool) {
	after := before.Apply(st.Edits...)
	subjects := map[types.NodeID]bool{}

	for _, e := range st.Edits {
		switch e := e.(type) {
		case policymodel.Join:
			subjects[e.Node.ID] = true
		case policymodel.Leave:
			subjects[e.ID] = true
		case policymodel.Retag:
			subjects[e.ID] = true
		default:
			return nil, false
		}
	}

	for id := range subjects {
		for _, w := range []policymodel.World{before, after} {
			if n, ok := w.Topology.Node(id); ok && slices.ContainsFunc(n.Approved, func(r int) bool { return policymodel.Prefixes[r].Bits() != 0 }) {
				return nil, false
			}
		}
	}

	return subjects, ruleClass(before) == "plain" && ruleClass(after) == "plain"
}

// churnNode is a node joining w for a moment: of a drawn node's owner, or
// with its tags, under an ID and at addresses no drawn step uses, so the
// steps drawn after still find the world they were drawn against once it
// leaves.
func churnNode(t *rapid.T, w policymodel.World, k int) (policymodel.Node, bool) {
	nodes := w.Topology.Nodes
	i := rapid.IntRange(0, 15).Draw(t, "churn-like")

	if len(nodes) == 0 || len(w.Topology.Users) == 0 {
		return policymodel.Node{}, false
	}

	w.Topology.NextID = types.NodeID(churnIDs + k) //nolint:gosec // small

	return transientNode(w, nodes[i%len(nodes)].ID), true
}

// churnIDs is where the IDs of nodes joining for a moment start, past any a
// drawn scenario reaches.
const churnIDs = 1000

// TestDeliveryConvergesThroughTheClient plays generated scenarios
// (policymodel's: any policy, topology and steps; now and then an
// endpoint set or cleared after a step, a write a client, the HA prober
// or an operator makes through its production entry point, or a node
// joining and then leaving; one case in two ending with a script moving
// one part of what a viewer is sent alone) against four States at once, one
// per combination of policy.capability_sources and policy.filter_chunks,
// each with its hub routing in step, a session per node and, behind each
// session, the Tailscale client's own map session reading every response
// as off the wire. Commits coalesce into one routing per step or not; at
// each step's end, drawn once for all four, sessions render what they were
// woken for, some lag to a later step, some writes fail after some of
// their responses (the session ends; it reconnects now or at the next
// step), some sessions reconnect cleanly, some before their old session
// ends, which lives on beside the new one for a step. It holds:
//
// Convergence, through the client: after every step, every session with
// no wake pending holds, as its client assembled it, what a fresh
// session's client holds of the latest snapshot — self, peers with their
// CapMaps and routes, the filter (the same rules; reordered only if the
// client's verdicts and app capabilities, in order, stay), SSH, DNS, DERP,
// profiles — and the chunks a fresh session names. So routing reached
// every session a step changed, and render, diff, the wire and the
// client's merge agree with a first map.
//
// The four combinations agree: what a node's client enforces is the same
// in all four, but for the one class capability form refuses.
//
// What every client holds is right, not merely fresh: its peers, their
// routes once routers are elected, its packet filter, the stamps it holds
// and its SSH policy are held to the reference, read for the latest world,
// in each combination ([deliveryRun.holdToReference]).
//
// The chunk scheme, on every response before the client reads it (see
// [deliveryWorld.checkWire]), and the filter a client assembles from its
// chunks answers as the filter served in one list. Chunk names are a
// function of content across every session and world of a case. A client
// keeping chunks across sessions holds after a reconnect's first map what
// a new session does. In capability mode, a step that only joins,
// deletes or retags other nodes sends no filter to a receiver served
// capability form at both ends that serves no route, under policies whose
// rules routing narrows ([ruleClass] "plain").
//
// The oracle for convergence is the client's own map session, and for
// agreement and for the served filter, its packet filter; both share with
// production only the render of a fresh session and the encoder. For
// correctness it is the reference and the client's filter, and for SSH a
// compile from scratch. The model
// of the client's chunks (policyv2.FilterChunks) is held to the real
// client after every response, and used alone only where the real client
// cannot go: chunk names held, and a client keeping them across sessions.
// Each failure names its part ([deliveryJudge]); deliveryJudgesEnv runs
// some parts alone.
func TestDeliveryConvergesThroughTheClient(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")
	// Each world sets its own options. A configuration can only pin an
	// option on, so the switches pin both off.
	t.Setenv(state.TestCapabilitySourcesEnv, "false")
	t.Setenv(state.TestFilterChunksEnv, "false")

	r := &deliveryRun{
		probes: probeCache{}, judges: deliveryJudges(t), steps: 5,
		reach: deliveryReach{wakes: newWakeTally(), writes: map[string]int{}, scripts: map[string]int{}},
	}

	// Scenarios lengthen with -rapid.steps (RAPID_STEPS), five steps at
	// its default. Under the race detector one step each: it sees the
	// client's goroutine and the hub's in any case, and long scenarios cost
	// it minutes.
	if f := flag.Lookup("rapid.steps"); f != nil {
		n, err := strconv.Atoi(f.Value.String())
		if err == nil {
			r.steps = max(1, n/6)
		}
	}

	if util.RaceEnabled {
		r.steps = 1
	}

	rapid.Check(t, func(t *rapid.T) { playDelivery(t, r) })

	reach := r.reach
	t.Log(reach)
	t.Log(&r.ref)

	// What follows asks what the run reached, which takes scenarios of
	// full length: under the race detector they are one step.
	if testing.Short() || util.RaceEnabled {
		return
	}

	deep := false

	if f := flag.Lookup("rapid.checks"); f != nil {
		n, err := strconv.Atoi(f.Value.String())
		deep = err == nil && n >= 1000
	}

	if r.judges[judgeReference] {
		r.ref.require(t, deep)
	}

	floors := map[string]int{
		"lagged renders": reach.lagged, "failed writes": reach.failed, "reconnects": reach.reconnected,
		"chunks deleted": reach.deleted, "overlapping reconnects": reach.overlapped, "address indexes held": reach.indexed,
	}

	// A run of the default length can judge no membership churn and see no
	// delivery flip, which only some cases draw; a deep one always does.
	if deep {
		floors["membership churn"], floors["delivery flips"] = reach.churnJudged, reach.flips
	}

	for name, n := range floors {
		if n == 0 {
			t.Errorf("no case reached %s", name)
		}
	}
}

// deliveryRun is what the cases of one run share: what they reached, the
// client's answers to comparisons, and the parts held.
type deliveryRun struct {
	reach  deliveryReach
	probes probeCache
	judges [numJudges]bool
	steps  int
	ref    referenceTally
}

func playDelivery(t *rapid.T, r *deliveryRun) {
	s := policymodel.Scenarios(r.steps).Draw(t, "scenario")
	coalesce := pbtChance(t, 3, "coalesce")
	mixed := pbtChance(t, 4, "mixed-versions")

	names := &chunkRegistry{byName: map[string]string{}, byContent: map[string]string{}}

	worlds := make([]*deliveryWorld, len(deliveryCombos))
	for i, c := range deliveryCombos {
		worlds[i] = newDeliveryWorld(t, r, c, s.Start, coalesce, mixed, names)
	}

	ids := func() []types.NodeID {
		out := make([]types.NodeID, 0, len(worlds[0].p.w.Topology.Nodes))
		for _, n := range worlds[0].p.w.Topology.Nodes {
			out = append(out, n.ID)
		}

		return out
	}

	agreed := map[[2]*netmap.NetworkMap]bool{}

	shared := false

	judge := func(at string) {
		held := make([]map[types.NodeID]*netmap.NetworkMap, len(worlds))
		for i, dw := range worlds {
			held[i] = dw.fresh(at)
		}

		combosAgree(t, at, r, worlds, held, agreed)

		shared = shared || slices.ContainsFunc(worlds, func(dw *deliveryWorld) bool { return dw.shared }) || policymodel.SharesAddress(worlds[0].p.w)
		r.holdToReference(t, at, worlds, held, shared)
	}

	for _, dw := range worlds {
		dw.deliver(stepPlan{}, ids())
	}

	judge("start")

	n := 0
	play := func(kind string, st policymodel.Step, writes ...func(*pbtWorld) string) {
		n++
		plan := stepPlans.Draw(t, "plan")
		touch := pbtChance(t, 3, "endpoint")
		clearEndpoint := pbtChance(t, 4, "clear-endpoint")
		who := rapid.IntRange(0, 15).Draw(t, "who")

		// Now and then a client, the HA prober or an operator writes too,
		// through its production entry point.
		if pbtChance(t, 3, "session-write") {
			sw := sessionWrites.Draw(t, "session")

			writes = append(writes, func(p *pbtWorld) string { return p.session(sw) })
		}

		before := worlds[0].p.w
		subjects, churn := membershipChurn(before, st)

		starts := make([]*state.Snapshot, len(worlds))
		current := make([]map[types.NodeID]bool, len(worlds))

		for j, dw := range worlds {
			starts[j] = dw.p.s.Snapshot()
			current[j] = map[types.NodeID]bool{}

			for id, s := range dw.sess {
				current[j][id] = len(s.sess.wakes) == 0
			}

			dw.kind = kind
			dw.step(st, touch, clearEndpoint, who, n, writes...)
		}

		t.Logf("step %d: %s", n, policymodel.Step{Edits: st.Edits})

		for j, dw := range worlds {
			if churn && dw.combo.capSources {
				dw.judgeChurn(starts[j], current[j], subjects, plan, ids())
			} else {
				dw.deliver(plan, ids())
			}
		}

		judge(fmt.Sprintf("step %d", n))
	}

	churned := 0

	for _, st := range s.Steps {
		play("step", st)

		// Now and then a node joins and then leaves, each alone: membership
		// moving and nothing else, which few drawn steps are; not in a
		// large world ([scriptedWorld]).
		if pbtChance(t, 4, "churn") && len(s.Start.Topology.Nodes) <= scriptedWorld {
			if n, ok := churnNode(t, worlds[0].p.w, churned); ok {
				churned++

				play("churn", policymodel.Step{Edits: []policymodel.Edit{policymodel.Join{Node: n}}})
				play("churn", policymodel.Step{Edits: []policymodel.Edit{policymodel.Leave{ID: n.ID}}})
			}
		}
	}

	// One case in eight ends with a script moving one part of what a
	// viewer is sent alone ([drawScript]): each is several steps of four
	// worlds, and routing per part is the route property's to judge. None
	// in a large world ([scriptedWorld]), nor under the race detector,
	// which a script gives no goroutine to watch.
	defer func() {
		for k, n := range worlds[0].p.made {
			r.reach.writes[k] += n
		}
	}()

	if pbtChance(t, 8, "script") && !util.RaceEnabled && len(s.Start.Topology.Nodes) <= scriptedWorld {
		name, acts := drawScript(t, worlds[0].p.w)
		r.reach.scripts[name]++

		// Its setup is one step, each of its moves a step of its own.
		var setup policymodel.Step

		for len(acts) > 0 && !acts[0].key {
			setup.Edits = append(setup.Edits, acts[0].step.Edits...)
			acts = acts[1:]
		}

		play("script "+name, setup)

		for _, a := range acts {
			if a.step != nil {
				play("script "+name, *a.step)

				continue
			}

			play("script "+name, policymodel.Step{}, func(p *pbtWorld) string { return p.sessionTo(a.node, a.kind, 0) })
		}
	}

	for _, dw := range worlds {
		dw.deliver(stepPlan{}, ids())
	}

	judge("settled")
}

// judgeChurn delivers a membership-only step, holding every receiver
// served capability form at both ends, serving no route, not among the
// step's subjects and current at its start to being sent no filter.
func (dw *deliveryWorld) judgeChurn(start *state.Snapshot, current, subjects map[types.NodeID]bool, plan stepPlan, ids []types.NodeID) {
	end := dw.p.s.Snapshot()

	for _, id := range slices.Sorted(maps.Keys(dw.sess)) {
		s := dw.sess[id]
		if subjects[id] || !current[id] || !capabilityForm(start.ReceiverFacts(id)) || !capabilityForm(end.ReceiverFacts(id)) ||
			routes(start, id) || routes(end, id) {
			continue
		}

		dw.reach.churnJudged++

		if len(s.sess.wakes) == 0 {
			continue
		}

		<-s.sess.wakes

		resps, err := s.st.Update(end)
		if err != nil {
			dw.fatalf("n%d renders r%d: %v", id, end.Rev(), err)
		}

		for _, r := range resps {
			if r.PacketFilters != nil {
				dw.failf(judgeChurn, "a step changing only %v sent n%d, served capability form, the filter %s",
					slices.Sorted(maps.Keys(subjects)), id, jsonOf(r.PacketFilters))
			}
		}

		dw.checkWire(s, resps, false)
		dw.write(s, resps)
		s.st.Delivered()
		dw.wokeFor(s, end, resps)
		s.rev, s.last = end.Rev(), end
		dw.logf("n%d renders r%d: %s", id, end.Rev(), describeResponses(resps))
	}

	dw.deliver(plan, ids)
}
