package servertest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/state/statemodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// The front-door property plays generated scenarios against a server
// through what its clients and its admin use: registration over Noise with
// a pre-auth key or an interactive login, the long poll, a client's map
// requests and logout, the v1 API, and a restart from the database. At
// every step's end, once nothing is pending, what each polling client
// assembled must be what a fresh session of its node is given, that must
// be what the reference grants the model's world, and what the server
// stored must be the model's, its rows its memory.
//
// The model takes the IDs and addresses registration hands out: a node it
// draws is renumbered and readdressed to what the server registered. A
// write the front door cannot make is left out of the model and counted:
// addresses moved after registration, a login of a user who cannot claim
// the node, a client that logged out reporting routes; and, outside the
// cases drawn patient, a client going away for good, which the server
// waits out for fifteen seconds. Users an identity provider makes, their
// renames and e-mails, and their logins' callbacks go through the State,
// as the OIDC handler makes them.

// fdQuietLimit bounds the wait for a quiet server: a session's end waits
// up to fifteen seconds for its node to come back before it disconnects.
const fdQuietLimit = time.Minute

// How a node joins.
const (
	// joinKey: a pre-auth key of its user, or of its tags alone.
	joinKey = iota
	// joinEphemeral: an ephemeral pre-auth key.
	joinEphemeral
	// joinUserTaggedKey: a tagged pre-auth key a user made.
	joinUserTaggedKey
	// joinLogin: an interactive login, approved as `headscale auth
	// register` does, or at the identity provider.
	joinLogin
	// joinLoginTagged: an interactive login, then an admin tags the node.
	joinLoginTagged
	numJoins
)

var joinNames = [numJoins]string{"pre-auth key", "ephemeral key", "tagged key a user made", "login", "login, then tags"}

// The steps the property draws besides the model's own.
const (
	stepWorld = iota
	stepBurst
	stepFlap
	stepRestartPoll
	stepClientRestart
	stepEndpoints
	stepRename
	stepLogout
	stepRelogin
	stepServerRestart
	stepOwnership
	stepIdentity
	stepRace
	stepClock
	stepRecords
	stepSecond
	stepSSHCheck
	stepOIDC
	numSteps
)

// fdJudges are the parts of the property a slice names: what the server
// stored, what clients hold against a fresh session (and that they poll
// as the model says), against the reference, and across a restart.
var fdJudges = []string{"stored", "client", "reference", "restart"}

var stepNames = [numSteps]string{
	"world", "burst", "flap", "poll restart", "client restart", "endpoints", "rename", "logout", "relogin", "server restart",
	"ownership", "identity", "race", "clock", "records", "second session", "ssh check", "oidc login",
}

// fdNode is a model node's client and how it joined, which a login, a
// relogin and the stored judge need; its Key is "" after a login.
type fdNode struct {
	statemodel.Joined

	tc *TestClient
	// reusable: a single-use key is spent by the registration, and a login
	// with it under a new node key is refused. keyID is the key's ID.
	reusable bool
	keyID    string
	// loggedOut is set once its client logged out: it holds no node key.
	loggedOut bool
	// extras are further map sessions of the node this step opened: the
	// same device's keys, polling beside tc until the step or the case
	// ends them.
	extras []*TestClient
}

// fdKeys is a node's tunnel keys as its client last registered with.
type fdKeys struct {
	node  key.NodePublic
	disco key.DiscoPublic
}

// fdRun is what the cases of one run share.
type fdRun struct {
	steps int
	tally *fdTally
	// loopLine is where serveLongPoll waits between updates.
	loopLine int
	held     policymodel.HeldJudge
	// slice is the part of the property the run holds (fdJudges), and
	// outside counts the cases it dropped.
	slice   policymodel.Slice
	outside int
}

// frontDoor is one case: a server, its clients, and the model of what
// they did.
type frontDoor struct {
	t   *rapid.T
	tb  *caseTB
	run *fdRun
	srv *TestServer

	apiKey string
	http   *http.Client

	capSources, chunks bool
	// patient cases disconnect clients for good, which the server waits
	// out for its reconnect grace; the others leave such edits out.
	patient bool
	// magicDNS names nodes in the tailnet's domain, so their names and the
	// DNS config reach every map.
	magicDNS bool
	// clock is whether the ephemeral inactivity timeout is drawn small
	// ([WithEphemeralTimeout]): an ephemeral node whose poll ends is
	// deleted that long after, unless its own connect cancels the timer.
	// A case running the small clock leaves out every step that would
	// leave an ephemeral node sessionless with the model holding it:
	// such a node is deleted grace and timeout later, which the model
	// cannot see coming.
	clock bool

	w         policymodel.World
	nodes     map[types.NodeID]*fdNode
	elections *policymodel.Elections
	// derp is whether the policy the server holds names a DERP region the
	// model's document does not ([recordsStep] added it); the next policy
	// write, which PUTs the model's document, drops it again.
	derp bool
	// records is what the records step published last; a restart serves
	// the configured ones alone, which is none here.
	records []tailcfg.DNSRecord
	// v2 is whether this case's admin writes go through the v2 API: an
	// OAuth client minted in process ([frontDoor.v2Token]), its writes
	// the property's v1 paths translated to ([frontDoor.translate2]).
	v2 bool
	// v2token is the case's v2 bearer, minted at the first translated
	// write.
	v2token string
	// idp is the case's identity provider, when it drew one: interactive
	// registrations go through its real callback.
	idp *MockIDP
	// oidcUsers are the users the callback created, by the subject claim
	// that made them.
	oidcUsers map[string]uint
	// oidcClaims are the claims the next login's callback carries; set by
	// the oidc step, consumed by the first interactive login after it.
	oidcClaims map[string]any
	// unheld are the subnet routes a burst left with no router available:
	// who held them last is history the election history missed, so the
	// routes go unjudged until a router can take them again.
	unheld map[netip.Prefix]bool

	// keys are the tunnel keys each node's client registered with, as
	// its entry must carry them on the wire ([policymodel.WireKeys]):
	// the level's own inputs, recorded at each registration and never
	// read back from the server.
	keys map[types.NodeID]fdKeys

	// stacks is reused by every quiet wait.
	stacks []byte
}

// TestFrontDoorClientsFollowTheModel holds real control clients, driven
// with the server through its front doors by generated scenarios, to a
// fresh session, the reference and the model: see the top of this file.
func TestFrontDoorClientsFollowTheModel(t *testing.T) {
	if testing.Short() {
		t.Skip("a server and real clients per case")
	}

	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")
	// Each case pins the options it draws on; the switches pin the rest off.
	t.Setenv(state.TestCapabilitySourcesEnv, "false")
	t.Setenv(state.TestFilterChunksEnv, "false")

	line, err := pollLoopLine()
	if err != nil {
		t.Fatalf("test sanity: %v", err)
	}

	slice, err := policymodel.SliceOf(fdJudges...)
	if err != nil {
		t.Fatal(err)
	}

	run := &fdRun{steps: fdSteps(), tally: newFDTally(), loopLine: line, slice: slice}

	rapid.Check(t, func(rt *rapid.T) { playFrontDoor(t, rt, run) })

	t.Log(run.tally)
	t.Log(&run.held)

	if !run.slice.Whole() {
		t.Logf("slice: %v; %d cases outside it", run.slice, run.outside)

		return
	}

	if f := flag.Lookup("rapid.checks"); f != nil {
		n, err := strconv.Atoi(f.Value.String())
		if err == nil && n >= 1000 {
			run.tally.require(t, &run.held)
		}
	}
}

// fdSteps is how many steps a case draws at most: a few at rapid's
// default, more with -rapid.steps.
func fdSteps() int {
	n := 8

	if f := flag.Lookup("rapid.steps"); f != nil {
		v, err := strconv.Atoi(f.Value.String())
		if err == nil {
			n = max(1, v/4)
		}
	}

	if util.RaceEnabled {
		n = max(1, n/2)
	}

	return n
}

// fdMaxNodes bounds the start world: every node is a real client.
const fdMaxNodes = 10

func playFrontDoor(t *testing.T, rt *rapid.T, run *fdRun) {
	t.Helper()

	tb := &caseTB{T: t, rt: rt}
	defer tb.end()

	fd := &frontDoor{
		t: rt, tb: tb, run: run,
		capSources: rapid.Bool().Draw(rt, "capability-sources"),
		chunks:     rapid.Bool().Draw(rt, "filter-chunks"),
		v2:         rapid.Bool().Draw(rt, "v2-api"),
		patient:    rapid.IntRange(0, 3).Draw(rt, "patient") == 3,
		magicDNS:   rapid.Bool().Draw(rt, "magic-dns"),
		// The ephemeral inactivity clock, drawn small in a third of the
		// cases, is what the clock step runs ([WithEphemeralTimeout]);
		// the rest pin it where no timer can fire inside a case.
		clock:     rapid.IntRange(0, 2).Draw(rt, "ephemeral-clock") == 0,
		nodes:     map[types.NodeID]*fdNode{},
		elections: policymodel.NewElections(),
		unheld:    map[netip.Prefix]bool{},
		keys:      map[types.NodeID]fdKeys{},
		stacks:    make([]byte, 1<<20),
	}

	start := policymodel.Worlds().Draw(rt, "start")
	if !run.slice.Holds(policymodel.Scenario{Start: start}) {
		run.outside++

		return
	}

	opts := []ServerOption{WithEphemeralTimeout(time.Hour), WithBatchDelay(20 * time.Millisecond)}

	fd.idp, fd.oidcUsers = nil, map[string]uint{}

	if rapid.Bool().Draw(rt, "oidc") {
		fd.idp = NewMockIDP()
		tb.Cleanup(fd.idp.Close)

		opts = append(opts, WithOIDC(fd.idp))
	}

	if fd.clock {
		opts[0] = WithEphemeralTimeout(fdClock)
	}

	if fd.capSources {
		opts = append(opts, WithCapabilitySources())
	}

	if fd.chunks {
		opts = append(opts, WithFilterChunks())
	}

	if fd.magicDNS {
		opts = append(opts, WithMagicDNS("frontdoor.example"))
	}

	fd.srv = NewServer(tb, opts...)
	fd.http = &http.Client{Transport: &http.Transport{DialContext: fd.srv.MemNet().Dial, DisableKeepAlives: true}}

	key, _, err := fd.srv.State().CreateAPIKey(nil)
	if err != nil {
		rt.Fatalf("API key: %v", err)
	}

	fd.apiKey = key

	run.tally.cases++

	fd.begin(start)
	fd.settle("the start")

	steps := rapid.IntRange(0, run.steps).Draw(rt, "steps")

	for i := range steps {
		at := fmt.Sprintf("step %d", i+1)

		kind := rapid.IntRange(0, 32).Draw(rt, "kind")

		switch {
		case kind < 6:
			fd.world(at, policymodel.Steps(fd.w).Draw(rt, "edits"))
		case kind < 9:
			fd.burst(at, rapid.IntRange(2, 4).Draw(rt, "burst"))
		case kind < 11:
			fd.weather(at, stepFlap)
		case kind < 12:
			fd.weather(at, stepRestartPoll)
		case kind < 13:
			fd.weather(at, stepClientRestart)
		case kind < 14:
			fd.weather(at, stepEndpoints)
		case kind < 15:
			fd.rename(at)
		case kind < 16:
			fd.logout(at)
		case kind < 17:
			fd.relogin(at)
		case kind < 19:
			fd.restart(at)
		case kind < 23:
			fd.ownership(at)
		case kind < 26:
			fd.identity(at)
		case kind < 28:
			fd.race(at)
		case kind == 28:
			fd.clockStep(at)
		case kind == 29:
			fd.recordsStep(at)
		case kind == 30:
			fd.sessionsStep(at)
		case kind == 31:
			fd.sshCheckStep(at)
		case kind == 32:
			fd.oidcStep(at)
		}

		fd.settle(at)
	}

	// The v2 key-renewal write, once per case of the v2 form, so its
	// reach never rests on a case drawing a renewal besides.
	if fd.v2 {
		fd.v2Renew("the v2 renewal")
		fd.settle("the v2 renewal")
	}
}

// begin brings the start world in as an admin and clients would: users,
// the policy, then each node in ID order.
func (fd *frontDoor) begin(start policymodel.World) {
	for _, u := range start.Topology.Users {
		fd.addUser(u)
	}

	fd.setPolicy(start.Policy)

	for _, n := range start.Topology.Nodes[:min(len(start.Topology.Nodes), fdMaxNodes)] {
		fd.join("the start", n)
	}
}

// world writes a step the model drew, an edit at a time, each through the
// front door that makes it, and waits for quiet after each: the election
// history is read at every edit, as the documented election follows every
// commit.
func (fd *frontDoor) world(at string, st policymodel.Step) {
	fd.run.tally.steps[stepNames[stepWorld]]++

	// A join takes the ID registration hands out; later edits of the step
	// name the node by the ID drawn.
	ids := map[types.NodeID]types.NodeID{}

	for _, e := range st.Edits {
		fd.edit(at, remap(e, ids), ids)
		fd.quiet(at)
		fd.elect()
		fd.requireStored(at + ": " + e.String())
	}
}

// burst writes steps the model draws one after another, n of them, with
// no wait between the edits: their commits race the hub's routing and
// the map sessions' coalescing, as an admin's script and busy clients
// make them race. Only the step's end is judged.
func (fd *frontDoor) burst(at string, n int) {
	fd.run.tally.steps[stepNames[stepBurst]]++

	for range n {
		ids := map[types.NodeID]types.NodeID{}

		for _, e := range policymodel.Steps(fd.w).Draw(fd.t, "edits").Edits {
			fd.edit(at, remap(e, ids), ids)
			fd.run.tally.edits["(in a burst)"]++
		}
	}

	fd.quiet(at)
	fd.elect()

	// The election history read only the burst's end: a route that ended
	// with no router to take it stays with whoever held it last, which
	// only the commits in between could say.
	for _, n := range fd.w.Topology.Nodes {
		for _, r := range n.Approved {
			if q := policymodel.Prefixes[r]; q.Bits() > 0 && slices.Contains(n.Announced, r) && !fd.served(q) {
				fd.unheld[q] = true
			}
		}
	}
}

// served reports whether some router can take subnet route q.
func (fd *frontDoor) served(q netip.Prefix) bool {
	for _, n := range fd.w.Topology.Nodes {
		r := slices.Index(policymodel.Prefixes, q)
		if slices.Contains(n.Announced, r) && slices.Contains(n.Approved, r) && !n.Offline && !n.Expired {
			return true
		}
	}

	return false
}

// remap renames the nodes e names by ids.
func remap(e policymodel.Edit, ids map[types.NodeID]types.NodeID) policymodel.Edit {
	id := func(x types.NodeID) types.NodeID {
		if y, ok := ids[x]; ok {
			return y
		}

		return x
	}

	switch e := e.(type) {
	case policymodel.Leave:
		e.ID = id(e.ID)

		return e
	case policymodel.Retag:
		e.ID = id(e.ID)

		return e
	case policymodel.Announce:
		e.ID = id(e.ID)

		return e
	case policymodel.Withdraw:
		e.ID = id(e.ID)

		return e
	case policymodel.Approve:
		e.ID = id(e.ID)

		return e
	case policymodel.Unapprove:
		e.ID = id(e.ID)

		return e
	case policymodel.SetClient:
		e.ID = id(e.ID)

		return e
	case policymodel.SetExpired:
		e.ID = id(e.ID)

		return e
	case policymodel.SetOnline:
		e.ID = id(e.ID)

		return e
	}

	return e
}

// edit makes e through its front door and applies to the model what it
// made.
func (fd *frontDoor) edit(at string, e policymodel.Edit, ids map[types.NodeID]types.NodeID) {
	kind := strings.TrimPrefix(fmt.Sprintf("%T", e), "policymodel.")

	switch e := e.(type) {
	case policymodel.Join:
		n := fd.join(at, e.Node)
		ids[e.Node.ID] = n.ID
	case policymodel.Leave:
		fd.leave(at, e.ID)
	case policymodel.Retag:
		if len(e.Tags) == 0 {
			fd.untag(at, e)

			return
		}

		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", e.ID), map[string]any{"tags": tagNames(e.Tags)}, nil)
		fd.made(kind, "API")
		fd.apply(e)
	case policymodel.Announce, policymodel.Withdraw, policymodel.SetClient:
		id := nodeOf(e)

		if fd.nodes[id].loggedOut {
			fd.made(kind, "left out (its client logged out)")

			return
		}

		next := fd.w.Apply(e)
		n, _ := next.Topology.Node(id)
		fd.report(at, id, n)
		fd.made(kind, "map request")
		fd.apply(e)
	case policymodel.Approve:
		fd.approve(at, e.ID, e.Routes, nil)
	case policymodel.Unapprove:
		fd.approve(at, e.ID, nil, e.Routes)
	case policymodel.SetExpired:
		body := map[string]any{}
		if !e.Expired {
			body["disableExpiry"] = true
		}

		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/expire", e.ID), body, nil)
		fd.made(kind, "API")
		fd.apply(e)
	case policymodel.SetOnline:
		fd.setOnline(at, kind, e)
	case policymodel.SetAddr:
		fd.made(kind, "left out (database only)")
	case policymodel.AddUser:
		fd.addUser(e.User)
	case policymodel.DeleteUser:
		fd.mustAPI(at, http.MethodDelete, fmt.Sprintf("/api/v1/user/%d", e.ID), nil, nil)
		fd.made(kind, "API")
		fd.apply(e)

		// The user's own pre-auth keys went with it: a node it tagged away
		// can no longer present one. Tagged keys it made stay, their tags'.
		var keys struct {
			PreAuthKeys []struct {
				ID string `json:"id"`
			} `json:"preAuthKeys"`
		}

		fd.mustAPI(at, http.MethodGet, "/api/v1/preauthkey", nil, &keys)

		for _, id := range slices.Sorted(maps.Keys(fd.nodes)) {
			nd := fd.nodes[id]
			if nd.KeyUser != e.ID || nd.keyID == "" {
				continue
			}

			listed := slices.ContainsFunc(keys.PreAuthKeys, func(k struct {
				ID string `json:"id"`
			},
			) bool {
				return k.ID == nd.keyID
			})

			switch {
			case nd.Tagged && !listed:
				fd.t.Fatalf("%s: u%d is deleted, and the tagged key n%d registered with is gone with it", at, e.ID, id)
			case !nd.Tagged && listed:
				fd.t.Fatalf("%s: u%d is deleted, and its own key n%d registered with is still listed", at, e.ID, id)
			case !nd.Tagged:
				nd.Key = ""
			}

			fd.made("DeleteUser", "its keys checked")
		}
	case policymodel.RenameUser:
		fd.renameUser(at, e)
	case policymodel.SetEmail:
		fd.updateUser(at, e.ID, func(u *types.User) { u.Email = e.Email })
		fd.made(kind, "identity provider")
		fd.apply(e)
	default:
		// A policy edit: the whole document, as an admin writes it.
		next := fd.w.Apply(e)
		if !bytes.Equal(next.Policy.HuJSON(), fd.w.Policy.HuJSON()) {
			fd.setPolicy(next.Policy)
		}

		fd.made("policy", "API")
		fd.w = next
	}
}

// setOnline brings e's client on or off its map session as the edit says:
// a connect through its client, a disconnect only a patient case makes,
// which a case running the small ephemeral clock leaves out of an
// ephemeral node rather than have the collector delete it under the
// model's back.
func (fd *frontDoor) setOnline(at string, kind string, e policymodel.SetOnline) {
	nd := fd.nodes[e.ID]

	switch {
	case nd.loggedOut && e.Online:
		fd.made(kind, "left out (its client logged out)")

		return
	case e.Online:
		fd.connect(at, e.ID)
		fd.made(kind, "connect")
	case !fd.patient:
		fd.made(kind, "left out (a case that does not wait out the reconnect grace)")

		return
	case nd.Ephemeral && fd.clock:
		fd.made(kind, "left out (the ephemeral clock would delete it)")

		return
	default:
		nd.tc.Disconnect(fd.tb)
		fd.made(kind, "disconnect")
	}

	fd.apply(e)
}

// nodeOf is the node a client report names.
func nodeOf(e policymodel.Edit) types.NodeID {
	switch e := e.(type) {
	case policymodel.Announce:
		return e.ID
	case policymodel.Withdraw:
		return e.ID
	case policymodel.SetClient:
		return e.ID
	}

	panic(fmt.Sprintf("no node in %T", e))
}

// apply applies e to the model.
func (fd *frontDoor) apply(e policymodel.Edit) { fd.w = fd.w.Apply(e) }

// made counts an edit of kind by the path it took.
func (fd *frontDoor) made(kind, path string) { fd.run.tally.edits[kind+": "+path]++ }

// addUser creates u: through the API for an API user, or as the identity
// provider's first login does for an OIDC one.
func (fd *frontDoor) addUser(u policymodel.User) {
	users, _ := policymodel.Topology{Users: []policymodel.User{u}}.Build()
	want := users[0]

	var (
		got  uint
		path string
	)

	switch {
	case u.OIDC():
		path = "identity provider"

		created, err := fd.srv.State().CreateUser(types.User{Name: want.Name, Email: want.Email, Provider: want.Provider, ProviderIdentifier: want.ProviderIdentifier})
		if err != nil {
			fd.t.Fatalf("create user %s: %v", u, err)
		}

		got = created.ID
	default:
		path = "API"

		var out struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		}

		fd.mustAPI("a user", http.MethodPost, "/api/v1/user", map[string]any{"name": u.Name, "email": u.Email}, &out)

		id, err := strconv.ParseUint(out.User.ID, 10, 64)
		if err != nil {
			fd.t.Fatalf("create user %s: id %q: %v", u, out.User.ID, err)
		}

		got = uint(id)
	}

	if got != u.ID {
		fd.t.Fatalf("user %s was created as u%d", u, got)
	}

	fd.made("AddUser", path)
	fd.apply(policymodel.AddUser{User: u})
}

// renameUser renames an API user through the API, an OIDC user as its
// next login with new claims does.
func (fd *frontDoor) renameUser(at string, e policymodel.RenameUser) {
	u, _ := fd.w.Topology.User(e.ID)

	switch {
	case u.OIDC():
		fd.updateUser(at, e.ID, func(u *types.User) { u.Name = e.Name })
		fd.made("RenameUser", "identity provider")
	default:
		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/user/%d/rename/%s", e.ID, e.Name), nil, nil)
		fd.made("RenameUser", "API")
	}

	fd.apply(e)
}

// updateUser changes a user as an OIDC login with new claims does.
func (fd *frontDoor) updateUser(at string, id uint, set func(*types.User)) {
	_, err := fd.srv.State().UpdateUser(types.UserID(id), func(u *types.User) error {
		set(u)

		return nil
	})
	if err != nil {
		fd.t.Fatalf("%s: update user u%d: %v", at, id, err)
	}
}

// setPolicy writes p through the API.
func (fd *frontDoor) setPolicy(p policymodel.Policy) {
	fd.mustAPI("the policy", http.MethodPut, "/api/v1/policy", map[string]any{"policy": string(p.HuJSON())}, nil)
	fd.w.Policy = p
	fd.derp = false
}

// tagNames are the policy tags of indices.
func tagNames(tags []int) []string {
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = policymodel.Tags[t]
	}

	return out
}

// hostinfo is what n's client reports: n as headscale holds it, its routes
// only when routes is set.
func (fd *frontDoor) hostinfo(n policymodel.Node, routes bool) *tailcfg.Hostinfo {
	hi := fd.w.Topology.BuildNode(n).Hostinfo.Clone()
	hi.BackendLogID = fmt.Sprintf("frontdoor-%d", n.ID)

	if !routes {
		hi.RoutableIPs = nil
	}

	return hi
}

// loginUser is who a login is approved as: u if the API can name it, else
// false.
func (fd *frontDoor) loginUser(u policymodel.User) bool {
	if u.OIDC() {
		return true
	}

	same := 0

	for _, o := range fd.w.Topology.Users {
		if o.Name == u.Name {
			same++
		}
	}

	return same == 1
}

// approver completes an interactive login as u: through the API, as
// `headscale auth register` does, or as the identity provider's callback
// does for an OIDC user.
func (fd *frontDoor) approver(u policymodel.User) func(authID string) error {
	return func(authID string) error {
		fd.awaitFollowup(authID)

		return fd.approveNow(u)(authID)
	}
}

// approverAt is approver at a drawn moment: mostly once the client's
// follow-up waits, as a person approves; one login in four at once,
// racing the follow-up on its way.
func (fd *frontDoor) approverAt(u policymodel.User) func(authID string) error {
	if rapid.IntRange(0, 3).Draw(fd.t, "approve-at") < 3 {
		return fd.approver(u)
	}

	fd.run.tally.edits["login approved as its follow-up arrives"]++

	return fd.approveNow(u)
}

// approveNow completes an interactive login as u at once.
func (fd *frontDoor) approveNow(u policymodel.User) func(authID string) error {
	return func(authID string) error {
		if u.OIDC() {
			id, err := types.AuthIDFromString(authID)
			if err != nil {
				return err
			}

			_, err = fd.srv.State().HandleNodeFromAuthPath(id, types.UserID(u.ID), nil, util.RegisterMethodOIDC)

			return err
		}

		return fd.api(http.MethodPost, "/api/v1/auth/register", map[string]any{"authId": authID, "user": u.Name}, nil)
	}
}

// oidcStep registers a node through the identity provider's real
// callback, as a person logging in does: the claims name a user the
// callback creates, or one an earlier draw of the step created, whose
// changed claims update it rather than make another.
func (fd *frontDoor) oidcStep(at string) {
	fd.run.tally.steps[stepNames[stepOIDC]]++

	if fd.idp == nil {
		fd.run.tally.steps[stepNames[stepOIDC]+" (no provider)"]++

		return
	}

	// The claims: a fresh subject, or an earlier draw's with a changed
	// name or e-mail.
	var u policymodel.User

	subjects := slices.Sorted(maps.Keys(fd.oidcUsers))

	if len(subjects) == 0 || rapid.Bool().Draw(fd.t, "oidc-first") {
		id := fd.nextUserID()
		sub := "u" + strconv.FormatUint(uint64(id), 10)

		u = policymodel.User{
			ID:       id,
			Name:     fd.drawName("oidc-name"),
			Email:    fd.drawEmail("oidc-email"),
			Provider: fd.idp.URL + "/" + sub,
		}

		fd.oidcClaims = map[string]any{
			"sub":                sub,
			"preferred_username": u.Name,
			"email":              u.Email,
		}

		fd.run.tally.steps[stepNames[stepOIDC]+": a first login"]++

		// A node to claim before the model's edits: the user exists in
		// the model once the claim is to happen, and the callback's
		// claims, carrying the same identity, are what makes the
		// server's. No node: no claim, and no claims left set for a
		// later login to pick up.
		n, ok := fd.pickOIDCNode()
		if !ok {
			fd.oidcClaims = nil

			return
		}

		fd.apply(policymodel.AddUser{User: u})
		fd.oidcUsers[sub] = id
		fd.untag(at, policymodel.Retag{ID: n, User: u.ID})

		// The same subject's changed claims, on a re-login of the node
		// just claimed: the callback must update the user it made,
		// never make another.
		email := fd.drawEmail("oidc-second-email")
		fd.oidcClaims = map[string]any{
			"sub": sub, "preferred_username": u.Name, "email": email,
		}

		fd.apply(policymodel.SetEmail{ID: u.ID, Email: email})
		fd.run.tally.steps[stepNames[stepOIDC]+": a changed e-mail"]++

		node, _ := fd.w.Topology.Node(n)
		fd.login(at, n, u, node)

		return
	}

	sub := subjects[rapid.IntRange(0, len(subjects)-1).Draw(fd.t, "oidc-subject")]

	u, _ = fd.w.Topology.User(fd.oidcUsers[sub])

	// A node to claim before anything else: no node, no model edits, and
	// no claims left set for a later login to pick up.
	node, ok := fd.pickOIDCNode()
	if !ok {
		fd.oidcClaims = nil

		return
	}

	switch rapid.IntRange(0, 2).Draw(fd.t, "oidc-claims") {
	case 0:
		// A changed e-mail, which must update the user the subject
		// already names, never make another.
		email := fd.drawEmail("oidc-new-email")
		fd.oidcClaims = map[string]any{
			"sub": sub, "preferred_username": u.Name, "email": email,
		}
		fd.run.tally.steps[stepNames[stepOIDC]+": a changed e-mail"]++

		fd.apply(policymodel.SetEmail{ID: u.ID, Email: email})
	case 1:
		// A changed name.
		name := fd.drawName("oidc-new-name")
		fd.oidcClaims = map[string]any{
			"sub": sub, "preferred_username": name, "email": u.Email,
		}
		fd.run.tally.steps[stepNames[stepOIDC]+": a changed name"]++

		fd.apply(policymodel.RenameUser{ID: u.ID, Name: name})
	default:
		// The same claims again: another device of the same user's.
		fd.oidcClaims = map[string]any{
			"sub": sub, "preferred_username": u.Name, "email": u.Email,
		}
		fd.run.tally.steps[stepNames[stepOIDC]+": another device"]++
	}

	fd.untag(at, policymodel.Retag{ID: node, User: u.ID})
}

// pickOIDCNode is a node the next claims login can claim: tagged, live,
// and claimable by any user, which a claims user is. It reports the
// node's ID.
func (fd *frontDoor) pickOIDCNode() (types.NodeID, bool) {
	n, ok := fd.pick("oidc-claimed", func(n policymodel.Node, nd *fdNode) bool {
		return n.Tagged() && !n.Offline && !n.Expired && !nd.loggedOut && nd.tc.Polling() &&
			nd.Method != util.RegisterMethodAuthKey
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepOIDC]+" (no node)"]++

		return 0, false
	}

	return n.ID, true
}

// loginApprover is how an interactive login's approval is driven: the
// oidc step's, through the identity provider's real callback with the
// claims it set; every other login approves as a person does, through
// the State, as the identity step's logins always have.
func (fd *frontDoor) loginApprover(as policymodel.User) func(authID string) error {
	if fd.idp == nil || fd.oidcClaims == nil {
		return fd.approverAt(as)
	}

	claims := fd.oidcClaims
	fd.oidcClaims = nil

	fd.idp.SetClaims(claims)

	return func(authID string) error {
		fd.run.tally.steps[stepNames[stepOIDC]+": a login through the callback"]++

		return DriveOIDCLogin(fd.tb, fd.srv, fd.idp, authID)
	}
}

// awaitFollowup waits until the client's follow-up request for authID is
// waiting for its verdict, as it is by the time a person approves the URL
// the client shows.
func (fd *frontDoor) awaitFollowup(authID string) {
	deadline := time.Now().Add(20 * time.Second)

	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	for {
		waiting, inFlight := fd.followupState()

		switch {
		case waiting:
			fd.run.tally.edits["login approved once its follow-up waits"]++

			return
		case !inFlight:
			// The follow-up was answered without waiting: approving now
			// lets the login report how.
			fd.run.tally.edits["login approved after its follow-up was answered"]++

			return
		case time.Now().After(deadline):
			fd.t.Fatalf("the follow-up of login %s never waited at the server", authID)
		}

		<-tick.C
	}
}

// followupState reports whether a registration's follow-up request waits
// at the server for its login's verdict, and whether a client's follow-up
// is still in flight.
func (fd *frontDoor) followupState() (bool, bool) {
	var waiting, inFlight bool

	for _, g := range goroutines(fd.dump()) {
		waiting = waiting || g.state == "select" && g.top == followupFunc
		inFlight = inFlight || strings.Contains(g.stack, "servertest.(*TestClient).waitLogin.func")
	}

	return waiting, inFlight
}

// joinKind draws how n joins: with a pre-auth key, an ephemeral one, a
// tagged key a user made, or a login. A node that starts offline never
// polls, so its registration leaves the inactivity timer armed: a case
// running the small clock joins it with a permanent key, which nothing
// deletes under the model's back.
func (fd *frontDoor) joinKind(n policymodel.Node, owner policymodel.User, users []policymodel.User, logins []policymodel.User) int {
	var kinds []int

	if n.Tagged() {
		kinds = []int{joinKey, joinEphemeral}
		if len(users) > 0 {
			kinds = append(kinds, joinUserTaggedKey)
		}

		if len(logins) > 0 {
			kinds = append(kinds, joinLoginTagged)
		}
	} else {
		kinds = []int{joinKey, joinEphemeral}
		if fd.loginUser(owner) {
			kinds = append(kinds, joinLogin)
		}
	}

	if n.Offline && fd.clock {
		kinds = slices.DeleteFunc(kinds, func(k int) bool { return k == joinEphemeral })
	}

	return kinds[rapid.IntRange(0, len(kinds)-1).Draw(fd.t, "join")]
}

// join registers n as its client and an admin bring it in, and applies to
// the model what that made, in the order it happened: the registration,
// at the ID and addresses the server handed out; an admin's tags, for a
// node a login brought in; the admin's approvals, before the client
// announces, so that auto-approval then adds what the model counts as its
// own; an admin's expiry; the first map session. It returns n as
// registered.
func (fd *frontDoor) join(at string, n policymodel.Node) policymodel.Node {
	users := fd.w.Topology.Users
	logins := slices.DeleteFunc(slices.Clone(users), func(u policymodel.User) bool { return !fd.loginUser(u) })
	owner, _ := fd.w.Topology.User(n.User)

	kind := fd.joinKind(n, owner, users, logins)
	fd.run.tally.joins[joinNames[kind]]++

	admitted := policymodel.Without(n.Approved, n.AutoApproved)
	full := kind != joinLoginTagged && len(admitted) == 0

	nd := &fdNode{Ephemeral: kind == joinEphemeral}

	opts := []ClientOption{
		WithHostinfo(fd.hostinfo(n, full)), WithUnknownClient(), WithUser(&types.User{}), WithoutNetmapHistory(), WithoutPoll(),
	}

	// as is who a login takes the node in as.
	as := owner

	switch kind {
	case joinLogin, joinLoginTagged:
		if kind == joinLoginTagged {
			as = logins[0]
		}

		nd.Method = util.RegisterMethodCLI
		if as.OIDC() {
			nd.Method = util.RegisterMethodOIDC
		}

		opts = append(opts, WithInteractiveLogin(fd.loginApprover(as)))
	default:
		nd.Method = util.RegisterMethodAuthKey

		// A single-use key is spent by the registration; a relogin with it
		// must still find the node it made.
		nd.reusable = rapid.Bool().Draw(fd.t, "reusable")
		body := map[string]any{"reusable": nd.reusable, "ephemeral": nd.Ephemeral}

		switch {
		case !n.Tagged():
			nd.KeyUser = n.User
		case kind == joinUserTaggedKey:
			nd.KeyUser = users[0].ID
		}

		nd.Tagged = n.Tagged()

		if nd.KeyUser != 0 {
			body["user"] = strconv.FormatUint(uint64(nd.KeyUser), 10)
		}

		if n.Tagged() {
			body["aclTags"] = tagNames(n.Tags)
		}

		var out struct {
			PreAuthKey struct {
				ID  string `json:"id"`
				Key string `json:"key"`
			} `json:"preAuthKey"`
		}

		fd.mustAPI(at, http.MethodPost, "/api/v1/preauthkey", body, &out)
		nd.Key, nd.keyID = out.PreAuthKey.Key, out.PreAuthKey.ID
		opts = append(opts, WithAuthKey(nd.Key))
	}

	tc, err := TryNewClient(fd.tb, fd.srv, fmt.Sprintf("n%d", n.ID), opts...)
	if err != nil {
		fd.t.Fatalf("%s: n%d does not register (%s): %v; its exchanges %s", at, n.ID, joinNames[kind], err, policymodel.JSON(tc.RegisterAttempts()))
	}

	nd.tc = tc

	nv, ok := fd.srv.State().GetNodeByNodeKey(tc.Persist().PrivateNodeKey.Public())
	if !ok {
		fd.t.Fatalf("%s: n%d registered (%s), and the server holds no node of its key", at, n.ID, joinNames[kind])
	}

	fd.answered(at, n.ID, tc)

	if nv.ID() != n.ID {
		fd.run.tally.edits["Join: renumbered"]++
	}

	var v4, v6 netip.Addr
	if a := nv.IPv4(); a.Valid() {
		v4 = a.Get()
	}

	if a := nv.IPv6(); a.Valid() {
		v6 = a.Get()
	}

	if v4 != n.V4 || v6 != n.V6 {
		fd.run.tally.edits["Join: readdressed"]++
	}

	want := n
	want.ID, want.V4, want.V6 = nv.ID(), v4, v6
	fd.nodes[want.ID] = nd

	reg := want
	reg.Approved, reg.AutoApproved, reg.Expired, reg.Offline = nil, nil, false, true

	if !full {
		reg.Announced = nil
	}

	if kind == joinLoginTagged {
		reg.Tags, reg.User = nil, as.ID
	}

	fd.apply(policymodel.Join{Node: reg})
	fd.made("Join", joinNames[kind])

	id := want.ID

	if kind == joinLoginTagged {
		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", id), map[string]any{"tags": tagNames(want.Tags)}, nil)
		fd.apply(policymodel.Retag{ID: id, Tags: want.Tags})
	}

	if len(admitted) > 0 {
		fd.approve(at, id, admitted, nil)
	}

	if !full && len(want.Announced) > 0 {
		cur, _ := fd.w.Topology.Node(id)
		cur.Announced = want.Announced
		fd.report(at, id, cur)
		fd.apply(policymodel.Announce{ID: id, Routes: want.Announced})
	}

	if want.Expired {
		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/expire", id), map[string]any{}, nil)
		fd.apply(policymodel.SetExpired{ID: id, Expired: true})
	}

	if !want.Offline {
		fd.connect(at, id)
		fd.apply(policymodel.SetOnline{ID: id, Online: true})
	}

	got, _ := fd.w.Topology.Node(id)

	return got
}

// answered holds what a registration answered tc to what the server
// stored: the node of its new key, owned by the user it was told it logs
// in as, the tagged devices' for a tagged node. The client takes its user
// from its first map once one arrives, which shows a tagged node itself
// as a user of its own (taggedSelfUserID in mapper), so for a tagged node
// that ID is its owner too.
func (fd *frontDoor) answered(at string, id types.NodeID, tc *TestClient) {
	p := tc.Persist()

	nv, ok := fd.srv.State().GetNodeByNodeKey(p.PrivateNodeKey.Public())
	if !ok {
		fd.t.Fatalf("%s: n%d's client was registered under a key the server holds no node of", at, id)
	}

	owner := types.TaggedDevices.ID
	if !nv.IsTagged() && nv.UserID().Valid() {
		owner = nv.UserID().Get()
	}

	// The keys its entry must carry on the wire ([policymodel.WireKeys]).
	fd.keys[nv.ID()] = fdKeys{node: p.PrivateNodeKey.Public(), disco: tc.discoKey}

	if got := uint(p.UserProfile.ID); got != owner && (!nv.IsTagged() || got != types.TaggedDevicesUserID+1+uint(nv.ID())) { //nolint:gosec // small
		fd.t.Fatalf("%s: n%d's client was told it logs in as user %d; the server stored its node as user %d's", at, nv.ID(), got, owner)
	}
}

// without is from less rs.
// approve sets id's approved routes through the API, the whole list as
// an admin does, adding add and dropping drop. The API takes one exit
// route in the list for both: an edit of one family is written, and
// modelled, as both, and a list still holding one family, as
// auto-approval of a node announcing one leaves it, gains the other.
func (fd *frontDoor) approve(at string, id types.NodeID, add, drop []int) {
	n, _ := fd.w.Topology.Node(id)
	exits := []int{exitRoute(4), exitRoute(6)}

	widen := func(rs []int) []int {
		if slices.ContainsFunc(rs, func(r int) bool { return slices.Contains(exits, r) }) {
			for _, x := range exits {
				if !slices.Contains(rs, x) {
					rs = append(rs, x)
					fd.run.tally.edits["approval of one exit family: both"]++
				}
			}
		}

		return rs
	}

	add, drop = widen(slices.Clone(add)), widen(slices.Clone(drop))

	want := policymodel.Without(n.Approved, drop)
	for _, r := range add {
		if !slices.Contains(want, r) {
			want = append(want, r)
		}
	}

	if slices.ContainsFunc(want, func(r int) bool { return slices.Contains(exits, r) }) {
		for _, x := range exits {
			if !slices.Contains(want, x) {
				want, add = append(want, x), append(add, x)
				fd.run.tally.edits["approval list holding one exit family: both"]++
			}
		}
	}

	routes := make([]string, 0, len(want))
	for _, r := range want {
		routes = append(routes, policymodel.Prefixes[r].String())
	}

	fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/approve_routes", id), map[string]any{"routes": routes}, nil)

	if len(add) > 0 {
		fd.apply(policymodel.Approve{ID: id, Routes: add})
		fd.made("Approve", "API")
	}

	if len(drop) > 0 {
		fd.apply(policymodel.Unapprove{ID: id, Routes: drop})
		fd.made("Unapprove", "API")
	}
}

// exitRoute is the index of the exit route of family f.
func exitRoute(f int) int {
	want := tsaddr.AllIPv4()
	if f == 6 {
		want = tsaddr.AllIPv6()
	}

	return slices.Index(policymodel.Prefixes, want)
}

// report has id's client report n's routes and client in a map request of
// its own, as tailscaled does when they change.
func (fd *frontDoor) report(at string, id types.NodeID, n policymodel.Node) {
	nd := fd.nodes[id]
	nd.tc.Direct().SetHostinfo(fd.hostinfo(n, true))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := nd.tc.Direct().SendUpdate(ctx)
	if err != nil {
		fd.t.Fatalf("%s: n%d's map request: %v", at, id, err)
	}
}

// connect opens id's map session.
func (fd *frontDoor) connect(at string, id types.NodeID) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := fd.nodes[id].tc.RestartPoll(ctx)
	if err != nil {
		fd.t.Fatalf("%s: n%d connects: %v", at, id, err)
	}
}

// leave deletes id: through the API, or, for an ephemeral node in session,
// sometimes as its client's logout does; an expired key's logout is
// answered as expired and leaves the node to the collector.
func (fd *frontDoor) leave(at string, id types.NodeID) {
	nd := fd.nodes[id]
	n, _ := fd.w.Topology.Node(id)

	if nd.Ephemeral && !n.Expired && nd.tc.Polling() && !fd.clock && rapid.Bool().Draw(fd.t, "ephemeral-logout") {
		// A case running the small clock never takes this path: the
		// deletion a logged-out ephemeral node arms lands inside the
		// case, while the model holds the node. The API delete below
		// drops it at once instead.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := nd.tc.LogoutAndDisconnect(ctx)
		if err != nil {
			fd.t.Fatalf("%s: n%d logs out: %v", at, id, err)
		}

		fd.made("Leave", "logout (ephemeral)")
	} else {
		fd.mustAPI(at, http.MethodDelete, fmt.Sprintf("/api/v1/node/%d", id), nil, nil)
		fd.made("Leave", "API")

		// The server ends a deleted node's session.
		if nd.tc.Polling() {
			select {
			case <-nd.tc.pollDone:
			case <-time.After(20 * time.Second):
				fd.t.Fatalf("%s: n%d was deleted, and its map session goes on", at, id)
			}
		}
	}

	fd.drop(id)
	fd.apply(policymodel.Leave{ID: id})
}

// drop ends id's client, its node gone.
func (fd *frontDoor) drop(id types.NodeID) {
	if nd := fd.nodes[id]; nd != nil {
		nd.tc.cleanupOnce()
	}

	delete(fd.nodes, id)
	delete(fd.keys, id)
}

// registrationKeys is the tunnel keys id's client registered with, for
// [policymodel.WireKeys].
func (fd *frontDoor) registrationKeys(id types.NodeID) (key.NodePublic, key.DiscoPublic) {
	k := fd.keys[id]
	return k.node, k.disco
}

// untag makes tagged node e.ID user e.User's, as that user's interactive
// login on it does: when the user can claim the node (it joined through a
// login, or with that user's key). Otherwise the login would add a
// device beside it, which the model cannot follow: left out.
func (fd *frontDoor) untag(at string, e policymodel.Retag) {
	nd := fd.nodes[e.ID]
	u, _ := fd.w.Topology.User(e.User)

	if nd.Method == util.RegisterMethodAuthKey && nd.KeyUser != e.User || !fd.loginUser(u) {
		fd.made("Login", "left out (a login it cannot claim)")

		return
	}

	n, _ := fd.w.Topology.Node(e.ID)
	fd.login(at, e.ID, u, n)
	fd.made("Login", "interactive login")
	fd.apply(e)
	fd.apply(policymodel.SetOnline{ID: e.ID, Online: true})
}

// autoApprove has the model run auto-approval on id, as the server does
// after every login, interactive or with a key, under a new node key
// (approveRoutesAfterRegistration): a route an admin unapproved comes back
// if the policy approves it. The model runs it only for a Retag to a
// user, a login taking a node back; for the other logins the driver
// announces what id announces already.
func (fd *frontDoor) autoApprove(id types.NodeID) {
	if n, ok := fd.w.Topology.Node(id); ok && len(n.Announced) > 0 {
		fd.apply(policymodel.Announce{ID: id, Routes: n.Announced})
	}
}

// login logs id's client in interactively as u, with a new node key, as
// `tailscale up --force-reauth` does; its map session restarts. A login
// that renews a user's node keeps how it registered. One that takes a
// tagged node back registers it as the login does and drops its key, and
// the device the user claimed is no longer ephemeral (processReauthTags),
// so the collector cannot delete it at its next disconnect.
func (fd *frontDoor) login(at string, id types.NodeID, u policymodel.User, n policymodel.Node) {
	nd := fd.nodes[id]

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := nd.tc.Login(ctx, nd.tc.Persist(), "", controlclient.LoginInteractive, fd.hostinfo(n, true), fd.loginApprover(u))
	if err != nil {
		fd.t.Fatalf("%s: n%d logs in as u%d: %v", at, id, u.ID, err)
	}

	fd.answered(at, id, nd.tc)

	nd.loggedOut = false

	if !n.Tagged() {
		return
	}

	nd.Method, nd.Key, nd.KeyUser, nd.reusable, nd.Tagged, nd.Ephemeral = util.RegisterMethodCLI, "", 0, false, false, false
	if u.OIDC() {
		nd.Method = util.RegisterMethodOIDC
	}
}

// pick draws one of the nodes ok accepts, in ID order; false when none.
func (fd *frontDoor) pick(label string, ok func(policymodel.Node, *fdNode) bool) (policymodel.Node, bool) {
	var can []policymodel.Node

	for _, n := range fd.w.Topology.Nodes {
		if ok(n, fd.nodes[n.ID]) {
			can = append(can, n)
		}
	}

	if len(can) == 0 {
		return policymodel.Node{}, false
	}

	return can[rapid.IntRange(0, len(can)-1).Draw(fd.t, label)], true
}

// weather moves a polling client's session as networks and tailscaled
// do; the model does not change.
func (fd *frontDoor) weather(at string, kind int) {
	n, ok := fd.pick("weathered", func(n policymodel.Node, nd *fdNode) bool {
		// An ephemeral node's poll ending arms the inactivity timer; the
		// reconnects these steps make are quick, but a case running the
		// small clock leaves them to it alone.
		return !n.Offline && !n.Expired && nd.tc.Polling() && (!nd.Ephemeral || !fd.clock)
	})
	if !ok {
		fd.run.tally.steps[stepNames[kind]+" (no node)"]++

		return
	}

	fd.run.tally.steps[stepNames[kind]]++

	nd := fd.nodes[n.ID]

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var err error

	switch kind {
	case stepFlap:
		// The session drops and the client registers again at once, well
		// inside the reconnect grace, with the key it still has, if any.
		nd.tc.Disconnect(fd.tb)
		err = nd.tc.Login(ctx, nd.tc.Persist(), nd.Key, controlclient.LoginDefault, fd.hostinfo(n, true), nil)
	case stepRestartPoll:
		err = nd.tc.RestartPoll(ctx)
	case stepClientRestart:
		err = nd.tc.Restart(ctx, fd.hostinfo(n, true))

		// The restart gave its client a new disco key, which its entry
		// must carry once its registration lands.
		keys := fd.keys[n.ID]
		keys.disco = nd.tc.discoKey
		fd.keys[n.ID] = keys
	case stepEndpoints:
		eps := fdEndpoints[rapid.IntRange(0, len(fdEndpoints)-1).Draw(fd.t, "endpoints")]
		nd.tc.Direct().SetEndpoints(eps)
		err = nd.tc.Direct().SendUpdate(ctx)
	}

	if err != nil {
		fd.t.Fatalf("%s: n%d %s: %v", at, n.ID, stepNames[kind], err)
	}
}

// fdClock is the ephemeral inactivity timeout a case drawing the small
// clock runs the garbage collector on: long enough that the reconnects
// the other steps make land well inside it, short enough that a case
// waits it out.
const fdClock = 8 * time.Second

// clockStep exercises the inactivity clock the ephemeral garbage collector
// runs on: an ephemeral node's poll ends, which arms its deletion timer,
// and it polls again well inside the timeout, as a client on flapping
// network weather does, without registering — the key it joined with may
// be spent, revoked with its user, or refused; the map session its own
// connect opens is what cancels the timer ([WithEphemeralTimeout]). The
// step waits the timeout out: a timer its own connect leaves armed
// deletes the node under its live session. Only a case that drew the
// small clock runs it.
func (fd *frontDoor) clockStep(at string) {
	if !fd.clock {
		fd.run.tally.steps[stepNames[stepClock]+" (no clock)"]++

		return
	}

	n, ok := fd.pick("clocked", func(n policymodel.Node, nd *fdNode) bool {
		if !nd.Ephemeral || n.Offline || n.Expired || !nd.tc.Polling() {
			return false
		}

		// What the step breaks is the connect cancelling the timer, so the
		// node must still be ephemeral in the server's eyes: a login may
		// have taken it back as a user's device since.
		nv, has := fd.srv.State().GetNodeByID(n.ID)

		return has && nv.IsEphemeral()
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepClock]+" (no node)"]++

		return
	}

	fd.run.tally.steps[stepNames[stepClock]]++

	nd := fd.nodes[n.ID]

	// The clock is wall time; nothing in the state tells the timer's
	// position, so the step waits it out by sleeping.
	nd.tc.Disconnect(fd.tb)
	time.Sleep(fdClock / 8) //nolint:forbidigo // arming the timer mid-window
	fd.connect(at, n.ID)
	time.Sleep(fdClock + 4*time.Second) //nolint:forbidigo // the timer's own wait

	if !nd.tc.Polling() {
		fd.t.Fatalf("%s: n%d does not poll again after its reconnect", at, n.ID)
	}
}

// fdRecords are the extra DNS records the records manager republishes
// through [state.State.SetExtraRecords]: names no node can hold, both
// families.
var fdRecords = []tailcfg.DNSRecord{
	{Name: "alpha.service.example", Type: "A", Value: "192.0.2.10"},
	{Name: "beta.service.example", Type: "A", Value: "192.0.2.11"},
	{Name: "gamma.service.example", Type: "AAAA", Value: "2001:db8::10"},
}

// fdDERPRegion is the region a policy's derpMap key adds: 900 is the
// configured map's own, so the two never collide.
const fdDERPRegion = 901

// fdDERPDoc is the derpMap key the records step writes beside the
// model's policy: one region, one node, ids matching, as the rules the
// loader applies demand.
const fdDERPDoc = `"derpMap": {"Regions": {"901": {"RegionID": 901, "RegionCode": "frontdoor", "RegionName": "Front Door", "Nodes": [
	{"Name": "901a", "RegionID": 901, "HostName": "127.0.0.1", "DERPPort": -1}]}}}`

// recordsStep changes what the running server serves behind its streams'
// maps — never a node itself: the extra DNS records the records manager
// republishes through [state.State.SetExtraRecords], and the DERP region
// a policy's derpMap key adds to the served document, which the next
// policy write — here or in any other step — drops again. The model
// holds neither; what must hold is that every client converges on what a
// fresh session is given, and that the region reaches every client's
// DERP map while the document names it ([judgeClients] checks that).
func (fd *frontDoor) recordsStep(at string) {
	fd.run.tally.steps[stepNames[stepRecords]]++

	kind := rapid.IntRange(0, 2).Draw(fd.t, "records")

	if kind < 2 {
		// Extra records: a drawn subset, empty included — a republish
		// that drops what was there does.
		var records []tailcfg.DNSRecord

		if kind == 0 {
			for _, r := range fdRecords {
				if rapid.Bool().Draw(fd.t, "record") {
					records = append(records, r)
				}
			}
		}

		fd.srv.State().SetExtraRecords(records)
		fd.records = slices.Clone(records)

		if len(records) > 0 {
			fd.run.tally.steps[stepNames[stepRecords]+": extra records published"]++
		} else {
			fd.run.tally.steps[stepNames[stepRecords]+": extra records cleared"]++
		}

		return
	}

	if !fd.derp {
		body := strings.TrimSpace(string(fd.w.Policy.HuJSON()))

		switch body {
		case "{}":
			body = "{" + fdDERPDoc + "}"
		default:
			body = strings.TrimSuffix(body, "}") + ",\n" + fdDERPDoc + "}"
		}

		// The document carries the model's tokens, so the write is
		// refused while they name several users, as the identity step's
		// rewrite is; the served document is unchanged then.
		amb := len(policymodel.NewView(fd.w).AmbiguousRefs()) > 0

		switch err := fd.api(http.MethodPut, "/api/v1/policy", map[string]any{"policy": body}, nil); {
		case err == nil:
			fd.derp = true
			fd.run.tally.steps[stepNames[stepRecords]+": the policy's DERP region added"]++
		case amb:
			fd.run.tally.steps[stepNames[stepRecords]+": the policy's DERP region (refused: a token names several users)"]++
		default:
			fd.t.Fatalf("%s: the policy's DERP region is not written: %v", at, err)
		}

		return
	}

	// The region leaves through the write every policy step makes: the
	// model's document, without the derpMap key.
	amb := len(policymodel.NewView(fd.w).AmbiguousRefs()) > 0

	switch err := fd.api(http.MethodPut, "/api/v1/policy", map[string]any{"policy": string(fd.w.Policy.HuJSON())}, nil); {
	case err == nil:
		fd.derp = false
		fd.run.tally.steps[stepNames[stepRecords]+": the policy's DERP region dropped"]++
	case amb:
		fd.run.tally.steps[stepNames[stepRecords]+": the policy's DERP region kept (refused: a token names several users)"]++
	default:
		fd.t.Fatalf("%s: the model's policy is not written back: %v", at, err)
	}
}

// sessionsStep drives one node holding more than one live map session:
// a second stream opened on the same device's identity while the first
// still drains, a session ended while another of its node's lives, and
// past the hub's limit, where the oldest stream is closed for the
// newcomer. The model changes nothing — a node is online while any of
// its sessions polls, and every client holds what a fresh session is
// given, whatever the hub does with the streams it admits.
func (fd *frontDoor) sessionsStep(at string) {
	fd.run.tally.steps[stepNames[stepSecond]]++

	n, ok := fd.pick("two-sessions", func(n policymodel.Node, nd *fdNode) bool {
		return !n.Offline && !n.Expired && !nd.loggedOut && nd.tc.Polling()
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepSecond]+" (no node)"]++

		return
	}

	nd := fd.nodes[n.ID]

	switch rapid.IntRange(0, 2).Draw(fd.t, "sessions") {
	case 0:
		// A second stream beside the first, and a commit both must see.
		fd.run.tally.steps[stepNames[stepSecond]+": a commit both streams must see"]++

		extra := fd.secondClient(n)
		nd.extras = append(nd.extras, extra)

		fd.endpointCommit(at, nd)
		fd.settle(at)

		// Ending the extra must not take the node offline: its first
		// session still polls.
		extra.Disconnect(fd.tb)

		nd.extras = nil

		fd.quiet(at)

	case 1:
		// The first session ends while the second lives: the node must
		// stay online, and the first must be able to come back.
		fd.run.tally.steps[stepNames[stepSecond]+": one ended while another lives"]++

		extra := fd.secondClient(n)
		nd.extras = append(nd.extras, extra)

		fd.settle(at)

		nd.tc.Disconnect(fd.tb)
		fd.settle(at)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := nd.tc.RestartPoll(ctx)
		if err != nil {
			fd.t.Fatalf("%s: n%d's first session does not come back: %v", at, n.ID, err)
		}

		extra.Disconnect(fd.tb)

		nd.extras = nil

		fd.quiet(at)

	default:
		// Past the limit: the fifth stream closes the oldest, the node
		// stays online through the rest, and the evicted client does not
		// thrash reconnecting.
		fd.run.tally.steps[stepNames[stepSecond]+": past the limit, the oldest evicted"]++

		for range 4 {
			nd.extras = append(nd.extras, fd.secondClient(n))
		}

		fd.quiet(at)

		if nd.tc.Polling() {
			fd.t.Fatalf("%s: n%d holds %d live sessions, and its oldest stream is not closed for the newcomer", at, n.ID, len(nd.extras)+1)
		}

		fd.quiet(at)

		if nd.tc.Polling() {
			fd.t.Fatalf("%s: n%d's evicted stream came back on its own", at, n.ID)
		}

		for _, extra := range nd.extras {
			extra.Disconnect(fd.tb)
		}

		nd.extras = nil

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := nd.tc.RestartPoll(ctx)
		if err != nil {
			fd.t.Fatalf("%s: n%d's evicted session does not come back: %v", at, n.ID, err)
		}

		fd.quiet(at)
	}
}

// sshPair is a source node and the destination login a check rule lets
// a connection claim.
type sshPair struct {
	src   policymodel.Node
	login string
}

// checkPairs is the source nodes and destination logins the served check
// rules cover, and the sources no check rule covers at all.
func (fd *frontDoor) checkPairs(rules []*tailcfg.SSHRule) ([]sshPair, map[types.NodeID]bool) {
	var covered []sshPair

	uncovered := make(map[types.NodeID]bool, len(fd.w.Topology.Nodes))

	for _, m := range fd.w.Topology.Nodes {
		uncovered[m.ID] = true
	}

	for _, r := range rules {
		if r == nil || r.Action == nil || r.Action.HoldAndDelegate == "" {
			continue
		}

		for _, p := range r.Principals {
			if p == nil {
				continue
			}

			// The rule names its sources by address, as the wire
			// serves them; a principal naming none stands for any
			// source.
			var srcs []policymodel.Node

			switch p.NodeIP {
			case "":
				// A principal naming no address stands for any
				// source: every node is one.
				srcs = fd.w.Topology.Nodes

				clear(uncovered)
			default:
				addr, err := netip.ParseAddr(p.NodeIP)
				if err != nil {
					continue
				}

				for _, m := range fd.w.Topology.Nodes {
					if m.V4 == addr || m.V6 == addr {
						srcs = []policymodel.Node{m}

						break
					}
				}
			}

			for _, src := range srcs {
				if p.NodeIP != "" {
					delete(uncovered, src.ID)
				}

				// The logins the rule's served map lets the connection
				// claim: root when granted, any non-root login when the
				// wildcard grants it (the source user's own name), and
				// any literal user the rule names.
				if r.SSHUsers["root"] == "root" {
					covered = append(covered, sshPair{src, "root"})
				}

				if r.SSHUsers["*"] == "=" && !src.Tagged() {
					if u, _ := fd.w.Topology.User(src.User); u.Name != "" {
						covered = append(covered, sshPair{src, u.Name})
					}
				}

				for login, local := range r.SSHUsers {
					if login != "root" && login != "*" && local != "" {
						covered = append(covered, sshPair{src, login})
					}
				}
			}
		}
	}

	return covered, uncovered
}

// makeCheckPair leaves the world holding a check rule covering a root
// login between dst's user's nodes, as an admin writes one, reporting
// whether it did: it needs a reference naming the user alone, a
// user-owned destination and a policy the tokens of which are
// unambiguous. A literal login is only allowed within one user, so the
// rule stays on that user's both sides.
func (fd *frontDoor) makeCheckPair(dst policymodel.Node) bool {
	v := policymodel.NewView(fd.w)

	if len(v.AmbiguousRefs()) > 0 {
		return false
	}

	dstUser, _ := fd.w.Topology.User(dst.User)

	ref := soloRef(v, dstUser)
	if dst.Tagged() || dstUser.ID == 0 || ref < 0 {
		return false
	}

	p := fd.w.Policy
	p.SSH = append(slices.Clone(p.SSH), policymodel.SSHRule{
		Check: true,
		Src:   []policymodel.Sel{{Kind: policymodel.SelUser, I: ref}},
		Dst:   []policymodel.Sel{{Kind: policymodel.SelUser, I: ref}},
		Users: []int{0}, // root
	})

	fd.setPolicy(p)
	fd.made("policy", "a check rule for the ssh step")

	return true
}

// soloRef is a user reference naming u alone, or -1.
func soloRef(v *policymodel.View, u policymodel.User) int {
	if u.ID == 0 {
		return -1
	}

	for r := range policymodel.UserRefs {
		if us := v.RefUsers(r); len(us) == 1 && us[0] == u.ID && !v.Ambiguous(r) {
			return r
		}
	}

	return -1
}

// sshCheckStep drives the SSH check action end to end, as tailscaled
// runs it: the destination node polls its served policy's check rule
// over its Noise connection, the answer holds and delegates, the check
// is approved or rejected through the auth endpoints the hardening made
// SSH-check-only, and the follow-up is given the verdict the approval
// left. A follow-up for a verdict a check has already spent is decided
// again, never replayed, and a poll for a connection no check rule
// covers is refused at once, never held.
func (fd *frontDoor) sshCheckStep(at string) {
	fd.run.tally.steps[stepNames[stepSSHCheck]]++

	// The destination: a live node whose client polls, its served rules
	// what the client itself has.
	n, ok := fd.pick("ssh-dst", func(n policymodel.Node, nd *fdNode) bool {
		return !n.Offline && !nd.loggedOut && nd.tc.Polling() && nd.tc.Netmap() != nil
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepSSHCheck]+" (no node)"]++

		return
	}

	nd := fd.nodes[n.ID]

	var rules []*tailcfg.SSHRule
	if p := nd.tc.Netmap().SSHPolicy; p != nil {
		rules = p.Rules
	}

	covered, uncovered := fd.checkPairs(rules)

	kind := rapid.IntRange(0, 2).Draw(fd.t, "ssh-check")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if kind < 2 && len(covered) == 0 {
		// The drawn policy drew no check rule a concrete pair and login
		// answer to; write one, so the approve and reject shapes run
		// wherever the step is drawn. The re-read rules then name the
		// pair; the uncovered set the refusal shape reads is stale, and
		// that shape was not drawn.
		if fd.makeCheckPair(n) {
			fd.settle(at)

			rules = nil
			if p := nd.tc.Netmap().SSHPolicy; p != nil {
				rules = p.Rules
			}

			covered, _ = fd.checkPairs(rules)
		}
	}

	if kind == 2 {
		// A poll no check rule covers: refused at once, never held.
		sources := slices.Sorted(maps.Keys(uncovered))
		if len(sources) == 0 {
			fd.run.tally.steps[stepNames[stepSSHCheck]+": every source checked (no refusal to drive)"]++

			return
		}

		src := sources[rapid.IntRange(0, len(sources)-1).Draw(fd.t, "uncovered")]
		login := fdSSHLogins[rapid.IntRange(0, len(fdSSHLogins)-1).Draw(fd.t, "login")]

		// The poll comes from the destination's own client, as tailssh
		// polls over the machine the connection lands on.
		action, err := nd.tc.SSHAction(ctx, src, n.ID, login, "")
		if err != nil {
			fd.t.Fatalf("%s: n%d's check of n%d as %s: %v", at, src, n.ID, login, err)
		}

		if action.HoldAndDelegate != "" || action.Accept {
			fd.t.Fatalf("%s: n%d's connection to n%d as %s, which no check rule covers, is held or accepted: %+v", at, src, n.ID, login, action)
		}

		fd.run.tally.steps[stepNames[stepSSHCheck]+": no rule, refused"]++

		return
	}

	if kind < 2 {
		if len(covered) == 0 {
			fd.run.tally.steps[stepNames[stepSSHCheck]+" (no check rule with a concrete login)"]++

			return
		}

		p := covered[rapid.IntRange(0, len(covered)-1).Draw(fd.t, "checked")]

		action, err := nd.tc.SSHAction(ctx, p.src.ID, n.ID, p.login, "")
		if err != nil {
			fd.t.Fatalf("%s: n%d's check of n%d as %s: %v", at, p.src.ID, n.ID, p.login, err)
		}

		if action.Accept {
			// Checked recently within the check period: the connection
			// is allowed without a new check.
			fd.run.tally.steps[stepNames[stepSSHCheck]+": auto-approved within the period"]++

			return
		}

		if action.HoldAndDelegate == "" {
			fd.t.Fatalf("%s: n%d's check of n%d as %s is neither held nor accepted: %+v", at, p.src.ID, n.ID, p.login, action)
		}

		spent, err := authIDOfHoldURL(action.HoldAndDelegate)
		if err != nil {
			fd.t.Fatalf("%s: n%d's check of n%d as %s holds a URL with no auth id: %v", at, p.src.ID, n.ID, p.login, err)
		}

		// The first round approves; a check vouches for one connection,
		// so a second follow-up for the spent verdict is decided again,
		// never replayed, and the fresh check it is given rejects.
		fd.mustAPI(at, http.MethodPost, "/api/v1/auth/approve", map[string]any{"authId": spent.String()}, nil)
		fd.run.tally.steps[stepNames[stepSSHCheck]+": approved"]++

		follow, err := nd.tc.SSHAction(ctx, p.src.ID, n.ID, p.login, spent.String())
		if err != nil {
			fd.t.Fatalf("%s: n%d's follow-up of n%d as %s: %v", at, p.src.ID, n.ID, p.login, err)
		}

		if !follow.Accept {
			fd.t.Fatalf("%s: n%d's approved check of n%d as %s is not accepted: %+v", at, p.src.ID, n.ID, p.login, follow)
		}

		again, err := nd.tc.SSHAction(ctx, p.src.ID, n.ID, p.login, spent.String())
		if err != nil {
			fd.t.Fatalf("%s: n%d's replayed follow-up of n%d as %s: %v", at, p.src.ID, n.ID, p.login, err)
		}

		if again.Accept || again.Reject {
			fd.t.Fatalf("%s: n%d's spent check of n%d as %s is replayed to a second follow-up: %+v", at, p.src.ID, n.ID, p.login, again)
		}

		fresh, err := authIDOfHoldURL(again.HoldAndDelegate)
		if err != nil {
			fd.t.Fatalf("%s: n%d's re-decided check of n%d as %s holds no new auth id: %v", at, p.src.ID, n.ID, p.login, err)
		}

		if fresh == spent {
			fd.t.Fatalf("%s: n%d's re-decided check of n%d as %s reuses the spent auth id", at, p.src.ID, n.ID, p.login)
		}

		fd.run.tally.steps[stepNames[stepSSHCheck]+": re-decided"]++

		// The second round rejects through the fresh check.
		fd.mustAPI(at, http.MethodPost, "/api/v1/auth/reject", map[string]any{"authId": fresh.String()}, nil)
		fd.run.tally.steps[stepNames[stepSSHCheck]+": rejected"]++

		last, err := nd.tc.SSHAction(ctx, p.src.ID, n.ID, p.login, fresh.String())
		if err != nil {
			fd.t.Fatalf("%s: n%d's rejected follow-up of n%d as %s: %v", at, p.src.ID, n.ID, p.login, err)
		}

		if !last.Reject {
			fd.t.Fatalf("%s: n%d's rejected check of n%d as %s is not rejected: %+v", at, p.src.ID, n.ID, p.login, last)
		}
	}
}

// fdSSHLogins are the concrete destination logins a check rule may map.
var fdSSHLogins = []string{"root", "alice"}

// authIDOfHoldURL is the auth id a HoldAndDelegate URL carries.
func authIDOfHoldURL(holdURL string) (types.AuthID, error) {
	u, err := url.Parse(holdURL)
	if err != nil {
		return types.AuthID(""), fmt.Errorf("parsing the hold URL: %w", err)
	}

	return types.AuthIDFromString(u.Query().Get("auth_id"))
}

// secondClient opens a further map session of node n on the same device
// identity as its client, which stays open beside it.
func (fd *frontDoor) secondClient(n policymodel.Node) *TestClient {
	fd.t.Helper()

	name := fmt.Sprintf("n%d-again-%d", n.ID, len(fd.nodes[n.ID].extras)+1)
	tc := SecondSessionClient(fd.tb, fd.srv, name, fd.nodes[n.ID].tc, fd.hostinfo(n, true))

	fd.run.tally.steps[stepNames[stepSecond]+": a second stream"]++

	return tc
}

// endpointCommit has the node's client report new endpoints, as the
// endpoints step does: a write through the map request path, so a commit
// every one of the node's live sessions must see.
func (fd *frontDoor) endpointCommit(at string, nd *fdNode) {
	eps := fdEndpoints[rapid.IntRange(0, len(fdEndpoints)-1).Draw(fd.t, "endpoints")]

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	nd.tc.Direct().SetEndpoints(eps)

	err := nd.tc.Direct().SendUpdate(ctx)
	if err != nil {
		fd.t.Fatalf("%s: %s reports endpoints: %v", at, nd.tc.Name, err)
	}
}

// rename has an admin rename a node, as `headscale nodes rename` does.
func (fd *frontDoor) rename(at string) {
	n, ok := fd.pick("renamed", func(policymodel.Node, *fdNode) bool { return true })
	if !ok {
		fd.run.tally.steps[stepNames[stepRename]+" (no node)"]++

		return
	}

	fd.run.tally.steps[stepNames[stepRename]]++

	name := fdNames[rapid.IntRange(0, len(fdNames)-1).Draw(fd.t, "name")]

	holder := types.NodeID(0)

	for _, nv := range fd.srv.State().Snapshot().ListNodes().All() {
		if nv.GivenName() == name {
			holder = nv.ID()
		}
	}

	err := fd.api(http.MethodPost, fmt.Sprintf("/api/v1/node/%d/rename/%s", n.ID, name), nil, nil)

	switch {
	case holder == 0 && err != nil:
		fd.t.Fatalf("%s: n%d is not renamed %q, which no node holds: %v", at, n.ID, name, err)
	case holder != 0 && holder != n.ID && err == nil:
		fd.t.Fatalf("%s: n%d is renamed %q, which n%d holds", at, n.ID, name, holder)
	}
}

// fdNames are names an admin gives nodes; two nodes may be given one.
var fdNames = []string{"web", "db", "n1"}

// fdEndpoints are what a client may report it is reachable at.
var fdEndpoints = [][]tailcfg.Endpoint{
	{{Addr: netip.MustParseAddrPort("192.0.2.1:41641"), Type: tailcfg.EndpointLocal}},
	{{Addr: netip.MustParseAddrPort("198.51.100.7:3478"), Type: tailcfg.EndpointSTUN}, {Addr: netip.MustParseAddrPort("192.0.2.1:41641"), Type: tailcfg.EndpointLocal}},
	{{Addr: netip.MustParseAddrPort("[2001:db8::1]:41641"), Type: tailcfg.EndpointLocal}},
}

// logout logs a client out, as `tailscale logout` does: its node expires,
// an ephemeral one is deleted, and its session ends.
func (fd *frontDoor) logout(at string) {
	n, ok := fd.pick("logs-out", func(n policymodel.Node, nd *fdNode) bool {
		// A case running the small clock leaves an ephemeral node alone:
		// its logout would arm a deletion the model cannot see coming.
		return !n.Expired && !nd.loggedOut && (!nd.Ephemeral || !fd.clock)
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepLogout]+" (no node)"]++

		return
	}

	fd.run.tally.steps[stepNames[stepLogout]]++

	nd := fd.nodes[n.ID]

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := nd.tc.LogoutAndDisconnect(ctx)
	if err != nil {
		fd.t.Fatalf("%s: n%d logs out: %v", at, n.ID, err)
	}

	if nd.Ephemeral {
		fd.drop(n.ID)
		fd.apply(policymodel.Leave{ID: n.ID})

		return
	}

	nd.loggedOut = true

	fd.apply(policymodel.SetExpired{ID: n.ID, Expired: true})
	fd.apply(policymodel.SetOnline{ID: n.ID, Online: false})
}

// relogin renews a node whose client logged out or whose key expired: it
// logs in again with a new node key, with its reusable pre-auth key or
// interactively as its user, and connects. A tagged node with no such key
// has no way back but a login that untags it. A user's own key presented
// for a node an admin tagged since takes it back as that user's device,
// untagged and no longer ephemeral (preAuthKeyClaimsTaggedNode).
func (fd *frontDoor) relogin(at string) {
	n, ok := fd.pick("logs-in", func(n policymodel.Node, nd *fdNode) bool {
		owner, _ := fd.w.Topology.User(n.User)

		return (n.Expired || nd.loggedOut) && (nd.Key != "" && nd.reusable && nd.keySpeaksFor(n) || !n.Tagged() && fd.loginUser(owner))
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepRelogin]+" (no node)"]++

		return
	}

	fd.run.tally.steps[stepNames[stepRelogin]]++

	nd := fd.nodes[n.ID]

	if nd.Key == "" || !nd.reusable {
		u, _ := fd.w.Topology.User(n.User)
		fd.login(at, n.ID, u, n)
		fd.apply(policymodel.SetExpired{ID: n.ID, Expired: false})
		fd.apply(policymodel.SetOnline{ID: n.ID, Online: true})
		fd.autoApprove(n.ID)

		return
	}

	edits := fd.keyLoginEdits(n)

	err := fd.keyLogin(n, nd.Key)
	if err != nil {
		fd.t.Fatalf("%s: n%d logs in again with its key: %v", at, n.ID, err)
	}

	fd.keyLoggedIn(at, n)
	fd.w = fd.w.Apply(edits...)
}

// v2Renew writes the v2 key-renewal form, which the drawn edits reach
// only when a case both draws an expiry renewal and takes the v2 API:
// an admin renews one unexpired node's key, which changes nothing, so
// every v2 case carries the write and a deep run always reaches it.
func (fd *frontDoor) v2Renew(at string) {
	n, ok := fd.pick("to-renew", func(n policymodel.Node, nd *fdNode) bool {
		return !n.Expired && !nd.loggedOut
	})
	if !ok {
		return
	}

	fd.edit(at, policymodel.SetExpired{ID: n.ID, Expired: false}, nil)
}

// keyLogin logs n's client in again with key under a new node key, as
// `tailscale up --force-reauth --auth-key` does; its map session restarts.
// Safe off the test's goroutine.
func (fd *frontDoor) keyLogin(n policymodel.Node, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	return fd.nodes[n.ID].tc.Login(ctx, fd.nodes[n.ID].tc.Persist(), key, controlclient.LoginInteractive, fd.hostinfo(n, true), nil)
}

// keyLoginEdits is what a login with n's key makes of n: a user's own key
// presented for a node an admin tagged since takes it back as that user's
// device (preAuthKeyClaimsTaggedNode), but only while its registration by
// the key still stands — an interactive login that re-registered the node
// left no key that claims it (ClaimableBy); any other login renews it. It
// connects, and the server runs auto-approval (see autoApprove).
func (fd *frontDoor) keyLoginEdits(n policymodel.Node) []policymodel.Edit {
	var out []policymodel.Edit

	if nd := fd.nodes[n.ID]; n.Tagged() && !nd.Tagged && nd.Method == util.RegisterMethodAuthKey {
		out = append(out, policymodel.Retag{ID: n.ID, User: nd.KeyUser})
	}

	if len(n.Announced) > 0 {
		out = append(out, policymodel.Announce{ID: n.ID, Routes: n.Announced})
	}

	return append(out, policymodel.SetExpired{ID: n.ID, Expired: false}, policymodel.SetOnline{ID: n.ID, Online: true})
}

// keyLoggedIn records a login with n's key: under a new node key it
// registers the node with the key, whatever registered it last (an
// interactive login may have since); the claimed device is no longer
// ephemeral.
func (fd *frontDoor) keyLoggedIn(at string, n policymodel.Node) {
	nd := fd.nodes[n.ID]

	fd.answered(at, n.ID, nd.tc)
	nd.loggedOut = false
	prior := nd.Method
	nd.Method = util.RegisterMethodAuthKey

	if n.Tagged() && !nd.Tagged && prior == util.RegisterMethodAuthKey {
		nd.Ephemeral = false
		fd.run.tally.edits["a user's key takes a tagged node back"]++
	}
}

// keySpeaksFor reports whether nd's key still speaks for n, as production
// decides it ([PreAuthKey.CanReauthenticate]): a tagged node an
// interactive login re-registered records no key that claims it, so a
// login with the key adds a device beside it — a shape the model does
// not carry, which the steps that log in with a key leave alone.
func (nd *fdNode) keySpeaksFor(n policymodel.Node) bool {
	return !n.Tagged() || nd.Method == util.RegisterMethodAuthKey
}

// The ownership scripts: where a node changes hands.
const (
	ownClaimLogin = iota
	ownKeyLogin
	ownReauthTags
	ownOwnerGone
	ownRetagApprover
	numOwn
)

var ownNames = [numOwn]string{"claim back by login", "login with its key", "login requesting tags", "a key gone with its user", "retag onto an approver"}

// ownership changes who owns a node through the front door, the
// neighbourhood the soak's driver gaps sat in: a user's login takes a
// tagged node back; a node logs in again with its key, which takes a
// tagged node back for the key's user; a login requests tags, which tags a
// user's node or keeps a tagged node tagged, renewing an expired key; a
// user's own key dies with the user, and a login with it is refused.
func (fd *frontDoor) ownership(at string) {
	kind := rapid.IntRange(0, numOwn-1).Draw(fd.t, "ownership")

	var done bool

	switch kind {
	case ownClaimLogin:
		done = fd.claimByLogin(at)
	case ownKeyLogin:
		done = fd.loginWithKey(at)
	case ownReauthTags:
		done = fd.reauthTags(at)
	case ownOwnerGone:
		done = fd.ownerGone(at)
	case ownRetagApprover:
		done = fd.retagApprover(at)
	}

	name := stepNames[stepOwnership] + ": " + ownNames[kind]
	if !done {
		name += " (no node)"
	}

	fd.run.tally.steps[stepNames[stepOwnership]]++
	fd.run.tally.steps[name]++
}

// claims reports whether a login as u takes over n's client's node rather
// than adding a device beside it: a user's node by its user, a tagged node
// by anyone unless a key registered it, then by the key's user.
func (fd *frontDoor) claims(n policymodel.Node, u policymodel.User) bool {
	if !fd.loginUser(u) {
		return false
	}

	if !n.Tagged() {
		return n.User == u.ID
	}

	nd := fd.nodes[n.ID]

	return nd.Method != util.RegisterMethodAuthKey || nd.KeyUser == u.ID
}

func (fd *frontDoor) claimByLogin(at string) bool {
	type pair struct {
		n policymodel.Node
		u policymodel.User
	}

	var can []pair

	for _, n := range fd.w.Topology.Nodes {
		for _, u := range fd.w.Topology.Users {
			if n.Tagged() && fd.claims(n, u) {
				can = append(can, pair{n, u})
			}
		}
	}

	// With no tagged node a login can take, an admin tags a user's node
	// first, and its user takes it back.
	if len(can) == 0 {
		var defined []int

		for t := range policymodel.Tags {
			if fd.w.Policy.DefinesTag(t) {
				defined = append(defined, t)
			}
		}

		n, ok := fd.pick("tag-to-claim", func(n policymodel.Node, nd *fdNode) bool {
			u, _ := fd.w.Topology.User(n.User)

			return len(defined) > 0 && fd.claims(n, u) && (nd.Method != util.RegisterMethodAuthKey || nd.KeyUser == n.User)
		})
		if !ok {
			return false
		}

		t := defined[rapid.IntRange(0, len(defined)-1).Draw(fd.t, "tag")]
		u, _ := fd.w.Topology.User(n.User)

		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", n.ID), map[string]any{"tags": tagNames([]int{t})}, nil)
		fd.apply(policymodel.Retag{ID: n.ID, Tags: []int{t}})
		fd.made("Retag", "API, to be claimed back")

		can = append(can, pair{n, u})
	}

	c := can[rapid.IntRange(0, len(can)-1).Draw(fd.t, "claim")]
	fd.untag(at, policymodel.Retag{ID: c.n.ID, User: c.u.ID})

	return true
}

func (fd *frontDoor) loginWithKey(at string) bool {
	n, ok := fd.pick("key-login", func(n policymodel.Node, nd *fdNode) bool {
		return nd.Key != "" && nd.reusable && nd.keySpeaksFor(n)
	})
	if !ok {
		return false
	}

	// The claim — a user's key taking a tagged node back under a new
	// node key — is the rarest of these logins, and its rarest form is
	// the ephemeral one, whose claim clears the ephemeral bit. When the
	// pick is not that, make one: an admin tags a node its user's own
	// reusable ephemeral key registered, and the key login that follows
	// claims it.
	if m, made := fd.makeKeyClaim(at); made && (!fd.nodes[n.ID].Ephemeral || !n.Tagged() || fd.nodes[n.ID].Tagged) {
		n = m
	}

	edits := fd.keyLoginEdits(n)

	err := fd.keyLogin(n, fd.nodes[n.ID].Key)
	if err != nil {
		fd.t.Fatalf("%s: n%d logs in again with its key: %v", at, n.ID, err)
	}

	fd.keyLoggedIn(at, n)
	fd.w = fd.w.Apply(edits...)

	return true
}

// makeKeyClaim makes the shape a login with a key claims: a user's node an
// ephemeral key of its user registered — tagged by the admin first, for
// only a tagged node can be claimed — and a fresh reusable key of its
// user, whose login takes the node back as that user's device, clearing
// the ephemeral bit. It reports the node it made claimable, when the
// world holds one to make.
func (fd *frontDoor) makeKeyClaim(at string) (policymodel.Node, bool) {
	var defined []int

	for t := range policymodel.Tags {
		if fd.w.Policy.DefinesTag(t) {
			defined = append(defined, t)
		}
	}

	m, ok := fd.pick("to-claim", func(n policymodel.Node, nd *fdNode) bool {
		return len(defined) > 0 && !n.Tagged() && nd.Ephemeral && nd.KeyUser == n.User &&
			nd.Method == util.RegisterMethodAuthKey && !nd.loggedOut
	})
	if !ok {
		return policymodel.Node{}, false
	}

	// The key that claims it may be fresh, of the user its registration
	// key speaks for ([types.NodeView.ClaimableBy]): the node's ephemeral
	// bit is its registration's, which only the claim clears.
	var out struct {
		PreAuthKey struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"preAuthKey"`
	}

	fd.mustAPI(at, http.MethodPost, "/api/v1/preauthkey", map[string]any{
		"reusable": true, "user": strconv.FormatUint(uint64(m.User), 10),
	}, &out)

	t := defined[rapid.IntRange(0, len(defined)-1).Draw(fd.t, "claim-tag")]

	fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", m.ID), map[string]any{"tags": tagNames([]int{t})}, nil)
	fd.apply(policymodel.Retag{ID: m.ID, Tags: []int{t}})
	fd.made("Retag", "API, its key to claim it")

	nd := fd.nodes[m.ID]
	nd.Key, nd.keyID, nd.reusable, nd.KeyUser, nd.Tagged = out.PreAuthKey.Key, out.PreAuthKey.ID, true, m.User, false

	n, _ := fd.w.Topology.Node(m.ID)

	return n, true
}

// ownsTag reports whether node n may take tag t at a login, on its own
// account: a user's node through its user. A tag-owned node carries no
// user, and tags among a tag's owners resolve to no node, so it owns no
// tag (processReauthTags, NodeCanHaveTag, resolveTagOwners).
func ownsTag(w policymodel.World, n policymodel.Node, t int) bool {
	return !n.Tagged() && userOwnsTag(w, n.User, t)
}

// noWildcardOwners is w with no user:*@domain token among tag owners or
// in groups: the user half of a login's tag check does not read one.
//
// TODO(kradalby): policy/owner-wildcard-user-half: a tag owner
// user:*@domain names that domain's users' devices through their
// addresses (Username.resolve builds the owner set), but not the users
// (resolveUser, behind UserCanHaveTag and NodeCanHaveTag's user fallback,
// matches the token as a name or e-mail). So a user's existing device may
// take the tag and the same user's login onto a tagged node, a new device
// or a pre-auth key may not. Fails closed. Followed here, counted;
// TestAWildcardTagOwnerNamesDevicesNotUsers holds it to production.
func noWildcardOwners(w policymodel.World) policymodel.World {
	wild := func(s policymodel.Sel) bool {
		return s.Kind == policymodel.SelUser && strings.HasPrefix(policymodel.UserRefs[s.I], "user:*@")
	}

	p := w.Policy
	for t := range p.TagOwners {
		p.TagOwners[t] = slices.DeleteFunc(slices.Clone(p.TagOwners[t]), wild)
	}

	for g := range p.Groups {
		p.Groups[g] = slices.DeleteFunc(slices.Clone(p.Groups[g]), func(ref int) bool { return strings.HasPrefix(policymodel.UserRefs[ref], "user:*@") })
	}

	w.Policy = p

	return w
}

// fdProbe is the ID of a node no world holds, standing for a user's device.
const fdProbe types.NodeID = 1 << 30

// userOwnsTag reports whether owners of tag t in w name user u, directly
// or through a group: whether they name a device of u's.
func userOwnsTag(w policymodel.World, u uint, t int) bool {
	probe := policymodel.Node{ID: fdProbe, User: u}
	w.Topology.Nodes = append(slices.Clone(w.Topology.Nodes), probe)

	return slices.ContainsFunc(policymodel.NewView(w).MembersOf(w.Policy.TagOwners[t]...), func(m policymodel.Node) bool { return m.ID == fdProbe })
}

// tagAsk is a login as u onto node n requesting tags.
type tagAsk struct {
	n    policymodel.Node
	u    policymodel.User
	tags []int
}

// tagLogins are the logins requesting tags that the server grants, every
// tag owned by the node or the user, and those it refuses.
func (fd *frontDoor) tagLogins() ([]tagAsk, []tagAsk) {
	var granted, refused []tagAsk

	for _, n := range fd.w.Topology.Nodes {
		for _, u := range fd.w.Topology.Users {
			if !fd.claims(n, u) {
				continue
			}

			var sets [][]int
			if n.Tagged() {
				sets = append(sets, n.Tags)
			}

			for t := range policymodel.Tags {
				if fd.w.Policy.DefinesTag(t) && !slices.Equal(n.Tags, []int{t}) {
					sets = append(sets, []int{t})
				}
			}

			for _, tags := range sets {
				ok := !slices.ContainsFunc(tags, func(t int) bool { return !ownsTag(fd.w, n, t) && !userOwnsTag(noWildcardOwners(fd.w), u.ID, t) })
				if ok {
					granted = append(granted, tagAsk{n, u, tags})
				} else {
					refused = append(refused, tagAsk{n, u, tags})
				}
			}
		}
	}

	return granted, refused
}

// makeTagOwner has an admin make a user who can log in onto a tagged node
// an owner of its tags, through a token naming that user alone, so that
// the user's login keeps the node tagged.
func (fd *frontDoor) makeTagOwner(at string) {
	v := policymodel.NewView(fd.w)
	if len(v.AmbiguousRefs()) > 0 {
		return
	}

	type owner struct {
		n   policymodel.Node
		ref int
	}

	var can []owner

	for _, n := range fd.w.Topology.Nodes {
		for ref := range policymodel.UserRefs {
			if strings.HasPrefix(policymodel.UserRefs[ref], "user:*@") {
				continue
			}

			if us := v.RefUsers(ref); n.Tagged() && len(us) == 1 && !v.Ambiguous(ref) {
				if u, _ := fd.w.Topology.User(us[0]); fd.claims(n, u) {
					can = append(can, owner{n, ref})
				}
			}
		}
	}

	if len(can) == 0 {
		return
	}

	o := can[rapid.IntRange(0, len(can)-1).Draw(fd.t, "tag-owner")]
	by := policymodel.Sel{Kind: policymodel.SelUser, I: o.ref}

	for _, t := range o.n.Tags {
		if owners := fd.w.Policy.TagOwners[t]; !slices.Contains(owners, by) {
			fd.edit(at, policymodel.SetTagOwners{Tag: t, Owners: append(slices.Clone(owners), by), Defined: true}, nil)
		}
	}

	fd.made("policy", "a login's user made an owner of a tagged node's tags")
}

// makeRenewable leaves the world holding a node an interactive login can
// renew while it stays tagged: a user's node tagged by the admin with a
// tag its user owns — made an owner first when no owned tag exists — so
// the user's login requesting the tag is granted and keeps the node the
// tag's. It reports whether it did.
func (fd *frontDoor) makeRenewable(at string) bool {
	n, ok := fd.pick("to-renew", func(n policymodel.Node, nd *fdNode) bool {
		u, _ := fd.w.Topology.User(n.User)

		// claims after the tag write is what matters: a key-registered
		// node stays its key user's claim alone.
		return !n.Tagged() && !nd.loggedOut && fd.claims(n, u) &&
			(nd.Method != util.RegisterMethodAuthKey || nd.KeyUser == u.ID)
	})
	if !ok {
		return false
	}

	u, _ := fd.w.Topology.User(n.User)

	t, ok := fd.renewableTag(at, u)
	if !ok {
		return false
	}

	fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", n.ID), map[string]any{"tags": tagNames([]int{t})}, nil)
	fd.apply(policymodel.Retag{ID: n.ID, Tags: []int{t}})
	fd.made("Retag", "API, its owner to renew it")

	return true
}

// renewRenewable manufactures a tagged node whose own tags its user owns
// when the world holds none, reporting whether it did; the caller then
// recomputes the granted asks.
func (fd *frontDoor) renewRenewable(at string, granted []tagAsk) bool {
	if slices.ContainsFunc(granted, func(a tagAsk) bool { return a.n.Tagged() && slices.Equal(a.n.Tags, a.tags) }) {
		return false
	}

	return fd.makeRenewable(at)
}

// tallyRenewal records that a case renewed a tagged node at a login:
// the floor require holds a deep run to.
func (fd *frontDoor) tallyRenewal(n policymodel.Node, tags []int) {
	if slices.Equal(n.Tags, tags) {
		fd.run.tally.steps[stepNames[stepOwnership]+": a login renews an expired tagged node"]++
	}
}

// renewableTag is a tag u owns, or a drawn one u is made an owner of
// through a reference naming it alone; it reports whether the policy can
// name u at all.
func (fd *frontDoor) renewableTag(at string, u policymodel.User) (int, bool) {
	v := policymodel.NewView(fd.w)

	var owned []int

	for t := range policymodel.Tags {
		if fd.w.Policy.DefinesTag(t) && userOwnsTag(noWildcardOwners(fd.w), u.ID, t) {
			owned = append(owned, t)
		}
	}

	slices.Sort(owned)

	if len(owned) > 0 {
		return owned[rapid.IntRange(0, len(owned)-1).Draw(fd.t, "owned-tag")], true
	}

	if len(v.AmbiguousRefs()) > 0 {
		return 0, false
	}

	ref := -1

	for r := range policymodel.UserRefs {
		if us := v.RefUsers(r); len(us) == 1 && us[0] == u.ID && !v.Ambiguous(r) {
			ref = r

			break
		}
	}

	if ref < 0 {
		return 0, false
	}

	t := rapid.IntRange(0, len(policymodel.Tags)-1).Draw(fd.t, "owner-tag")
	by := policymodel.Sel{Kind: policymodel.SelUser, I: ref}

	if !slices.Contains(fd.w.Policy.TagOwners[t], by) {
		fd.edit(at, policymodel.SetTagOwners{
			Tag:     t,
			Owners:  append(slices.Clone(fd.w.Policy.TagOwners[t]), by),
			Defined: true,
		}, nil)
	}

	return t, true
}

// reauthTags has a user log a node in interactively requesting tags, as
// `tailscale up --force-reauth --advertise-tags` does: a tag the node or
// the user owns is granted, and the node becomes, or stays, the tags',
// its key renewed; a request any tag of which neither owns is refused
// and changes nothing. A tagged node is expired first now and then.
func (fd *frontDoor) reauthTags(at string) bool {
	if rapid.Bool().Draw(fd.t, "make-owner") {
		fd.makeTagOwner(at)
	}

	granted, refused := fd.tagLogins()

	// The renewal shape — a tagged node asking its own tags back at a
	// login, expired first (the survivor, C31) — needs a tagged node
	// whose tags its claimant owns. With none in the world, make one: a
	// user's node, tagged by the admin with a tag its user owns or is
	// made an owner of, so the user's login keeps the node tagged and
	// renews it.
	renewal := fd.renewRenewable(at, granted)
	if renewal {
		granted, refused = fd.tagLogins()
	}

	refuse := len(refused) > 0 && (len(granted) == 0 || rapid.IntRange(0, 3).Draw(fd.t, "refused-tags") == 3)

	if len(granted) == 0 && !refuse {
		return false
	}

	pool := granted
	if refuse {
		pool = refused
	}

	// A tagged node asking for the tags it has comes first: the shape that
	// renews a tagged node's key while it stays tagged.
	if same := slices.DeleteFunc(slices.Clone(pool), func(a tagAsk) bool { return !a.n.Tagged() || !slices.Equal(a.n.Tags, a.tags) }); len(same) > 0 && (renewal || rapid.Bool().Draw(fd.t, "keep-tags")) {
		pool = same
	}

	a := pool[rapid.IntRange(0, len(pool)-1).Draw(fd.t, "tags-login")]
	n, nd := a.n, fd.nodes[a.n.ID]

	if !refuse && n.Tagged() && !n.Expired && (renewal || rapid.Bool().Draw(fd.t, "expire-first")) {
		fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/expire", n.ID), map[string]any{}, nil)
		fd.apply(policymodel.SetExpired{ID: n.ID, Expired: true})
		n, _ = fd.w.Topology.Node(n.ID)
	}

	hi := fd.hostinfo(n, true)
	hi.RequestTags = tagNames(a.tags)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	approve := fd.approverAt(a.u)
	if refuse {
		approve = fd.approver(a.u)
	}

	err := nd.tc.Login(ctx, nd.tc.Persist(), "", controlclient.LoginInteractive, hi, approve)

	if refuse {
		if err == nil {
			fd.t.Fatalf("%s: n%d logs in as u%d requesting %v, which neither owns, and is let in", at, n.ID, a.u.ID, tagNames(a.tags))
		}

		// The client keeps its node key; its session comes back.
		if !n.Offline {
			fd.connect(at, n.ID)
		}

		fd.made("Login requesting tags", "refused (tags neither node nor user owns)")

		if !slices.ContainsFunc(a.tags, func(t int) bool { return !ownsTag(fd.w, n, t) && !userOwnsTag(fd.w, a.u.ID, t) }) {
			fd.made("Login requesting tags", "refused as a user:*@ owner names its user (policy/owner-wildcard-user-half)")
		}

		return true
	}

	if err != nil {
		fd.t.Fatalf("%s: n%d logs in as u%d requesting %v: %v", at, n.ID, a.u.ID, tagNames(a.tags), err)
	}

	fd.answered(at, n.ID, nd.tc)
	nd.loggedOut = false

	what := "a user's node tagged"

	if n.Tagged() {
		// A login onto a tagged node registers it as the login does.
		nd.Method = util.RegisterMethodCLI
		if a.u.OIDC() {
			nd.Method = util.RegisterMethodOIDC
		}

		what = "a tagged node retagged"
		if slices.Equal(n.Tags, a.tags) {
			what = "a tagged node stays tagged"
		}

		if n.Expired {
			what += ", its key renewed"

			fd.tallyRenewal(n, a.tags)
		}
	}

	if !slices.Equal(n.Tags, a.tags) {
		fd.apply(policymodel.Retag{ID: n.ID, Tags: a.tags})
	}

	fd.apply(policymodel.SetExpired{ID: n.ID, Expired: false})
	fd.apply(policymodel.SetOnline{ID: n.ID, Online: true})
	fd.autoApprove(n.ID)
	fd.made("Login requesting tags", what)

	return true
}

// ownerGone tags a user's node away from the user whose own key registered
// it, deletes that user, whose keys go with it, and has the node log in
// with the dead key: the login is refused and changes nothing.
func (fd *frontDoor) ownerGone(at string) bool {
	var defined []int

	for t := range policymodel.Tags {
		if fd.w.Policy.DefinesTag(t) {
			defined = append(defined, t)
		}
	}

	n, ok := fd.pick("owner-gone", func(n policymodel.Node, nd *fdNode) bool {
		alone := !slices.ContainsFunc(fd.w.Topology.Nodes, func(m policymodel.Node) bool { return m.ID != n.ID && m.User == n.User && !m.Tagged() })

		return len(defined) > 0 && !n.Tagged() && nd.Key != "" && !nd.Tagged && nd.KeyUser == n.User && alone
	})
	if !ok {
		return false
	}

	nd := fd.nodes[n.ID]
	t := defined[rapid.IntRange(0, len(defined)-1).Draw(fd.t, "tag-away")]
	dead, owner := nd.Key, n.User

	fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", n.ID), map[string]any{"tags": tagNames([]int{t})}, nil)
	fd.apply(policymodel.Retag{ID: n.ID, Tags: []int{t}})
	fd.edit(at, policymodel.DeleteUser{ID: owner}, nil)

	n, _ = fd.w.Topology.Node(n.ID)

	err := fd.keyLogin(n, dead)
	if err == nil {
		fd.t.Fatalf("%s: n%d logs in with the key of u%d, deleted with it", at, n.ID, owner)
	}

	if !n.Offline {
		fd.connect(at, n.ID)
	}

	fd.made("Login with a key gone with its user", "refused")

	return true
}

// retagApprover has an admin tag a node onto a tag that auto-approves a
// route it announces and is not approved for: the node announces one if
// it has none, the tag is defined and made an approver of the route if it
// is not, and the tag write must approve the route.
func (fd *frontDoor) retagApprover(at string) bool {
	if len(policymodel.NewView(fd.w).AmbiguousRefs()) > 0 {
		return false
	}

	n, ok := fd.pick("retagged", func(n policymodel.Node, nd *fdNode) bool { return !nd.loggedOut })
	if !ok {
		return false
	}

	pending := policymodel.Without(n.Announced, n.Approved)
	if len(pending) == 0 {
		var routes []int

		for r := range policymodel.Prefixes {
			if !slices.Contains(n.Announced, r) && !policymodel.NewView(fd.w).Approvable(n, r) {
				routes = append(routes, r)
			}
		}

		if len(routes) == 0 {
			return false
		}

		r := routes[rapid.IntRange(0, len(routes)-1).Draw(fd.t, "announced")]
		fd.edit(at, policymodel.Announce{ID: n.ID, Routes: []int{r}}, nil)
		n, _ = fd.w.Topology.Node(n.ID)
		pending = policymodel.Without(n.Announced, n.Approved)
	}

	if len(pending) == 0 {
		return false
	}

	r := pending[rapid.IntRange(0, len(pending)-1).Draw(fd.t, "pending")]
	t := rapid.IntRange(0, len(policymodel.Tags)-1).Draw(fd.t, "approver-tag")

	if !fd.w.Policy.DefinesTag(t) {
		fd.edit(at, policymodel.SetTagOwners{Tag: t, Owners: fd.w.Policy.TagOwners[t], Defined: true}, nil)
	}

	tagged := n
	tagged.Tags, tagged.User = []int{t}, 0

	if !policymodel.NewView(fd.w).Approvable(tagged, r) {
		aa := fd.w.Policy.AutoApprovers
		by := policymodel.Sel{Kind: policymodel.SelTag, I: t}

		// The document keys approvals by route: a route already listed
		// gains the tag.
		aa.Routes = slices.Clone(aa.Routes)

		switch i := slices.IndexFunc(aa.Routes, func(ra policymodel.RouteApproval) bool { return ra.Route == r }); {
		case policymodel.Prefixes[r].Bits() == 0:
			aa.Exit = append(slices.Clone(aa.Exit), by)
		case i >= 0:
			aa.Routes[i].By = append(slices.Clone(aa.Routes[i].By), by)
		default:
			aa.Routes = append(aa.Routes, policymodel.RouteApproval{Route: r, By: []policymodel.Sel{by}})
		}

		fd.edit(at, policymodel.SetAutoApprovers{AutoApprovers: aa}, nil)
	}

	fd.mustAPI(at, http.MethodPost, fmt.Sprintf("/api/v1/node/%d/tags", n.ID), map[string]any{"tags": tagNames([]int{t})}, nil)
	fd.apply(policymodel.Retag{ID: n.ID, Tags: []int{t}})
	fd.made("Retag", "API, onto an approver of a route it announces")

	return true
}

// The identity collisions an admin and an identity provider can make.
const (
	idOIDC = iota
	idCreate
	idRename
	idClaims
	idRewrite
	numID
)

var idNames = [numID]string{"OIDC user sharing a name or e-mail", "API user created", "API user renamed", "OIDC claims changed", "policy written again"}

// fdUserNames and fdUserEmails are the names and e-mails the policy's
// user tokens name.
var (
	fdUserNames  = []string{"erin", "alice", "bob", "carol", "dave"}
	fdUserEmails = []string{"", "erin@example.com", "bob@example.com", "carol@example.org", "dave@example.com", "alice@example.org"}
)

// identity makes users collide, as an admin and an identity provider can:
// an OIDC user sharing another's name or e-mail, an API user created or
// renamed onto a name others hold, OIDC claims changing onto another's,
// and the policy written again once its tokens name two users. The
// reference reads a token two users answer to as naming nobody, as the
// server does once users change under an accepted policy; the API's
// answers are held to what its handlers promise.
func (fd *frontDoor) identity(at string) {
	kind := rapid.IntRange(0, numID-1).Draw(fd.t, "identity")
	label := stepNames[stepIdentity] + ": " + idNames[kind]

	switch kind {
	case idOIDC:
		label += fd.identityOIDC()
	case idCreate:
		label += fd.identityCreate(at)
	case idRename:
		label += fd.identityRename(at)
	case idClaims:
		label += fd.identityClaims(at)
	case idRewrite:
		label += fd.identityRewrite(at)
	}

	if len(policymodel.NewView(fd.w).AmbiguousRefs()) > 0 {
		fd.run.tally.edits["identity: the policy holds a token several users answer to"]++
	}

	fd.run.tally.steps[stepNames[stepIdentity]]++
	fd.run.tally.steps[label]++
}

// drawName draws a name the policy's tokens or a user holds.
func (fd *frontDoor) drawName(label string) string {
	pool := slices.Clone(fdUserNames)

	for _, u := range fd.w.Topology.Users {
		if u.Name != "" {
			pool = append(pool, u.Name)
		}
	}

	return pool[rapid.IntRange(0, len(pool)-1).Draw(fd.t, label)]
}

// drawEmail draws an e-mail the policy's tokens or a user holds.
func (fd *frontDoor) drawEmail(label string) string {
	pool := slices.Clone(fdUserEmails)

	for _, u := range fd.w.Topology.Users {
		pool = append(pool, u.Email)
	}

	return pool[rapid.IntRange(0, len(pool)-1).Draw(fd.t, label)]
}

// holders are the users holding name, but except.
func (fd *frontDoor) holders(name string, except uint) []policymodel.User {
	return slices.DeleteFunc(slices.Clone(fd.w.Topology.Users), func(u policymodel.User) bool { return u.Name != name || u.ID == except })
}

func (fd *frontDoor) identityOIDC() string {
	id := fd.nextUserID()
	u := policymodel.User{ID: id, Name: fd.drawName("oidc-name"), Email: fd.drawEmail("oidc-email"), Provider: "https://idp.example.com/" + strconv.FormatUint(uint64(id), 10)}
	collides := len(fd.holders(u.Name, id)) > 0 || u.Email != "" && slices.ContainsFunc(fd.w.Topology.Users, func(o policymodel.User) bool { return o.Email == u.Email })

	fd.addUser(u)

	if collides {
		return " (collides)"
	}

	return ""
}

func (fd *frontDoor) identityCreate(at string) string {
	nm, em := fd.drawName("api-name"), fd.drawEmail("api-email")
	hold := fd.holders(nm, 0)
	err := fd.api(http.MethodPost, "/api/v1/user", map[string]any{"name": nm, "email": em}, nil)

	if len(hold) > 0 {
		if err == nil || !strings.Contains(err.Error(), "409") {
			fd.t.Fatalf("%s: creating API user %q, which u%d holds: %v", at, nm, hold[0].ID, err)
		}

		return " (refused: the name is held)"
	}

	if err != nil {
		fd.t.Fatalf("%s: creating API user %q: %v", at, nm, err)
	}

	fd.apply(policymodel.AddUser{User: policymodel.User{ID: fd.nextUserID(), Name: nm, Email: em}})

	return ""
}

func (fd *frontDoor) identityRename(at string) string {
	var api []policymodel.User

	for _, u := range fd.w.Topology.Users {
		if !u.OIDC() {
			api = append(api, u)
		}
	}

	if len(api) == 0 {
		return " (no API user)"
	}

	a := api[rapid.IntRange(0, len(api)-1).Draw(fd.t, "renamed-user")]
	nm := fd.drawName("new-name")
	hold := fd.holders(nm, a.ID)

	switch {
	case nm == a.Name:
		return " (its own name)"
	case len(hold) > 0:
		err := fd.api(http.MethodPost, fmt.Sprintf("/api/v1/user/%d/rename/%s", a.ID, nm), nil, nil)
		if err == nil || !strings.Contains(err.Error(), "409") {
			fd.t.Fatalf("%s: renaming u%d to %q, which u%d holds: %v", at, a.ID, nm, hold[0].ID, err)
		}

		return " (refused: the name is held)"
	}

	fd.renameUser(at, policymodel.RenameUser{ID: a.ID, Name: nm})

	return ""
}

func (fd *frontDoor) identityClaims(at string) string {
	var oidc []policymodel.User

	for _, u := range fd.w.Topology.Users {
		if u.OIDC() {
			oidc = append(oidc, u)
		}
	}

	if len(oidc) == 0 {
		return " (no OIDC user)"
	}

	users := fd.w.Topology.Users
	o := oidc[rapid.IntRange(0, len(oidc)-1).Draw(fd.t, "claims-user")]
	src := users[rapid.IntRange(0, len(users)-1).Draw(fd.t, "claims-from")]

	if rapid.Bool().Draw(fd.t, "claims-email") {
		fd.updateUser(at, o.ID, func(u *types.User) { u.Email = src.Email })
		fd.apply(policymodel.SetEmail{ID: o.ID, Email: src.Email})

		return " (e-mail)"
	}

	fd.updateUser(at, o.ID, func(u *types.User) { u.Name = src.Name })
	fd.apply(policymodel.RenameUser{ID: o.ID, Name: src.Name})

	return " (name)"
}

func (fd *frontDoor) identityRewrite(at string) string {
	amb := policymodel.NewView(fd.w).AmbiguousRefs()
	err := fd.api(http.MethodPut, "/api/v1/policy", map[string]any{"policy": string(fd.w.Policy.HuJSON())}, nil)

	switch {
	case len(amb) > 0 && err == nil:
		fd.t.Fatalf("%s: the policy is written again though its tokens %v name several users", at, amb)
	case len(amb) == 0 && err != nil:
		fd.t.Fatalf("%s: the policy, its tokens unambiguous, is not written again: %v", at, err)
	case len(amb) > 0:
		return " (refused: a token names several users)"
	}

	// The write put the model's document: a DERP region the records step
	// added to the served one is gone with it.
	fd.derp = false

	return ""
}

// nextUserID is the ID the next user created takes: users' IDs are never
// handed out twice.
func (fd *frontDoor) nextUserID() uint {
	next := max(fd.w.Topology.NextUserID, 1)
	if us := fd.w.Topology.Users; len(us) > 0 {
		next = max(next, us[len(us)-1].ID+1)
	}

	return next
}

// The races: two front-door writes to one node at once.
const (
	raceExpireLogin = iota
	raceExpireLogout
	raceDeleteLogout
	numRaces
)

var raceNames = [numRaces]string{"an admin's expiry and a login with the node's key", "an admin's expiry and the client's logout", "an admin's deletion and the client's logout"}

// race starts two writes to one node at once, an admin's and its
// client's, and holds the server to the outcome of one order of them or
// the other.
func (fd *frontDoor) race(at string) {
	kind := rapid.IntRange(0, numRaces-1).Draw(fd.t, "race")
	fd.run.tally.steps[stepNames[stepRace]]++

	var (
		n  policymodel.Node
		ok bool
	)

	switch kind {
	case raceExpireLogin:
		n, ok = fd.pick("racer", func(n policymodel.Node, nd *fdNode) bool { return nd.Key != "" && nd.reusable && nd.keySpeaksFor(n) })

		// The claim is the rarest shape a key login takes here; when the
		// drawn racer is not one, make it, as the ownership step does
		// ([frontDoor.makeKeyClaim]).
		if m, made := fd.makeKeyClaim(at); made && (!ok || !n.Tagged() || fd.nodes[n.ID].Tagged || !fd.nodes[n.ID].Ephemeral) {
			n, ok = m, true
		}
	default:
		n, ok = fd.pick("racer", func(n policymodel.Node, nd *fdNode) bool {
			// A case running the small clock leaves an ephemeral node to
			// this racer's expiry alone: its logout would arm a deletion
			// the model cannot see coming.
			return !n.Expired && !nd.loggedOut && (kind != raceExpireLogout || !fd.clock || !nd.Ephemeral)
		})
	}

	if !ok {
		fd.run.tally.steps[stepNames[stepRace]+": "+raceNames[kind]+" (no node)"]++

		return
	}

	nd := fd.nodes[n.ID]
	base := fd.w
	expire := func() error {
		return fd.api(http.MethodPost, fmt.Sprintf("/api/v1/node/%d/expire", n.ID), map[string]any{}, nil)
	}
	logout := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		return nd.tc.LogoutAndDisconnect(ctx)
	}

	var outcomes map[string]policymodel.World

	switch kind {
	case raceExpireLogin:
		edits := fd.keyLoginEdits(n)
		expiry := policymodel.SetExpired{ID: n.ID, Expired: true}

		errA, errB := both(expire, func() error { return fd.keyLogin(n, nd.Key) })
		if errA != nil || errB != nil {
			fd.t.Fatalf("%s: n%d: the expiry (%v) and the login with its key (%v) racing", at, n.ID, errA, errB)
		}

		fd.keyLoggedIn(at, n)

		outcomes = map[string]policymodel.World{
			"the login last":  base.Apply(expiry).Apply(edits...),
			"the expiry last": base.Apply(edits...).Apply(expiry),
		}
	case raceExpireLogout:
		_, errB := both(expire, logout)

		fd.quiet(at)

		polling := nd.tc.Polling()
		gone := base.Apply(policymodel.Leave{ID: n.ID})
		expired := base.Apply(policymodel.SetExpired{ID: n.ID, Expired: true}, policymodel.SetOnline{ID: n.ID, Online: polling})
		nd.loggedOut = errB == nil

		outcomes = map[string]policymodel.World{"expired": expired}
		if nd.Ephemeral {
			outcomes["deleted by its logout"] = gone
		}
	case raceDeleteLogout:
		// Either may fail, as the other got there first; the node goes.
		_, _ = both(func() error { return fd.api(http.MethodDelete, fmt.Sprintf("/api/v1/node/%d", n.ID), nil, nil) }, logout)

		outcomes = map[string]policymodel.World{"deleted": base.Apply(policymodel.Leave{ID: n.ID})}
	}

	fd.quiet(at)
	won := fd.outcome(at, n.ID, outcomes)
	fd.run.tally.steps[stepNames[stepRace]+": "+raceNames[kind]+", "+won]++
}

// both runs a and b at once and returns their errors.
func both(a, b func() error) (error, error) {
	var (
		ea, eb error
		wg     sync.WaitGroup
	)

	start := make(chan struct{})

	wg.Go(func() {
		<-start

		ea = a()
	})
	wg.Go(func() {
		<-start

		eb = b()
	})

	close(start)
	wg.Wait()

	return ea, eb
}

// outcome takes as the model the outcome whose node id the server holds,
// and fails when it holds none of them.
func (fd *frontDoor) outcome(at string, id types.NodeID, outcomes map[string]policymodel.World) string {
	nv, held := fd.srv.State().Snapshot().GetNode(id)

	var diffs []string

	for _, name := range slices.Sorted(maps.Keys(outcomes)) {
		w := outcomes[name]
		n, ok := w.Topology.Node(id)

		switch {
		case ok != held:
			diffs = append(diffs, fmt.Sprintf("%s: the node held %t", name, held))

			continue
		case !ok:
			fd.w = w
			fd.drop(id)

			return name
		}

		if d := statemodel.NodeDiff(nv.AsStruct(), w, n, fd.nodes[id].Joined); d != "" {
			diffs = append(diffs, name+": "+d)

			continue
		}

		fd.w = w

		return name
	}

	fd.t.Fatalf("%s: n%d after the race matches no order of it: %s", at, id, strings.Join(diffs, "; "))

	return ""
}

// restart restarts the server from its database; every client that was
// polling reconnects, in ID order. What each held before must survive
// but for what a restart may change (see durable).
func (fd *frontDoor) restart(at string) {
	fd.run.tally.steps[stepNames[stepServerRestart]]++
	fd.run.tally.restarts++

	// A restart serves the configured extra records alone, which is none
	// here; the published ones were the running server's own state.
	fd.records = nil

	held := map[types.NodeID]string{}

	for _, id := range slices.Sorted(maps.Keys(fd.nodes)) {
		if nd := fd.nodes[id]; nd.tc.Polling() {
			held[id] = durable(nd.tc.Netmap())
		}
	}

	fd.srv.Restart(fd.tb)

	// The new server remembers no sessions, and no one who held a route.
	fd.elections = policymodel.NewElections()
	clear(fd.unheld)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ids := slices.Sorted(maps.Keys(held))

	// A case running the small clock reconnects its ephemeral nodes
	// first, with no quiet on the way: the restarted server schedules
	// every ephemeral node's deletion when it comes up, so their
	// reconnects must land inside the timeout, not behind other nodes'
	// quiet waits.
	if fd.clock {
		for _, id := range ids {
			nd := fd.nodes[id]
			if !nd.Ephemeral {
				continue
			}

			select {
			case <-nd.tc.pollDone:
			case <-ctx.Done():
				fd.t.Fatalf("%s: n%d's map session outlived the server", at, id)
			}

			err := nd.tc.RestartPoll(ctx)
			if err != nil {
				fd.t.Fatalf("%s: n%d reconnects after the restart: %v", at, id, err)
			}
		}
	}

	for _, id := range ids {
		nd := fd.nodes[id]

		// The old server ended the session; the client sees the stream
		// close, then polls the new one. A node the clock pre-pass
		// already reconnected holds a fresh session with this server:
		// its pollDone is a new channel, so closing the old one again is
		// not what it waits for.
		if !nd.tc.Polling() {
			select {
			case <-nd.tc.pollDone:
			case <-ctx.Done():
				fd.t.Fatalf("%s: n%d's map session outlived the server", at, id)
			}

			err := nd.tc.RestartPoll(ctx)
			if err != nil {
				fd.t.Fatalf("%s: n%d reconnects after the restart: %v", at, id, err)
			}
		}

		fd.quiet(at)
		fd.elect()
	}

	fd.quiet(at)

	for _, id := range slices.Sorted(maps.Keys(held)) {
		nd := fd.nodes[id]
		if !nd.tc.Polling() {
			fd.t.Fatalf("%s: n%d does not poll the restarted server", at, id)
		}

		if now := durable(nd.tc.Netmap()); now != held[id] && fd.run.slice.Judges("restart") {
			fd.t.Fatalf("%s: n%d's client holds after the restart what it did not before:\nbefore %s\nafter  %s", at, id, held[id], now)
		}
	}
}

// api calls the v1 API as an admin.
func (fd *frontDoor) api(method, path string, body, out any) error {
	if fd.v2 {
		if kind, m2, p2, b2, ctype, raw, ok := fd.translate2(method, path, body); ok {
			return fd.api2(kind, m2, p2, b2, ctype, raw, out)
		}
	}

	var r io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}

		r = bytes.NewReader(b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, fd.srv.URL+path, r)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+fd.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := fd.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(msg)) //nolint:err113
	}

	if out != nil {
		return json.Unmarshal(msg, out)
	}

	return nil
}

// fdV2Scopes are the scopes of the case's v2 OAuth client: every write
// the property translates.
var fdV2Scopes = []string{"devices:core", "devices:routes", "policy_file"}

// fdV2Tags are the client's tags: the policy's own three, so the v2 tag
// write's grant check — which no v1 write has — is always satisfied.
var fdV2Tags = []string{"tag:a", "tag:b", "tag:c"}

// translate2 is the v2 form of one of the property's admin writes, with
// the reach tally of its kind. ok reports that the write has a v2 form
// at all: the users' writes do not (the hosted API manages users
// through the identity provider, and v2 has no user write), and neither
// do the reads. Where the two APIs differ it is the shape that differs —
// the name in the body, the expiry as a key switch, the policy as a raw
// document — each in the handler it belongs to.
func (fd *frontDoor) translate2(method, path string, body any) (string, string, string, any, string, bool, bool) {
	tally := func(kind string) {
		fd.run.tally.steps["v2 write: "+kind]++
	}

	switch method {
	case http.MethodDelete:
		if id, found := strings.CutPrefix(path, "/api/v1/node/"); found {
			tally("device deleted")

			return "device deleted", http.MethodDelete, "/api/v2/device/" + id, nil, "", false, true
		}
	case http.MethodPost:
		rest, found := strings.CutPrefix(path, "/api/v1/node/")
		if !found {
			return "", "", "", nil, "", false, false
		}

		id, sub, _ := strings.Cut(rest, "/")

		switch sub {
		case "tags":
			tally("tags")

			return "tags", http.MethodPost, "/api/v2/device/" + id + "/tags", body, "", false, true
		case "expire":
			// v1: disableExpiry => a nil expiry; absent body => now.
			// v2: the key switch is the renewal, the expire path now.
			if body, isMap := body.(map[string]any); isMap && body["disableExpiry"] == true {
				tally("key renewed")

				return "key renewed", http.MethodPost, "/api/v2/device/" + id + "/key",
					map[string]any{"keyExpiryDisabled": true}, "", false, true
			}

			tally("expired")

			return "expired", http.MethodPost, "/api/v2/device/" + id + "/expire", nil, "", false, true
		case "approve_routes":
			tally("routes")

			return "routes", http.MethodPost, "/api/v2/device/" + id + "/routes", body, "", false, true
		default:
			if name, found := strings.CutPrefix(sub, "rename/"); found {
				tally("renamed")

				return "renamed", http.MethodPost, "/api/v2/device/" + id + "/name",
					map[string]any{"name": name}, "", false, true
			}
		}
	case http.MethodPut:
		if path == "/api/v1/policy" {
			tally("policy")

			doc, _ := body.(map[string]any)["policy"].(string)

			return "policy", http.MethodPost, "/api/v2/tailnet/-/acl", doc, "application/hujson", true, true
		}
	}

	return "", "", "", nil, "", false, false
}

// api2 is [frontDoor.api] for the v2 form of a write: the case's OAuth
// token, the content type the translated write needs.
func (fd *frontDoor) api2(kind, method, path string, body any, ctype string, raw bool, out any) error {
	var r io.Reader

	if raw {
		r = strings.NewReader(body.(string)) //nolint:forcetypeassert // translate2 made it
	} else if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}

		r = bytes.NewReader(b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, fd.srv.URL+path, r)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+fd.v2Token())

	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := fd.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode/100 != 2 {
		// A refused write is the answer the step or edit expects, named
		// by the v2 form it came through.
		fd.run.tally.steps["v2 write: "+kind+" (refused)"]++

		return fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(msg)) //nolint:err113
	}

	fd.run.tally.steps["v2 write: "+kind+" (done)"]++

	if out != nil {
		return json.Unmarshal(msg, out)
	}

	return nil
}

// v2Token is the case's v2 bearer: an OAuth client minted in process,
// its scopes every write the property translates, its tags the policy's
// own three.
func (fd *frontDoor) v2Token() string {
	fd.tb.Helper()

	if fd.v2token != "" {
		return fd.v2token
	}

	secret, _, err := fd.srv.State().CreateOAuthClient(fdV2Scopes, fdV2Tags, "front door", nil)
	if err != nil {
		fd.t.Fatalf("minting the v2 OAuth client: %v", err)
	}

	form := url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fd.srv.URL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		fd.t.Fatalf("the v2 token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := fd.http.Do(req)
	if err != nil {
		fd.t.Fatalf("the v2 token request: %v", err)
	}
	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
	}

	err = json.NewDecoder(resp.Body).Decode(&tok)
	if err != nil {
		fd.t.Fatalf("the v2 token: %v", err)
	}

	if tok.AccessToken == "" {
		fd.t.Fatal("the v2 token is empty")
	}

	fd.v2token = tok.AccessToken

	return fd.v2token
}

// mustAPI is api, failing the case on an error.
func (fd *frontDoor) mustAPI(at, method, path string, body, out any) {
	err := fd.api(method, path, body, out)
	if err != nil {
		fd.t.Fatalf("%s: %v", at, err)
	}
}

// elect advances the election history to the server as it is now: who
// connected when, as the server stamped it, and what each node can take.
func (fd *frontDoor) elect() {
	snap := fd.srv.State().Snapshot()

	all := snap.ListNodes().AsSlice()
	slices.SortFunc(all, func(a, b types.NodeView) int {
		if c := a.SessionStart().Compare(b.SessionStart()); c != 0 {
			return c
		}

		return int(a.ID()) - int(b.ID()) //nolint:gosec // small
	})

	for i, nv := range all {
		fd.elections.Started[nv.ID()] = uint64(i + 1) //nolint:gosec // small
	}

	fd.elections.Commit(statemodel.ElectionNodes(snap))

	for q := range fd.unheld {
		if fd.served(q) {
			delete(fd.unheld, q)
		}
	}
}

// settle waits for quiet and holds everything to the model: what the
// server stored, who polls, and what each polling client holds.
func (fd *frontDoor) settle(at string) {
	fd.quiet(at)
	fd.elect()
	fd.requireStored(at)
	fd.judgeClients(at)
}

// caseTB is the outer test as one rapid case uses it: what the case
// starts is cleaned up when it ends, failures are rapid's, so that it
// shrinks them, and the clients' logs are dropped.
type caseTB struct {
	*testing.T

	rt       *rapid.T
	cleanups []func()
}

func (c *caseTB) Helper()                           {}
func (c *caseTB) Cleanup(f func())                  { c.cleanups = append(c.cleanups, f) }
func (c *caseTB) Logf(string, ...any)               {}
func (c *caseTB) Log(...any)                        {}
func (c *caseTB) Errorf(format string, args ...any) { c.rt.Errorf(format, args...) }
func (c *caseTB) Error(args ...any)                 { c.rt.Error(args...) }
func (c *caseTB) Fatalf(format string, args ...any) { c.rt.Fatalf(format, args...) }
func (c *caseTB) Fatal(args ...any)                 { c.rt.Fatal(args...) }
func (c *caseTB) FailNow()                          { c.rt.FailNow() }

// TempDir is removed when the case ends, not the test.
func (c *caseTB) TempDir() string {
	d, err := os.MkdirTemp("", "frontdoor-")
	if err != nil {
		c.rt.Fatalf("temp dir: %v", err)
	}

	c.Cleanup(func() { _ = os.RemoveAll(d) })

	return d
}

func (c *caseTB) end() {
	cs := c.cleanups
	c.cleanups = nil

	for _, f := range slices.Backward(cs) {
		f()
	}
}

// fdTally counts what a run did.
type fdTally struct {
	cases, restarts int
	steps, edits    map[string]int
	joins           map[string]int
	// clients counts the clients held to a fresh session; unseen the
	// peers held offline without the LastSeen a fresh session gives
	// (render/lastseen-patchify).
	clients, unseen int
	// quiets counts the waits for quiet, and how long they took.
	quiets             int
	quietAll, quietMax time.Duration
}

func newFDTally() *fdTally {
	return &fdTally{steps: map[string]int{}, edits: map[string]int{}, joins: map[string]int{}}
}

func (t *fdTally) String() string {
	mean := time.Duration(0)
	if t.quiets > 0 {
		mean = t.quietAll / time.Duration(t.quiets)
	}

	return fmt.Sprintf("front door: cases %d, server restarts %d; steps %v; joins %v; edits %v; "+
		"clients held to a fresh session %d; peers held offline without LastSeen %d; quiet waits %d (mean %v, longest %v)",
		t.cases, t.restarts, t.steps, t.joins, t.edits, t.clients, t.unseen, t.quiets, mean, t.quietMax)
}

// require fails a deep run that never took some step or join, never
// restarted, or held nothing of some kind to the reference.
func (t *fdTally) require(tb testing.TB, held *policymodel.HeldJudge) {
	tb.Helper()

	for _, s := range stepNames {
		if t.steps[s] == 0 {
			tb.Errorf("no case took a %s step", s)
		}
	}

	for _, j := range joinNames {
		if t.joins[j] == 0 {
			tb.Errorf("no node joined with a %s", j)
		}
	}

	// The renewal shape the ownership step manufactures: a survivor
	// (C31) lives exactly here, so a deep run must have taken it.
	if t.steps[stepNames[stepOwnership]+": a login renews an expired tagged node"] == 0 {
		tb.Errorf("no case renewed an expired tagged node at a login")
	}

	// The key-claim shape the ownership step manufactures: two survivors
	// (C35) live exactly here, so a deep run must have taken it.
	if t.edits["a user's key takes a tagged node back"] == 0 {
		tb.Errorf("no case claimed a tagged node back with its key")
	}

	// Every kind of write the v2 translation routes must have gone
	// through it somewhere in a deep run.
	for _, kind := range []string{
		"v2 write: tags", "v2 write: expired", "v2 write: key renewed",
		"v2 write: routes", "v2 write: renamed", "v2 write: device deleted", "v2 write: policy",
	} {
		if t.steps[kind] == 0 {
			tb.Errorf("no case wrote through the v2 form: %s", kind)
		}
	}

	// The SSH check's shapes: the approval and the rejection it hands the
	// follow-up, and the refusal no rule covers. A deep run must have
	// driven each.
	for _, kind := range []string{
		stepNames[stepSSHCheck] + ": approved", stepNames[stepSSHCheck] + ": rejected",
		stepNames[stepSSHCheck] + ": no rule, refused",
	} {
		if t.steps[kind] == 0 {
			tb.Errorf("no case took the ssh shape: %s", kind)
		}
	}

	// The identity provider's callback: a login driven through it, the
	// user its claims made, and that user's changed claims (the changed
	// e-mail, which the first login's second round always drives; the
	// changed name and the another-device shapes ride on drawn second
	// logins and are reported, not floored).
	for _, kind := range []string{
		stepNames[stepOIDC] + ": a login through the callback",
		stepNames[stepOIDC] + ": a changed e-mail",
	} {
		if t.steps[kind] == 0 {
			tb.Errorf("no case logged in through the identity provider: %s", kind)
		}
	}

	for name, n := range map[string]int{
		"clients": held.Clients, "peer sets": held.PeerSets, "route pairs": held.RoutePairs, "filters": held.Filters, "primaries": held.Primaries,
	} {
		if n == 0 {
			tb.Errorf("no case held %s to the reference", name)
		}
	}
}

// TestRenamingToANameAnOIDCUserHoldsAnswers409 pins the decision: an API
// rename never produces a name another user already holds, so renaming an
// API user onto a name an OIDC user holds answers 409 and changes
// nothing.
func TestRenamingToANameAnOIDCUserHoldsAnswers409(t *testing.T) {
	srv := NewServer(t)

	_, err := srv.State().CreateUser(types.User{
		Name: "alice", Provider: util.RegisterMethodOIDC, ProviderIdentifier: sql.NullString{String: "https://idp.example.com/1", Valid: true},
	})
	require.NoError(t, err)

	bob := srv.CreateUser(t, "bob")
	fd := &frontDoor{srv: srv, apiKey: srv.CreateAPIKey(t, nil), http: &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial, DisableKeepAlives: true}}}

	err = fd.api(http.MethodPost, fmt.Sprintf("/api/v1/user/%d/rename/alice", bob.ID), nil, nil)
	require.ErrorContains(t, err, "409")

	renamed, err := srv.State().GetUserByID(types.UserID(bob.ID))
	require.NoError(t, err)
	assert.Equal(t, "bob", renamed.Name, "the refused rename changes nothing")
}

// TestCreatingANameOIDCUsersHoldAnswers409 pins the decision: an API
// create never produces a name another user already holds, however many
// OIDC users hold it.
func TestCreatingANameOIDCUsersHoldAnswers409(t *testing.T) {
	srv := NewServer(t)

	for i, name := range []string{"alice", "alice", "bob"} {
		_, err := srv.State().CreateUser(types.User{
			Name: name, Provider: util.RegisterMethodOIDC, ProviderIdentifier: sql.NullString{String: fmt.Sprintf("https://idp.example.com/%d", i), Valid: true},
		})
		require.NoError(t, err)
	}

	fd := &frontDoor{srv: srv, apiKey: srv.CreateAPIKey(t, nil), http: &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial, DisableKeepAlives: true}}}

	require.ErrorContains(t, fd.api(http.MethodPost, "/api/v1/user", map[string]any{"name": "bob"}, nil), "409", "one OIDC user holds bob")
	require.ErrorContains(t, fd.api(http.MethodPost, "/api/v1/user", map[string]any{"name": "alice"}, nil), "409", "two OIDC users hold alice")
}

// TestAWildcardTagOwnerNamesDevicesNotUsers pins
// policy/owner-wildcard-user-half: with tag:a owned by user:*@example.com,
// bob (bob@example.com) logging in on his own node requesting tag:a is
// granted it, through his node's address, and bob logging in on a node an
// admin tagged requesting tag:a is refused, the token matching no user by
// name or e-mail. It fails once both are answered alike; then drop
// noWildcardOwners from the front-door property.
func TestAWildcardTagOwnerNamesDevicesNotUsers(t *testing.T) {
	srv := NewServer(t)

	_, err := srv.State().SetPolicy([]byte(`{"tagOwners": {"tag:a": ["user:*@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`))
	require.NoError(t, err)

	bob, err := srv.State().CreateUser(types.User{Name: "bob", Email: "bob@example.com"})
	require.NoError(t, err)

	approve := func(authID string) error { return srv.ApproveAuth(t.Context(), authID, "bob") }
	requestA := func(name string) *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{BackendLogID: name, Hostname: name, RequestTags: []string{"tag:a"}}
	}

	own := NewClient(t, srv, "own", WithUser(bob), WithoutPoll())
	tagged := NewClient(t, srv, "tagged", WithUser(bob), WithoutPoll())

	nv, ok := srv.State().GetNodeByNodeKey(tagged.Persist().PrivateNodeKey.Public())
	require.True(t, ok)

	_, err = srv.State().SetNodeTags(nv.ID(), []string{"tag:a"})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	require.NoError(t, own.Login(ctx, own.Persist(), "", controlclient.LoginInteractive, requestA("own"), approve), "bob's own node, through its address")

	// TODO(kradalby): policy/owner-wildcard-user-half: the same user, refused.
	assert.ErrorContains(t, tagged.Login(ctx, tagged.Persist(), "", controlclient.LoginInteractive, requestA("tagged"), approve),
		"not permitted", "bob logging in on a tagged node: the wildcard owner names no user")
}

// TestAKeyClaimsOnlyWhatItRegistered pins the front door's claim model to
// production: a user's key takes a tagged node back only while its
// registration by the key still stands (preAuthKeyClaimsTaggedNode behind
// ClaimableBy); an interactive login that re-registered the node leaves no
// key that claims it, and a login with the key adds a device beside it.
func TestAKeyClaimsOnlyWhatItRegistered(t *testing.T) {
	tagged := policymodel.Node{ID: 5, Tags: []int{1}}
	fd := &frontDoor{nodes: map[types.NodeID]*fdNode{5: {KeyUser: 2}}}

	claims := func(method string) bool {
		fd.nodes[5].Method = method

		return slices.ContainsFunc(fd.keyLoginEdits(tagged), func(e policymodel.Edit) bool {
			_, ok := e.(policymodel.Retag)
			return ok
		})
	}

	require.True(t, claims(util.RegisterMethodAuthKey), "the key takes back a node an admin tagged since")
	require.False(t, claims(util.RegisterMethodCLI), "a login re-registered the node: the key claims nothing")
}

// TestAKeyDoesNotClaimWhatALoginReRegistered pins the shape the front
// door's keyLoginEdits models: after an interactive login re-registered
// a tagged node, keeping its tags, the node records no key that claims it
// (ClaimableBy), and a login with the key that joined it adds a device
// beside it rather than taking it back (preAuthKeyClaimsTaggedNode).
func TestAKeyDoesNotClaimWhatALoginReRegistered(t *testing.T) {
	srv := NewServer(t)

	_, err := srv.State().SetPolicy([]byte(`{"tagOwners": {"tag:a": ["bob@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`))
	require.NoError(t, err)

	bob, err := srv.State().CreateUser(types.User{Name: "bob", Email: "bob@example.com"})
	require.NoError(t, err)
	authKey := srv.CreatePreAuthKey(t, types.UserID(bob.ID))
	client := NewClient(t, srv, "n", WithAuthKey(authKey), WithoutPoll())

	nv, ok := srv.State().GetNodeByNodeKey(client.Persist().PrivateNodeKey.Public())
	require.True(t, ok)

	id := nv.ID()

	_, err = srv.State().SetNodeTags(id, []string{"tag:a"})
	require.NoError(t, err)

	approve := func(authID string) error { return srv.ApproveAuth(t.Context(), authID, "bob") }
	requestA := &tailcfg.Hostinfo{BackendLogID: "servertest-claim", Hostname: "claim", RequestTags: []string{"tag:a"}}
	plain := &tailcfg.Hostinfo{BackendLogID: "servertest-claim", Hostname: "claim"}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	require.NoError(t, client.Login(ctx, client.Persist(), "", controlclient.LoginInteractive, requestA, approve),
		"bob re-logs in on his tagged node, requesting its tag")

	nodes := srv.State().GetNodesByMachineKeyAllUsers(client.MachineKey())
	require.Len(t, nodes, 1, "the interactive login keeps the node")

	require.NoError(t, client.Login(ctx, client.Persist(), authKey, controlclient.LoginInteractive, plain, nil),
		"the key that joined the node logs in again")

	nodes = srv.State().GetNodesByMachineKeyAllUsers(client.MachineKey())
	require.Len(t, nodes, 2, "the key claims nothing: it adds a device beside the node")

	still, ok := srv.State().GetNodeByID(id)
	require.True(t, ok)
	assert.True(t, still.IsTagged(), "the tagged node keeps its tags")
	assert.Equal(t, util.RegisterMethodCLI, still.RegisterMethod(), "and its interactive registration")
}
