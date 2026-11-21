package servertest

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"pgregory.net/rapid"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
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
	numSteps
)

var stepNames = [numSteps]string{
	"world", "burst", "flap", "poll restart", "client restart", "endpoints", "rename", "logout", "relogin", "server restart",
}

// fdNode is a model node's client and how it joined, which a login, a
// relogin and the stored judge need.
type fdNode struct {
	tc *TestClient
	// method is how it last registered; key the pre-auth key it can log
	// in again with, "" after a login; keyUser that key's user, or the
	// user who made a tagged key, 0 for a tags-only key.
	method    string
	key       string
	keyUser   uint
	ephemeral bool
	// reusable: a single-use key is spent by the registration, and a login
	// with it under a new node key is refused.
	reusable bool
	// loggedOut is set once its client logged out: it holds no node key.
	loggedOut bool
}

// fdRun is what the cases of one run share.
type fdRun struct {
	steps int
	tally *fdTally
	// loopLine is where serveLongPoll waits between updates.
	loopLine int
	verdicts policymodel.Verdicts
	form     policymodel.FormJudge
	// passed holds the filters held to the reference already, by
	// everything the comparison reads.
	passed map[string]bool
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

	w         policymodel.World
	nodes     map[types.NodeID]*fdNode
	elections *policymodel.Elections
	// unheld are the subnet routes a burst left with no router available:
	// who held them last is history the election history missed, so the
	// routes go unjudged until a router can take them again.
	unheld map[netip.Prefix]bool

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

	run := &fdRun{steps: fdSteps(), tally: newFDTally(), loopLine: line, passed: map[string]bool{}}

	rapid.Check(t, func(rt *rapid.T) { playFrontDoor(t, rt, run) })

	t.Log(run.tally)
	t.Logf("reference: filters %v; form %v", &run.verdicts, &run.form)

	if f := flag.Lookup("rapid.checks"); f != nil {
		n, err := strconv.Atoi(f.Value.String())
		if err == nil && n >= 1000 {
			run.tally.require(t)
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
		patient:    rapid.IntRange(0, 3).Draw(rt, "patient") == 3,
		magicDNS:   rapid.Bool().Draw(rt, "magic-dns"),
		nodes:      map[types.NodeID]*fdNode{},
		elections:  policymodel.NewElections(),
		unheld:     map[netip.Prefix]bool{},
		stacks:     make([]byte, 1<<20),
	}

	start := policymodel.Worlds().Draw(rt, "start")

	opts := []ServerOption{WithEphemeralTimeout(time.Hour), WithBatchDelay(20 * time.Millisecond)}
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

		kind := rapid.IntRange(0, 20).Draw(rt, "kind")

		switch {
		case kind < 8:
			fd.world(at, policymodel.Steps(fd.w).Draw(rt, "edits"))
		case kind < 11:
			fd.burst(at, rapid.IntRange(2, 4).Draw(rt, "burst"))
		case kind < 13:
			fd.weather(at, stepFlap)
		case kind < 14:
			fd.weather(at, stepRestartPoll)
		case kind < 15:
			fd.weather(at, stepClientRestart)
		case kind < 16:
			fd.weather(at, stepEndpoints)
		case kind < 17:
			fd.rename(at)
		case kind < 18:
			fd.logout(at)
		case kind < 19:
			fd.relogin(at)
		default:
			fd.restart(at)
		}

		fd.settle(at)
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
		default:
			nd.tc.Disconnect(fd.tb)
			fd.made(kind, "disconnect")
		}

		fd.apply(e)
	case policymodel.SetAddr, policymodel.SwapAddrs:
		fd.made(kind, "left out (database only)")
	case policymodel.AddUser:
		fd.addUser(e.User)
	case policymodel.DeleteUser:
		fd.mustAPI(at, http.MethodDelete, fmt.Sprintf("/api/v1/user/%d", e.ID), nil, nil)
		fd.made(kind, "API")
		fd.apply(e)
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

// addUser creates u: through the API, or as the identity provider's first
// login does for an OIDC user; also through the State for an API user
// whose name an OIDC user already holds, which the API refuses.
func (fd *frontDoor) addUser(u policymodel.User) {
	users, _ := policymodel.Topology{Users: []policymodel.User{u}}.Build()
	want := users[0]

	var (
		got  uint
		path string
	)

	taken := slices.ContainsFunc(fd.w.Topology.Users, func(o policymodel.User) bool { return o.Name == u.Name })

	switch {
	case u.OIDC() || taken:
		path = "identity provider"
		if !u.OIDC() {
			// TODO(kradalby): policymodel/api-user-name: the model
			// creates an API user with a name an OIDC user holds, which
			// the API refuses ("user already exists"). Counted.
			path = "State (the API refuses a name an OIDC user holds)"
		}

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

	if u.OIDC() {
		fd.updateUser(at, e.ID, func(u *types.User) { u.Name = e.Name })
		fd.made("RenameUser", "identity provider")
	} else {
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
	_, nodes := policymodel.Topology{Users: fd.w.Topology.Users, Nodes: []policymodel.Node{n}}.Build()

	hi := nodes[0].Hostinfo.Clone()
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

	kind := kinds[rapid.IntRange(0, len(kinds)-1).Draw(fd.t, "join")]
	fd.run.tally.joins[joinNames[kind]]++

	admitted := without(n.Approved, n.AutoApproved)
	full := kind != joinLoginTagged && len(admitted) == 0

	nd := &fdNode{ephemeral: kind == joinEphemeral}

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

		nd.method = util.RegisterMethodCLI
		if as.OIDC() {
			nd.method = util.RegisterMethodOIDC
		}

		opts = append(opts, WithInteractiveLogin(fd.approver(as)))
	default:
		nd.method = util.RegisterMethodAuthKey

		// A single-use key is spent by the registration; a relogin with it
		// must still find the node it made.
		nd.reusable = rapid.Bool().Draw(fd.t, "reusable")
		body := map[string]any{"reusable": nd.reusable, "ephemeral": nd.ephemeral}

		switch {
		case !n.Tagged():
			nd.keyUser = n.User
		case kind == joinUserTaggedKey:
			nd.keyUser = users[0].ID
		}

		if nd.keyUser != 0 {
			body["user"] = strconv.FormatUint(uint64(nd.keyUser), 10)
		}

		if n.Tagged() {
			body["aclTags"] = tagNames(n.Tags)
		}

		var out struct {
			PreAuthKey struct {
				Key string `json:"key"`
			} `json:"preAuthKey"`
		}

		fd.mustAPI(at, http.MethodPost, "/api/v1/preauthkey", body, &out)
		nd.key = out.PreAuthKey.Key
		opts = append(opts, WithAuthKey(nd.key))
	}

	tc, err := TryNewClient(fd.tb, fd.srv, fmt.Sprintf("n%d", n.ID), opts...)
	if err != nil {
		fd.t.Fatalf("%s: n%d does not register (%s): %v; its exchanges %s", at, n.ID, joinNames[kind], err, jsonOf(tc.RegisterAttempts()))
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
// in as, the tagged devices' for a tagged node.
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

	if got := uint(p.UserProfile.ID); got != owner { //nolint:gosec // small
		fd.t.Fatalf("%s: n%d's client was told it logs in as user %d; the server stored its node as user %d's", at, nv.ID(), got, owner)
	}
}

// without is from less rs.
func without(from, rs []int) []int {
	return slices.DeleteFunc(slices.Clone(from), func(r int) bool { return slices.Contains(rs, r) })
}

// approve sets id's approved routes through the API, the whole list as
// an admin does, adding add and dropping drop. The API takes one exit
// route for both, so an edit of one family is written, and modelled, as
// both.
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

	want := without(n.Approved, drop)
	for _, r := range add {
		if !slices.Contains(want, r) {
			want = append(want, r)
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

	if nd.ephemeral && !n.Expired && nd.tc.Polling() && rapid.Bool().Draw(fd.t, "ephemeral-logout") {
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
}

// untag makes tagged node e.ID user e.User's, as that user's interactive
// login on it does: when the user can claim the node (it joined through a
// login, or with that user's key). Otherwise the login would add a
// device beside it, which the model cannot follow: left out.
func (fd *frontDoor) untag(at string, e policymodel.Retag) {
	nd := fd.nodes[e.ID]
	u, _ := fd.w.Topology.User(e.User)

	if nd.method == util.RegisterMethodAuthKey && nd.keyUser != e.User || !fd.loginUser(u) {
		fd.made("Login", "left out (a login it cannot claim)")

		return
	}

	n, _ := fd.w.Topology.Node(e.ID)
	fd.login(at, e.ID, u, n)
	fd.made("Login", "interactive login")
	fd.apply(e)
	fd.apply(policymodel.SetOnline{ID: e.ID, Online: true})
}

// login logs id's client in interactively as u, with a new node key, as
// `tailscale up --force-reauth` does; its map session restarts. A login
// that takes a tagged node back registers it as the login does; one that
// renews a user's node keeps how it registered.
func (fd *frontDoor) login(at string, id types.NodeID, u policymodel.User, n policymodel.Node) {
	nd := fd.nodes[id]

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := nd.tc.Login(ctx, nd.tc.Persist(), "", controlclient.LoginInteractive, fd.hostinfo(n, true), fd.approver(u))
	if err != nil {
		fd.t.Fatalf("%s: n%d logs in as u%d: %v", at, id, u.ID, err)
	}

	fd.answered(at, id, nd.tc)

	nd.loggedOut = false

	if !n.Tagged() {
		return
	}

	nd.method, nd.key, nd.keyUser, nd.reusable = util.RegisterMethodCLI, "", 0, false
	if u.OIDC() {
		nd.method = util.RegisterMethodOIDC
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
		return !n.Offline && !n.Expired && nd.tc.Polling()
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
		// inside the reconnect grace.
		nd.tc.Disconnect(fd.tb)
		nd.tc.Reconnect(fd.tb)
	case stepRestartPoll:
		err = nd.tc.RestartPoll(ctx)
	case stepClientRestart:
		err = nd.tc.Restart(ctx, fd.hostinfo(n, true))
	case stepEndpoints:
		eps := fdEndpoints[rapid.IntRange(0, len(fdEndpoints)-1).Draw(fd.t, "endpoints")]
		nd.tc.Direct().SetEndpoints(eps)
		err = nd.tc.Direct().SendUpdate(ctx)
	}

	if err != nil {
		fd.t.Fatalf("%s: n%d %s: %v", at, n.ID, stepNames[kind], err)
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
	n, ok := fd.pick("logs-out", func(n policymodel.Node, nd *fdNode) bool { return !n.Expired && !nd.loggedOut })
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

	if nd.ephemeral {
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
// has no way back but a login that untags it.
func (fd *frontDoor) relogin(at string) {
	n, ok := fd.pick("logs-in", func(n policymodel.Node, nd *fdNode) bool {
		owner, _ := fd.w.Topology.User(n.User)

		return (n.Expired || nd.loggedOut) && (nd.key != "" && nd.reusable || !n.Tagged() && fd.loginUser(owner))
	})
	if !ok {
		fd.run.tally.steps[stepNames[stepRelogin]+" (no node)"]++

		return
	}

	fd.run.tally.steps[stepNames[stepRelogin]]++

	nd := fd.nodes[n.ID]

	if nd.key == "" || !nd.reusable {
		u, _ := fd.w.Topology.User(n.User)
		fd.login(at, n.ID, u, n)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := nd.tc.Login(ctx, nd.tc.Persist(), nd.key, controlclient.LoginInteractive, fd.hostinfo(n, true), nil)
		if err != nil {
			fd.t.Fatalf("%s: n%d logs in again with its key: %v", at, n.ID, err)
		}

		fd.answered(at, n.ID, nd.tc)
		nd.loggedOut = false
	}

	fd.apply(policymodel.SetExpired{ID: n.ID, Expired: false})
	fd.apply(policymodel.SetOnline{ID: n.ID, Online: true})
}

// restart restarts the server from its database; every client that was
// polling reconnects, in ID order. What each held before must survive
// but for what a restart may change (see durable).
func (fd *frontDoor) restart(at string) {
	fd.run.tally.steps[stepNames[stepServerRestart]]++
	fd.run.tally.restarts++

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

	for _, id := range slices.Sorted(maps.Keys(held)) {
		nd := fd.nodes[id]

		// The old server ended the session; the client sees the stream
		// close, then polls the new one.
		select {
		case <-nd.tc.pollDone:
		case <-ctx.Done():
			fd.t.Fatalf("%s: n%d's map session outlived the server", at, id)
		}

		err := nd.tc.RestartPoll(ctx)
		if err != nil {
			fd.t.Fatalf("%s: n%d reconnects after the restart: %v", at, id, err)
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

		if now := durable(nd.tc.Netmap()); now != held[id] {
			fd.t.Fatalf("%s: n%d's client holds after the restart what it did not before:\nbefore %s\nafter  %s", at, id, held[id], now)
		}
	}
}

// api calls the v1 API as an admin.
func (fd *frontDoor) api(method, path string, body, out any) error {
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

	nodes := make([]policymodel.RefNode, 0, len(all))

	for i, nv := range all {
		n := nv.AsStruct()
		fd.elections.Started[n.ID] = uint64(i + 1) //nolint:gosec // small
		nodes = append(nodes, policymodel.RefNode{
			ID: n.ID, Tags: n.Tags, Announced: n.AnnouncedRoutes(), Approved: n.ApprovedRoutes,
			Unavailable: !n.Online() || n.IsExpired(),
		})
	}

	fd.elections.Commit(nodes, map[types.NodeID]bool{})

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
	// clients counts the clients held to a fresh session, refClients those
	// held to the reference too; unseen the peers held offline without the
	// LastSeen a fresh session gives (render/lastseen-patchify).
	clients, refClients, unseen int
	peerSets, routePairs        int
	filters, primaries          int
	contested                   map[string]int
	skipped                     map[string]int
	// quiets counts the waits for quiet, and how long they took.
	quiets             int
	quietAll, quietMax time.Duration
}

func newFDTally() *fdTally {
	return &fdTally{
		steps: map[string]int{}, edits: map[string]int{}, joins: map[string]int{},
		contested: map[string]int{}, skipped: map[string]int{},
	}
}

func (t *fdTally) String() string {
	mean := time.Duration(0)
	if t.quiets > 0 {
		mean = t.quietAll / time.Duration(t.quiets)
	}

	return fmt.Sprintf("front door: cases %d, server restarts %d; steps %v; joins %v; edits %v; "+
		"clients held to a fresh session %d, to the reference %d (peer sets %d, route pairs %d, filters %d, primaries %d; contested %v; skipped %v); "+
		"peers held offline without LastSeen %d; quiet waits %d (mean %v, longest %v)",
		t.cases, t.restarts, t.steps, t.joins, t.edits, t.clients, t.refClients, t.peerSets, t.routePairs, t.filters, t.primaries,
		t.contested, t.skipped, t.unseen, t.quiets, mean, t.quietMax)
}

// require fails a deep run that never took some step or join, never
// restarted, or held nothing of some kind to the reference.
func (t *fdTally) require(tb testing.TB) {
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

	for name, n := range map[string]int{
		"clients": t.refClients, "peer sets": t.peerSets, "route pairs": t.routePairs, "filters": t.filters, "primaries": t.primaries,
	} {
		if n == 0 {
			tb.Errorf("no case held %s to the reference", name)
		}
	}
}
