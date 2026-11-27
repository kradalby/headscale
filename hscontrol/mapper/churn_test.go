package mapper

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
	"tailscale.com/version"
)

// engUsers are group:eng's users in the churn shapes. A group write adds
// editedUser to the group and takes them out again.
var engUsers = []string{"u0", "u1", "u2", "u3", "u4"}

const editedUser = "u5"

func engGroup(edited bool) string {
	members := slices.Clone(engUsers)
	if edited {
		members = append(members, editedUser)
	}

	for i, u := range members {
		members[i] = `"` + u + `@"`
	}

	return `"group:eng":[` + strings.Join(members, ",") + `]`
}

// meshPolicy lets every member reach every other. tag:server is there only
// for the tag write to move a member to, out of the mesh.
const meshPolicy = `{"tagOwners":{"tag:server":["u0@"]},
	"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:member:*"]}]}`

// groupAllPolicy lets group:eng reach every node: every node receives the
// rule, and its sources are the group's members.
func groupAllPolicy(edited bool) string {
	return `{"groups":{` + engGroup(edited) + `},"tagOwners":{"tag:server":["u0@"]},
		"acls":[{"action":"accept","src":["group:eng"],"dst":["*:*"]}]}`
}

// routersPolicy meshes the members and lets group:eng reach the subnets
// the tag:router nodes serve (see shapeFixture), so every router's filter
// names the group's members.
func routersPolicy(edited bool) string {
	return `{"groups":{` + engGroup(edited) + `},
		"tagOwners":{"tag:router":["u0@"],"tag:server":["u0@"]},
		"acls":[
			{"action":"accept","src":["autogroup:member"],"dst":["autogroup:member:*"]},
			{"action":"accept","src":["group:eng"],"dst":["10.0.0.0/8:*"]}]}`
}

// selectorsPolicy names sources every way a policy can (users, overlapping
// groups, tags, autogroups) over nodes some of which carry one or two tags
// (see shapeFixture), so a node holds several of the identities its rules
// name.
func selectorsPolicy(edited bool) string {
	return `{"groups":{` + engGroup(edited) + `,
			"group:ops":["u3@","u4@","u5@","u6@"],
			"group:sales":["u6@","u7@","u8@","u9@"]},
		"tagOwners":{"tag:web":["group:ops"],"tag:db":["group:ops"],"tag:ci":["group:ops"],"tag:server":["group:ops"]},
		"acls":[
			{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]},
			{"action":"accept","src":["group:eng"],"dst":["tag:web:*","tag:db:5432","group:eng:22"]},
			{"action":"accept","src":["group:ops"],"dst":["*:*"]},
			{"action":"accept","src":["group:sales"],"dst":["tag:web:443"]},
			{"action":"accept","src":["tag:web"],"dst":["tag:db:5432"]},
			{"action":"accept","src":["tag:ci"],"dst":["tag:web:22","tag:db:22"]},
			{"action":"accept","src":["u1@","u8@"],"dst":["tag:ci:*"]}]}`
}

// rulesPolicy is a policy of a few dozen rules over the routers shape's
// tailnet: per user k, group:g<k> reaches every subnet and user k+1's nodes,
// and u<k>@ reaches the routers, each on a port of its own, so a router is
// sent a rule per user and a join moves two of them. group:eng is edited
// by the group write; rule moves the port of group:g3's rule, which
// reaches the routers and u4's nodes.
func rulesPolicy(group, rule bool) string {
	port := 1003
	if rule {
		port = 1103
	}

	groups := make([]string, 0, 11)
	groups = append(groups, engGroup(group))

	acls := make([]string, 0, 32)
	acls = append(acls,
		`{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}`,
		`{"action":"accept","src":["group:eng"],"dst":["tag:server:*"]}`)

	for k := range 10 {
		groups = append(groups, fmt.Sprintf(`"group:g%d":["u%d@"]`, k, k))

		subnet := fmt.Sprintf(`"10.0.0.0/8:%d"`, 1000+k)
		if k == 3 {
			subnet = fmt.Sprintf(`"10.0.0.0/8:%d","u4@:%d"`, port, port)
		}

		acls = append(acls,
			fmt.Sprintf(`{"action":"accept","src":["group:g%d"],"dst":[%s]}`, k, subnet),
			fmt.Sprintf(`{"action":"accept","src":["group:g%d"],"dst":["u%d@:%d"]}`, k, (k+1)%10, 2000+k),
			fmt.Sprintf(`{"action":"accept","src":["u%d@"],"dst":["tag:router:%d"]}`, k, 3000+k))
	}

	return `{"groups":{` + strings.Join(groups, ",") + `},
		"tagOwners":{"tag:router":["u0@"],"tag:server":["u0@"]},
		"acls":[` + strings.Join(acls, ",") + `]}`
}

// benchShapes are policy shapes only the chunk benchmark runs: the pinned
// work tables list every shape of scalingPolicies.
var benchShapes = map[string]string{"rules": rulesPolicy(false, false)}

// shapePolicy returns a shape's policy, as setup leaves it.
func shapePolicy(shape string) string {
	if p, ok := scalingPolicies[shape]; ok {
		return p
	}

	return benchShapes[shape]
}

// shapeFixture tags the nodes the routers and selectors shapes' policies
// name, in the database before the state loads it: tagging a loaded
// tailnet one node at a time recompiles the policy for each.
//   - routers: every fifth node is a tag:router serving a /24 of its own in
//     10.0.0.0/8; subnetRouters brings them online.
//   - selectors: every fourth node is tagged, in turn tag:web, tag:db, or
//     tag:ci and tag:web.
func shapeFixture(tb testing.TB, database *db.HSDatabase, shape string, nodes []*types.Node) {
	tb.Helper()

	var tag func(i int, node *types.Node) bool

	switch shape {
	case "routers", "rules":
		tag = func(i int, node *types.Node) bool {
			if i%5 != 0 {
				return false
			}

			k := i / 5
			route := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", k/256, k%256))

			hi := node.Hostinfo.Clone()
			if hi == nil {
				hi = &tailcfg.Hostinfo{}
			}

			hi.RoutableIPs = []netip.Prefix{route}
			node.Tags, node.Hostinfo, node.ApprovedRoutes = []string{"tag:router"}, hi, []netip.Prefix{route}

			return true
		}
	case "selectors":
		sets := [][]string{{"tag:web"}, {"tag:db"}, {"tag:ci", "tag:web"}}
		tag = func(i int, node *types.Node) bool {
			if i%4 != 1 {
				return false
			}

			node.Tags = sets[(i/4)%len(sets)]

			return true
		}
	default:
		return
	}

	for i, node := range nodes {
		if !tag(i, node) {
			continue
		}

		node.UserID, node.User = nil, nil
		err := database.DB.Model(node).Select("tags", "user_id", "host_info", "approved_routes").Updates(node).Error
		require.NoError(tb, err)
	}
}

// subnetRouters brings the routers shape's routers online, so each is its
// subnet's primary, and checks the shape: a member of group:eng sees a
// router, through its subnet, and a member outside the group does not.
// The rules shape's members all reach the routers: it brings them online
// and checks nothing.
func subnetRouters(tb testing.TB, s *state.State, shape string) {
	tb.Helper()

	if shape == "rules" {
		for _, nv := range s.ListNodes().All() {
			if nv.IsTagged() {
				s.Connect(nv.ID())
			}
		}

		return
	}

	owners := userNames(tb, s)

	var router, eng, other types.NodeView

	for _, nv := range s.ListNodes().All() {
		switch {
		case nv.IsTagged():
			s.Connect(nv.ID())

			if !router.Valid() {
				router = nv
			}
		case !eng.Valid() && owners[types.UserID(nv.UserID().Get())] == engUsers[0]:
			eng = nv
		case !other.Valid() && !slices.Contains(engUsers, owners[types.UserID(nv.UserID().Get())]):
			other = nv
		}
	}

	require.True(tb, router.Valid() && eng.Valid() && other.Valid(), "the shape has routers, members of group:eng and others")

	snap := s.Snapshot()
	require.Contains(tb, snap.PeerView(eng.ID()), router.ID())
	require.NotContains(tb, snap.PeerView(other.ID()), router.ID())

	require.Equal(tb, router.ApprovedRoutes().AsSlice(), snap.RoutesForPeer(eng, mustNode(tb, s, router.ID())))
}

func userNames(tb testing.TB, s *state.State) map[types.UserID]string {
	tb.Helper()

	users, err := s.ListAllUsers()
	require.NoError(tb, err)

	names := make(map[types.UserID]string, len(users))
	for _, u := range users {
		names[types.UserID(u.ID)] = u.Name
	}

	return names
}

// churnShape is what the churn writes need of a policy shape.
type churnShape struct {
	// subject reports whether churn writes pick nv, owned by owner ("" when
	// tagged): a node of an identity the policy names. Nil picks any node.
	subject func(nv types.NodeView, owner string) bool
	// retag returns the tags a tag write gives nv; nil when the shape
	// names no tag to move a node to.
	retag func(nv types.NodeView) []string
	// policy returns the shape's policy, with editedUser in group:eng when
	// edited; nil when the shape names no group.
	policy func(edited bool) string
	// rule returns the shape's policy with one rule's port moved when
	// edited; nil when no write edits a rule.
	rule func(edited bool) string
}

func member(nv types.NodeView, _ string) bool { return !nv.IsTagged() }

func engMember(nv types.NodeView, owner string) bool {
	return !nv.IsTagged() && slices.Contains(engUsers, owner)
}

func retagTo(tag string) func(types.NodeView) []string {
	return func(types.NodeView) []string { return []string{tag} }
}

// nextTag moves a node of the tags shape to the next tag of the chain its
// policy makes.
func nextTag(nv types.NodeView) []string {
	k, err := strconv.Atoi(strings.TrimPrefix(nv.Tags().At(0), "tag:t"))
	if err != nil {
		panic(err)
	}

	return []string{fmt.Sprintf("tag:t%d", (k+1)%20)}
}

var churnShapes = map[string]churnShape{
	"allow-all": {},
	"self":      {},
	"users":     {},
	"tags":      {retag: nextTag},
	"via":       {subject: member, retag: retagTo("tag:r")},
	"mesh":      {subject: member, retag: retagTo("tag:server")},
	"group-all": {subject: engMember, retag: retagTo("tag:server"), policy: groupAllPolicy},
	"routers":   {subject: engMember, retag: retagTo("tag:server"), policy: routersPolicy},
	"selectors": {subject: member, retag: retagTo("tag:server"), policy: selectorsPolicy},
	"rules": {
		subject: member, retag: retagTo("tag:server"),
		policy: func(edited bool) string { return rulesPolicy(edited, false) },
		rule:   func(edited bool) string { return rulesPolicy(false, edited) },
	},
}

// churnWrite is a write that moves a node into or out of what the policy
// names, through the entry point production uses for it.
type churnWrite struct {
	// applies reports whether a shape has what the write changes.
	applies func(churnShape) bool
	// write makes write i, which the caller delivers, and sets the run's
	// subjects.
	write func(cr *churnRun, tb testing.TB, i int)
	// restore undoes write i, delivering without counting, so that every
	// write starts from the tailnet setup built; the benchmark stops its
	// timer for it. Nil when writes alternate instead.
	restore func(cr *churnRun, tb testing.TB, i int)
}

// chunkWrites are writes only the chunk benchmark runs, apart from
// churnWrites for the same reason as benchShapes.
var chunkWrites = map[string]churnWrite{
	// rule moves one rule's port through the API's policy update.
	"rule": {applies: func(cs churnShape) bool { return cs.rule != nil }, write: (*churnRun).rule},
}

var churnWrites = map[string]churnWrite{
	// join registers a node that did not exist, under a pre-auth key of a
	// subject's identity, as a client's first login does. Its session,
	// first map and coming online are not part of it: see
	// BenchmarkFirstMap and the online kind.
	"join": {applies: func(churnShape) bool { return true }, write: (*churnRun).join, restore: (*churnRun).unjoin},
	// leave deletes a subject, as the API does.
	"leave": {applies: func(churnShape) bool { return true }, write: (*churnRun).leave, restore: (*churnRun).replace},
	// tag sets a subject's tags as the API does: a tagged node moves to
	// another tag the policy names, a member becomes tagged.
	"tag": {applies: func(cs churnShape) bool { return cs.retag != nil }, write: (*churnRun).tag, restore: (*churnRun).untag},
	// group adds editedUser to group:eng and takes them out, in turn,
	// through the API's policy update: a group edit is a policy edit.
	"group": {applies: func(cs churnShape) bool { return cs.policy != nil }, write: (*churnRun).group},
}

// churnRun is a scalingRun whose writes change who is in the tailnet and
// what the policy says of them.
type churnRun struct {
	*scalingRun

	cfg    *types.Config
	shape  churnShape
	owners map[types.UserID]string

	// picks are the subjects writes pick in turn; a restore that replaces
	// one puts the replacement in its place.
	picks []types.NodeID
	// authKeys holds a reusable pre-auth key per subject identity.
	authKeys map[identity]string
	// machine and node are the keys of the next node to register, made
	// outside the timed region.
	machine key.MachinePublic
	node    key.NodePublic

	// undo is what the last write's restore needs.
	undo struct {
		id       types.NodeID
		who      identity
		hostname string
		tags     []string
	}

	// policies are the group write's documents, as setup leaves the
	// policy and edited; moved are editedUser's nodes. rules are the rule
	// write's.
	policies [2][]byte
	rules    [2][]byte
	moved    []types.NodeID
}

// identity is what a node registers as: a user, or tags.
type identity struct {
	user types.UserID
	tags string // sorted and comma-joined; empty for a user's node
}

func identityOf(nv types.NodeView) identity {
	if nv.IsTagged() {
		return identity{tags: strings.Join(nv.Tags().AsSlice(), ",")}
	}

	return identity{user: types.UserID(nv.UserID().Get())}
}

func newChurnRun(tb testing.TB, s *state.State, streams []*Stream, shape string) *churnRun {
	tb.Helper()

	cr := &churnRun{
		scalingRun: newScalingRun(s, streams),
		cfg:        streams[0].cfg,
		shape:      churnShapes[shape],
		owners:     userNames(tb, s),
		authKeys:   make(map[identity]string),
	}
	cr.hub, cr.watch = streams[0].hub, true
	cr.sized = newSizedEncoder()
	cr.encode = cr.sized.fn
	cr.subjects = make(map[types.NodeID]struct{})

	for _, nv := range s.ListNodes().All() {
		var owner string
		if !nv.IsTagged() {
			owner = cr.owners[types.UserID(nv.UserID().Get())]
		}

		if owner == editedUser {
			cr.moved = append(cr.moved, nv.ID())
		}

		if cr.shape.subject != nil && !cr.shape.subject(nv, owner) {
			continue
		}

		cr.picks = append(cr.picks, nv.ID())

		who := identityOf(nv)
		if _, ok := cr.authKeys[who]; ok {
			continue
		}

		var (
			uid  *types.UserID
			tags []string
		)

		if who.tags != "" {
			tags = strings.Split(who.tags, ",")
		} else {
			uid = &who.user
		}

		pak, err := s.CreatePreAuthKey(uid, true, false, nil, tags)
		require.NoError(tb, err)

		cr.authKeys[who] = pak.Key
	}

	require.NotEmpty(tb, cr.picks, "the shape has subjects")

	if cr.shape.policy != nil {
		cr.policies = [2][]byte{[]byte(cr.shape.policy(false)), []byte(cr.shape.policy(true))}
		require.Equal(tb, shapePolicy(shape), string(cr.policies[0]), "setup leaves the unedited policy")
		require.NotEmpty(tb, cr.moved, "the group write moves nodes")
	}

	if cr.shape.rule != nil {
		cr.rules = [2][]byte{[]byte(cr.shape.rule(false)), []byte(cr.shape.rule(true))}
		require.Equal(tb, shapePolicy(shape), string(cr.rules[0]), "setup leaves the unedited policy")
	}

	cr.freshKeys()

	return cr
}

func (cr *churnRun) freshKeys() {
	cr.machine, cr.node = key.NewMachine().Public(), key.NewNode().Public()
}

// pick returns write i's subject.
func (cr *churnRun) pick(tb testing.TB, i int) types.NodeView {
	tb.Helper()

	id := cr.picks[i%len(cr.picks)]

	nv, ok := cr.s.GetNodeByID(id)
	if !ok {
		tb.Fatalf("subject %d is gone", id)
	}

	return nv
}

// changed names the nodes the write being delivered changed.
func (cr *churnRun) changed(ids ...types.NodeID) {
	clear(cr.subjects)

	for _, id := range ids {
		cr.subjects[id] = struct{}{}
	}
}

// remember keeps what a restore of nv's write needs.
func (cr *churnRun) remember(nv types.NodeView) {
	cr.undo.id, cr.undo.who, cr.undo.hostname = nv.ID(), identityOf(nv), nv.Hostname()
	cr.undo.tags = nv.Tags().AsSlice()
}

// register logs a node of who in with a pre-auth key, as a client does,
// under the keys made for it.
func (cr *churnRun) register(tb testing.TB, who identity, hostname string) types.NodeView {
	tb.Helper()

	nv, err := cr.s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: cr.authKeys[who]},
		NodeKey:  cr.node,
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname, GoVersion: runtime.Version(), IPNVersion: version.Long()},
	}, cr.machine)
	if err != nil {
		tb.Fatal(err)
	}

	return nv
}

// flush delivers what a restore committed without counting it.
func (cr *churnRun) flush(tb testing.TB) {
	tb.Helper()

	work := cr.scalingWork
	cr.deliver(tb)
	cr.scalingWork = work
}

// remove deletes id and flushes.
func (cr *churnRun) remove(tb testing.TB, id types.NodeID) {
	tb.Helper()

	require.NoError(tb, cr.s.DeleteNode(mustNode(tb, cr.s, id)))
	cr.flush(tb)
}

// open starts a session for id, as the node's first poll does.
func (cr *churnRun) open(tb testing.TB, id types.NodeID) {
	tb.Helper()

	st := NewStream(cr.cfg, cr.hub, id, capVer)
	_, err := st.Initial(cr.s.Snapshot())
	require.NoError(tb, err)
	st.Delivered()

	cr.streams = append(cr.streams, st)
	cr.byNode[id] = st
}

func (cr *churnRun) join(tb testing.TB, i int) {
	tb.Helper()

	nv := cr.pick(tb, i)
	joined := cr.register(tb, identityOf(nv), "joiner")

	cr.undo.id = joined.ID()
	cr.changed(joined.ID())
}

func (cr *churnRun) unjoin(tb testing.TB, _ int) {
	tb.Helper()

	cr.remove(tb, cr.undo.id)
	cr.freshKeys()
}

func (cr *churnRun) leave(tb testing.TB, i int) {
	tb.Helper()

	nv := cr.pick(tb, i)
	cr.remember(nv)

	err := cr.s.DeleteNode(nv)
	if err != nil {
		tb.Fatal(err)
	}

	cr.changed(nv.ID())
}

// replace registers a node of the identity and name write i's subject
// had, with a session of its own, in its place.
func (cr *churnRun) replace(tb testing.TB, i int) {
	tb.Helper()

	nv := cr.register(tb, cr.undo.who, cr.undo.hostname)
	cr.freshKeys()
	cr.flush(tb)
	cr.open(tb, nv.ID())

	cr.picks[i%len(cr.picks)] = nv.ID()
}

func (cr *churnRun) tag(tb testing.TB, i int) {
	tb.Helper()

	nv := cr.pick(tb, i)
	cr.remember(nv)

	_, err := cr.s.SetNodeTags(nv.ID(), cr.shape.retag(nv))
	if err != nil {
		tb.Fatal(err)
	}

	cr.changed(nv.ID())
}

// untag gives a retagged node its tags back. A member cannot get its user
// back through tags, so a new node of that user replaces it.
func (cr *churnRun) untag(tb testing.TB, i int) {
	tb.Helper()

	if len(cr.undo.tags) > 0 {
		_, err := cr.s.SetNodeTags(cr.undo.id, cr.undo.tags)
		require.NoError(tb, err)
		cr.flush(tb)

		return
	}

	cr.remove(tb, cr.undo.id)
	cr.replace(tb, i)
}

func (cr *churnRun) group(tb testing.TB, i int) {
	tb.Helper()

	_, err := cr.s.UpdatePolicy(tb.Context(), cr.policies[(i+1)%2])
	if err != nil {
		tb.Fatal(err)
	}

	cr.changed(cr.moved...)
}

// rule moves the port of one rule of the shape's policy, and back, in
// turn, through the API's policy update. It changes no node.
func (cr *churnRun) rule(tb testing.TB, i int) {
	tb.Helper()

	_, err := cr.s.UpdatePolicy(tb.Context(), cr.rules[(i+1)%2])
	if err != nil {
		tb.Fatal(err)
	}

	cr.changed()
}

// requireSettled is [scalingRun.requireSettled] for churn: every write
// changes something some session sees.
func (cr *churnRun) requireSettled(tb testing.TB, kind string) {
	tb.Helper()

	cr.scalingRun.requireSettled(tb, kind)
	require.Zero(tb, cr.quiet, "every churn write wakes work")
}

// watched does for snap what the hub's watcher does besides waking
// sessions: advance the render caches, and forget deleted nodes, which
// ends their sessions.
func (sc *scalingRun) watched(snap *state.Snapshot, change state.Change) {
	sc.hub.advance(snap)

	for _, id := range change.Nodes {
		if _, live := snap.GetNode(id); live {
			continue
		}

		sc.hub.forget(id)

		if _, ok := sc.byNode[id]; ok {
			delete(sc.byNode, id)
			sc.streams = slices.DeleteFunc(sc.streams, func(st *Stream) bool { return st.nodeID == id })
		}
	}
}

// account adds what resp, sent to id, carries to the run's byte counts,
// reporting false when the sized encoder did not encode resp.
func (sc *scalingRun) account(id types.NodeID, resp *tailcfg.MapResponse) bool {
	size, ok := sc.sized.sizes[resp]
	if !ok {
		return false
	}

	sc.restBytes += size.json - size.filter

	if _, ok := sc.subjects[id]; ok {
		sc.selfFilterBytes += size.filter

		return true
	}

	sc.filterBytes += size.filter

	if resp.PacketFilters != nil {
		sc.filterSends++
	}

	for name, rules := range resp.PacketFilters {
		switch {
		case name == "*":
		case rules == nil:
			sc.chunksDeleted++
		default:
			sc.chunksSent++
		}
	}

	return true
}

// benchChurn runs a churn kind of [BenchmarkScalingWrites], or of
// [BenchmarkChunkedWrites]. A write's restore runs with the timer stopped.
func benchChurn(b *testing.B, kind, shape string, n int) {
	b.Helper()

	s, streams := scalingTailnet(b, n, shape)
	cr := newChurnRun(b, s, streams, shape)

	w, ok := churnWrites[kind]
	if !ok {
		w = chunkWrites[kind]
	}

	var i int

	for b.Loop() {
		w.write(cr, b, i)
		cr.deliver(b)

		if w.restore != nil {
			b.StopTimer()
			w.restore(cr, b, i)
			b.StartTimer()
		}

		i++
	}

	cr.requireSettled(b, kind)

	per := func(v int) float64 { return float64(v) / float64(i) }
	b.ReportMetric(per(cr.woken), "woken/op")
	b.ReportMetric(per(cr.updates), "updates/op")
	b.ReportMetric(per(cr.rendered), "peer-renders/op")
	b.ReportMetric(per(cr.encoded), "encoded-bytes/op")
	b.ReportMetric(per(cr.filterBytes), "filter-bytes/op")
	b.ReportMetric(per(cr.filterSends), "filter-sends/op")
	b.ReportMetric(per(cr.selfFilterBytes), "self-filter-bytes/op")
	b.ReportMetric(per(cr.restBytes), "rest-bytes/op")
	b.ReportMetric(per(cr.commits), "commits/op")
	b.ReportMetric(per(cr.chunksSent), "chunks-sent/op")
	b.ReportMetric(per(cr.chunksDeleted), "chunks-deleted/op")
}

// BenchmarkChunkedWrites measures what named filter chunks change: the
// churn kinds and a one-rule policy edit under a policy of a few dozen
// rules with subnet routers, which are sent addresses (see rulesPolicy).
// chunks-sent/op and chunks-deleted/op count the chunks the woken sessions
// were sent and told to delete; address mode sends its whole filter as one.
// HEADSCALE_SCALE_NODES sets the size.
func BenchmarkChunkedWrites(b *testing.B) {
	for _, kind := range []string{"join", "leave", "tag", "group", "rule"} {
		for _, n := range benchSizes(b, 1000) {
			b.Run(fmt.Sprintf("%s/rules/nodes=%d", kind, n), func(b *testing.B) {
				benchChurn(b, kind, "rules", n)
			})
		}
	}
}

// BenchmarkCoalescedChurn is [BenchmarkScalingWrites]' churn kinds with a
// second commit the hub routes with each write: an endpoint write of a node
// apart from the subjects, as commits coalesce under load.
// HEADSCALE_SCALE_NODES sets the size.
func BenchmarkCoalescedChurn(b *testing.B) {
	n := 1000

	if v, ok := os.LookupEnv("HEADSCALE_SCALE_NODES"); ok {
		var err error

		n, err = strconv.Atoi(v)
		require.NoError(b, err)
	}

	for _, kind := range []string{"join", "leave", "tag"} {
		for _, shape := range []string{"mesh", "group-all", "users", "selectors", "routers"} {
			w := churnWrites[kind]
			if !w.applies(churnShapes[shape]) {
				continue
			}

			b.Run(fmt.Sprintf("%s/%s/nodes=%d", kind, shape, n), func(b *testing.B) {
				s, streams := scalingTailnet(b, n, shape)
				cr := newChurnRun(b, s, streams, shape)

				var i int

				for b.Loop() {
					w.write(cr, b, i)
					scalingEndpoint(b, s, cr.streams[(i*37+11)%len(cr.streams)].nodeID, i)
					cr.deliver(b)

					if w.restore != nil {
						b.StopTimer()
						w.restore(cr, b, i)
						b.StartTimer()
					}

					i++
				}

				per := func(v int) float64 { return float64(v) / float64(i) }
				b.ReportMetric(per(cr.woken), "woken/op")
				b.ReportMetric(per(cr.updates), "updates/op")
				b.ReportMetric(per(cr.rendered), "peer-renders/op")
				b.ReportMetric(per(cr.filterBytes), "filter-bytes/op")
				b.ReportMetric(per(cr.filterSends), "filter-sends/op")
				b.ReportMetric(per(cr.restBytes), "rest-bytes/op")
				b.ReportMetric(per(cr.commits), "commits/op")
			})
		}
	}
}

// BenchmarkEndpointAfterChurn measures an endpoint write right after a
// join or a tag change and its restore: the served filters are cached per
// commit that moves a policy fact, so every session the churn did not wake
// cuts its unchanged filter again at its next render, here the endpoint
// write's. filter-cuts/op counts those cuts; a cache keyed on what each
// node's rules read would remove them. HEADSCALE_SCALE_NODES sets the size.
func BenchmarkEndpointAfterChurn(b *testing.B) {
	n := 400

	if v, ok := os.LookupEnv("HEADSCALE_SCALE_NODES"); ok {
		var err error

		n, err = strconv.Atoi(v)
		require.NoError(b, err)
	}

	for _, kind := range []string{"join", "tag"} {
		for _, shape := range []string{"mesh", "users", "selectors", "routers"} {
			w := churnWrites[kind]
			if !w.applies(churnShapes[shape]) {
				continue
			}

			b.Run(fmt.Sprintf("%s/%s/nodes=%d", kind, shape, n), func(b *testing.B) {
				s, streams := scalingTailnet(b, n, shape)
				cr := newChurnRun(b, s, streams, shape)

				var i, cuts, woken int

				for b.Loop() {
					b.StopTimer()
					w.write(cr, b, i)
					cr.deliver(b)

					if w.restore != nil {
						w.restore(cr, b, i)
					}

					was, wasWoken := state.FilterCuts(), cr.woken

					b.StartTimer()

					// A node apart from the churn's subjects, picked in turn.
					scalingEndpoint(b, s, cr.streams[(i*37+11)%len(cr.streams)].nodeID, i)
					cr.deliver(b)

					cuts += int(state.FilterCuts() - was) //nolint:gosec // small
					woken += cr.woken - wasWoken
					i++
				}

				b.ReportMetric(float64(cuts)/float64(i), "filter-cuts/op")
				b.ReportMetric(float64(woken)/float64(i), "woken/op")
			})
		}
	}
}

// TestScalingWriteWorkChurn is [TestScalingWriteWork] for the churn kinds,
// adding the sessions other than the subjects' sent a packet filter: the
// fan-out a write's filter change costs. The counts are exact, as there.
func TestScalingWriteWorkChurn(t *testing.T) {
	// Pinned to address form: the counts are address mode's work; capability mode re-renders the peers whose stamps a write moves, and sends fewer filters (BenchmarkScalingWrites reports both).
	t.Setenv(state.TestCapabilitySourcesEnv, "false")

	const n, writes = 100, 4

	// Sessions woken, sessions sent an update, peers rendered, and
	// sessions other than the subjects' sent a packet filter, over the
	// writes. A joiner has no session, and a leaver's ends with it.
	//
	// A rule naming the subject's identity as a source lists its
	// addresses, so every session receiving that rule is sent a new
	// filter: all of them under mesh, group-all and routers, where the
	// rule reaches every member or every node, and none under allow-all,
	// whose source is "*". A destination naming it moves only the filters
	// of the nodes holding the addresses that came or went, so a tag:tN
	// node's join leaves the other tag:tN nodes' filters alone. A routed
	// peer renders again only for a viewer whose side set moved, or when
	// its routes' cover or what every route reads did, and then only when
	// the routes it gives differ: a join or a group edit elsewhere moves
	// neither for the routers' subnets.
	ceilings := map[string][4]int{
		"group/group-all": {400, 400, 1600, 360},
		"group/routers":   {112, 112, 640, 80},
		"group/selectors": {280, 280, 0, 248},
		"join/allow-all":  {400, 400, 400, 0},
		"join/group-all":  {400, 400, 400, 400},
		"join/mesh":       {400, 400, 400, 400},
		"join/routers":    {400, 400, 400, 400},
		"join/selectors":  {308, 308, 308, 248},
		"join/self":       {40, 40, 40, 40},
		"join/tags":       {40, 40, 40, 20},
		"join/users":      {40, 40, 40, 40},
		"join/via":        {400, 400, 400, 40},
		"leave/allow-all": {396, 396, 0, 0},
		"leave/group-all": {396, 396, 0, 396},
		"leave/mesh":      {396, 396, 0, 396},
		"leave/routers":   {396, 396, 0, 396},
		"leave/selectors": {304, 304, 0, 244},
		"leave/self":      {36, 36, 0, 36},
		"leave/tags":      {40, 40, 0, 20},
		"leave/users":     {36, 36, 0, 36},
		"leave/via":       {396, 396, 0, 40},
		"tag/group-all":   {400, 400, 196, 396},
		"tag/mesh":        {400, 400, 0, 396},
		"tag/routers":     {400, 400, 0, 396},
		"tag/selectors":   {308, 308, 120, 244},
		"tag/tags":        {80, 80, 72, 40},
		"tag/via":         {400, 400, 396, 40},
	}

	for _, kind := range slices.Sorted(maps.Keys(churnWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			w := churnWrites[kind]
			if !w.applies(churnShapes[shape]) {
				continue
			}

			t.Run(kind+"/"+shape, func(t *testing.T) {
				s, streams := scalingTailnet(t, n, shape)
				cr := newChurnRun(t, s, streams, shape)

				for i := range writes {
					w.write(cr, t, i)
					cr.deliver(t)

					if w.restore != nil {
						w.restore(cr, t, i)
					}
				}

				cr.requireSettled(t, kind)

				limit, ok := ceilings[kind+"/"+shape]
				require.True(t, ok, "no ceiling for %s/%s", kind, shape)

				got := [4]int{cr.woken, cr.updates, cr.rendered, cr.filterSends}
				assert.Equal(t, limit, got, "sessions woken, updated, peers rendered, others sent a filter")
			})
		}
	}
}

// TestScalingWriteWorkChurnCapability is [TestScalingWriteWorkChurn] in
// capability mode, adding the work routing makes on the way: the filters
// cut, and the expansions built. A receiver sent capabilities reads no
// membership but its own, so a join, leave or retag cuts the subjects'
// filters and those of receivers still sent addresses, and wakes a session
// only for what it renders: the subject as a peer.
func TestScalingWriteWorkChurnCapability(t *testing.T) {
	t.Setenv(state.TestCapabilitySourcesEnv, "true")
	// The audit cuts filters of its own, which the counts would include.
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	const n, writes = 100, 4

	// Sessions woken, sent an update, peers rendered, others sent a
	// packet filter, filters cut, selector resolutions built, members those
	// listed, over the writes.
	//
	// Woken = updated: a join or retag renders the subject for its viewers,
	// a leave drops it, and a group edit restamps editedUser's nodes for
	// each of their viewers; nobody else is woken. The filters sent and cut
	// are the receivers still sent addresses whose filter moved: the subnet
	// routers (20) under routers, the via routers (10) under via, the
	// retagged subject itself, and editedUser's nodes entering or leaving a
	// rule's destinations under selectors. Only cutting an address form
	// resolves selectors: the routers' two (members, group:eng; via: members
	// and the via tag).
	ceilings := map[string][7]int{
		"group/group-all": {400, 400, 3960, 0, 0, 0, 0},
		"group/routers":   {400, 400, 3168, 80, 80, 8, 496},
		"group/selectors": {400, 400, 3168, 0, 32, 0, 0},
		"join/allow-all":  {400, 400, 400, 0, 0, 0, 0},
		"join/group-all":  {400, 400, 400, 0, 0, 0, 0},
		"join/mesh":       {400, 400, 400, 0, 0, 0, 0},
		"join/routers":    {400, 400, 400, 80, 80, 8, 488},
		"join/selectors":  {308, 308, 308, 0, 0, 0, 0},
		"join/self":       {40, 40, 40, 0, 0, 0, 0},
		"join/tags":       {40, 40, 40, 0, 0, 0, 0},
		"join/users":      {40, 40, 40, 0, 0, 0, 0},
		"join/via":        {400, 400, 400, 40, 40, 8, 404},
		"leave/allow-all": {396, 396, 0, 0, 0, 0, 0},
		"leave/group-all": {396, 396, 0, 0, 0, 0, 0},
		"leave/mesh":      {396, 396, 0, 0, 0, 0, 0},
		"leave/routers":   {396, 396, 0, 80, 80, 8, 472},
		"leave/selectors": {304, 304, 0, 0, 0, 0, 0},
		"leave/self":      {36, 36, 0, 0, 0, 0, 0},
		"leave/tags":      {40, 40, 0, 0, 0, 0, 0},
		"leave/users":     {36, 36, 0, 0, 0, 0, 0},
		"leave/via":       {396, 396, 0, 40, 40, 8, 396},
		"tag/group-all":   {400, 400, 196, 0, 4, 0, 0},
		"tag/mesh":        {400, 400, 0, 0, 4, 0, 0},
		"tag/routers":     {400, 400, 0, 80, 84, 8, 472},
		"tag/selectors":   {308, 308, 120, 0, 4, 0, 0},
		"tag/tags":        {80, 80, 72, 0, 4, 0, 0},
		"tag/via":         {400, 400, 396, 40, 44, 8, 400},
	}

	for _, kind := range slices.Sorted(maps.Keys(churnWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			w := churnWrites[kind]
			if !w.applies(churnShapes[shape]) {
				continue
			}

			t.Run(kind+"/"+shape, func(t *testing.T) {
				s, streams := scalingTailnet(t, n, shape)
				cr := newChurnRun(t, s, streams, shape)

				var work [3]uint64

				for i := range writes {
					w.write(cr, t, i)

					before := capWork()

					cr.deliver(t)

					for k, v := range capWork() {
						work[k] += v - before[k]
					}

					if w.restore != nil {
						w.restore(cr, t, i)
					}
				}

				cr.requireSettled(t, kind)

				got := [7]int{cr.woken, cr.updates, cr.rendered, cr.filterSends, int(work[0]), int(work[1]), int(work[2])} //nolint:gosec // small
				limit, ok := ceilings[kind+"/"+shape]
				require.True(t, ok, "no ceiling for %s/%s", kind, shape)
				assert.Equal(t, limit, got, "sessions woken, updated, peers rendered, others sent a filter, filters cut, resolutions built, members listed")
			})
		}
	}
}

// TestChurnInvariantsCapability is plan check H on the wire: in capability
// mode a join, leave or retag sends no packet filter to a node other than
// the one written unless that node is sent its filter as addresses, and
// wakes no session that has nothing to send but the subnet routers and
// exit nodes every rule change recuts (decision D7). Every shape, alone
// and with two writes coalesced into one routing.
func TestChurnInvariantsCapability(t *testing.T) {
	t.Setenv(state.TestCapabilitySourcesEnv, "true")

	const n, writes = 40, 3

	for _, kind := range []string{"join", "leave", "tag"} {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			w := churnWrites[kind]
			if !w.applies(churnShapes[shape]) {
				continue
			}

			for _, coalesce := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/coalesced=%t", kind, shape, coalesce), func(t *testing.T) {
					s, streams := scalingTailnet(t, n, shape)
					cr := newChurnRun(t, s, streams, shape)

					var addressSends, idle int

					cr.observe = func(snap *state.Snapshot, id types.NodeID, out []*tailcfg.MapResponse) {
						nv, ok := snap.GetNode(id)
						d7 := ok && (len(nv.SubnetRoutes()) > 0 || nv.IsExitNode())

						if len(out) == 0 && !d7 {
							idle++
						}

						if _, subject := cr.subjects[id]; subject {
							return
						}

						for _, resp := range out {
							if resp.PacketFilters == nil {
								continue
							}

							if capabilityForm(snap.ReceiverFacts(id)) {
								t.Errorf("node %d, sent capabilities, was sent a packet filter", id)
							}

							addressSends++
						}
					}

					for i := range writes {
						w.write(cr, t, i)

						if coalesce {
							// A second commit the hub routes with the first:
							// an endpoint write of a node apart from the
							// subjects, whose viewers have its endpoint to
							// render.
							scalingEndpoint(t, s, cr.streams[(i*37+11)%len(cr.streams)].nodeID, i)
						}

						cr.deliver(t)

						if w.restore != nil {
							w.restore(cr, t, i)
						}
					}

					cr.requireSettled(t, kind)

					assert.Zero(t, idle, "sessions woken with nothing to send, beyond the routers and exits every rule change recuts")
					t.Logf("filters sent to nodes sent addresses %d, commits %d", addressSends, cr.commits)
				})
			}
		}
	}
}

// joinStages is what one join, or one leave, cost each stage between the
// write and the sessions it woke: the commit with every cell it moved,
// Since, Route, and the renders of the sessions woken, with a joiner's
// first map.
type joinStages struct {
	allocs, bytes [numStages]uint64
	ns            [numStages]int64
	woken         int
}

const (
	stageCommit = iota
	stageSince
	stageRoute
	stageRender
	numStages
)

var stageNames = [numStages]string{"commit", "Since", "Route", "render"}

// selfTailnet is n nodes in users of ten, official clients, under a policy
// that lets each user's nodes reach one another: a node's viewers are its
// user's nodes at any size.
func selfTailnet(tb testing.TB, n int) (*types.Config, *state.State) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/h.db"},
		},

		ServerURL: "https://headscale.test",
		Policy:    types.PolicyConfig{Mode: types.PolicyModeDB}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)
	require.NoError(tb, database.DB.Exec("PRAGMA synchronous = OFF").Error)

	for _, u := range database.CreateUsersForTest(n/10, "u") {
		database.CreateRegisteredNodesForTest(u, 10, u.Name)
	}

	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}]}`))
	require.NoError(tb, err)

	return cfg, s
}

// measureJoinStages joins a node to the first user of a [selfTailnet] of
// n nodes and deletes it again, rounds times after a warm-up, and returns
// the mean cost of each stage of a join and of a leave: the same viewers
// at any n, so a stage that grows with n grows with the tailnet.
func measureJoinStages(t *testing.T, n int) (joinStages, joinStages) {
	t.Helper()

	cfg, s := selfTailnet(t, n)
	hub := NewHub()

	first := s.ListNodes().At(0)
	owner, err := s.GetUserByID(types.UserID(first.User().ID()))
	require.NoError(t, err)

	streams := map[types.NodeID]*Stream{}

	for _, nv := range s.ListNodes().All() {
		if nv.User().ID() != owner.ID {
			continue
		}

		st := NewStream(cfg, hub, nv.ID(), capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		st.Delivered()

		streams[nv.ID()] = st
	}

	const warm, rounds = 2, 5

	var join, leave joinStages

	last := s.Snapshot()

	// write measures one write through every stage into into, after a
	// warm-up; joiner, when set, opens its session.
	write := func(into *joinStages, measured bool, commit func(), joiner types.NodeID) {
		var at [numStages + 1]runtime.MemStats

		var times [numStages + 1]time.Time

		mark := func(i int) {
			runtime.ReadMemStats(&at[i])
			times[i] = time.Now()
		}

		runtime.GC()
		mark(0)

		commit()
		mark(1)

		snap := s.Snapshot()
		change := snap.Since(last)

		mark(2)

		all, wake := Route(last, snap, change)

		mark(3)

		require.False(t, all, "a join or leave wakes its viewers, not everyone")

		for id := range wake {
			if st := streams[id]; st != nil {
				_, err := st.Update(snap)
				require.NoError(t, err)
				st.Delivered()
			}
		}

		if joiner != 0 {
			st := NewStream(cfg, hub, joiner, capVer)
			_, err := st.Initial(snap)
			require.NoError(t, err)
			st.Delivered()
		}

		mark(4)

		last = snap

		if !measured {
			return
		}

		for i := range numStages {
			into.allocs[i] += at[i+1].Mallocs - at[i].Mallocs
			into.bytes[i] += at[i+1].TotalAlloc - at[i].TotalAlloc
			into.ns[i] += times[i+1].Sub(times[i]).Nanoseconds()
		}

		into.woken = len(wake)
	}

	for i := range warm + rounds {
		node := s.CreateRegisteredNodeForTest(owner, fmt.Sprintf("joiner-%d", i))
		node.User = owner

		write(&join, i >= warm, func() { s.PutNodeInStoreForTest(*node) }, node.ID)
		write(&leave, i >= warm, func() { s.DeleteNodeFromStoreForTest(node.ID) }, 0)
	}

	for _, w := range []*joinStages{&join, &leave} {
		for i := range numStages {
			w.allocs[i] /= rounds
			w.bytes[i] /= rounds
			w.ns[i] /= rounds
		}
	}

	return join, leave
}

// TestJoinCostPerStage measures one join and one leave in capability mode
// at 100 and at 10,000 nodes with the same viewers, from the write through
// the commit, Since, Route and the renders of the sessions woken, and pins
// per stage what stays and what grows. Since and Route stay; the renders
// stay but for the peer classes' prune, which visits every class when the
// peers move. The commit grows: the compile, which still runs for SSH and
// node capabilities, resolves autogroup:member again at every membership
// change (at 10,000 nodes ≈ 10 MB, 25,000 allocations of the commit's 10.8
// MB, 25,800), and the posting and side lists the subject enters and the
// sorted node list are slices copied whole (≈ 340 KB).
func TestJoinCostPerStage(t *testing.T) {
	if testing.Short() || util.RaceEnabled {
		t.Skip("builds a 10,000 node tailnet")
	}

	t.Setenv(state.TestCapabilitySourcesEnv, "true")
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	smallJoin, smallLeave := measureJoinStages(t, 100)
	largeJoin, largeLeave := measureJoinStages(t, 10_000)

	for _, c := range []struct {
		name         string
		small, large joinStages
	}{{"join", smallJoin, largeJoin}, {"leave", smallLeave, largeLeave}} {
		t.Logf("%s: woken %d at 100, %d at 10000", c.name, c.small.woken, c.large.woken)

		for i := range numStages {
			t.Logf("%s %-7s allocs %6d -> %6d  bytes %9d -> %9d  time %9d -> %9d ns", c.name, stageNames[i],
				c.small.allocs[i], c.large.allocs[i], c.small.bytes[i], c.large.bytes[i], c.small.ns[i], c.large.ns[i])
		}

		assert.Equal(t, c.small.woken, c.large.woken, "test sanity: the same viewers at both sizes")

		for _, i := range []int{stageSince, stageRoute} {
			assert.LessOrEqual(t, c.large.allocs[i], c.small.allocs[i]+2, "%s %s allocates what moved", c.name, stageNames[i])
			assert.LessOrEqual(t, c.large.bytes[i], c.small.bytes[i]+1<<10, "%s %s", c.name, stageNames[i])
		}

		assert.LessOrEqual(t, float64(c.large.allocs[stageRender]), 1.25*float64(c.small.allocs[stageRender]), "%s renders allocate the viewers'", c.name)
		assert.LessOrEqual(t, c.large.bytes[stageRender], c.small.bytes[stageRender]+320<<10, "%s renders: the class prune", c.name)
		assert.LessOrEqual(t, c.large.allocs[stageCommit], uint64(30_000), "%s commit: the compile", c.name)
		assert.LessOrEqual(t, c.large.bytes[stageCommit], uint64(13<<20), "%s commit: the compile and the lists", c.name)
	}
}

// TestChurnWakesEverySessionItChanges renders every session again after
// each churn write is delivered: none may have anything left to send, or
// the benchmark's timed delivery would leave work out.
func TestChurnWakesEverySessionItChanges(t *testing.T) {
	const n, writes = 50, 3

	for _, kind := range slices.Sorted(maps.Keys(churnWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			w := churnWrites[kind]
			if !w.applies(churnShapes[shape]) {
				continue
			}

			t.Run(kind+"/"+shape, func(t *testing.T) {
				s, streams := scalingTailnet(t, n, shape)
				cr := newChurnRun(t, s, streams, shape)

				for i := range writes {
					w.write(cr, t, i)
					cr.deliver(t)

					// Against a render of its own first: the session's next
					// update reads the caches routing left it, and would
					// share a mistake of theirs.
					fresh := s.Snapshot().Uncached()

					for _, st := range cr.streams {
						stale, err := freshDiff(st.cfg, fresh, st.nodeID, capVer, st.sent, &versionCache{})
						require.NoError(t, err)
						require.Empty(t, stale, "write %d left node %d holding a stale map: %s", i, st.nodeID, describeResponses(stale))

						out, err := st.Update(s.Snapshot())
						require.NoError(t, err)
						require.Empty(t, out, "write %d left node %d something to send", i, st.nodeID)
						st.Delivered()
					}

					if w.restore != nil {
						w.restore(cr, t, i)
					}
				}
			})
		}
	}
}

// sizedEncoder encodes as benchEncode does, recording for each response
// the JSON bytes it took and how many of them are packet filters. It
// measures the encoder's output around PacketFilters as they are written,
// rather than encoding them twice.
type sizedEncoder struct {
	opts   jsonv2.Options
	filter int
	sizes  map[*tailcfg.MapResponse]responseSize
	fn     func(*tailcfg.MapResponse, bool) ([]byte, error)
}

type responseSize struct{ json, filter int }

// wireFilters encodes as PacketFilters does but is another type, so the
// sized encoder's marshaler for that field does not call itself.
type wireFilters map[string][]tailcfg.FilterRule

var errLegacyPacketFilter = errors.New("the sized encoder measures PacketFilters, not PacketFilter")

func newSizedEncoder() *sizedEncoder {
	e := &sizedEncoder{sizes: make(map[*tailcfg.MapResponse]responseSize)}
	e.opts = jsonv2.JoinOptions(jsonv1.DefaultOptionsV1(), jsonv2.WithMarshalers(jsonv2.JoinMarshalers(
		jsonv2.MarshalToFunc(marshalNode),
		jsonv2.MarshalToFunc(e.marshalFilters),
	)))
	e.fn = e.encode

	return e
}

func (e *sizedEncoder) marshalFilters(enc *jsontext.Encoder, filters map[string][]tailcfg.FilterRule) error {
	start := enc.OutputOffset()
	err := jsonv2.MarshalEncode(enc, wireFilters(filters))
	// The encoder writes the ':' after the field name with the value.
	e.filter += int(enc.OutputOffset()-start) - 1

	return err
}

func (e *sizedEncoder) encode(resp *tailcfg.MapResponse, compress bool) ([]byte, error) {
	if resp.PacketFilter != nil {
		return nil, errLegacyPacketFilter
	}

	e.filter = 0

	b, err := jsonv2.Marshal(resp, e.opts)
	if err != nil {
		return nil, err
	}

	e.sizes[resp] = responseSize{json: len(b), filter: e.filter}

	if !compress {
		return b, nil
	}

	return zstdframe.AppendEncode(nil, b, zstdframe.FastestCompression), nil
}

// TestSizedEncoderMatchesMarshal checks the sized encoder writes what the
// poll loop does, and that the filter bytes it counts are the encoding of
// PacketFilters, on the maps of a churning tailnet.
func TestSizedEncoderMatchesMarshal(t *testing.T) {
	// Pinned to address form: it needs writes that send filters, which capability form spares the receivers it reaches; and to the whole filter, which it reads as "base".
	t.Setenv(state.TestCapabilitySourcesEnv, "false")
	t.Setenv(state.TestFilterChunksEnv, "false")

	s, streams := scalingTailnet(t, 40, "selectors")
	e := newSizedEncoder()

	check := func(resps []*tailcfg.MapResponse) {
		t.Helper()

		for _, resp := range resps {
			want, err := Marshal(resp)
			require.NoError(t, err)

			got, err := e.fn(resp, false)
			require.NoError(t, err)
			require.Equal(t, string(want), string(got))

			filters, err := jsonv1.Marshal(resp.PacketFilters)
			require.NoError(t, err)

			wantFilter := 0
			if resp.PacketFilters != nil {
				wantFilter = len(filters)
			}

			assert.Equal(t, responseSize{json: len(want), filter: wantFilter}, e.sizes[resp])
		}
	}

	first, err := NewStream(streams[0].cfg, NewHub(), streams[0].nodeID, capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, first[0].PacketFilters["base"], "the first map carries a filter")
	check(first)

	cr := newChurnRun(t, s, streams, "selectors")
	cr.encode = func(resp *tailcfg.MapResponse, compress bool) ([]byte, error) {
		check([]*tailcfg.MapResponse{resp})

		return cr.sized.fn(resp, compress)
	}

	for _, kind := range slices.Sorted(maps.Keys(churnWrites)) {
		w := churnWrites[kind]
		w.write(cr, t, 0)
		cr.deliver(t)

		if w.restore != nil {
			w.restore(cr, t, 0)
		}
	}

	require.Positive(t, cr.filterBytes, "the writes sent filters")
}

// benchSizes returns the tailnet sizes a benchmark runs: defaults, or the
// one HEADSCALE_SCALE_NODES names.
func benchSizes(tb testing.TB, defaults ...int) []int {
	tb.Helper()

	v, ok := os.LookupEnv("HEADSCALE_SCALE_NODES")
	if !ok {
		return defaults
	}

	n, err := strconv.Atoi(v)
	require.NoError(tb, err)

	return []int{n}
}
