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
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
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
	case "routers":
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
func subnetRouters(tb testing.TB, s *state.State) {
	tb.Helper()

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
	// policy and edited; moved are editedUser's nodes.
	policies [2][]byte
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
		require.Equal(tb, scalingPolicies[shape], string(cr.policies[0]), "setup leaves the unedited policy")
		require.NotEmpty(tb, cr.moved, "the group write moves nodes")
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
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
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

	return true
}

// benchChurn runs a churn kind of [BenchmarkScalingWrites]. A write's
// restore runs with the timer stopped.
func benchChurn(b *testing.B, kind, shape string, n int) {
	b.Helper()

	s, streams := scalingTailnet(b, n, shape)
	cr := newChurnRun(b, s, streams, shape)
	w := churnWrites[kind]

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
	const n, writes = 100, 4

	// Sessions woken, sessions sent an update, peers rendered, and
	// sessions other than the subjects' sent a packet filter, over the
	// writes. A joiner has no session, and a leaver's ends with it.
	//
	// A rule naming the subject's identity as a source lists its
	// addresses, so every session receiving that rule is sent a new
	// filter: all of them under mesh, group-all and routers, where the
	// rule reaches every member or every node, and none under allow-all,
	// whose source is "*". A group-all rule has a "*" destination, so its
	// recompile wakes every session (Change.Global). The routers shape's
	// routers re-render every routed peer after each recompile.
	ceilings := map[string][4]int{
		"group/group-all": {400, 400, 1600, 360},
		"group/routers":   {272, 112, 3840, 80},
		"group/selectors": {400, 280, 0, 248},
		"join/allow-all":  {400, 400, 400, 0},
		"join/group-all":  {400, 400, 400, 400},
		"join/mesh":       {400, 400, 400, 400},
		"join/routers":    {400, 400, 3600, 400},
		"join/selectors":  {308, 308, 308, 248},
		"join/self":       {40, 40, 40, 40},
		"join/tags":       {60, 40, 40, 20},
		"join/users":      {40, 40, 40, 40},
		"join/via":        {400, 400, 2380, 40},
		"leave/allow-all": {396, 396, 0, 0},
		"leave/group-all": {396, 396, 0, 396},
		"leave/mesh":      {396, 396, 0, 396},
		"leave/routers":   {396, 396, 3120, 396},
		"leave/selectors": {304, 304, 0, 244},
		"leave/self":      {36, 36, 0, 36},
		"leave/tags":      {56, 40, 0, 20},
		"leave/users":     {36, 36, 0, 36},
		"leave/via":       {396, 396, 1960, 40},
		"tag/group-all":   {400, 400, 196, 396},
		"tag/mesh":        {400, 400, 0, 396},
		"tag/routers":     {400, 400, 3120, 396},
		"tag/selectors":   {308, 308, 120, 244},
		"tag/tags":        {80, 80, 72, 40},
		"tag/via":         {400, 400, 2376, 40},
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

					for _, st := range cr.streams {
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
