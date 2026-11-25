package mapper

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state/statemodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/mem"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// The driver writes a model node through the State's production entry
// points wherever production can express the write: registration with a
// pre-auth key or through the auth path, a login, a restart re-registering
// with the node's key, the client's map requests, the admin's tag, route
// and expiry writes, deletion and the ephemeral collector. What production
// cannot write goes to the store: the database row and the world, as an
// edit of the database and a restart would leave them. That is addresses
// other than the allocator's, an endpoint cleared, a login of a user who
// cannot claim the node, and approvals no order of writes reaches: a batch
// of edits moved them, or a start's shapes moved the node after they were
// given.
//
// Production allocates IDs and addresses; the driver steers it to the
// model's. The model's IDs follow the column's autoincrement but for the
// nodes a delivery case joins for a moment, so the driver moves the
// counter only for those and for the joins after them. The allocator
// hands out addresses in sequence, which is the model's own address of
// each ID while registrations come in ID order; the driver predicts each
// one, holds registration to it, and stores the model's address where it
// differs.
//
// After every write, every node production holds equals the model's on
// what the model holds (owner, addresses, routes and their approvals,
// client, expiry, connection) and on how the driver registered it, and
// every database row equals its node in memory on the columns a write
// persists: the model's predictions of auto-approval, tag ownership and
// a login's renewal are judged against what production stored.

// nodeWrite counts the calls one node's write made: to production entry
// points, and to the store, with why.
type nodeWrite struct {
	prod   int
	stores []string
}

// storeColumns are the columns a store write may move.
var storeColumns = []string{"IPv4", "IPv6", "Endpoints", "UserID", "Tags", "Expiry", "ApprovedRoutes", "AutoApprovedRoutes"}

// homeDERPRegion is the one region of the driver's DERP map, which every
// client reports as its home and it holds of every node, whatever a
// later report leaves out.
const homeDERPRegion = tailcfg.DERPRegionID(999)

// begin starts counting one node's write of kind; the returned func
// tallies it.
func (p *pbtWorld) begin(kind string) func() {
	cur := &nodeWrite{}
	p.cur = cur

	return func() {
		p.cur = nil
		p.tally(kind, cur)
	}
}

// tally counts one node write of kind by the path it took.
func (p *pbtWorld) tally(kind string, w *nodeWrite) {
	path := "production"

	if len(w.stores) > 0 {
		slices.Sort(w.stores)
		why := strings.Join(slices.Compact(w.stores), ", ")

		path = "store (" + why + ")"
		if w.prod > 0 {
			path = "production and store (" + why + ")"
		}
	}

	p.made[kind+": "+path]++
}

// kindOr is the kind of the edit being written, or def.
func (p *pbtWorld) kindOr(def string) string {
	if p.kind != "" {
		return p.kind
	}

	return def
}

// produce makes one production call of the write in progress, counted by
// part, the path it takes.
func (p *pbtWorld) produce(id types.NodeID, part string, write func() error) {
	p.t.Helper()

	p.made["call "+part]++

	p.call(func() {
		err := write()
		if err != nil {
			p.t.Fatalf("n%d: %s: %v", id, part, err)
		}
	})
}

// store writes what production cannot: set applied to id as production
// holds it, into its row and into the world.
func (p *pbtWorld) store(reason string, id types.NodeID, set func(*types.Node)) {
	p.t.Helper()

	nv, ok := p.s.Snapshot().GetNode(id)
	if !ok {
		p.t.Fatalf("n%d: store %s: no such node", id, reason)
	}

	n := nv.AsStruct()
	set(n)

	// The State's gate: an expired key is not online.
	n.IsOnline = new(n.ShouldBeOnline())

	row := *n
	row.User, row.AuthKey = nil, nil

	err := p.s.DB().DB.Select(storeColumns).Updates(&row).Error
	if err != nil {
		p.t.Fatalf("n%d: store %s: %v", id, reason, err)
	}

	if p.cur != nil {
		p.cur.stores = append(p.cur.stores, reason)
	}

	p.storing = true

	p.call(func() { p.s.PutNodeInStoreForTest(*n) })

	p.storing = false
}

// steerID has the next registration take id: the counter the column
// autoincrements from is moved when it would hand out another.
func (p *pbtWorld) steerID(id types.NodeID) {
	p.t.Helper()

	db := p.s.DB().DB

	var seq, top int64

	err := db.Raw("SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence WHERE name = 'nodes'").Scan(&seq).Error
	if err == nil {
		err = db.Raw("SELECT COALESCE(MAX(id), 0) FROM nodes").Scan(&top).Error
	}

	if err != nil {
		p.t.Fatalf("n%d: reading the node ID counter: %v", id, err)
	}

	want := int64(id) //nolint:gosec // small
	if max(seq, top)+1 == want {
		return
	}

	if top >= want {
		p.t.Fatalf("n%d: a node holds ID %d already", id, top)
	}

	res := db.Exec("UPDATE sqlite_sequence SET seq = ? WHERE name = 'nodes'", want-1)
	if res.Error == nil && res.RowsAffected == 0 {
		res = db.Exec("INSERT INTO sqlite_sequence (name, seq) VALUES ('nodes', ?)", want-1)
	}

	if res.Error != nil {
		p.t.Fatalf("n%d: moving the node ID counter: %v", id, res.Error)
	}

	p.made["node IDs steered"]++
}

// nextAddr is the address a sequential allocator hands out after prev:
// the next one Tailscale does not reserve, past the via range whole.
func nextAddr(prev netip.Addr) netip.Addr {
	a := prev.Next()
	for tsaddr.ChromeOSVMRange().Contains(a) || a == tsaddr.TailscaleServiceIP() || a == tsaddr.TailscaleServiceIPv6() {
		a = a.Next()
	}

	// The via range's addresses are routes, never node addresses, so the
	// allocator skips the whole /64 (db/ip.go).
	if r := tsaddr.TailscaleViaRange(); r.Contains(a) {
		a = netipx.RangeOfPrefix(r).To().Next()
	}

	return a
}

// newcomer is a node being registered: model node n built as tn, and its
// write's count.
type newcomer struct {
	n  policymodel.Node
	tn *types.Node
	w  *nodeWrite
}

// register writes new nodes as clients and an admin bring them in: each
// registers, then each has the admin approve what auto-approval does not,
// its client send its first map request, an admin expire it, its first map
// session open. All register first, so that where nodes share addresses
// what each announces is approved against all of them, as the model's
// start is.
func (p *pbtWorld) register(fresh []newcomer, w policymodel.World) {
	p.t.Helper()

	kind := p.kindOr("Join")

	for i := range fresh {
		fresh[i].w = &nodeWrite{}
		p.cur = fresh[i].w
		p.enrol(fresh[i], w)
	}

	for i := range fresh {
		p.cur = fresh[i].w
		p.settleIn(fresh[i], w)
		p.cur = nil
		p.tally(kind, fresh[i].w)
	}
}

// enrol registers nc as its client does, steered to the model's ID and
// holding the allocator to its sequence: without the routes it announces
// where its addresses or the admin's approvals must come first.
func (p *pbtWorld) enrol(nc newcomer, w policymodel.World) {
	p.t.Helper()

	n, tn, id := nc.n, nc.tn, nc.n.ID
	users := w.Topology.Users

	p.steerID(id)

	full := tn.Hostinfo.Clone()
	// Every client reports its home DERP with its hostinfo; later reports
	// may leave it out (see [pbtWorld.report]), and the stored hostinfo
	// must keep it.
	if full.NetInfo == nil {
		full.NetInfo = &tailcfg.NetInfo{PreferredDERP: homeDERPRegion}
	}

	bare := full.Clone()
	bare.RoutableIPs = nil

	// Auto-approvers are matched by address: what the node announces waits
	// for the model's addresses where registration hands out others.
	v4, v6 := nextAddr(p.alloc[0]), nextAddr(p.alloc[1])
	moved := n.V4 != v4 || n.V6 != v6
	alone := !moved && len(admitted(tn)) == 0

	oidc := false

	if u := slices.IndexFunc(users, func(u policymodel.User) bool { return u.ID == n.User }); u >= 0 {
		oidc = users[u].OIDC()
	}

	// An admin tags only with tags the policy defines.
	defined := !slices.ContainsFunc(n.Tags, func(t int) bool { return !w.Policy.DefinesTag(t) })

	var (
		ri  statemodel.Joined
		got types.NodeView
	)

	switch {
	case n.Tagged() && len(users) > 0 && defined && id%2 == 0:
		// An admin tags a node a user brought in.
		ri.Method = util.RegisterMethodCLI
		got = p.login(id, tn.MachineKey, tn.NodeKey, tn.Hostname, users[0].ID, ri.Method)
		p.produce(id, "tags", func() error {
			_, err := p.s.SetNodeTags(id, tn.Tags)
			return err
		})
	case n.Tagged() || !oidc && id%2 == 1:
		ri.Method, ri.Ephemeral = util.RegisterMethodAuthKey, id%3 == 0

		var uid *types.UserID

		switch {
		case !n.Tagged():
			u := types.UserID(n.User)
			uid, ri.KeyUser = &u, n.User
		case len(users) > 0 && id%4 == 3:
			// A tagged key a user made: the node is the tags', and that
			// user's login takes it back.
			u := types.UserID(users[0].ID)
			uid, ri.KeyUser = &u, users[0].ID
		}

		pak, err := p.s.CreatePreAuthKey(uid, false, ri.Ephemeral, nil, tn.Tags)
		if err != nil {
			p.t.Fatalf("n%d: pre-auth key: %v", id, err)
		}

		ri.Key, ri.Tagged = pak.Key, n.Tagged()

		hi := bare
		if alone {
			hi = full
		}

		p.produce(id, "register", func() error {
			var err error

			got, err = p.s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				NodeKey: tn.NodeKey, Hostinfo: hi, Auth: &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			}, tn.MachineKey)

			return err
		})
	default:
		ri.Method = util.RegisterMethodCLI
		if oidc {
			ri.Method = util.RegisterMethodOIDC
		}

		got = p.login(id, tn.MachineKey, tn.NodeKey, tn.Hostname, n.User, ri.Method)
	}

	if got.ID() != id {
		p.t.Fatalf("registration took n%d for the model's n%d", got.ID(), id)
	}

	p.reg[id] = ri
	// The keys its entry must carry on the wire ([policymodel.WireKeys]),
	// and the home DERP its client reported with its hostinfo.
	p.regkeys[id] = regKeys{node: tn.NodeKey, disco: tn.DiscoKey}
	p.derp[id] = homeDERPRegion

	// The allocator's sequence, judged.
	if got.IPv4().Get() != v4 || got.IPv6().Get() != v6 {
		p.t.Fatalf("n%d registered at %v %v, the allocator's next addresses are %s %s", id, got.IPv4(), got.IPv6(), v4, v6)
	}

	p.alloc = [2]netip.Addr{v4, v6}

	if moved {
		p.store("address", id, func(c *types.Node) { c.IPv4, c.IPv6 = tn.IPv4, tn.IPv6 })
	}
}

// admitted is what of tn's approvals an admin made: what auto-approval
// did not.
func admitted(tn *types.Node) []netip.Prefix {
	return slices.DeleteFunc(slices.Clone(tn.ApprovedRoutes), func(r netip.Prefix) bool { return slices.Contains(tn.AutoApprovedRoutes, r) })
}

// expireSweep marks offline what expired since the last sweep, as the
// server's task loop runs it after an expiry.
func (p *pbtWorld) expireSweep() {
	p.call(func() { p.lastExpiryCheck, _ = p.s.ExpireExpiredNodes(p.lastExpiryCheck) })
}

// settleIn finishes nc's registration into w: the admin approves the rest
// before the client announces, so that what auto-approval then adds is
// what the model counts as its own; the client's first map request; an
// admin's expiry; the first map session.
func (p *pbtWorld) settleIn(nc newcomer, w policymodel.World) {
	p.t.Helper()

	n, tn, id := nc.n, nc.tn, nc.n.ID

	if admin := admitted(tn); len(admin) > 0 {
		p.produce(id, "approve", func() error {
			_, err := p.s.SetApprovedRoutes(id, admin)
			return err
		})
	}

	p.produce(id, "map request", func() error {
		return p.s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{NodeKey: tn.NodeKey, DiscoKey: tn.DiscoKey, Hostinfo: tn.Hostinfo.Clone()})
	})

	// A start's shapes can move a node's owner or addresses after its
	// routes were auto-approved, which leaves approvals w's auto-approvers
	// no longer give; only a write before the move reaches them.
	v := policymodel.NewView(w)
	approvable := slices.DeleteFunc(slices.Clone(n.Announced), func(r int) bool { return !v.Approvable(n, r) })

	if !slices.Equal(approvable, n.AutoApproved) {
		p.store("approvals from before a move", id, func(c *types.Node) {
			c.ApprovedRoutes, c.AutoApprovedRoutes = tn.ApprovedRoutes, tn.AutoApprovedRoutes
		})
	}

	if n.Expired {
		p.produce(id, "expiry", func() error {
			_, err := p.s.SetNodeExpiry(id, &expiredAt)
			return err
		})
		p.expireSweep()
	}

	p.online(n)
}

// login has a node log in as user uid through the auth path, as a CLI or
// OIDC registration does: a new node, or the machine's tagged node taken
// back.
func (p *pbtWorld) login(id types.NodeID, machine key.MachinePublic, node key.NodePublic, hostname string, uid uint, method string) types.NodeView {
	p.t.Helper()

	return p.loginWith(id, machine, node, &tailcfg.Hostinfo{Hostname: hostname}, uid, method)
}

// loginWith is login with the client reporting hi.
func (p *pbtWorld) loginWith(id types.NodeID, machine key.MachinePublic, node key.NodePublic, hi *tailcfg.Hostinfo, uid uint, method string) types.NodeView {
	p.t.Helper()

	// The hostinfo a client registers with carries its home DERP.
	if hi.NetInfo == nil {
		hi = hi.Clone()
		hi.NetInfo = &tailcfg.NetInfo{PreferredDERP: homeDERPRegion}
	}

	authID := types.MustAuthID()

	err := p.s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machine, NodeKey: node, Hostname: hi.Hostname, Hostinfo: hi,
	}))
	if err != nil {
		p.t.Fatalf("n%d: pending login: %v", id, err)
	}

	var got types.NodeView

	p.produce(id, "login", func() error {
		var err error

		got, err = p.s.HandleNodeFromAuthPath(authID, types.UserID(uid), nil, method)

		return err
	})

	return got
}

// change writes node n's move from was, built as tn, a part at a time in
// the order the model's edits take: owner, addresses, what its client
// reports and the admin's approvals, expiry, connection. cur is the world
// as written so far; the approvals go where the model, played against
// it, says production's auto-approval then lands on n's, and to the store
// where no order does.
func (p *pbtWorld) change(cur policymodel.World, was, n policymodel.Node, tn *types.Node) {
	p.t.Helper()
	defer p.begin(p.kindOr("batch"))()

	id := n.ID
	owner := !slices.Equal(was.Tags, n.Tags) || !n.Tagged() && was.User != n.User

	var lead []policymodel.Edit
	if owner {
		lead = append(lead, policymodel.Retag{ID: id, Tags: n.Tags, User: n.User})
	}

	for _, f := range []int{4, 6} {
		if was.Addr(f) != n.Addr(f) {
			lead = append(lead, policymodel.SetAddr{ID: id, Family: f, Addr: n.Addr(f)})
		}
	}

	var reports []policymodel.Edit
	if add := policymodel.Without(n.Announced, was.Announced); len(add) > 0 {
		reports = append(reports, policymodel.Announce{ID: id, Routes: add})
	}

	if drop := policymodel.Without(was.Announced, n.Announced); len(drop) > 0 {
		reports = append(reports, policymodel.Withdraw{ID: id, Routes: drop})
	}

	if was.Client != n.Client {
		reports = append(reports, policymodel.SetClient{ID: id, Client: n.Client})
	}

	start := cur.Apply(lead...)
	approve := func(w policymodel.World, routes []int) policymodel.World {
		held, _ := w.Topology.Node(id)
		return w.Apply(policymodel.Unapprove{ID: id, Routes: held.Approved}, policymodel.Approve{ID: id, Routes: routes})
	}

	// The admin's approvals: none (0), after the report, before it;
	// failing all three, the store.
	const (
		approveAfter = iota + 1
		approveBefore
		approveNone
	)

	before := policymodel.Without(n.Approved, n.AutoApproved)
	plan := approveNone

	for pl := range approveNone {
		w := start
		if pl == approveBefore {
			w = approve(w, before)
		}

		w = w.Apply(reports...)
		if pl == approveAfter {
			w = approve(w, n.Approved)
		}

		if got, _ := w.Topology.Node(id); sameRoutes(got, n) {
			plan = pl

			break
		}
	}

	switch {
	case owner && n.Tagged() && definesAll(cur.Policy, n.Tags):
		p.produce(id, "tags", func() error {
			_, err := p.s.SetNodeTags(id, tn.Tags)
			return err
		})
	case owner && n.Tagged():
		p.storeTags(id, tn.Tags, tn)
	case owner:
		p.untag(was, n, tn, cur.Topology.Users)
	}

	if was.V4 != n.V4 || was.V6 != n.V6 {
		p.store("address", id, func(c *types.Node) { c.IPv4, c.IPv6 = tn.IPv4, tn.IPv6 })
	}

	setApproved := func(routes []int) {
		p.produce(id, "approve", func() error {
			_, err := p.s.SetApprovedRoutes(id, prefixes(routes))
			return err
		})
	}

	if plan == approveBefore {
		setApproved(before)
	}

	if len(reports) > 0 {
		p.report(n, tn)
	}

	switch plan {
	case approveAfter:
		setApproved(n.Approved)
	case approveNone:
		p.store("approvals no order reaches", id, func(c *types.Node) {
			c.ApprovedRoutes, c.AutoApprovedRoutes = tn.ApprovedRoutes, tn.AutoApprovedRoutes
		})
	}

	// A login renews the key.
	if expired := was.Expired && (!owner || n.Tagged()); expired != n.Expired {
		var at *time.Time
		if n.Expired {
			at = &expiredAt
		}

		p.produce(id, "expiry", func() error {
			_, err := p.s.SetNodeExpiry(id, at)
			return err
		})
		p.expireSweep()
	}

	p.online(n)
}

// definesAll reports whether pol defines every one of tags: an admin
// tags a node with no other.
func definesAll(pol policymodel.Policy, tags []int) bool {
	return !slices.ContainsFunc(tags, func(t int) bool { return !pol.DefinesTag(t) })
}

// storeTags gives node id tags the document in force does not define, as
// it came to hold them before a policy write dropped them, with the
// approvals the model's tag write auto-approved, which the store stands
// in for as it does for the tags.
func (p *pbtWorld) storeTags(id types.NodeID, tags []string, tn *types.Node) {
	p.t.Helper()

	p.store("tags the document does not define", id, func(c *types.Node) {
		c.Tags, c.UserID, c.User = tags, nil, nil
		c.ApprovedRoutes, c.AutoApprovedRoutes = tn.ApprovedRoutes, tn.AutoApprovedRoutes
	})
}

// sameRoutes reports whether a and b agree on all but expiry and
// connection.
func sameRoutes(a, b policymodel.Node) bool {
	a.Expired, a.Offline, b.Expired, b.Offline = false, false, false, false

	return reflect.DeepEqual(a, b)
}

// prefixes is rs as prefixes, sorted.
func prefixes(rs []int) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(rs))
	for _, r := range rs {
		out = append(out, policymodel.Prefixes[r])
	}

	return slices.SortedFunc(slices.Values(out), netip.Prefix.Compare)
}

// untag makes tagged node was user n.User's: a login of that user, when it
// claims the node (it registered through a login, or with that user's
// key); else, as headscale would add a device beside it, the store.
func (p *pbtWorld) untag(was, n policymodel.Node, tn *types.Node, users []policymodel.User) {
	p.t.Helper()

	id := n.ID
	ri := p.reg[id]

	if was.Tagged() && (ri.Method != util.RegisterMethodAuthKey || ri.KeyUser == n.User) {
		nv, _ := p.s.Snapshot().GetNode(id)

		method := util.RegisterMethodCLI
		if u := slices.IndexFunc(users, func(u policymodel.User) bool { return u.ID == n.User }); u >= 0 && users[u].OIDC() {
			method = util.RegisterMethodOIDC
		}

		// With a new node key and what the client reports, as `tailscale
		// up --force-reauth` does: the registration then runs
		// auto-approval for the new owner, as the model's login does.
		hi := nv.Hostinfo().AsStruct()
		if hi == nil {
			hi = &tailcfg.Hostinfo{}
		}

		hi.Hostname = nv.Hostname()
		k := reauthKey(nv.NodeKey())
		p.loginWith(id, nv.MachineKey(), k, hi, n.User, method)
		p.regkeys[id] = regKeys{node: k, disco: nv.DiscoKey()}
		p.reg[id] = statemodel.Joined{Method: method}

		return
	}

	// A store stand-in for a login production refuses: the whole of what
	// the model's login made of the node, the auto-approval it ran
	// included.
	p.store("login it cannot claim", id, func(c *types.Node) {
		c.Tags, c.UserID, c.User, c.Expiry = nil, tn.UserID, tn.User, nil
		c.ApprovedRoutes, c.AutoApprovedRoutes = tn.ApprovedRoutes, tn.AutoApprovedRoutes
	})

	ri.Key = ""
	p.reg[id] = ri
}

// reauthKey is the node key a client takes for a new login after k,
// derived from k so a case replays.
func reauthKey(k key.NodePublic) key.NodePublic {
	raw := k.AppendTo(nil)
	raw[1]++

	return key.NodePublicFromRaw32(mem.B(raw))
}

// registrationKeys is the tunnel keys n's client registered with, for
// [policymodel.WireKeys].
func (p *pbtWorld) registrationKeys(n types.NodeID) (key.NodePublic, key.DiscoPublic) {
	k := p.regkeys[n]
	return k.node, k.disco
}

// report has n's client report what tn announces and runs: a restart
// re-registering with its key now and then, when it has one that finds
// the node, else a map request.
func (p *pbtWorld) report(n policymodel.Node, tn *types.Node) {
	p.t.Helper()

	id := n.ID
	nv, _ := p.s.Snapshot().GetNode(id)
	cur := nv.AsStruct()

	hi := cur.Hostinfo.Clone()
	if hi == nil {
		hi = &tailcfg.Hostinfo{}
	}

	want := tn.Hostinfo
	hi.RoutableIPs = slices.Clone(want.RoutableIPs)
	hi.GoVersion, hi.IPNVersion, hi.App, hi.AppConnector = want.GoVersion, want.IPNVersion, want.App, want.AppConnector

	p.reports++

	ri := p.reg[id]
	finds := ri.KeyUser == 0 || cur.IsTagged() || cur.UserID != nil && *cur.UserID == ri.KeyUser

	if ri.Key != "" && finds && !cur.IsExpired() && p.reports%2 == 0 {
		p.produce(id, "restart", func() error {
			_, err := p.s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				NodeKey: cur.NodeKey, Hostinfo: hi, Auth: &tailcfg.RegisterResponseAuth{AuthKey: ri.Key},
			}, cur.MachineKey)

			return err
		})
	} else {
		// Every third report leaves NetInfo out, as a client does whose
		// home DERP did not change: the stored hostinfo keeps it.
		if hi.NetInfo != nil && p.reports%3 == 0 {
			hi.NetInfo = nil
			p.made["map request without NetInfo"]++
		}

		p.produce(id, "map request", func() error {
			return p.s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{NodeKey: cur.NodeKey, DiscoKey: cur.DiscoKey, Endpoints: cur.Endpoints, Hostinfo: hi})
		})
	}

	// The request outlives the call as the client's own struct, which it
	// may reuse: what the State stored must share no memory with it.
	if len(hi.RoutableIPs) > 0 {
		hi.RoutableIPs[0] = netip.MustParsePrefix("203.0.113.0/25")
	}

	if hi.NetInfo != nil {
		hi.NetInfo.PreferredDERP++
	}
}

// online opens or closes n's connections as the model says: a node
// connects through [state.State.Connect] after any other write, as its
// first map session follows registration.
func (p *pbtWorld) online(n policymodel.Node) {
	switch {
	case !n.Offline && len(p.conns[n.ID]) == 0:
		p.connect(n.ID)
	case n.Offline:
		for len(p.conns[n.ID]) > 0 {
			p.disconnect(n.ID)
		}
	}
}

// leave deletes n: an ephemeral node with no session as the collector
// does, one in session as its client's logout does, any other as an admin
// does.
func (p *pbtWorld) leave(n policymodel.Node) {
	p.t.Helper()
	defer p.begin(p.kindOr("Leave"))()

	id := n.ID

	nv, ok := p.s.Snapshot().GetNode(id)
	if !ok {
		p.t.Fatalf("n%d leaves, and the State has no such node", id)
	}

	switch ri := p.reg[id]; {
	case ri.Ephemeral && len(p.conns[id]) == 0:
		p.produce(id, "ephemeral collector", func() error {
			deleted, err := p.s.DeleteEphemeralNode(id)
			if err == nil && !deleted {
				err = fmt.Errorf("an idle ephemeral node %w", errNotDeleted)
			}

			return err
		})
	case ri.Ephemeral && !nv.IsExpired():
		p.produce(id, "logout", func() error {
			now := time.Now()

			left, err := p.s.LogoutNode(nv, &now)
			if err == nil && left.Valid() {
				err = fmt.Errorf("an ephemeral node logging out %w", errNotDeleted)
			}

			return err
		})
	default:
		p.produce(id, "delete", func() error { return p.s.DeleteNode(nv) })
	}

	delete(p.conns, id)
	delete(p.reg, id)
	delete(p.derp, id)
}

var errNotDeleted = errors.New("was not deleted")

// endpoint sets id's endpoints as its client reports them, in a map
// request of nothing else; a clear goes to the store, since a map request
// cannot clear them.
func (p *pbtWorld) endpoint(id types.NodeID, eps []netip.AddrPort) {
	p.t.Helper()
	defer p.begin("Endpoint")()

	nv, ok := p.s.Snapshot().GetNode(id)
	if !ok {
		return
	}

	if len(eps) == 0 {
		p.store("clear", id, func(c *types.Node) { c.Endpoints = nil })

		return
	}

	p.produce(id, "map request", func() error {
		return p.s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{NodeKey: nv.NodeKey(), DiscoKey: nv.DiscoKey(), Endpoints: eps})
	})
}

// requireStored holds what production stored to the model after a write
// ([statemodel.Stored]), and that every node's stored hostinfo keeps the
// home DERP its client reported: a report without NetInfo carries it, and
// nothing the client keeps shares memory with what was stored.
func (p *pbtWorld) requireStored(after string) {
	p.t.Helper()

	if !p.unstored {
		if d := statemodel.Stored(p); d != "" {
			p.t.Fatalf("after %s: %s", after, d)
		}

		for _, nv := range p.s.Snapshot().ListNodes().All() {
			hi := nv.Hostinfo()
			if !hi.Valid() || !hi.NetInfo().Valid() || hi.NetInfo().PreferredDERP() != p.derp[nv.ID()] {
				p.t.Fatalf("after %s: n%d's stored hostinfo does not hold its home DERP %d", after, nv.ID(), p.derp[nv.ID()])
			}
		}
	}
}

// storeKinds are the node writes the share leaves out: addresses, which no
// production path moves once registration handed them out, and endpoints,
// no part of a node's lifecycle.
var storeKinds = []string{"SetAddr", "Endpoint"}

// entryCalls are the production calls a deep run must make each of.
var entryCalls = []string{
	"register", "login", "restart", "tags", "approve", "map request", "expiry", "delete", "logout", "ephemeral collector",
}

// untaggingLogin names, among the paths requireCarried asks for, a login
// that takes a tagged node back.
const untaggingLogin = "untagging login"

// requireCarried fails a deep run in which some production call, or an
// untagging login, went unmade, but those in rare, or fewer than nine in
// ten node writes reached a production entry point.
func requireCarried(t *testing.T, made map[string]int, rare ...string) {
	t.Helper()

	for _, c := range entryCalls {
		if made["call "+c] == 0 && !slices.Contains(rare, c) {
			t.Errorf("no write went through the %s path", c)
		}
	}

	if made["Login: production"] == 0 && !slices.Contains(rare, untaggingLogin) {
		t.Errorf("no login that untags a node went through production")
	}

	if prod, all := carried(made); prod*10 < all*9 {
		t.Errorf("%d of %d node writes reached a production entry point", prod, all)
	}
}

// carried counts, of the node writes made tallies, those of a kind
// production can write, and of them those that reached a production
// entry point, whatever went to the store beside.
func carried(made map[string]int) (int, int) {
	prod, all := 0, 0

	for k, n := range made {
		kind, path, ok := strings.Cut(k, ": ")
		if !ok || slices.Contains(storeKinds, kind) {
			continue
		}

		all += n

		if strings.HasPrefix(path, "production") {
			prod += n
		}
	}

	return prod, all
}
