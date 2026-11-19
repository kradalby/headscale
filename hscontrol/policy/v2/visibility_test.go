package v2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// sideModel is the role-based visibility of one compile, built from
// scratch: sides, classes keyed by side set, and the via plan.
type sideModel struct {
	pm    *PolicyManager
	users types.Users
	nodes *NodeMap
	list  types.Nodes

	t     *Templates
	roles Roles
	posts Postings
	appr  SubnetApprovals
	sides Sides
	peers *PeerClasses
	via   ViaPlans
}

func newSideModel(t *testing.T, pm *PolicyManager, users types.Users, nodes types.Nodes) *sideModel {
	t.Helper()

	requireSortedByID(t, nodes)

	m := &sideModel{pm: pm, users: users, nodes: nodeMapOf(nodes), list: nodes}

	sel := SelectorsFor(nil, pm)
	us := NewUserSets(nil, sel, users)
	m.roles = Roles{}.Update(us, m.nodes, nil)
	m.posts = Postings{}.Update(m.roles)
	m.appr = SubnetApprovals{}.Update(m.nodes)
	m.t = BuildTemplates(nil, sel)
	m.sides = UpdateSides(Sides{}, m.t, m.roles, m.posts, m.appr, m.nodes)
	m.peers = RolePeers(nil, m.sides)
	m.via = UpdateViaPlans(ViaPlans{}, m.sides)

	return m
}

func (m *sideModel) audit() (SidesReport, error) {
	return AuditSides(SidesAudit{
		Templates: m.t, Roles: m.roles, Postings: m.posts, Approvals: m.appr, Nodes: m.nodes,
		Sides: m.sides, Peers: m.peers, Via: m.via.Plan,
		List: m.list.ViewSlice(), Users: m.users, Policy: m.pm, Current: true,
	})
}

// sideNode is a node for side tests: an address per family as given, "" for
// none, routes approved and announced, only approved, or only announced.
func sideNode(id types.NodeID, user *types.User, v4, v6 string, tags []string, routes ...string) *types.Node {
	n := &types.Node{ID: id, Hostname: fmt.Sprintf("n%d", id), GivenName: fmt.Sprintf("n%d", id), Tags: tags, Hostinfo: &tailcfg.Hostinfo{}}
	if user != nil {
		n.User, n.UserID = user, &user.ID
	}

	if v4 != "" {
		n.IPv4 = new(netip.MustParseAddr(v4))
	}

	if v6 != "" {
		n.IPv6 = new(netip.MustParseAddr(v6))
	}

	for _, r := range routes {
		switch r[0] {
		case '+': // approved only
			n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix(r[1:]))
		case '~': // announced only
			n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, netip.MustParsePrefix(r[1:]))
		default:
			p := netip.MustParsePrefix(r)
			n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, p)
			n.ApprovedRoutes = append(n.ApprovedRoutes, p)
		}
	}

	return n
}

var sideUsers = types.Users{
	{ID: 1, Name: "alice"},
	{ID: 2, Name: "bob"},
	{ID: 3, Name: "carol", Email: "carol@example.com"},
}

func TestSidesSmoke(t *testing.T) {
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "fd7a:115c:a1e0::1", nil),
		sideNode(2, alice, "100.64.0.2", "", nil),
		sideNode(3, bob, "100.64.0.3", "fd7a:115c:a1e0::3", nil),
		sideNode(4, nil, "100.64.0.4", "fd7a:115c:a1e0::4", []string{"tag:a"}),
		sideNode(5, nil, "100.64.0.5", "fd7a:115c:a1e0::5", []string{"tag:b"}, "10.0.0.0/24", "100.64.0.0/30"),
		sideNode(6, nil, "100.64.0.6", "fd7a:115c:a1e0::6", []string{"tag:b"}, "0.0.0.0/0", "::/0"),
		sideNode(7, carol, "100.64.0.7", "fd7a:115c:a1e0::7", nil, "+10.1.0.0/24"),
		sideNode(8, carol, "", "", nil, "10.0.0.0/24"),
		sideNode(9, bob, "100.64.0.3", "", nil),
	}

	for i, pol := range sidePolicies {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(pol), sideUsers, nodes.ViewSlice())
			require.NoError(t, err)

			m := newSideModel(t, pm, sideUsers, nodes)
			rep, err := m.audit()
			require.NoError(t, err)
			t.Logf("%+v", rep)
		})
	}
}

var sidePolicies = []string{
	``,
	`{"acls": []}`,
	`{"tagOwners": {"tag:a": [], "tag:b": []},
	  "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`,
	`{"groups": {"group:a": ["alice@", "carol@example.com"]},
	  "tagOwners": {"tag:a": [], "tag:b": []},
	  "acls": [
		{"action": "accept", "src": ["group:a"], "dst": ["tag:a:22"]},
		{"action": "accept", "src": ["tag:b"], "dst": ["autogroup:member:80"]},
		{"action": "accept", "src": ["*"], "dst": ["10.0.0.0/8:*", "autogroup:internet:*"]}]}`,
	`{"tagOwners": {"tag:a": [], "tag:b": []},
	  "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
	           {"action": "accept", "src": ["alice@"], "dst": ["tag:a:*"]}]}`,
	`{"tagOwners": {"tag:a": [], "tag:b": []},
	  "grants": [
		{"src": ["alice@", "tag:a"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:b"]},
		{"src": ["alice@", "tag:a"], "dst": ["10.0.0.0/24", "autogroup:internet"], "ip": ["tcp:22"], "via": ["tag:b"]},
		{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"]},
		{"src": ["autogroup:member"], "dst": ["tag:b"], "ip": ["*"], "via": ["tag:b"], "app": {"example.com/cap/x": [{}]}}]}`,
	`{"groups": {"group:a": ["alice@", "carol@example.com"]},
	  "tagOwners": {"tag:a": [], "tag:b": []},
	  "grants": [
		{"src": ["group:a"], "dst": ["tag:a", "tag:b"], "app": {"tailscale.com/cap/drive": [{"shares": ["*"], "access": "rw"}]}},
		{"src": ["*"], "dst": ["*"], "app": {"tailscale.com/cap/relay": [{}]}},
		{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["tcp:22"], "app": {"tailscale.com/cap/drive": [{"shares": ["*"]}]}}]}`,
	`{"tagOwners": {"tag:a": [], "tag:b": []},
	  "acls": [
		{"action": "accept", "src": ["autogroup:danger-all"], "dst": ["tag:a:*"]},
		{"action": "accept", "src": ["tag:a", "10.0.0.0/8"], "dst": ["*:22"]}]}`,
}

// routeCase is one route access a quirk case pins: what viewer may use of
// routes through peer.
type routeCase struct {
	viewer, peer types.NodeID
	routes, want []string
}

// viaCase is one via steering a quirk case pins.
type viaCase struct {
	viewer, peer           types.NodeID
	include, exclude, prim []string
}

// TestSidesQuirks pins, case by case, what today's visibility, route access
// and via steering do in the shapes that are not pure identity, with the
// answers written out by hand; every case also passes the audit against the
// compile.
func TestSidesQuirks(t *testing.T) {
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	unloaded := func(n *types.Node, uid uint) *types.Node {
		n.User, n.UserID = nil, &uid

		return n
	}
	noUserID := func(n *types.Node) *types.Node {
		n.UserID = nil

		return n
	}
	keepsUser := func(n *types.Node, u *types.User) *types.Node {
		n.User, n.UserID = u, &u.ID

		return n
	}

	exit := []string{"0.0.0.0/0", "::/0"}

	tests := []struct {
		name   string
		policy string
		nodes  types.Nodes
		peers  map[types.NodeID][]types.NodeID
		routes []routeCase
		via    []viaCase
	}{
		{
			// The clique is by UserID: a node whose user is not loaded is in
			// it, one without a UserID is not, nor is a tagged node keeping
			// its creator.
			name:   "clique-by-user-id",
			policy: `{"acls": []}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				unloaded(sideNode(2, nil, "100.64.0.2", "", nil), 1),
				noUserID(sideNode(3, alice, "100.64.0.3", "", nil)),
				keepsUser(sideNode(4, nil, "100.64.0.4", "", []string{"tag:x"}), alice),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}, 3: nil, 4: nil},
		},
		{
			// A member without an address is on no side by membership; the
			// clique still holds it.
			name:   "addressless-member",
			policy: `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(2, alice, "", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2, 3}, 2: {1}, 3: {1}},
		},
		{
			// Holding a member's address puts a node on the member's side.
			name:   "shared-address",
			policy: `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(4, carol, "100.64.0.1", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{1: {3}, 3: {1, 4}, 4: {3}},
		},
		{
			// Routing over a member's address puts a router on the member's
			// side; the reverse route test then gives the destination the
			// route.
			name:   "router-covers-member",
			policy: `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "100.64.0.0/31"),
			},
			peers: map[types.NodeID][]types.NodeID{1: {3}, 3: {1, 5}, 5: {3}},
			routes: []routeCase{
				{viewer: 3, peer: 5, routes: []string{"100.64.0.0/31"}, want: []string{"100.64.0.0/31"}},
				{viewer: 1, peer: 5, routes: []string{"100.64.0.0/31"}},
			},
		},
		{
			// * as a source holds every approved subnet route, announced or
			// not: an address only an approval holds is a source.
			name:   "wildcard-source-holds-approvals",
			policy: `{"acls": [{"action": "accept", "src": ["*"], "dst": ["bob@:22"]}]}`,
			nodes: types.Nodes{
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(6, carol, "192.168.0.6", "", nil),
				sideNode(7, nil, "100.64.0.7", "", []string{"tag:r"}, "+192.168.0.0/24"),
				sideNode(8, alice, "192.168.1.8", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{3: {6, 7}, 6: {3}, 7: {3}, 8: nil},
		},
		{
			// * as a destination is every address: any addressed node, any
			// router, address or not, and so the exit nodes.
			name:   "wildcard-destination-is-everything",
			policy: `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["*:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(6, carol, "192.168.0.6", "", nil),
				sideNode(8, nil, "", "", []string{"tag:x"}, "10.0.0.0/24"),
				sideNode(9, nil, "100.64.0.9", "", []string{"tag:e"}, exit...),
			},
			peers: map[types.NodeID][]types.NodeID{1: {6, 8, 9}, 6: {1}, 8: {1}, 9: {1}},
		},
		{
			// A destination reaching the internet makes exit nodes its
			// destinations, and their exit routes the viewer's.
			name:   "internet-destination-reaches-exits",
			policy: `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["8.8.8.0/24:443"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(9, nil, "100.64.0.9", "", []string{"tag:e"}, exit...),
				sideNode(10, nil, "100.64.0.10", "", []string{"tag:x"}),
			},
			peers:  map[types.NodeID][]types.NodeID{1: {9}, 9: {1}, 10: nil},
			routes: []routeCase{{viewer: 1, peer: 9, routes: exit, want: exit}, {viewer: 10, peer: 9, routes: exit}},
		},
		{
			// An exit node lists the sources of a capability to the internet;
			// they do not list it.
			name:   "exit-lists-capability-sources",
			policy: `{"grants": [{"src": ["alice@"], "dst": ["8.8.8.0/24"], "app": {"example.com/cap/x": [{}]}}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(9, nil, "100.64.0.9", "", []string{"tag:e"}, exit...),
			},
			peers: map[types.NodeID][]types.NodeID{1: nil, 9: {1}},
		},
		{
			// A via router of the grant, addressed, and its sources see each
			// other; a router of another tag or route, or without an address,
			// does not. Steering includes the route on the elected router,
			// the lowest ID, and excludes it on the others.
			name:   "via-router",
			policy: `{"tagOwners": {"tag:r": [], "tag:s": []}, "grants": [{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.0.0.0/24"),
				sideNode(6, nil, "100.64.0.6", "", []string{"tag:r"}, "10.1.0.0/24"),
				sideNode(7, nil, "", "", []string{"tag:r"}, "10.0.0.0/24"),
				sideNode(8, nil, "100.64.0.8", "", []string{"tag:s"}, "10.0.0.0/24"),
			},
			peers: map[types.NodeID][]types.NodeID{1: {5}, 5: {1}, 3: nil, 6: nil, 7: nil, 8: nil},
			via: []viaCase{
				{viewer: 1, peer: 5, include: []string{"10.0.0.0/24"}},
				{viewer: 1, peer: 7, exclude: []string{"10.0.0.0/24"}},
				{viewer: 1, peer: 8, exclude: []string{"10.0.0.0/24"}},
				{viewer: 3, peer: 5},
			},
		},
		{
			// A via router among its own grant's sources sees the nodes
			// holding its address.
			name:   "via-router-on-own-source",
			policy: `{"tagOwners": {"tag:r": []}, "grants": [{"src": ["tag:r"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.0.0.0/24"),
				sideNode(6, bob, "100.64.0.5", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{5: {6}, 6: {5}},
		},
		{
			// A self destination names an owner's nodes by address: another
			// user's node holding one is on its side, both ways.
			name:   "self-by-address",
			policy: `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(4, bob, "100.64.0.1", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2, 3, 4}, 2: {1, 4}, 3: {1, 4}, 4: {1, 2, 3}},
		},
		{
			// A self capability to the internet shows its sources to exit
			// nodes; without a companion there is no rule from the owner's
			// other nodes, so node 2 is not among them.
			name:   "self-capability-to-internet-without-companion",
			policy: `{"tagOwners": {"tag:e": []}, "grants": [{"src": ["bob@"], "dst": ["autogroup:self"], "app": {"example.com/cap/x": [{}]}}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "8.8.8.1", "", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
				sideNode(3, bob, "8.8.8.1", "", nil),
				sideNode(4, nil, "100.64.0.4", "", []string{"tag:e"}, exit...),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2, 3}, 2: {1, 3}, 3: {1, 2}, 4: {1, 3}},
		},
		{
			// With a companion, the owner's nodes are the companion rule's
			// sources and the named public address its destination: exits
			// list them all.
			name:   "self-capability-to-internet-with-companion",
			policy: `{"tagOwners": {"tag:e": []}, "grants": [{"src": ["bob@"], "dst": ["autogroup:self"], "app": {"tailscale.com/cap/relay": [{}]}}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "8.8.8.1", "", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
				sideNode(3, bob, "8.8.8.1", "", nil),
				sideNode(4, nil, "100.64.0.4", "", []string{"tag:e"}, exit...),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2, 3}, 2: {1, 3}, 3: {1, 2}, 4: {1, 2, 3}},
		},
		{
			// A companion-bearing grant that names none of alice's nodes does
			// not lend its companion to the one that names the public owner.
			name: "self-companion-from-another-grant",
			policy: `{"tagOwners": {"tag:e": []}, "grants": [
				{"src": ["bob@"], "dst": ["autogroup:self"], "app": {"example.com/cap/x": [{}]}},
				{"src": ["carol@example.com"], "dst": ["autogroup:self"], "app": {"tailscale.com/cap/relay": [{}]}}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "8.8.8.1", "", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
				sideNode(3, bob, "8.8.8.1", "", nil),
				sideNode(4, nil, "100.64.0.4", "", []string{"tag:e"}, exit...),
				sideNode(5, carol, "100.64.0.5", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{2: {1, 3}, 4: {1, 3}},
		},
		{
			// An owner's port self rules reaching the internet link exit
			// owners with the named side; an owner that is not an exit node
			// gains nothing from it.
			name:   "self-exit-link-needs-an-exit-owner",
			policy: `{"acls": [{"action": "accept", "src": ["bob@"], "dst": ["autogroup:self:22"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "8.8.8.1", "", nil),
				sideNode(2, alice, "", "", nil),
				sideNode(3, bob, "8.8.8.1", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2, 3}, 2: {1}, 3: {1}},
		},
		{
			// An owner node without an address that routes over another owner
			// node holds its user's owner side, so it sees the named side.
			name:   "addressless-owner-routes-over-an-owner",
			policy: `{"acls": [{"action": "accept", "src": ["bob@"], "dst": ["autogroup:self:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "", "", nil, "100.64.0.0/31"),
				sideNode(2, alice, "100.64.0.1", "", nil),
				sideNode(3, alice, "100.64.0.5", "", nil),
				sideNode(4, bob, "100.64.0.5", "", nil),
			},
			peers: map[types.NodeID][]types.NodeID{1: {2, 3, 4}, 4: {1, 2, 3}},
		},
		{
			// Steering tests a "*" source against what it resolves to, not
			// the approved routes the filter's "*" adds: a viewer whose only
			// address an approval covers takes no regular grant's primary.
			name: "steering-wildcard-source-by-resolution",
			policy: `{"tagOwners": {"tag:r": [], "tag:x": []}, "grants": [
				{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]},
				{"src": ["*"], "dst": ["10.0.0.0/24"], "ip": ["*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "10.9.0.1", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.0.0.0/24"),
				sideNode(6, nil, "100.64.0.6", "", []string{"tag:x"}, "+10.9.0.0/24"),
			},
			via: []viaCase{{viewer: 1, peer: 5, include: []string{"10.0.0.0/24"}}},
		},
		{
			// SSH rules make nobody a peer.
			name:   "ssh-makes-no-peers",
			policy: `{"tagOwners": {"tag:s": []}, "acls": [], "ssh": [{"action": "accept", "src": ["alice@"], "dst": ["tag:s"], "users": ["root"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, nil, "100.64.0.3", "", []string{"tag:s"}),
			},
			peers: map[types.NodeID][]types.NodeID{1: nil, 3: nil},
		},
		{
			// A subnet route on the reverse test: the viewer is a
			// destination and the route overlaps the sources. An exit route
			// needs a rule from the viewer to the internet.
			name: "route-access",
			policy: `{"tagOwners": {"tag:r": [], "tag:e": []}, "acls": [
				{"action": "accept", "src": ["10.0.0.0/24"], "dst": ["alice@:*"]},
				{"action": "accept", "src": ["bob@"], "dst": ["autogroup:internet:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.0.0.0/24"),
				sideNode(9, nil, "100.64.0.9", "", []string{"tag:e"}, exit...),
			},
			peers: map[types.NodeID][]types.NodeID{1: {5}, 5: {1}, 3: {9}, 9: {3}},
			routes: []routeCase{
				{viewer: 1, peer: 5, routes: []string{"10.0.0.0/24"}, want: []string{"10.0.0.0/24"}},
				{viewer: 3, peer: 9, routes: exit, want: exit},
				{viewer: 1, peer: 9, routes: exit},
				{viewer: 3, peer: 5, routes: []string{"10.0.0.0/24"}},
			},
		},
	}

	prefixes := func(ss []string) []netip.Prefix {
		if len(ss) == 0 {
			return nil
		}

		out := make([]netip.Prefix, 0, len(ss))
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}

		return out
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.policy), sideUsers, tt.nodes.ViewSlice())
			require.NoError(t, err)

			m := newSideModel(t, pm, sideUsers, tt.nodes)

			for id, want := range tt.peers {
				got := m.peers.Peers(id)
				if len(want) > 0 || len(got) > 0 {
					require.Equal(t, want, got, "peers of %d", id)
				}
			}

			for _, rc := range tt.routes {
				got := m.sides.RouteAccess(rc.viewer, prefixes(rc.routes))
				require.Equal(t, prefixes(rc.want), got, "routes %d may use through %d", rc.viewer, rc.peer)
			}

			for _, vc := range tt.via {
				viewer, _ := m.nodes.Get(vc.viewer)
				peer, _ := m.nodes.Get(vc.peer)
				got := m.via.Plan.Steer(m.sides, viewer.View(), peer.View(), m.via.Plan.StaticPrimary)
				require.Equal(t, prefixes(vc.include), got.Include, "via include %d from %d", vc.viewer, vc.peer)
				require.Equal(t, prefixes(vc.exclude), got.Exclude, "via exclude %d from %d", vc.viewer, vc.peer)
				require.Equal(t, prefixes(vc.prim), got.UsePrimary, "via primary %d from %d", vc.viewer, vc.peer)
			}

			_, err = m.audit()
			require.NoError(t, err)
		})
	}
}

// sideStep is one incremental update of a model: nodes replaced by next.
func (m *sideModel) step(t *testing.T, us *UserSets, next types.Nodes) {
	t.Helper()

	e := m.nodes.Edit()
	seen := map[types.NodeID]bool{}

	for _, n := range next {
		seen[n.ID] = true
		if old, ok := m.nodes.Get(n.ID); !ok || old != n {
			e.Set(n.ID, n)
		}
	}

	for id := range m.nodes.All() {
		if !seen[id] {
			e.Delete(id)
		}
	}

	m.nodes, m.list = e.Done(), next
	m.roles = m.roles.Update(us, m.nodes, nil)
	m.posts = m.posts.Update(m.roles)
	m.appr = m.appr.Update(m.nodes)
	m.sides = UpdateSides(m.sides, m.t, m.roles, m.posts, m.appr, m.nodes)
	m.peers = RolePeers(m.peers, m.sides)
	m.via = UpdateViaPlans(m.via, m.sides)

	var err error

	m.pm, err = NewPolicyManagerFrom(m.pm, m.pm.src, m.users, next.ViewSlice())
	require.NoError(t, err)
}

// TestRolePeersJoinCostFollowsChange pins that a join computes the
// joiner's side set and only the views of the classes its atoms are
// adjacent to, at any tailnet size: under pairs of literals a join touches
// one pair; under a mesh every class reads the one atom that moved, and
// shares its holders' slice instead of copying it.
func TestRolePeersJoinCostFollowsChange(t *testing.T) {
	for _, shape := range []string{"pairs", "tag-pairs", "self"} {
		for _, n := range []int{100, 400} {
			t.Run(fmt.Sprintf("%s/nodes=%d", shape, n), func(t *testing.T) {
				nodes, users, pol := diversePeerPolicy(n, shape)
				joiner := nodes[n-1]
				nodes = nodes[:n-1]

				pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
				require.NoError(t, err)

				m := newSideModel(t, pm, users, nodes)
				before := m.peers
				views, _ := before.ViewsComputed()

				m.step(t, NewUserSets(nil, m.t.sel, users), append(slices.Clone(nodes), joiner))

				_, total := m.sides.Computed()
				computed := m.sides.computed
				after, _ := m.peers.ViewsComputed()

				assert.Equal(t, 1, computed, "side sets computed by the join")
				assert.LessOrEqual(t, after-views, 2, "class views computed by the join")
				assert.Positive(t, total)

				kept := 0

				for _, node := range nodes {
					if sameSlice(before.View(node.ID), m.peers.View(node.ID)) {
						kept++
					}
				}

				assert.GreaterOrEqual(t, kept, len(nodes)-2, "views kept by identity")

				_, err = m.audit()
				require.NoError(t, err)
			})
		}
	}

	t.Run("mesh", func(t *testing.T) {
		users := types.Users{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}, {ID: 3, Name: "u3"}}

		nodes := make(types.Nodes, 0, 300)
		for i := range 300 {
			nodes = append(nodes, sideNode(types.NodeID(i+1), &users[i%3], netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}).String(), "", nil)) //nolint:gosec // bounded
		}

		pol := []byte(`{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`)

		pm, err := NewPolicyManager(pol, users, nodes[:299].ViewSlice())
		require.NoError(t, err)

		m := newSideModel(t, pm, users, nodes[:299])
		views, _ := m.peers.ViewsComputed()

		m.step(t, NewUserSets(nil, m.t.sel, users), nodes)

		after, _ := m.peers.ViewsComputed()
		assert.Equal(t, 1, m.sides.computed, "side sets computed by the join")
		assert.Equal(t, 3, after-views, "the three users' classes read the members, which moved")

		// Every class shares the members' list itself.
		first := m.peers.View(1)
		for _, node := range nodes {
			assert.True(t, sameSlice(first, m.peers.View(node.ID)), "node %d shares the view", node.ID)
		}

		_, err = m.audit()
		require.NoError(t, err)
	})
}

// TestKeyedClassesChanged holds Changed and Same of classes keyed by side
// set against a node-by-node comparison.
func TestKeyedClassesChanged(t *testing.T) {
	alice, bob := &sideUsers[0], &sideUsers[1]

	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil),
		sideNode(2, alice, "100.64.0.2", "", nil),
		sideNode(3, bob, "100.64.0.3", "", nil),
		sideNode(4, nil, "100.64.0.4", "", []string{"tag:a"}),
	}

	pol := []byte(`{"tagOwners": {"tag:a": []}, "acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:a:*"]}]}`)

	pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	old := m.peers

	require.True(t, old.Same(old))
	require.ElementsMatch(t, []types.NodeID{1, 2, 3, 4}, old.Changed(nil))

	// bob's node joins alice's user: it sees tag:a and alice's nodes, and
	// they see it.
	moved := sideNode(3, alice, "100.64.0.3", "", nil)
	m.step(t, NewUserSets(nil, m.t.sel, sideUsers), types.Nodes{nodes[0], nodes[1], moved, nodes[3]})

	require.False(t, m.peers.Same(old))
	require.ElementsMatch(t, []types.NodeID{1, 2, 3, 4}, m.peers.Changed(old))

	// A fifth, unrelated node: only it changes.
	extra := sideNode(5, nil, "100.64.0.5", "", []string{"tag:b"})
	prev := m.peers
	m.step(t, NewUserSets(nil, m.t.sel, sideUsers), types.Nodes{nodes[0], nodes[1], moved, nodes[3], extra})
	require.Equal(t, []types.NodeID{5}, m.peers.Changed(prev))
}

// TestElectViaIncremental holds the incremental election over via plans
// against one from scratch, across plan changes and touched routes.
func TestElectViaIncremental(t *testing.T) {
	route := netip.MustParsePrefix("10.0.0.0/24")
	other := netip.MustParsePrefix("10.0.1.0/24")

	router := func(id types.NodeID, routes ...string) *types.Node {
		return sideNode(id, nil, fmt.Sprintf("100.64.0.%d", id), "", []string{"tag:r"}, routes...)
	}

	pol := []byte(`{"tagOwners": {"tag:r": []}, "grants": [{"src": ["alice@"], "dst": ["10.0.0.0/16"], "ip": ["*"], "via": ["tag:r"]}]}`)
	alice := &sideUsers[0]

	steps := []types.Nodes{
		{sideNode(1, alice, "100.64.0.1", "", nil), router(5, route.String()), router(6, route.String())},
		{sideNode(1, alice, "100.64.0.1", "", nil), router(5, route.String()), router(6, route.String(), other.String())},
		{sideNode(1, alice, "100.64.0.1", "", nil), router(6, route.String(), other.String())},
		{sideNode(1, alice, "100.64.0.1", "", nil), router(4, other.String()), router(6, route.String())},
	}

	elect := func(candidates views.Slice[types.NodeID], _ types.NodeID) (types.NodeID, bool) {
		if candidates.Len() == 0 {
			return 0, false
		}

		return candidates.At(0), true
	}

	pm, err := NewPolicyManager(pol, sideUsers, steps[0].ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, steps[0])
	us := NewUserSets(nil, m.t.sel, sideUsers)
	inc := ElectVia(nil, m.via.Plan, nil, elect)

	for i, next := range steps[1:] {
		prevPlan := m.via.Plan
		m.step(t, us, next)

		// Touch nothing: a moved plan must be enough to elect anew.
		inc = ElectVia(inc, m.via.Plan, nil, elect)
		full := ElectVia(nil, m.via.Plan, nil, elect)

		require.True(t, sameViaWinners(inc.winners, full.winners), "step %d: incremental election", i)
		require.NotSame(t, prevPlan, m.via.Plan, "step %d: the candidates moved, so the plan did", i)
	}

	// The same plan with a touched route elects that route again.
	inc = ElectVia(inc, m.via.Plan, map[netip.Prefix]struct{}{route: {}}, func(c views.Slice[types.NodeID], _ types.NodeID) (types.NodeID, bool) {
		return c.At(c.Len() - 1), true
	})
	require.Equal(t, inc.Primary(viaTags([]Tag{"tag:r"}), route), types.NodeID(6))
}

// BenchmarkRolePeersBuild builds every side set and every class keyed by
// side set from scratch.
func BenchmarkRolePeersBuild(b *testing.B) {
	for _, shape := range []string{"mesh", "pairs", "tag-pairs", "dense", "self"} {
		for _, n := range []int{1000, 2000} {
			b.Run(fmt.Sprintf("%s/nodes=%d", shape, n), func(b *testing.B) {
				var (
					nodes types.Nodes
					users types.Users
					pol   []byte
				)

				if shape == "mesh" {
					users = make(types.Users, n/10)
					for i := range users {
						users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i)} //nolint:gosec // bounded
					}

					for i := range n {
						nodes = append(nodes, sideNode(types.NodeID(i+1), &users[i%len(users)], //nolint:gosec // bounded
							netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}).String(), "", nil)) //nolint:gosec // bounded
					}

					pol = []byte(`{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`)
				} else {
					nodes, users, pol = diversePeerPolicy(n, shape)
				}

				pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
				require.NoError(b, err)

				all := nodeMapOf(nodes)
				sel := SelectorsFor(nil, pm)
				roles := Roles{}.Update(NewUserSets(nil, sel, users), all, nil)
				posts := Postings{}.Update(roles)
				appr := SubnetApprovals{}.Update(all)
				tmpl := BuildTemplates(nil, sel)

				for _, phase := range []string{"sides", "classes"} {
					b.Run(phase, func(b *testing.B) {
						b.ReportAllocs()

						s := UpdateSides(Sides{}, tmpl, roles, posts, appr, all)

						var built *PeerClasses

						for b.Loop() {
							switch phase {
							case "sides":
								s = buildSides(tmpl.sidePlan(), roles, posts, appr, all)
							case "classes":
								built = &PeerClasses{keyed: buildKeyed(s, nil)}
							}
						}

						if built != nil {
							b.ReportMetric(float64(len(built.Views())), "views/op")
						}
					})
				}
			})
		}
	}
}

// TestSidesIncremental moves, one write at a time, the shapes whose side
// sets an update reaches only through another node: a node whose own
// touch set moves because of a node it shares an address with, seen by a
// router over its other address; a via router that becomes one because a
// node it routes over is tagged, seen by a node holding its address; an
// approval that puts an address inside "*"; a UserID that leaves the
// clique; a route that comes to cover a member; an owner that keeps only
// its route over its user; a via router whose router atom reaches, then
// leaves, the router over its address; a node leaving a shared address; a
// via destination moving into a route. Peers
// before and after are written out by hand; every step is also audited,
// incremental against a build from scratch.
func TestSidesIncremental(t *testing.T) {
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	tests := []struct {
		name          string
		policy        string
		nodes         types.Nodes
		write         func(types.Nodes) types.Nodes
		before, after map[types.NodeID][]types.NodeID
	}{
		{
			// carol's node shares alice's first node's IPv4 only; when it
			// becomes bob's, bob's self source names alice's node by that
			// address, and the router over alice's node's IPv6 joins her
			// user's self rules.
			name:   "named-through-a-shared-address",
			policy: `{"tagOwners": {"tag:r": []}, "acls": [{"action": "accept", "src": ["bob@"], "dst": ["autogroup:self:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "fd7a:115c:a1e0::1", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
				sideNode(3, carol, "100.64.0.1", "", nil),
				sideNode(4, nil, "100.64.0.4", "", []string{"tag:r"}, "fd7a:115c:a1e0::1/128"),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], n[1], sideNode(3, bob, "100.64.0.1", "", nil), n[3]}
			},
			before: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}, 3: nil, 4: nil},
			after:  map[types.NodeID][]types.NodeID{1: {2, 3, 4}, 2: {1, 3, 4}, 3: {1, 2}, 4: {1, 2}},
		},
		{
			// Tagging the node the router routes over makes it a via router
			// of the grant; it is among the grant's sources by its route, so
			// it sees the node holding its address.
			name: "via-router-through-a-covered-node",
			policy: `{"tagOwners": {"tag:r": [], "tag:x": []}, "grants": [
				{"src": ["alice@", "100.64.0.8/30"], "dst": ["tag:x"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "100.64.0.8/30"),
				sideNode(6, bob, "100.64.0.5", "", nil),
				sideNode(8, carol, "100.64.0.8", "", nil),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], n[1], n[2], sideNode(8, nil, "100.64.0.8", "", []string{"tag:x"})}
			},
			before: map[types.NodeID][]types.NodeID{1: nil, 5: nil, 6: nil, 8: nil},
			after:  map[types.NodeID][]types.NodeID{1: {5}, 5: {1, 6, 8}, 6: {5}, 8: {5}},
		},
		{
			// An approval of an announced route puts the address inside it
			// among "*"'s sources.
			name:   "approval-puts-an-address-in-wildcard",
			policy: `{"tagOwners": {"tag:r": []}, "acls": [{"action": "accept", "src": ["*"], "dst": ["bob@:22"]}]}`,
			nodes: types.Nodes{
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(6, carol, "192.168.0.6", "", nil),
				sideNode(7, nil, "100.64.0.7", "", []string{"tag:r"}, "~192.168.0.0/24"),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], n[1], sideNode(7, nil, "100.64.0.7", "", []string{"tag:r"}, "192.168.0.0/24")}
			},
			before: map[types.NodeID][]types.NodeID{3: {7}, 6: nil, 7: {3}},
			after:  map[types.NodeID][]types.NodeID{3: {6, 7}, 6: {3}, 7: {3}},
		},
		{
			// An owner address going public takes its user's self rules to
			// the internet: exits join their destinations, though no node
			// they show changed.
			name:   "owner-address-goes-public",
			policy: `{"tagOwners": {"tag:e": []}, "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:22"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
				sideNode(9, nil, "100.64.0.9", "", []string{"tag:e"}, "0.0.0.0/0", "::/0"),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], sideNode(2, alice, "8.8.4.2", "", nil), n[2]}
			},
			before: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}, 9: nil},
			after:  map[types.NodeID][]types.NodeID{1: {2, 9}, 2: {1, 9}, 9: {1, 2}},
		},
		{
			// The clique follows the UserID, which a write can move alone.
			name:   "user-id-leaves-the-clique",
			policy: `{"acls": []}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(2, alice, "100.64.0.2", "", nil),
			},
			write: func(n types.Nodes) types.Nodes {
				moved := sideNode(2, alice, "100.64.0.2", "", nil)
				moved.UserID = &bob.ID

				return types.Nodes{n[0], moved}
			},
			before: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
			after:  map[types.NodeID][]types.NodeID{1: nil, 2: nil},
		},
		{
			// A route coming to cover a source member puts the router on
			// its side.
			name:   "route-comes-to-cover-a-member",
			policy: `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, bob, "100.64.0.3", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], n[1], sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "100.64.0.0/31")}
			},
			before: map[types.NodeID][]types.NodeID{1: {3}, 3: {1}, 5: nil},
			after:  map[types.NodeID][]types.NodeID{1: {3}, 3: {1, 5}, 5: {3}},
		},
		{
			// An owner losing its address keeps its route over another
			// owner of its user: it holds the owner atom through the route
			// alone, and stays on the self rules' destination side, seen by
			// bob's node and the alice node sharing its address.
			name:   "owner-loses-its-address-keeps-its-route",
			policy: `{"acls": [{"action": "accept", "src": ["bob@"], "dst": ["autogroup:self:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.9", "", nil, "100.64.0.0/31"),
				sideNode(2, alice, "100.64.0.1", "", nil),
				sideNode(3, alice, "100.64.0.5", "", nil),
				sideNode(4, bob, "100.64.0.5", "", nil),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{sideNode(1, alice, "", "", nil, "100.64.0.0/31"), n[1], n[2], n[3]}
			},
			before: map[types.NodeID][]types.NodeID{1: {2, 3, 4}, 2: {1, 3, 4}, 3: {1, 2, 4}, 4: {1, 2, 3}},
			after:  map[types.NodeID][]types.NodeID{1: {2, 3, 4}, 2: {1, 3, 4}, 3: {1, 2, 4}, 4: {1, 2, 3}},
		},
		{
			// A route into the grant's destinations makes the node a via
			// router, on its own sources by that route; nothing else of it
			// moves, so the router over its address reads its router atom
			// alone, and comes to see it.
			name: "covered-node-becomes-a-via-router",
			policy: `{"tagOwners": {"tag:r": [], "tag:y": []}, "grants": [
				{"src": ["10.0.0.0/24"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.1.0.0/24"),
				sideNode(7, nil, "100.64.0.7", "", []string{"tag:y"}, "100.64.0.5/32"),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.0.0.0/24"), n[1]}
			},
			before: map[types.NodeID][]types.NodeID{5: nil, 7: nil},
			after:  map[types.NodeID][]types.NodeID{5: {7}, 7: {5}},
		},
		{
			// The via router leaves the route over its address for one a
			// node like it keeps: the route's atoms stay, and only its
			// router atom tells the router over it to stop seeing it.
			name: "via-router-leaves-a-route",
			policy: `{"tagOwners": {"tag:r": [], "tag:y": []}, "grants": [
				{"src": ["10.0.0.0/24"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				sideNode(4, nil, "100.64.0.4", "", []string{"tag:r"}),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "10.0.0.0/24"),
				sideNode(7, nil, "100.64.0.7", "", []string{"tag:y"}, "100.64.0.4/31"),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], sideNode(5, nil, "100.64.0.9", "", []string{"tag:r"}, "10.0.0.0/24"), n[2]}
			},
			before: map[types.NodeID][]types.NodeID{4: nil, 5: {7}, 7: {5}},
			after:  map[types.NodeID][]types.NodeID{4: nil, 5: nil, 7: nil},
		},
		{
			// A node leaving a shared address takes its roles off the node
			// still holding it.
			name:   "shared-address-left",
			policy: `{"acls": [{"action": "accept", "src": ["carol@example.com"], "dst": ["bob@:*"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(3, carol, "100.64.0.1", "", nil),
				sideNode(4, bob, "100.64.0.4", "", nil),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], sideNode(3, carol, "100.64.0.3", "", nil), n[2]}
			},
			before: map[types.NodeID][]types.NodeID{1: {4}, 3: {4}, 4: {1, 3}},
			after:  map[types.NodeID][]types.NodeID{1: nil, 3: {4}, 4: {3}},
		},
		{
			// A via grant's identity destination moving its address into a
			// router's route makes the router serve the grant.
			name: "via-destination-moves-into-a-route",
			policy: `{"tagOwners": {"tag:r": [], "tag:a": []}, "grants": [
				{"src": ["alice@"], "dst": ["tag:a"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				sideNode(1, alice, "100.64.0.1", "", nil),
				sideNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, "100.64.0.8/30"),
				sideNode(8, nil, "100.64.0.20", "", []string{"tag:a"}),
			},
			write: func(n types.Nodes) types.Nodes {
				return types.Nodes{n[0], n[1], sideNode(8, nil, "100.64.0.9", "", []string{"tag:a"})}
			},
			before: map[types.NodeID][]types.NodeID{1: nil, 5: nil, 8: nil},
			after:  map[types.NodeID][]types.NodeID{1: {5}, 5: {1}, 8: nil},
		},
	}

	requirePeers := func(t *testing.T, m *sideModel, want map[types.NodeID][]types.NodeID, what string) {
		t.Helper()

		for id, peers := range want {
			if got := m.peers.Peers(id); len(peers) > 0 || len(got) > 0 {
				require.Equal(t, peers, got, "%s: peers of %d", what, id)
			}
		}

		_, err := m.audit()
		require.NoError(t, err, what)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.policy), sideUsers, tt.nodes.ViewSlice())
			require.NoError(t, err)

			m := newSideModel(t, pm, sideUsers, tt.nodes)
			requirePeers(t, m, tt.before, "before")

			m.step(t, NewUserSets(nil, m.t.sel, sideUsers), tt.write(tt.nodes))
			requirePeers(t, m, tt.after, "after")
		})
	}
}

// joinBench is n members of ten users on 100.64.0.0/16 under a rule from
// every member to every member and a via grant to a subnet; with wide set,
// a tagged router also approves 100.64.0.0/16, so every join lands inside
// its route. One member joins and leaves in turn.
type joinBench struct {
	us     *UserSets
	t      *Templates
	nodes  *NodeMap
	roles  Roles
	posts  Postings
	appr   SubnetApprovals
	sides  Sides
	via    ViaPlans
	joiner *types.Node
	router types.NodeID
	in     bool
}

func newJoinBench(tb testing.TB, n int, wide bool) *joinBench {
	tb.Helper()

	users := make(types.Users, 10)
	for i := range users {
		users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i)} //nolint:gosec // bounded
	}

	member := func(i int) *types.Node {
		return sideNode(types.NodeID(i+1), &users[i%10], //nolint:gosec // bounded
			netip.AddrFrom4([4]byte{100, 64, byte((i + 2) >> 8), byte(i + 2)}).String(), "", nil) //nolint:gosec // bounded
	}

	nodes := make(types.Nodes, 0, n+1)
	for i := range n {
		nodes = append(nodes, member(i))
	}

	routes := []string{"10.0.0.0/24"}
	if wide {
		routes = append(routes, "100.64.0.0/16")
	}

	router := sideNode(types.NodeID(n+1), nil, "100.64.255.254", "", []string{"tag:r"}, routes...) //nolint:gosec // bounded
	nodes = append(nodes, router)

	pol := []byte(`{"tagOwners": {"tag:r": []},
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}],
		"grants": [{"src": ["autogroup:member"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`)

	// The selectors come from the document alone.
	pm, err := NewPolicyManager(pol, users, views.Slice[types.NodeView]{})
	require.NoError(tb, err)

	sel := SelectorsFor(nil, pm)
	w := &joinBench{us: NewUserSets(nil, sel, users), t: BuildTemplates(nil, sel), nodes: nodeMapOf(nodes), router: router.ID}
	w.roles = Roles{}.Update(w.us, w.nodes, nil)
	w.posts = Postings{}.Update(w.roles)
	w.appr = SubnetApprovals{}.Update(w.nodes)
	w.sides = UpdateSides(Sides{}, w.t, w.roles, w.posts, w.appr, w.nodes)
	w.via = UpdateViaPlans(ViaPlans{}, w.sides)
	w.joiner = sideNode(types.NodeID(n+2), &users[0], "100.64.0.1", "", nil) //nolint:gosec // bounded

	return w
}

// move joins the joiner, or takes it out again, up to the sides' inputs.
func (w *joinBench) move() {
	e := w.nodes.Edit()
	if w.in {
		e.Delete(w.joiner.ID)
	} else {
		e.Set(w.joiner.ID, w.joiner)
	}

	w.in = !w.in
	w.nodes = e.Done()
	w.roles = w.roles.Update(w.us, w.nodes, nil)
	w.posts = w.posts.Update(w.roles)
	w.appr = w.appr.Update(w.nodes)
}

// TestSidesJoinCost pins what a join costs where every member is inside
// one router's route, at any tailnet size: the joiner's side set and no
// other, no index entry visited, the via plan kept though a regular rule
// names every member; and that route access builds a side set's shared
// rules once, whoever asks.
func TestSidesJoinCost(t *testing.T) {
	for _, n := range []int{400, 1600} {
		t.Run(fmt.Sprintf("nodes=%d", n), func(t *testing.T) {
			w := newJoinBench(t, n, true)

			for range 4 {
				_, before := w.sides.Computed()
				builds := w.via.Builds

				w.move()
				w.sides = UpdateSides(w.sides, w.t, w.roles, w.posts, w.appr, w.nodes)
				w.via = UpdateViaPlans(w.via, w.sides)

				_, after := w.sides.Computed()

				want := 0
				if w.in {
					want = 1
				}

				assert.Equal(t, want, after-before, "side sets computed, joined=%t", w.in)
				assert.Zero(t, w.sides.scanned, "index entries visited")
				assert.Equal(t, builds, w.via.Builds, "via plans built")
			}

			require.NoError(t, sameSides(w.sides, buildSides(w.t.sidePlan(), w.roles, w.posts, w.appr, w.nodes)))

			r, _ := w.nodes.Get(w.router)
			routes := r.SubnetRoutes()
			builds := w.sides.rules.builds
			classes := map[RoleSet]struct{}{}

			for id := range n {
				w.sides.RouteAccess(types.NodeID(id+1), routes) //nolint:gosec // bounded
				w.sides.RouteAccess(types.NodeID(id+1), routes) //nolint:gosec // bounded

				rs, _ := w.sides.Of(types.NodeID(id + 1)) //nolint:gosec // bounded
				classes[rs] = struct{}{}
			}

			assert.Equal(t, len(classes), w.sides.rules.builds-builds, "shared rules built")
		})
	}
}

// BenchmarkSidesJoin times what one join costs the sides and the via plan,
// with and without a router whose route holds every member.
func BenchmarkSidesJoin(b *testing.B) {
	for _, wide := range []bool{false, true} {
		for _, n := range []int{4000, 16000} {
			b.Run(fmt.Sprintf("wide=%t/nodes=%d", wide, n), func(b *testing.B) {
				for _, phase := range []string{"sides", "via"} {
					b.Run(phase, func(b *testing.B) {
						w := newJoinBench(b, n, wide)
						_, sets := w.sides.Computed()
						builds := w.via.Builds

						b.ReportAllocs()

						for b.Loop() {
							b.StopTimer()
							w.move()

							if phase == "sides" {
								b.StartTimer()
							}

							w.sides = UpdateSides(w.sides, w.t, w.roles, w.posts, w.appr, w.nodes)

							if phase == "sides" {
								b.StopTimer()
							} else {
								b.StartTimer()
							}

							w.via = UpdateViaPlans(w.via, w.sides)

							if phase == "sides" {
								b.StartTimer()
							}
						}

						_, after := w.sides.Computed()
						b.ReportMetric(float64(after-sets)/float64(b.N), "sets/op")
						b.ReportMetric(float64(w.via.Builds-builds)/float64(b.N), "plans/op")
					})
				}
			})
		}
	}
}

// BenchmarkRouteAccess asks, member after member, which of the wide
// router's routes each may use through it.
func BenchmarkRouteAccess(b *testing.B) {
	w := newJoinBench(b, 4000, true)
	r, _ := w.nodes.Get(w.router)
	routes := r.SubnetRoutes()

	b.ReportAllocs()

	i := 0
	for b.Loop() {
		w.sides.RouteAccess(types.NodeID(i%4000+1), routes) //nolint:gosec // bounded
		i++
	}
}

// sideGen draws policies and topologies for the random differential: few
// addresses, so nodes share them; routes over other nodes' addresses, host
// routes, unannounced approvals and exits; every kind of selector, port and
// capability rules with and without companions, self and via.
type sideGen struct {
	r      *rand.Rand
	public bool

	// facts, when set, draws what each node's client reports beyond the
	// policy: its client, app connector and announced routes; sparse
	// draws from more addresses and gives fewer nodes routes, so most
	// nodes are sent capabilities.
	facts  *rand.Rand
	sparse bool
}

func (g sideGen) pick(from ...string) string { return from[g.r.IntN(len(from))] }

func (g sideGen) some(n int, from ...string) []string {
	out := make([]string, 0, n)
	for range 1 + g.r.IntN(n) {
		out = append(out, g.pick(from...))
	}

	return out
}

func (g sideGen) srcs() []string {
	return g.some(3, "*", "alice@", "bob@", "carol@example.com", "group:g", "tag:a", "tag:r", "tag:e",
		"autogroup:member", "autogroup:tagged", "autogroup:danger-all", "hnet", "100.64.0.0/30", "100.64.0.4",
		"10.0.0.0/24", "8.8.8.0/29", "fd7a:115c:a1e0::/120")
}

func (g sideGen) dsts() []string {
	return g.some(3, "*", "alice@", "bob@", "group:g", "tag:a", "tag:r", "tag:e", "autogroup:member",
		"autogroup:tagged", "autogroup:internet", "hnet", "hpub", "100.64.0.0/30", "100.64.0.2",
		"10.0.0.0/16", "10.0.0.0/24", "8.8.8.0/24", "fd7a:115c:a1e0::/120")
}

// selfSrcs are sources a self destination takes.
func (g sideGen) selfSrcs() []string {
	return g.some(2, "*", "alice@", "bob@", "carol@example.com", "group:g", "autogroup:member")
}

func quoted(ss []string) string {
	b, err := json.Marshal(ss)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func (g sideGen) policy() []byte {
	rules := make([]string, 0, 2)
	grants := make([]string, 0, 3)

	for range g.r.IntN(3) {
		src, dsts := g.srcs(), g.dsts()
		if g.r.IntN(4) == 0 {
			src, dsts = g.selfSrcs(), []string{"autogroup:self"}
		}

		ports := g.pick("*", "22")

		for i := range dsts {
			dsts[i] += ":" + ports
		}

		rules = append(rules, fmt.Sprintf(`{"action": "accept", "src": %s, "dst": %s}`, quoted(src), quoted(dsts)))
	}

	for range 1 + g.r.IntN(3) {
		src, dst := g.srcs(), g.dsts()

		var parts []string

		switch g.r.IntN(4) {
		case 0:
			src, dst = g.selfSrcs(), []string{"autogroup:self"}
		case 1:
			dst = g.some(2, "10.0.0.0/24", "10.0.0.0/16", "100.64.0.0/30", "hnet", "tag:a", "autogroup:internet")

			parts = append(parts, `"via": ["tag:r"]`)
		}

		app := g.r.IntN(4)
		if slices.Contains(dst, "autogroup:internet") {
			app = 3
		}

		switch app {
		case 0:
			parts = append(parts, `"app": {"tailscale.com/cap/relay": [{}]}`)
		case 1:
			parts = append(parts, `"app": {"example.com/cap/x": [{}]}`)
		case 2:
			parts = append(parts, `"ip": ["*"]`, `"app": {"tailscale.com/cap/relay": [{}]}`)
		default:
			ip := g.pick("*", "tcp:22")
			if g.facts != nil && g.facts.IntN(5) == 0 {
				// A protocol without ports, which the client matches by
				// address only.
				ip = "gre:*"
			}

			parts = append(parts, fmt.Sprintf(`"ip": [%q]`, ip))
		}

		grants = append(grants, fmt.Sprintf(`{"src": %s, "dst": %s, %s}`, quoted(src), quoted(dst), strings.Join(parts, ", ")))
	}

	if g.r.IntN(4) == 0 {
		// A rule whose sources can be one owner's nodes, before self rules
		// over two protocols: that owner's self rule over its protocol
		// merges at its key, which comes and goes with tag:e's nodes and
		// moves with the source's members.
		grants = append([]string{
			fmt.Sprintf(`{"src": [%q], "dst": ["tag:e"], "ip": ["tcp:22"]}`, g.pick("alice@", "bob@", "group:g")),
			`{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["udp:80"]}`,
			`{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["tcp:443"]}`,
		}, grants...)
	}

	// Service hosts add their service IPs to their local nets, so they are
	// sent addresses in capability mode.
	attrs := ""
	if g.r.IntN(4) == 0 {
		attrs = fmt.Sprintf(`, "nodeAttrs": [{"target": %s, "attr": ["service-host"]}]`,
			quoted(g.some(2, "tag:a", "tag:e", "alice@", "bob@", "autogroup:member")))
	}

	return fmt.Appendf(nil, `{"groups": {"group:g": ["alice@", "carol@example.com"]},
	"tagOwners": {"tag:a": [], "tag:r": ["alice@"], "tag:e": []},
	"hosts": {"hnet": "10.0.0.0/24", "hpub": "8.8.8.0/24"},
	"acls": [%s], "grants": [%s]%s}`, strings.Join(rules, ",\n\t\t"), strings.Join(grants, ",\n\t\t"), attrs)
}

// addrs are the addresses nodes draw from: few, so they share them.
func (g sideGen) addrs() ([]string, []string) {
	v4 := []string{"100.64.0.1", "100.64.0.2", "100.64.0.3", "100.64.0.4", "100.64.0.5", "10.0.0.5"}
	v6 := []string{"fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2", "fd7a:115c:a1e0::3"}

	if g.public {
		v4 = append(v4, "8.8.8.1", "8.8.8.2", "8.8.8.9", "192.168.0.6")
		v6 = append(v6, "2606:4700::1")
	}

	if g.sparse {
		for i := 6; i < 40; i++ {
			v4 = append(v4, fmt.Sprintf("100.64.0.%d", i))
			v6 = append(v6, fmt.Sprintf("fd7a:115c:a1e0::%x", i))
		}
	}

	return v4, v6
}

func (g sideGen) node(id types.NodeID) *types.Node {
	v4, v6 := g.addrs()

	var user *types.User

	var tags []string

	switch g.r.IntN(5) {
	case 0:
		tags = g.some(2, "tag:a", "tag:r", "tag:e")
		if g.r.IntN(3) == 0 {
			user = &sideUsers[g.r.IntN(len(sideUsers))]
		}
	default:
		user = &sideUsers[g.r.IntN(len(sideUsers))]
	}

	var a4, a6 string

	if g.r.IntN(6) > 0 {
		a4 = g.pick(v4...)
	}

	if g.r.IntN(2) == 0 {
		a6 = g.pick(v6...)
	}

	var routes []string

	n := g.r.IntN(3)
	if g.sparse && g.r.IntN(4) > 0 {
		n = 0
	}

	if slices.Contains(tags, "tag:r") {
		n++
	}

	for range n {
		r := g.pick("10.0.0.0/24", "10.0.0.0/16", "100.64.0.0/30", "100.64.0.4/32", "100.64.0.1/32",
			"0.0.0.0/0", "::/0", "exit", "8.8.8.0/24", "fd7a:115c:a1e0::/120", "192.168.0.0/24")

		mode := g.pick("", "", "+", "~")
		if r == "exit" {
			routes = append(routes, mode+"0.0.0.0/0", mode+"::/0")

			continue
		}

		routes = append(routes, mode+r)
	}

	node := sideNode(id, user, a4, a6, tags, routes...)
	if user != nil && len(tags) > 0 {
		node.Tags = tags
	}

	g.clientFacts(node)

	return node
}

// clientFacts draws, when g draws facts, what n's client reports of
// itself: mostly the official client; else tailscale-rs, a client that
// says nothing, or an app connector.
func (g sideGen) clientFacts(n *types.Node) {
	if g.facts == nil {
		return
	}

	switch g.facts.IntN(10) {
	case 0:
		n.Hostinfo.App = "tailscale-rs"
	case 1:
	case 2:
		officialHostinfo(n.Hostinfo).AppConnector.Set(true)
	default:
		officialHostinfo(n.Hostinfo)
	}
}

// step is one to three joins, leaves and replacements, coalesced.
func (g sideGen) step(nodes types.Nodes) types.Nodes {
	next := slices.Clone(nodes)

	for range 1 + g.r.IntN(3) {
		switch op := g.r.IntN(3); {
		case op == 0 || len(next) < 2:
			next = append(next, g.node(next[len(next)-1].ID+1))
		case op == 1:
			i := g.r.IntN(len(next))
			next = slices.Delete(next, i, i+1)
		default:
			i := g.r.IntN(len(next))
			next[i] = g.node(next[i].ID)
		}
	}

	return next
}

func describeNodes(nodes types.Nodes) string {
	var b strings.Builder

	for _, n := range nodes {
		owner := "-"
		if n.UserID != nil {
			owner = strconv.FormatUint(uint64(*n.UserID), 10)
		}

		fmt.Fprintf(&b, "  %d user=%s tags=%v ips=%v approved=%v announced=%v\n",
			n.ID, owner, n.Tags, n.IPs(), n.ApprovedRoutes, n.AnnouncedRoutes())
	}

	return b.String()
}

// requireRouteRulesSame holds [RouteRules.Same] to what it stands for:
// across a step that keeps the route rules, every viewer whose node, side
// set and facts are the same is given the same routes by every router whose
// node and routes' cover are the same, as routing assumes in waking none of
// them. It returns how many pairs it held.
func requireRouteRulesSame(t *testing.T, was, is Sides, wasList, isList types.Nodes, via *ViaPlan, where ...any) int {
	t.Helper()

	if !is.RouteRules(via).Same(was.RouteRules(via)) {
		return 0
	}

	unchanged := func(moved []types.NodeID) map[types.NodeID]*types.Node {
		out := map[types.NodeID]*types.Node{}

		for _, a := range wasList {
			for _, b := range isList {
				if a == b && !slices.Contains(moved, a.ID) {
					out[a.ID] = a
				}
			}
		}

		return out
	}

	viewers, routers := unchanged(is.ViewersMovedSince(was)), unchanged(is.RoutersMovedSince(was.RouteCover()))

	held := 0

	for vid := range viewers {
		for _, r := range routers {
			routes := slices.Concat(r.SubnetRoutes(), r.ExitRoutes())
			if r.ID == vid || len(routes) == 0 {
				continue
			}

			before, after := was.RouteAccess(vid, routes), is.RouteAccess(vid, routes)
			if !slices.Equal(before, after) {
				t.Fatalf("%v: the route rules are the same, but viewer %d is given %v of router %d's routes, was %v", where, vid, after, r.ID, before)
			}

			held++
		}
	}

	return held
}

// TestSidesRandomDifferential draws compilable policies and topologies at
// random and holds the role-based visibility, route access and steering,
// built from scratch and then moved by coalesced joins, leaves and
// replacements, against the compile's pair scan and classes, its matchers
// and its via inspection, at every pair: once with tailnet addresses, once
// from a pool with public ones. HEADSCALE_SIDES_SEED replays a run; a
// failure names the seed, the policy and the nodes.
func TestSidesRandomDifferential(t *testing.T) {
	seed := uint64(time.Now().UnixNano()) //nolint:gosec // any seed

	if v := os.Getenv("HEADSCALE_SIDES_SEED"); v != "" {
		var err error

		seed, err = strconv.ParseUint(v, 10, 64)
		require.NoError(t, err)
	}

	t.Logf("HEADSCALE_SIDES_SEED=%d", seed)

	rounds := 300
	if testing.Short() {
		rounds = 40
	}

	// The capability variants also hold every node's capability form to
	// its address form through the client (check D); sparse ones give
	// fewer nodes routes and shared addresses, so most are sent
	// capabilities.
	variants := []struct {
		public, caps, sparse bool
		stream               uint64
	}{
		{stream: 0},
		{public: true, stream: 1},
		{caps: true, stream: 10},
		{caps: true, sparse: true, stream: 11},
		{public: true, caps: true, stream: 12},
		{public: true, caps: true, sparse: true, stream: 13},
	}

	for _, v := range variants {
		public := v.public

		t.Run(fmt.Sprintf("public=%t/caps=%t/sparse=%t", v.public, v.caps, v.sparse), func(t *testing.T) {
			g := sideGen{r: rand.New(rand.NewPCG(seed, v.stream)), public: public, sparse: v.sparse} //nolint:gosec // reproducible
			if v.caps {
				g.facts = rand.New(rand.NewPCG(seed, v.stream+100)) //nolint:gosec // reproducible
			}

			var (
				rep      SidesReport
				compiled int
				// keptPairs counts the pairs held to their routes across a
				// step that kept the route rules.
				keptPairs int
				reach     = capReach{}
			)

			for round := range rounds {
				pol := g.policy()

				nodes := make(types.Nodes, 0, 10)
				for i := range 3 + g.r.IntN(6) {
					nodes = append(nodes, g.node(types.NodeID(i+1))) //nolint:gosec // bounded
				}

				pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
				if err != nil {
					continue
				}

				compiled++

				m := newSideModel(t, pm, sideUsers, nodes)
				us := NewUserSets(nil, m.t.sel, sideUsers)

				for step := range 4 {
					if step > 0 {
						was, wasList := m.sides, m.list
						m.step(t, us, g.step(m.list))
						keptPairs += requireRouteRulesSame(t, was, m.sides, wasList, m.list, m.via.Plan,
							"seed", seed, "public", public, "round", round, "step", step)
					}

					got, err := m.audit()
					if err != nil {
						t.Fatalf("HEADSCALE_SIDES_SEED=%d public=%t round %d step %d: %v\npolicy:\n%s\nnodes:\n%s",
							seed, public, round, step, err, pol, describeNodes(m.list))
					}

					rep.Add(got)

					// The same states serve filters: each node's against the
					// compile, and against the global filter reduced to it.
					filters := NewFilters(m.t, m.posts, m.appr, m.list.ViewSlice())
					for _, n := range m.list {
						want, err := m.pm.FilterForNode(n.View())
						require.NoError(t, err)

						served, err := filters.ForNode(n.ID, ReceiverFacts{})
						require.NoError(t, err)

						if !reflect.DeepEqual(want, served) {
							t.Fatalf("HEADSCALE_SIDES_SEED=%d public=%t round %d step %d: node %d served %v, the compile %v\npolicy:\n%s\nnodes:\n%s",
								seed, public, round, step, n.ID, served, want, pol, describeNodes(m.list))
						}
					}

					requireServedAgreesWithGlobal(t, filters, m.list.ViewSlice(), "seed", seed, "public", public, "round", round, "step", step)

					if v.caps {
						cm := newCapModel(t, m)
						for _, n := range m.list {
							p := cm.requireCapEquivalent(t, n.ID, "HEADSCALE_SIDES_SEED", seed, "round", round, "step", step, "policy", string(pol), "nodes", describeNodes(m.list))
							cm.reach(t, n.ID, p, reach)
						}
					}
				}
			}

			if v.caps {
				t.Logf("capability form held to address form: %v", reach)

				if !testing.Short() {
					reach.require(t)
				}

				return
			}

			checked, own := agreementOf(t)
			t.Logf("compiled %d of %d: %+v; served ≡ global filter reduced on %d node filters (%d with own rules skipped)",
				compiled, rounds, rep, checked, own)
			require.Positive(t, checked, "node filters held to the global filter")
			require.Positive(t, own, "nodes with own rules met")
			require.Greater(t, compiled, rounds/2, "policies compiled")

			// A short run is too few rounds to reach the rarest shapes.
			if testing.Short() {
				return
			}

			// The claim covers these: each was reached.
			shapes := map[string]int{
				"shared address": rep.SharedAddress, "covering": rep.Covering, "single family": rep.SingleFamily,
				"unaddressed": rep.Unaddressed, "exit": rep.Exit, "one-family exit": rep.ExitOneFamily,
				"inside approved": rep.InsideApproved, "via targets": rep.ViaTargets, "steered": rep.Steered,
				"tagged with user": rep.TaggedWithUser, "via router on source": rep.ViaRouterOnSrc,
				"named by address only": rep.NamedByAddressOnly, "unaddressed covering own": rep.UnaddressedCoveringOwn,
				"routes kept": rep.RoutesKept,
			}
			shapes["pairs kept with the route rules"] = keptPairs

			if public {
				shapes["public"] = rep.Public
				shapes["public route"] = rep.PublicRoute
				shapes["public named by app"] = rep.PublicNamedApp
				shapes["wildcard steering outside"] = rep.WildcardSteerOutside
			}

			for name, n := range shapes {
				assert.Positive(t, n, "shape %q reached", name)
			}
		})
	}
}

// TestPeersDistinguishCapabilityFromIP: an app-only grant to an internet
// range lists the client on the exit node but not the exit node on the
// client, while the same grant with ip links both; the classes must follow
// document edits between the two.
func TestPeersDistinguishCapabilityFromIP(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}}
	client := sideNode(1, &users[0], "100.64.0.1", "fd7a:115c:a1e0::1", nil)
	exit := sideNode(2, nil, "100.64.0.2", "fd7a:115c:a1e0::2", []string{"tag:exit"})
	exit.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{tsaddr.AllIPv4()}}
	exit.ApprovedRoutes = []netip.Prefix{tsaddr.AllIPv4()}
	nodes := types.Nodes{client, exit}

	ip := []byte(`{"tagOwners":{"tag:exit":[]},"grants":[{"src":["alice@"],"dst":["8.8.8.0/24"],"ip":["*"]}]}`)
	app := []byte(`{"tagOwners":{"tag:exit":[]},"grants":[{"src":["alice@"],"dst":["8.8.8.0/24"],"app":{"example.com/cap/test":[{}]}}]}`)

	pm, err := NewPolicyManager(ip, users, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, users, nodes)
	us := NewUserSets(nil, m.t.sel, users)

	for i, src := range [][]byte{app, ip, app} {
		var ok bool

		us, ok = m.edit(t, us, src)
		require.True(t, ok, "edit %d accepted", i)

		_, err := m.audit()
		require.NoError(t, err, "edit %d", i)

		if bytes.Equal(src, app) {
			require.Empty(t, m.peers.Peers(client.ID), "edit %d: the client does not see the exit node", i)
		} else {
			require.Equal(t, []types.NodeID{exit.ID}, m.peers.Peers(client.ID), "edit %d", i)
		}

		require.Equal(t, []types.NodeID{client.ID}, m.peers.Peers(exit.ID), "edit %d: the exit node lists the client", i)
	}
}
