package policymodel

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Topology is the users and nodes a policy is compiled against.
type Topology struct {
	// Users and Nodes are in ID order.
	Users []User
	Nodes []Node

	// NextID is the ID the next join takes unless it reuses one on
	// purpose: IDs are not reused otherwise, as in production.
	NextID types.NodeID
}

// User is a user as a policy's tokens resolve it.
type User struct {
	ID          uint
	Name, Email string
}

// Node is a node as the policy and its client see it.
type Node struct {
	ID types.NodeID
	// User is the owner of an untagged node, and the user a tagged node
	// still carries, or zero for none.
	User uint
	// Tags holds indices into Tags; a node with tags is owned by them.
	Tags []int

	// V4 and V6 are the node's addresses; the zero Addr is none.
	V4, V6 netip.Addr

	// Announced and Approved hold indices into Prefixes, sorted: what the
	// node advertises and what is approved for it, apart.
	Announced, Approved []int

	Client           Client
	Expired, Offline bool
}

// Client is what a node's client reports of itself.
type Client uint8

const (
	// Official is the current Tailscale client.
	Official Client = iota
	// Unknown reports no versions.
	Unknown
	// TailscaleRS is tailscale-rs, which parses capability sources but
	// looks none up.
	TailscaleRS
	// AppConnector is the official client running as an app connector.
	AppConnector
)

const numClients = int(AppConnector) + 1

func (c Client) String() string {
	return [...]string{"official", "unknown-client", "tailscale-rs", "app-connector"}[c]
}

// Tagged reports whether tags own n.
func (n Node) Tagged() bool { return len(n.Tags) > 0 }

// Addrs is n's addresses, IPv4 first.
func (n Node) Addrs() []netip.Addr {
	var out []netip.Addr

	for _, a := range []netip.Addr{n.V4, n.V6} {
		if a.IsValid() {
			out = append(out, a)
		}
	}

	return out
}

// Addr is n's address in family 4 or 6.
func (n Node) Addr(family int) netip.Addr {
	if family == 4 {
		return n.V4
	}

	return n.V6
}

func setAddr(n *Node, family int, a netip.Addr) {
	if family == 4 {
		n.V4 = a
	} else {
		n.V6 = a
	}
}

// Exit reports whether n is an exit node: an exit route announced and
// approved.
func (n Node) Exit() bool {
	for _, r := range []int{exit4, exit6} {
		if slices.Contains(n.Announced, r) && slices.Contains(n.Approved, r) {
			return true
		}
	}

	return false
}

// Node returns the node with id.
func (t Topology) Node(id types.NodeID) (Node, bool) {
	i, ok := slices.BinarySearchFunc(t.Nodes, id, func(n Node, id types.NodeID) int { return cmp.Compare(n.ID, id) })
	if !ok {
		return Node{}, false
	}

	return t.Nodes[i], true
}

// User returns the user with id.
func (t Topology) User(id uint) (User, bool) {
	i := slices.IndexFunc(t.Users, func(u User) bool { return u.ID == id })
	if i < 0 {
		return User{}, false
	}

	return t.Users[i], true
}

// nextID is the ID a plain join takes.
func (t Topology) nextID() types.NodeID {
	next := t.NextID
	if len(t.Nodes) > 0 {
		next = max(next, t.Nodes[len(t.Nodes)-1].ID+1)
	}

	return max(next, 1)
}

// officialHostinfo is what a current Tailscale client reports of itself:
// built with Go, a release headscale serves.
func officialHostinfo(hi *tailcfg.Hostinfo) {
	hi.GoVersion, hi.IPNVersion = "go1.27.3", "1.94.1-t0123456789ab-g0123456789ab"
}

// expiredAt is when expired nodes expired: a fixed time in the past, so
// building twice gives the same nodes.
var expiredAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// Build returns t's users and nodes as headscale holds them; each node's
// User points into the users returned. Keys derive from the node ID, so
// building twice gives equal values.
func (t Topology) Build() (types.Users, types.Nodes) {
	users := make(types.Users, len(t.Users))
	for i, u := range t.Users {
		users[i] = types.User{Name: u.Name, Email: u.Email}
		users[i].ID = u.ID
	}

	nodes := make(types.Nodes, len(t.Nodes))
	for i, n := range t.Nodes {
		nodes[i] = n.build(users)
	}

	return users, nodes
}

func (n Node) build(users types.Users) *types.Node {
	name := fmt.Sprintf("n%d", n.ID)

	tn := &types.Node{
		ID:         n.ID,
		MachineKey: key.MachinePublicFromRaw32(mem.B(rawKey(1, n.ID))),
		NodeKey:    key.NodePublicFromRaw32(mem.B(rawKey(2, n.ID))),
		DiscoKey:   key.DiscoPublicFromRaw32(mem.B(rawKey(3, n.ID))),
		Hostname:   name,
		GivenName:  name,
		Hostinfo:   &tailcfg.Hostinfo{Hostname: name},
		IsOnline:   new(!n.Offline),
	}

	for _, tag := range n.Tags {
		tn.Tags = append(tn.Tags, Tags[tag])
	}

	slices.Sort(tn.Tags)

	if n.User != 0 {
		i := slices.IndexFunc(users, func(u types.User) bool { return u.ID == n.User })
		if i >= 0 {
			tn.User, tn.UserID = &users[i], new(users[i].ID)
		}
	}

	if n.V4.IsValid() {
		tn.IPv4 = new(n.V4)
	}

	if n.V6.IsValid() {
		tn.IPv6 = new(n.V6)
	}

	for _, r := range n.Announced {
		tn.Hostinfo.RoutableIPs = append(tn.Hostinfo.RoutableIPs, Prefixes[r])
	}

	for _, r := range n.Approved {
		tn.ApprovedRoutes = append(tn.ApprovedRoutes, Prefixes[r])
	}

	switch n.Client {
	case Official:
		officialHostinfo(tn.Hostinfo)
	case Unknown:
	case TailscaleRS:
		tn.Hostinfo.App = "tailscale-rs"
		tn.Hostinfo.IPNVersion = "1.94.1"
	case AppConnector:
		officialHostinfo(tn.Hostinfo)
		tn.Hostinfo.AppConnector.Set(true)
	}

	if n.Expired {
		tn.Expiry = new(expiredAt)
	}

	return tn
}

func rawKey(kind byte, id types.NodeID) []byte {
	b := make([]byte, 32)
	b[0] = kind
	binary.BigEndian.PutUint64(b[24:], uint64(id))

	return b
}

func (u User) String() string {
	s := fmt.Sprintf("u%d %s", u.ID, u.Name)
	if u.Email != "" {
		s += " <" + u.Email + ">"
	}

	return s
}

// String is n as a row of the node table: only what differs from a plain
// node is shown, apart from the owner and addresses.
func (n Node) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "n%d", n.ID)

	if n.Tagged() {
		tags := make([]string, len(n.Tags))
		for i, t := range n.Tags {
			tags[i] = Tags[t]
		}

		fmt.Fprintf(&b, " tags=[%s]", strings.Join(tags, " "))

		if n.User != 0 {
			fmt.Fprintf(&b, " user=u%d", n.User)
		}
	} else {
		fmt.Fprintf(&b, " u%d", n.User)
	}

	addr := func(a netip.Addr) string {
		if a.IsValid() {
			return a.String()
		}

		return "-"
	}

	fmt.Fprintf(&b, " %s %s", addr(n.V4), addr(n.V6))

	if len(n.Announced) > 0 {
		fmt.Fprintf(&b, " announces=[%s]", strings.Join(routeStrings(n.Announced), " "))
	}

	if len(n.Approved) > 0 {
		fmt.Fprintf(&b, " approved=[%s]", strings.Join(routeStrings(n.Approved), " "))
	}

	if n.Client != Official {
		b.WriteString(" " + n.Client.String())
	}

	if n.Expired {
		b.WriteString(" expired")
	}

	if n.Offline {
		b.WriteString(" offline")
	}

	return b.String()
}

// GoString prints t as a user and a node table.
func (t Topology) GoString() string {
	var b strings.Builder

	b.WriteString("users:\n")

	for _, u := range t.Users {
		b.WriteString("  " + u.String() + "\n")
	}

	b.WriteString("nodes:\n")

	for _, n := range t.Nodes {
		b.WriteString("  " + n.String() + "\n")
	}

	return b.String()
}
