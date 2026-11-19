package policymodel

import (
	"bytes"
	"cmp"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
)

// World is everything a policy is compiled from.
type World struct {
	Policy   Policy
	Topology Topology
}

// GoString prints w as its policy document and its user and node tables.
func (w World) GoString() string {
	return "policy:\n" + indent(w.Policy.GoString()) + w.Topology.GoString()
}

// Step is edits committed together, and the nodes whose sessions read
// what they are served once the commit is in: a driver renders those
// sessions, or reads those nodes' filters, there and nowhere else. Every
// session reads the start.
type Step struct {
	Edits []Edit
	Reads []types.NodeID
}

func (s Step) String() string {
	parts := make([]string, len(s.Edits))
	for i, e := range s.Edits {
		parts[i] = e.String()
	}

	out := strings.Join(parts, "; ")

	if len(s.Reads) > 0 {
		reads := make([]string, len(s.Reads))
		for i, id := range s.Reads {
			reads[i] = fmt.Sprintf("n%d", id)
		}

		out += " | " + strings.Join(reads, " ") + " read"
	}

	return out
}

// Scenario is a start and the steps taken from it, each valid against the
// world the earlier ones produce.
type Scenario struct {
	Start World
	Steps []Step
}

// Worlds returns the start and the world after each step.
func (s Scenario) Worlds() []World {
	out := make([]World, 0, len(s.Steps)+1)

	w := s.Start
	out = append(out, w)

	for _, st := range s.Steps {
		w = w.Apply(st.Edits...)
		out = append(out, w)
	}

	return out
}

// end is the world after s's last step.
func (s Scenario) end() World {
	w := s.Start
	for _, st := range s.Steps {
		w = w.Apply(st.Edits...)
	}

	return w
}

// GoString prints s's start and its steps, numbered from 1.
func (s Scenario) GoString() string {
	var b strings.Builder

	b.WriteString(s.Start.GoString())
	b.WriteString("steps:\n")

	for i, st := range s.Steps {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, st)
	}

	return b.String()
}

// Edit is one write headscale accepts, valid against the world it was
// drawn for. It changes what its name says, and what headscale changes
// with it: announcing or withdrawing a route, tagging a node or
// registering one runs auto-approval.
type Edit interface {
	fmt.Stringer

	apply(w *World)
	// undo is the edit that takes w.Apply(e) back to w, false when
	// headscale has none: a deleted node or user comes back under a new
	// ID.
	undo(w World) (Edit, bool)
}

// Apply returns w after edits, in order. w is not changed.
func (w World) Apply(edits ...Edit) World {
	c := w.clone()

	for _, e := range edits {
		e.apply(&c)
	}

	canon(&c)

	return c
}

// Commit returns w after st and what a system must be told to commit st
// in one go.
func (w World) Commit(st Step) (World, Change) {
	next := w.Apply(st.Edits...)

	return next, changes(w, next)
}

// Undo returns a step of writes that takes w.Apply(step.Edits...) back to
// w, but for the ID counters, and whether there is one: there is none
// when the step deletes a node or a user, or when auto-approval or a
// manual approval moved approvals that no write puts back.
func Undo(w World, step Step) (Step, bool) {
	var inv Step

	ok := true
	cur := w

	for _, e := range step.Edits {
		u, has := e.undo(cur)
		ok = ok && has

		if has {
			inv.Edits = append(inv.Edits, u)
		}

		cur = cur.Apply(e)
	}

	slices.Reverse(inv.Edits)

	back := cur.Apply(inv.Edits...)
	back.Topology.NextID, back.Topology.NextUserID = w.Topology.NextID, w.Topology.NextUserID

	// Writing w's document again is refused if the users have made a
	// token in it ambiguous since it was written.
	if !reflect.DeepEqual(cur.Policy, back.Policy) && len(NewView(back).AmbiguousRefs()) > 0 {
		ok = false
	}

	return inv, ok && reflect.DeepEqual(back, w)
}

// Change is what a system must be told to commit a step.
type Change struct {
	// Removed were deleted; Nodes were added or changed, or carry a user
	// whose name or e-mail changed. Both in ID order.
	Removed, Nodes []types.NodeID
	// Users and Policy changed.
	Users, Policy bool
}

func changes(before, after World) Change {
	var c Change

	for _, n := range before.Topology.Nodes {
		if _, ok := after.Topology.Node(n.ID); !ok {
			c.Removed = append(c.Removed, n.ID)
		}
	}

	for _, n := range after.Topology.Nodes {
		old, ok := before.Topology.Node(n.ID)
		u0, _ := before.Topology.User(n.User)
		u1, _ := after.Topology.User(n.User)

		if !ok || !reflect.DeepEqual(old, n) || u0 != u1 {
			c.Nodes = append(c.Nodes, n.ID)
		}
	}

	c.Users = !slices.Equal(before.Topology.Users, after.Topology.Users)
	c.Policy = !reflect.DeepEqual(before.Policy, after.Policy) && !bytes.Equal(before.Policy.HuJSON(), after.Policy.HuJSON())

	return c
}

func (w World) clone() World {
	c := w

	p := &c.Policy
	for i := range p.Groups {
		p.Groups[i] = slices.Clone(p.Groups[i])
	}

	for i := range p.TagOwners {
		p.TagOwners[i] = slices.Clone(p.TagOwners[i])
	}

	p.ACLs = cloneEach(p.ACLs, Rule.clone)
	p.Grants = cloneEach(p.Grants, Rule.clone)
	p.SSH = cloneEach(p.SSH, SSHRule.clone)
	p.NodeAttrs = cloneEach(p.NodeAttrs, NodeAttr.clone)
	p.AutoApprovers = p.AutoApprovers.clone()

	c.Topology.Users = slices.Clone(c.Topology.Users)
	c.Topology.Nodes = cloneEach(c.Topology.Nodes, Node.clone)

	return c
}

func cloneEach[E any](s []E, f func(E) E) []E {
	if s == nil {
		return nil
	}

	out := make([]E, len(s))
	for i, e := range s {
		out[i] = f(e)
	}

	return out
}

func (r Rule) clone() Rule {
	r.Src = slices.Clone(r.Src)
	r.Dst = slices.Clone(r.Dst)
	r.IP = slices.Clone(r.IP)
	r.App = slices.Clone(r.App)
	r.Via = slices.Clone(r.Via)

	return r
}

func (r SSHRule) clone() SSHRule {
	r.Src = slices.Clone(r.Src)
	r.Dst = slices.Clone(r.Dst)
	r.Users = slices.Clone(r.Users)

	return r
}

func (a NodeAttr) clone() NodeAttr {
	a.Targets = slices.Clone(a.Targets)
	a.Attrs = slices.Clone(a.Attrs)

	return a
}

func (a AutoApprovers) clone() AutoApprovers {
	a.Routes = cloneEach(a.Routes, func(r RouteApproval) RouteApproval {
		r.By = slices.Clone(r.By)

		return r
	})
	a.Exit = slices.Clone(a.Exit)

	return a
}

func (n Node) clone() Node {
	n.Tags = slices.Clone(n.Tags)
	n.Announced = slices.Clone(n.Announced)
	n.Approved = slices.Clone(n.Approved)
	n.AutoApproved = slices.Clone(n.AutoApproved)

	return n
}

// canon writes every empty list as nil, so equal worlds are DeepEqual.
func canon(w *World) {
	p := &w.Policy
	for i := range p.Groups {
		p.Groups[i] = nilIfEmpty(p.Groups[i])
	}

	for i := range p.TagOwners {
		p.TagOwners[i] = nilIfEmpty(p.TagOwners[i])
	}

	for _, rs := range []*[]Rule{&p.ACLs, &p.Grants} {
		*rs = nilIfEmpty(*rs)
		for i := range *rs {
			r := &(*rs)[i]
			r.IP, r.App, r.Via = nilIfEmpty(r.IP), nilIfEmpty(r.App), nilIfEmpty(r.Via)
		}
	}

	p.AllowAll = p.AllowAll && len(p.ACLs) == 0 && len(p.Grants) == 0
	p.SSH = nilIfEmpty(p.SSH)
	p.NodeAttrs = nilIfEmpty(p.NodeAttrs)
	p.AutoApprovers.Routes = nilIfEmpty(p.AutoApprovers.Routes)
	p.AutoApprovers.Exit = nilIfEmpty(p.AutoApprovers.Exit)

	t := &w.Topology
	t.Users = nilIfEmpty(t.Users)
	t.Nodes = nilIfEmpty(t.Nodes)

	for i := range t.Nodes {
		n := &t.Nodes[i]
		n.Tags, n.Announced, n.Approved = nilIfEmpty(n.Tags), nilIfEmpty(n.Announced), nilIfEmpty(n.Approved)
		n.AutoApproved = nilIfEmpty(n.AutoApproved)
	}
}

func nilIfEmpty[S ~[]E, E any](s S) S {
	if len(s) == 0 {
		return nil
	}

	return s
}

func nodeIn(w *World, id types.NodeID) *Node {
	i := slices.IndexFunc(w.Topology.Nodes, func(n Node) bool { return n.ID == id })
	if i < 0 {
		return nil
	}

	return &w.Topology.Nodes[i]
}

func userIn(w *World, id uint) *User {
	i := slices.IndexFunc(w.Topology.Users, func(u User) bool { return u.ID == id })
	if i < 0 {
		return nil
	}

	return &w.Topology.Users[i]
}

func (w World) mustNode(id types.NodeID) Node {
	n, _ := w.Topology.Node(id)

	return n
}

// addRoutes and dropRoutes keep route lists sorted and free of repeats.
func addRoutes(to, rs []int) []int {
	out := slices.Clone(to)
	for _, r := range rs {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}

	slices.Sort(out)

	return out
}

func dropRoutes(from, rs []int) []int {
	return slices.DeleteFunc(slices.Clone(from), func(r int) bool { return slices.Contains(rs, r) })
}

func keepRoutes(from, rs []int) []int {
	return slices.DeleteFunc(slices.Clone(from), func(r int) bool { return !slices.Contains(rs, r) })
}

// autoApprove is what headscale does when a node's announced routes may
// have changed: approvals the auto-approvers gave a route no longer
// announced go, then every announced route they approve is approved.
func autoApprove(w *World, id types.NodeID, drop bool) {
	n := nodeIn(w, id)
	if n == nil {
		return
	}

	if drop {
		gone := dropRoutes(n.AutoApproved, n.Announced)
		n.Approved = dropRoutes(n.Approved, gone)
		n.AutoApproved = keepRoutes(n.AutoApproved, n.Announced)
	}

	v := NewView(*w)

	for _, r := range n.Announced {
		if !slices.Contains(n.Approved, r) && v.Approvable(*n, r) {
			n.Approved = addRoutes(n.Approved, []int{r})
			n.AutoApproved = addRoutes(n.AutoApproved, []int{r})
		}
	}
}

// Join registers Node: headscale runs auto-approval over what it
// announces.
type Join struct{ Node Node }

func (e Join) apply(w *World) {
	if nodeIn(w, e.Node.ID) != nil {
		return
	}

	t := &w.Topology
	i, _ := slices.BinarySearchFunc(t.Nodes, e.Node.ID, func(n Node, id types.NodeID) int { return cmp.Compare(n.ID, id) })
	t.Nodes = slices.Insert(t.Nodes, i, e.Node.clone())
	t.NextID = max(t.NextID, e.Node.ID+1)

	autoApprove(w, e.Node.ID, true)
}

func (e Join) undo(World) (Edit, bool) { return Leave{e.Node.ID}, true }

func (e Join) String() string { return "join " + e.Node.String() }

// Leave deletes a node.
type Leave struct{ ID types.NodeID }

func (e Leave) apply(w *World) {
	w.Topology.Nodes = slices.DeleteFunc(w.Topology.Nodes, func(n Node) bool { return n.ID == e.ID })
}

func (e Leave) undo(World) (Edit, bool) { return nil, false }

func (e Leave) String() string { return fmt.Sprintf("leave n%d", e.ID) }

// Retag sets a node's tags, as an admin does (tags the policy defines;
// the node loses its user, and auto-approval runs); or, with none, makes
// it User's again, as a login of that user does.
type Retag struct {
	ID   types.NodeID
	Tags []int
	User uint
}

func (e Retag) apply(w *World) {
	n := nodeIn(w, e.ID)
	if n == nil {
		return
	}

	if len(e.Tags) == 0 {
		n.Tags, n.User = nil, e.User

		return
	}

	n.Tags, n.User = slices.Clone(e.Tags), 0

	autoApprove(w, e.ID, false)
}

func (e Retag) undo(w World) (Edit, bool) {
	n := w.mustNode(e.ID)

	return Retag{e.ID, n.Tags, n.User}, true
}

func (e Retag) String() string {
	if len(e.Tags) == 0 {
		return fmt.Sprintf("n%d logs in as u%d, untagged", e.ID, e.User)
	}

	tags := make([]string, len(e.Tags))
	for i, t := range e.Tags {
		tags[i] = Tags[t]
	}

	return fmt.Sprintf("retag n%d [%s]", e.ID, strings.Join(tags, " "))
}

// SetAddr sets a node's address in one family; the zero Addr is none.
// headscale hands addresses out only at registration and backfill, so a
// driver writes this through the store.
type SetAddr struct {
	ID     types.NodeID
	Family int
	Addr   netip.Addr
}

func (e SetAddr) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		setAddr(n, e.Family, e.Addr)
	}
}

func (e SetAddr) undo(w World) (Edit, bool) {
	return SetAddr{e.ID, e.Family, w.mustNode(e.ID).Addr(e.Family)}, true
}

func (e SetAddr) String() string {
	a := "-"
	if e.Addr.IsValid() {
		a = e.Addr.String()
	}

	return fmt.Sprintf("n%d v%d=%s", e.ID, e.Family, a)
}

// SwapAddrs exchanges two nodes' addresses in one family.
type SwapAddrs struct {
	A, B   types.NodeID
	Family int
}

func (e SwapAddrs) apply(w *World) {
	a, b := nodeIn(w, e.A), nodeIn(w, e.B)
	if a == nil || b == nil {
		return
	}

	x, y := a.Addr(e.Family), b.Addr(e.Family)
	setAddr(a, e.Family, y)
	setAddr(b, e.Family, x)
}

func (e SwapAddrs) undo(World) (Edit, bool) { return e, true }

func (e SwapAddrs) String() string {
	return fmt.Sprintf("swap v%d of n%d and n%d", e.Family, e.A, e.B)
}

// Announce adds routes a node advertises; auto-approval runs.
type Announce struct {
	ID     types.NodeID
	Routes []int
}

func (e Announce) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Announced = addRoutes(n.Announced, e.Routes)
		autoApprove(w, e.ID, true)
	}
}

func (e Announce) undo(w World) (Edit, bool) {
	return Withdraw{e.ID, dropRoutes(e.Routes, w.mustNode(e.ID).Announced)}, true
}

func (e Announce) String() string {
	return fmt.Sprintf("n%d announces [%s]", e.ID, strings.Join(routeStrings(e.Routes), " "))
}

// Withdraw removes routes a node advertises: an approval the
// auto-approvers gave goes with it, one an admin gave stays.
type Withdraw struct {
	ID     types.NodeID
	Routes []int
}

func (e Withdraw) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Announced = dropRoutes(n.Announced, e.Routes)
		autoApprove(w, e.ID, true)
	}
}

func (e Withdraw) undo(w World) (Edit, bool) {
	return Announce{e.ID, keepRoutes(e.Routes, w.mustNode(e.ID).Announced)}, true
}

func (e Withdraw) String() string {
	return fmt.Sprintf("n%d withdraws [%s]", e.ID, strings.Join(routeStrings(e.Routes), " "))
}

// Approve approves routes for a node, announced or not, as an admin
// setting its approved routes does: what the auto-approvers approved
// becomes the admin's.
type Approve struct {
	ID     types.NodeID
	Routes []int
}

func (e Approve) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Approved = addRoutes(n.Approved, e.Routes)
		n.AutoApproved = nil
	}
}

func (e Approve) undo(w World) (Edit, bool) {
	return Unapprove{e.ID, dropRoutes(e.Routes, w.mustNode(e.ID).Approved)}, true
}

func (e Approve) String() string {
	return fmt.Sprintf("approve [%s] for n%d", strings.Join(routeStrings(e.Routes), " "), e.ID)
}

// Unapprove takes routes' approval away, as an admin setting the node's
// approved routes does; what is announced stays.
type Unapprove struct {
	ID     types.NodeID
	Routes []int
}

func (e Unapprove) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Approved = dropRoutes(n.Approved, e.Routes)
		n.AutoApproved = nil
	}
}

func (e Unapprove) undo(w World) (Edit, bool) {
	return Approve{e.ID, keepRoutes(e.Routes, w.mustNode(e.ID).Approved)}, true
}

func (e Unapprove) String() string {
	return fmt.Sprintf("unapprove [%s] for n%d", strings.Join(routeStrings(e.Routes), " "), e.ID)
}

// SetClient sets what a node's client reports of itself.
type SetClient struct {
	ID     types.NodeID
	Client Client
}

func (e SetClient) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Client = e.Client
	}
}

func (e SetClient) undo(w World) (Edit, bool) { return SetClient{e.ID, w.mustNode(e.ID).Client}, true }

func (e SetClient) String() string { return fmt.Sprintf("n%d client=%s", e.ID, e.Client) }

// SetExpired expires a node or renews it.
type SetExpired struct {
	ID      types.NodeID
	Expired bool
}

func (e SetExpired) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Expired = e.Expired
	}
}

func (e SetExpired) undo(w World) (Edit, bool) {
	return SetExpired{e.ID, w.mustNode(e.ID).Expired}, true
}

func (e SetExpired) String() string {
	if e.Expired {
		return fmt.Sprintf("n%d expires", e.ID)
	}

	return fmt.Sprintf("n%d renewed", e.ID)
}

// SetOnline connects a node or disconnects it.
type SetOnline struct {
	ID     types.NodeID
	Online bool
}

func (e SetOnline) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Offline = !e.Online
	}
}

func (e SetOnline) undo(w World) (Edit, bool) {
	return SetOnline{e.ID, !w.mustNode(e.ID).Offline}, true
}

func (e SetOnline) String() string {
	if e.Online {
		return fmt.Sprintf("n%d online", e.ID)
	}

	return fmt.Sprintf("n%d offline", e.ID)
}

// AddUser creates User: through the API with a name no other API user
// has, or at its first OIDC login.
type AddUser struct{ User User }

func (e AddUser) apply(w *World) {
	if userIn(w, e.User.ID) != nil {
		return
	}

	t := &w.Topology
	i, _ := slices.BinarySearchFunc(t.Users, e.User.ID, func(u User, id uint) int { return cmp.Compare(u.ID, id) })
	t.Users = slices.Insert(t.Users, i, e.User)
	t.NextUserID = max(t.NextUserID, e.User.ID+1)
}

func (e AddUser) undo(World) (Edit, bool) { return DeleteUser{e.User.ID}, true }

func (e AddUser) String() string { return "add user " + e.User.String() }

// DeleteUser deletes a user who owns no node.
type DeleteUser struct{ ID uint }

func (e DeleteUser) apply(w *World) {
	w.Topology.Users = slices.DeleteFunc(w.Topology.Users, func(u User) bool { return u.ID == e.ID })
}

func (e DeleteUser) undo(World) (Edit, bool) { return nil, false }

func (e DeleteUser) String() string { return fmt.Sprintf("delete user u%d", e.ID) }

// RenameUser sets a user's name: an API user's through the API, to a name
// no other API user has; an OIDC user's at a login with new claims.
type RenameUser struct {
	ID   uint
	Name string
}

func (e RenameUser) apply(w *World) {
	if u := userIn(w, e.ID); u != nil {
		u.Name = e.Name
	}
}

func (e RenameUser) undo(w World) (Edit, bool) {
	u, _ := w.Topology.User(e.ID)

	return RenameUser{e.ID, u.Name}, true
}

func (e RenameUser) String() string { return fmt.Sprintf("rename u%d to %s", e.ID, e.Name) }

// SetEmail sets an OIDC user's e-mail at a login with new claims; "" is
// none. An API user's e-mail is set when it is created.
type SetEmail struct {
	ID    uint
	Email string
}

func (e SetEmail) apply(w *World) {
	if u := userIn(w, e.ID); u != nil {
		u.Email = e.Email
	}
}

func (e SetEmail) undo(w World) (Edit, bool) {
	u, _ := w.Topology.User(e.ID)

	return SetEmail{e.ID, u.Email}, true
}

func (e SetEmail) String() string { return fmt.Sprintf("u%d email=%q", e.ID, e.Email) }

// Policy edits. Each writes a document headscale's policy write accepts:
// it parses, compiles, and holds no user token two users answer to.

func ruleAt(w *World, r RuleRef) *Rule { return &(*ruleList(&w.Policy, r.Grant))[r.I] }

// SetPorts sets the ports of an ACL's destination At, or of a grant's ip
// entry At.
type SetPorts struct {
	Rule      RuleRef
	At, Ports int
}

func (e SetPorts) apply(w *World) {
	r := ruleAt(w, e.Rule)
	if e.Rule.Grant {
		r.IP[e.At].Ports = e.Ports
	} else {
		r.Dst[e.At].Ports = e.Ports
	}
}

func (e SetPorts) undo(w World) (Edit, bool) {
	r := w.Policy.Rule(e.Rule)
	if e.Rule.Grant {
		return SetPorts{e.Rule, e.At, r.IP[e.At].Ports}, true
	}

	return SetPorts{e.Rule, e.At, r.Dst[e.At].Ports}, true
}

func (e SetPorts) String() string {
	part := "dst"
	if e.Rule.Grant {
		part = "ip"
	}

	return fmt.Sprintf("%s %s[%d] ports %s", e.Rule, part, e.At, Ports[e.Ports])
}

// SetProto sets an ACL's protocol, or that of a grant's ip entry At.
type SetProto struct {
	Rule      RuleRef
	At, Proto int
}

func (e SetProto) apply(w *World) {
	r := ruleAt(w, e.Rule)
	if e.Rule.Grant {
		r.IP[e.At].Proto = e.Proto
	} else {
		r.Proto = e.Proto
	}
}

func (e SetProto) undo(w World) (Edit, bool) {
	r := w.Policy.Rule(e.Rule)
	if e.Rule.Grant {
		return SetProto{e.Rule, e.At, r.IP[e.At].Proto}, true
	}

	return SetProto{e.Rule, e.At, r.Proto}, true
}

func (e SetProto) String() string {
	proto := Protos[e.Proto]
	if proto == "" {
		proto = "default"
	}

	if e.Rule.Grant {
		return fmt.Sprintf("%s ip[%d] proto %s", e.Rule, e.At, proto)
	}

	return fmt.Sprintf("%s proto %s", e.Rule, proto)
}

// SetIP replaces a grant's ip list.
type SetIP struct {
	Rule RuleRef
	IP   []IP
}

func (e SetIP) apply(w *World) { ruleAt(w, e.Rule).IP = slices.Clone(e.IP) }

func (e SetIP) undo(w World) (Edit, bool) { return SetIP{e.Rule, w.Policy.Rule(e.Rule).IP}, true }

func (e SetIP) String() string {
	ips := make([]string, len(e.IP))
	for i, ip := range e.IP {
		ips[i] = ip.String()
	}

	return fmt.Sprintf("%s ip=[%s]", e.Rule, strings.Join(ips, " "))
}

// SetApp replaces a grant's app capabilities and their values.
type SetApp struct {
	Rule RuleRef
	App  []App
}

func (e SetApp) apply(w *World) { ruleAt(w, e.Rule).App = slices.Clone(e.App) }

func (e SetApp) undo(w World) (Edit, bool) { return SetApp{e.Rule, w.Policy.Rule(e.Rule).App}, true }

func (e SetApp) String() string {
	caps := make([]string, len(e.App))
	for i, a := range e.App {
		caps[i] = Apps[a.Cap] + "=" + strings.Join(AppValues[a.Value], ",")
	}

	return fmt.Sprintf("%s app=[%s]", e.Rule, strings.Join(caps, " "))
}

// SetVia replaces a grant's via tags.
type SetVia struct {
	Rule RuleRef
	Via  []int
}

func (e SetVia) apply(w *World) { ruleAt(w, e.Rule).Via = slices.Clone(e.Via) }

func (e SetVia) undo(w World) (Edit, bool) { return SetVia{e.Rule, w.Policy.Rule(e.Rule).Via}, true }

func (e SetVia) String() string {
	via := make([]string, len(e.Via))
	for i, v := range e.Via {
		via[i] = Tags[v]
	}

	return fmt.Sprintf("%s via=[%s]", e.Rule, strings.Join(via, " "))
}

// SwapRules swaps two rules of one list.
type SwapRules struct {
	Grant bool
	I, J  int
}

func (e SwapRules) apply(w *World) {
	l := *ruleList(&w.Policy, e.Grant)
	l[e.I], l[e.J] = l[e.J], l[e.I]
}

func (e SwapRules) undo(World) (Edit, bool) { return e, true }

func (e SwapRules) String() string {
	return fmt.Sprintf("swap %s and %s", RuleRef{e.Grant, e.I}, RuleRef{e.Grant, e.J})
}

// SetSel replaces a rule's source At, or destination At, with Sel.
type SetSel struct {
	Rule RuleRef
	Dst  bool
	At   int
	Sel  Sel
}

func (e SetSel) apply(w *World) {
	r := ruleAt(w, e.Rule)
	if e.Dst {
		r.Dst[e.At].Sel = e.Sel
	} else {
		r.Src[e.At] = e.Sel
	}
}

func (e SetSel) undo(w World) (Edit, bool) {
	r := w.Policy.Rule(e.Rule)
	if e.Dst {
		return SetSel{e.Rule, true, e.At, r.Dst[e.At].Sel}, true
	}

	return SetSel{e.Rule, false, e.At, r.Src[e.At]}, true
}

func (e SetSel) String() string {
	return fmt.Sprintf("%s %s[%d]=%s", e.Rule, side(e.Dst), e.At, e.Sel)
}

func side(dst bool) string {
	if dst {
		return "dst"
	}

	return "src"
}

// AddSel inserts Sel into a rule's sources, or destinations, at At; an
// ACL's destination with Ports.
type AddSel struct {
	Rule  RuleRef
	Dst   bool
	At    int
	Sel   Sel
	Ports int
}

func (e AddSel) apply(w *World) {
	r := ruleAt(w, e.Rule)
	if e.Dst {
		r.Dst = slices.Insert(r.Dst, e.At, Dest{Sel: e.Sel, Ports: e.Ports})
	} else {
		r.Src = slices.Insert(r.Src, e.At, e.Sel)
	}
}

func (e AddSel) undo(World) (Edit, bool) { return RemoveSel{e.Rule, e.Dst, e.At}, true }

func (e AddSel) String() string {
	return fmt.Sprintf("%s %s+[%d]=%s", e.Rule, side(e.Dst), e.At, e.Sel)
}

// RemoveSel deletes a rule's source At, or destination At; at least one
// stays.
type RemoveSel struct {
	Rule RuleRef
	Dst  bool
	At   int
}

func (e RemoveSel) apply(w *World) {
	r := ruleAt(w, e.Rule)
	if e.Dst {
		r.Dst = slices.Delete(r.Dst, e.At, e.At+1)
	} else {
		r.Src = slices.Delete(r.Src, e.At, e.At+1)
	}
}

func (e RemoveSel) undo(w World) (Edit, bool) {
	r := w.Policy.Rule(e.Rule)
	if e.Dst {
		return AddSel{e.Rule, true, e.At, r.Dst[e.At].Sel, r.Dst[e.At].Ports}, true
	}

	return AddSel{e.Rule, false, e.At, r.Src[e.At], 0}, true
}

func (e RemoveSel) String() string { return fmt.Sprintf("%s %s-[%d]", e.Rule, side(e.Dst), e.At) }

// SetGroup sets a group's members, indices into UserRefs.
type SetGroup struct {
	Group   int
	Members []int
}

func (e SetGroup) apply(w *World) { w.Policy.Groups[e.Group] = slices.Clone(e.Members) }

func (e SetGroup) undo(w World) (Edit, bool) {
	return SetGroup{e.Group, w.Policy.Groups[e.Group]}, true
}

func (e SetGroup) String() string {
	refs := make([]string, len(e.Members))
	for i, m := range e.Members {
		refs[i] = UserRefs[m]
	}

	return fmt.Sprintf("%s=[%s]", Groups[e.Group], strings.Join(refs, " "))
}

// SetHost moves a host by Shift from its default prefix.
type SetHost struct{ Host, Shift int }

func (e SetHost) apply(w *World) { w.Policy.Hosts[e.Host] = e.Shift }

func (e SetHost) undo(w World) (Edit, bool) { return SetHost{e.Host, w.Policy.Hosts[e.Host]}, true }

func (e SetHost) String() string {
	return fmt.Sprintf("%s=%s", Hosts[e.Host], Prefixes[(hostDefault[e.Host]+e.Shift)%numRulePrefixes])
}

// SetTagOwners sets a tag's tagOwners entry: its owners, and whether it
// is defined though nothing names it and it has none.
type SetTagOwners struct {
	Tag     int
	Owners  []Sel
	Defined bool
}

func (e SetTagOwners) apply(w *World) {
	w.Policy.TagOwners[e.Tag] = slices.Clone(e.Owners)
	w.Policy.Defined[e.Tag] = e.Defined
}

func (e SetTagOwners) undo(w World) (Edit, bool) {
	return SetTagOwners{e.Tag, w.Policy.TagOwners[e.Tag], w.Policy.Defined[e.Tag]}, true
}

func (e SetTagOwners) String() string {
	s := fmt.Sprintf("tagOwners %s=%s", Tags[e.Tag], joinSels(e.Owners))
	if e.Defined {
		s += " defined"
	}

	return s
}

// AddRule inserts Rule at Ref; a document allowing everything gets its
// first rule.
type AddRule struct {
	Ref  RuleRef
	Rule Rule
}

func (e AddRule) apply(w *World) {
	l := ruleList(&w.Policy, e.Ref.Grant)
	*l = slices.Insert(*l, e.Ref.I, e.Rule.clone())
	w.Policy.AllowAll = false
}

func (e AddRule) undo(w World) (Edit, bool) {
	if w.Policy.AllowAll {
		return AllowAll{}, true
	}

	return RemoveRule{e.Ref}, true
}

func (e AddRule) String() string { return fmt.Sprintf("add %s %s", e.Ref, e.Rule.json(e.Ref.Grant)) }

// RemoveRule deletes a rule; with the last one goes all access.
type RemoveRule struct{ Ref RuleRef }

func (e RemoveRule) apply(w *World) {
	l := ruleList(&w.Policy, e.Ref.Grant)
	*l = slices.Delete(*l, e.Ref.I, e.Ref.I+1)
}

func (e RemoveRule) undo(w World) (Edit, bool) { return AddRule{e.Ref, w.Policy.Rule(e.Ref)}, true }

func (e RemoveRule) String() string { return "remove " + e.Ref.String() }

// AllowAll deletes every rule and both rule sections, which allows
// everything.
type AllowAll struct{}

func (AllowAll) apply(w *World) {
	w.Policy.ACLs, w.Policy.Grants, w.Policy.AllowAll = nil, nil, true
}

func (AllowAll) undo(w World) (Edit, bool) {
	if w.Policy.AllowAll {
		return AllowAll{}, true
	}

	return SetRules{w.Policy.ACLs, w.Policy.Grants}, true
}

func (AllowAll) String() string { return "allow all: no acls, no grants" }

// SetRules replaces every rule.
type SetRules struct{ ACLs, Grants []Rule }

func (e SetRules) apply(w *World) {
	w.Policy.ACLs, w.Policy.Grants = cloneEach(e.ACLs, Rule.clone), cloneEach(e.Grants, Rule.clone)
	w.Policy.AllowAll = false
}

func (e SetRules) undo(w World) (Edit, bool) {
	if w.Policy.AllowAll {
		return AllowAll{}, true
	}

	return SetRules{w.Policy.ACLs, w.Policy.Grants}, true
}

func (e SetRules) String() string {
	return fmt.Sprintf("set %d acls and %d grants", len(e.ACLs), len(e.Grants))
}

// ReplaceUserRefs replaces, wherever the document names it, the user
// token From[i] with To[i]: what an admin does when a token stops naming
// one user, since no other write is accepted until it does.
type ReplaceUserRefs struct{ From, To []int }

func (e ReplaceUserRefs) apply(w *World) {
	w.Policy = w.Policy.mapRefs(func(r int) int {
		if i := slices.Index(e.From, r); i >= 0 {
			return e.To[i]
		}

		return r
	})
}

// undo replaces back the tokens the document held. It has none when it
// wrote one of them onto a token the document held already, or two onto
// one: replacing back cannot tell them apart.
func (e ReplaceUserRefs) undo(w World) (Edit, bool) {
	held := w.Policy.userRefs()

	var inv ReplaceUserRefs

	for i, from := range e.From {
		if !slices.Contains(held, from) {
			continue
		}

		to := e.To[i]
		if slices.Contains(inv.From, to) || slices.Contains(held, to) && !slices.Contains(e.From, to) {
			return nil, false
		}

		inv.From, inv.To = append(inv.From, to), append(inv.To, from)
	}

	return inv, true
}

func (e ReplaceUserRefs) String() string {
	parts := make([]string, len(e.From))
	for i := range e.From {
		parts[i] = UserRefs[e.From[i]] + " -> " + UserRefs[e.To[i]]
	}

	return "replace " + strings.Join(parts, ", ")
}

// SetSSH replaces the ssh section.
type SetSSH struct{ Rules []SSHRule }

func (e SetSSH) apply(w *World) { w.Policy.SSH = cloneEach(e.Rules, SSHRule.clone) }

func (e SetSSH) undo(w World) (Edit, bool) { return SetSSH{w.Policy.SSH}, true }

func (e SetSSH) String() string {
	rs := make([]string, len(e.Rules))
	for i, r := range e.Rules {
		rs[i] = r.json()
	}

	return "ssh=[" + strings.Join(rs, ", ") + "]"
}

// SetNodeAttrs replaces the nodeAttrs section.
type SetNodeAttrs struct{ Attrs []NodeAttr }

func (e SetNodeAttrs) apply(w *World) { w.Policy.NodeAttrs = cloneEach(e.Attrs, NodeAttr.clone) }

func (e SetNodeAttrs) undo(w World) (Edit, bool) { return SetNodeAttrs{w.Policy.NodeAttrs}, true }

func (e SetNodeAttrs) String() string {
	as := make([]string, len(e.Attrs))
	for i, a := range e.Attrs {
		as[i] = a.json()
	}

	return "nodeAttrs=[" + strings.Join(as, ", ") + "]"
}

// SetAutoApprovers replaces the autoApprovers section. headscale approves
// nothing on it: auto-approval runs when a node's routes change.
type SetAutoApprovers struct{ AutoApprovers AutoApprovers }

func (e SetAutoApprovers) apply(w *World) { w.Policy.AutoApprovers = e.AutoApprovers.clone() }

func (e SetAutoApprovers) undo(w World) (Edit, bool) {
	return SetAutoApprovers{w.Policy.AutoApprovers}, true
}

func (e SetAutoApprovers) String() string { return "autoApprovers=" + e.AutoApprovers.json() }

func indent(s string) string {
	var b strings.Builder

	for line := range strings.Lines(s) {
		b.WriteString("  " + line)
	}

	return b.String()
}
