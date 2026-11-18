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

// Step is edits committed together.
type Step []Edit

func (s Step) String() string {
	parts := make([]string, len(s))
	for i, e := range s {
		parts[i] = e.String()
	}

	return strings.Join(parts, "; ")
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
		w = w.Apply(st...)
		out = append(out, w)
	}

	return out
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

// Edit changes exactly what its name says. An edit is valid against the
// world it was drawn for; applied elsewhere it may do nothing.
type Edit interface {
	fmt.Stringer

	apply(w *World)
	// undo is the edit that takes w.Apply(e) back to w.
	undo(w World) Edit
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

// Undo returns the step that takes w.Apply(step...) back to w, but for
// Topology.NextID: IDs are not handed out twice.
func Undo(w World, step Step) Step {
	inv := make(Step, 0, len(step))

	for _, e := range step {
		inv = append(inv, e.undo(w))
		w = w.Apply(e)
	}

	slices.Reverse(inv)

	return inv
}

// Change is what a system must be told to commit a step.
type Change struct {
	// Removed were deleted; Nodes were added or changed, to be written
	// after the removals. A node in both was deleted and registered again
	// under its ID. Both in ID order.
	Removed, Nodes []types.NodeID
	// Users and Policy changed.
	Users, Policy bool
}

// Commit returns w after st and what a system must be told to commit st
// in one go.
func (w World) Commit(st Step) (World, Change) {
	next := w.Apply(st...)

	return next, changes(w, next, st)
}

func changes(before, after World, st Step) Change {
	var c Change

	// A leave the step later undoes with a join of the same ID.
	var rejoined []types.NodeID

	for i, e := range st {
		if l, ok := e.(Leave); ok && slices.ContainsFunc(st[i+1:], func(o Edit) bool { j, ok := o.(Join); return ok && j.Node.ID == l.ID }) {
			rejoined = append(rejoined, l.ID)
		}
	}

	for _, n := range before.Topology.Nodes {
		if _, ok := after.Topology.Node(n.ID); !ok || slices.Contains(rejoined, n.ID) {
			c.Removed = append(c.Removed, n.ID)
		}
	}

	for _, n := range after.Topology.Nodes {
		old, ok := before.Topology.Node(n.ID)
		if !ok || !reflect.DeepEqual(old, n) || slices.Contains(rejoined, n.ID) {
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

// Join adds Node.
type Join struct{ Node Node }

func (e Join) apply(w *World) {
	if nodeIn(w, e.Node.ID) != nil {
		return
	}

	t := &w.Topology
	i, _ := slices.BinarySearchFunc(t.Nodes, e.Node.ID, func(n Node, id types.NodeID) int { return cmp.Compare(n.ID, id) })
	t.Nodes = slices.Insert(t.Nodes, i, e.Node.clone())
	t.NextID = max(t.NextID, e.Node.ID+1)
}

func (e Join) undo(World) Edit { return Leave{e.Node.ID} }

func (e Join) String() string { return "join " + e.Node.String() }

// Leave deletes a node.
type Leave struct{ ID types.NodeID }

func (e Leave) apply(w *World) {
	w.Topology.Nodes = slices.DeleteFunc(w.Topology.Nodes, func(n Node) bool { return n.ID == e.ID })
}

func (e Leave) undo(w World) Edit { return Join{w.mustNode(e.ID)} }

func (e Leave) String() string { return fmt.Sprintf("leave n%d", e.ID) }

// Retag sets a node's tags and the user it carries; no tags makes the
// user its owner.
type Retag struct {
	ID   types.NodeID
	Tags []int
	User uint
}

func (e Retag) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Tags, n.User = slices.Clone(e.Tags), e.User
	}
}

func (e Retag) undo(w World) Edit {
	n := w.mustNode(e.ID)

	return Retag{e.ID, n.Tags, n.User}
}

func (e Retag) String() string {
	if len(e.Tags) == 0 {
		return fmt.Sprintf("untag n%d to u%d", e.ID, e.User)
	}

	tags := make([]string, len(e.Tags))
	for i, t := range e.Tags {
		tags[i] = Tags[t]
	}

	s := fmt.Sprintf("retag n%d [%s]", e.ID, strings.Join(tags, " "))
	if e.User != 0 {
		s += fmt.Sprintf(" user=u%d", e.User)
	}

	return s
}

// SetOwner sets the user a node belongs to, or, if tagged, carries.
type SetOwner struct {
	ID   types.NodeID
	User uint
}

func (e SetOwner) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.User = e.User
	}
}

func (e SetOwner) undo(w World) Edit { return SetOwner{e.ID, w.mustNode(e.ID).User} }

func (e SetOwner) String() string { return fmt.Sprintf("n%d user=u%d", e.ID, e.User) }

// SetAddr sets a node's address in one family; the zero Addr is none.
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

func (e SetAddr) undo(w World) Edit {
	return SetAddr{e.ID, e.Family, w.mustNode(e.ID).Addr(e.Family)}
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

func (e SwapAddrs) undo(World) Edit { return e }

func (e SwapAddrs) String() string {
	return fmt.Sprintf("swap v%d of n%d and n%d", e.Family, e.A, e.B)
}

// Announce adds routes a node advertises.
type Announce struct {
	ID     types.NodeID
	Routes []int
}

func (e Announce) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Announced = addRoutes(n.Announced, e.Routes)
	}
}

func (e Announce) undo(w World) Edit {
	return Withdraw{e.ID, dropRoutes(e.Routes, w.mustNode(e.ID).Announced)}
}

func (e Announce) String() string {
	return fmt.Sprintf("n%d announces [%s]", e.ID, strings.Join(routeStrings(e.Routes), " "))
}

// Withdraw removes routes a node advertises; their approval stays.
type Withdraw struct {
	ID     types.NodeID
	Routes []int
}

func (e Withdraw) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Announced = dropRoutes(n.Announced, e.Routes)
	}
}

func (e Withdraw) undo(w World) Edit {
	return Announce{e.ID, keepRoutes(e.Routes, w.mustNode(e.ID).Announced)}
}

func (e Withdraw) String() string {
	return fmt.Sprintf("n%d withdraws [%s]", e.ID, strings.Join(routeStrings(e.Routes), " "))
}

// Approve approves routes for a node, announced or not.
type Approve struct {
	ID     types.NodeID
	Routes []int
}

func (e Approve) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Approved = addRoutes(n.Approved, e.Routes)
	}
}

func (e Approve) undo(w World) Edit {
	return Unapprove{e.ID, dropRoutes(e.Routes, w.mustNode(e.ID).Approved)}
}

func (e Approve) String() string {
	return fmt.Sprintf("approve [%s] for n%d", strings.Join(routeStrings(e.Routes), " "), e.ID)
}

// Unapprove takes routes' approval away; what is announced stays.
type Unapprove struct {
	ID     types.NodeID
	Routes []int
}

func (e Unapprove) apply(w *World) {
	if n := nodeIn(w, e.ID); n != nil {
		n.Approved = dropRoutes(n.Approved, e.Routes)
	}
}

func (e Unapprove) undo(w World) Edit {
	return Approve{e.ID, keepRoutes(e.Routes, w.mustNode(e.ID).Approved)}
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

func (e SetClient) undo(w World) Edit { return SetClient{e.ID, w.mustNode(e.ID).Client} }

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

func (e SetExpired) undo(w World) Edit { return SetExpired{e.ID, w.mustNode(e.ID).Expired} }

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

func (e SetOnline) undo(w World) Edit { return SetOnline{e.ID, !w.mustNode(e.ID).Offline} }

func (e SetOnline) String() string {
	if e.Online {
		return fmt.Sprintf("n%d online", e.ID)
	}

	return fmt.Sprintf("n%d offline", e.ID)
}

// AddUser adds User.
type AddUser struct{ User User }

func (e AddUser) apply(w *World) {
	if userIn(w, e.User.ID) != nil {
		return
	}

	t := &w.Topology
	i, _ := slices.BinarySearchFunc(t.Users, e.User.ID, func(u User, id uint) int { return cmp.Compare(u.ID, id) })
	t.Users = slices.Insert(t.Users, i, e.User)
}

func (e AddUser) undo(World) Edit { return DeleteUser{e.User.ID} }

func (e AddUser) String() string { return "add user " + e.User.String() }

// DeleteUser deletes a user no node belongs to or carries.
type DeleteUser struct{ ID uint }

func (e DeleteUser) apply(w *World) {
	w.Topology.Users = slices.DeleteFunc(w.Topology.Users, func(u User) bool { return u.ID == e.ID })
}

func (e DeleteUser) undo(w World) Edit {
	u, _ := w.Topology.User(e.ID)

	return AddUser{u}
}

func (e DeleteUser) String() string { return fmt.Sprintf("delete user u%d", e.ID) }

// RenameUser sets a user's name.
type RenameUser struct {
	ID   uint
	Name string
}

func (e RenameUser) apply(w *World) {
	if u := userIn(w, e.ID); u != nil {
		u.Name = e.Name
	}
}

func (e RenameUser) undo(w World) Edit {
	u, _ := w.Topology.User(e.ID)

	return RenameUser{e.ID, u.Name}
}

func (e RenameUser) String() string { return fmt.Sprintf("rename u%d to %s", e.ID, e.Name) }

// SetEmail sets a user's e-mail; "" is none.
type SetEmail struct {
	ID    uint
	Email string
}

func (e SetEmail) apply(w *World) {
	if u := userIn(w, e.ID); u != nil {
		u.Email = e.Email
	}
}

func (e SetEmail) undo(w World) Edit {
	u, _ := w.Topology.User(e.ID)

	return SetEmail{e.ID, u.Email}
}

func (e SetEmail) String() string { return fmt.Sprintf("u%d email=%q", e.ID, e.Email) }

// SetPorts sets the ports of an ACL's destination At, or of a grant's ip
// entry At.
type SetPorts struct {
	Rule      RuleRef
	At, Ports int
}

func (e SetPorts) apply(w *World) {
	r := &(*ruleList(&w.Policy, e.Rule.Grant))[e.Rule.I]
	if e.Rule.Grant {
		r.IP[e.At].Ports = e.Ports
	} else {
		r.Dst[e.At].Ports = e.Ports
	}
}

func (e SetPorts) undo(w World) Edit {
	r := w.Policy.Rule(e.Rule)
	if e.Rule.Grant {
		return SetPorts{e.Rule, e.At, r.IP[e.At].Ports}
	}

	return SetPorts{e.Rule, e.At, r.Dst[e.At].Ports}
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
	r := &(*ruleList(&w.Policy, e.Rule.Grant))[e.Rule.I]
	if e.Rule.Grant {
		r.IP[e.At].Proto = e.Proto
	} else {
		r.Proto = e.Proto
	}
}

func (e SetProto) undo(w World) Edit {
	r := w.Policy.Rule(e.Rule)
	if e.Rule.Grant {
		return SetProto{e.Rule, e.At, r.IP[e.At].Proto}
	}

	return SetProto{e.Rule, e.At, r.Proto}
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

// SwapRules swaps two rules of one list.
type SwapRules struct {
	Grant bool
	I, J  int
}

func (e SwapRules) apply(w *World) {
	l := *ruleList(&w.Policy, e.Grant)
	l[e.I], l[e.J] = l[e.J], l[e.I]
}

func (e SwapRules) undo(World) Edit { return e }

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
	r := &(*ruleList(&w.Policy, e.Rule.Grant))[e.Rule.I]
	if e.Dst {
		r.Dst[e.At].Sel = e.Sel
	} else {
		r.Src[e.At] = e.Sel
	}
}

func (e SetSel) undo(w World) Edit {
	r := w.Policy.Rule(e.Rule)
	if e.Dst {
		return SetSel{e.Rule, true, e.At, r.Dst[e.At].Sel}
	}

	return SetSel{e.Rule, false, e.At, r.Src[e.At]}
}

func (e SetSel) String() string {
	side := "src"
	if e.Dst {
		side = "dst"
	}

	return fmt.Sprintf("%s %s[%d]=%s", e.Rule, side, e.At, e.Sel)
}

// SetGroup sets a group's members, indices into UserRefs.
type SetGroup struct {
	Group   int
	Members []int
}

func (e SetGroup) apply(w *World) { w.Policy.Groups[e.Group] = slices.Clone(e.Members) }

func (e SetGroup) undo(w World) Edit { return SetGroup{e.Group, w.Policy.Groups[e.Group]} }

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

func (e SetHost) undo(w World) Edit { return SetHost{e.Host, w.Policy.Hosts[e.Host]} }

func (e SetHost) String() string {
	return fmt.Sprintf("%s=%s", Hosts[e.Host], Prefixes[(hostDefault[e.Host]+e.Shift)%numRulePrefixes])
}

// SetTagOwners sets a tag's owners.
type SetTagOwners struct {
	Tag    int
	Owners []Sel
}

func (e SetTagOwners) apply(w *World) { w.Policy.TagOwners[e.Tag] = slices.Clone(e.Owners) }

func (e SetTagOwners) undo(w World) Edit { return SetTagOwners{e.Tag, w.Policy.TagOwners[e.Tag]} }

func (e SetTagOwners) String() string {
	return fmt.Sprintf("tagOwners %s=%s", Tags[e.Tag], joinSels(e.Owners))
}

// AddRule inserts Rule at Ref.
type AddRule struct {
	Ref  RuleRef
	Rule Rule
}

func (e AddRule) apply(w *World) {
	l := ruleList(&w.Policy, e.Ref.Grant)
	*l = slices.Insert(*l, e.Ref.I, e.Rule.clone())
}

func (e AddRule) undo(World) Edit { return RemoveRule{e.Ref} }

func (e AddRule) String() string { return fmt.Sprintf("add %s %s", e.Ref, e.Rule.json(e.Ref.Grant)) }

// RemoveRule deletes a rule.
type RemoveRule struct{ Ref RuleRef }

func (e RemoveRule) apply(w *World) {
	l := ruleList(&w.Policy, e.Ref.Grant)
	*l = slices.Delete(*l, e.Ref.I, e.Ref.I+1)
}

func (e RemoveRule) undo(w World) Edit { return AddRule{e.Ref, w.Policy.Rule(e.Ref)} }

func (e RemoveRule) String() string { return "remove " + e.Ref.String() }

// SetSSH replaces the ssh section.
type SetSSH struct{ Rules []SSHRule }

func (e SetSSH) apply(w *World) { w.Policy.SSH = cloneEach(e.Rules, SSHRule.clone) }

func (e SetSSH) undo(w World) Edit { return SetSSH{w.Policy.SSH} }

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

func (e SetNodeAttrs) undo(w World) Edit { return SetNodeAttrs{w.Policy.NodeAttrs} }

func (e SetNodeAttrs) String() string {
	as := make([]string, len(e.Attrs))
	for i, a := range e.Attrs {
		as[i] = a.json()
	}

	return "nodeAttrs=[" + strings.Join(as, ", ") + "]"
}

// SetAutoApprovers replaces the autoApprovers section.
type SetAutoApprovers struct{ AutoApprovers AutoApprovers }

func (e SetAutoApprovers) apply(w *World) { w.Policy.AutoApprovers = e.AutoApprovers.clone() }

func (e SetAutoApprovers) undo(w World) Edit { return SetAutoApprovers{w.Policy.AutoApprovers} }

func (e SetAutoApprovers) String() string { return "autoApprovers=" + e.AutoApprovers.json() }

func indent(s string) string {
	var b strings.Builder

	for line := range strings.Lines(s) {
		b.WriteString("  " + line)
	}

	return b.String()
}
