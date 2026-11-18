package policymodel

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Policy is a policy document as indices into the vocabulary. Every value
// the generators draw is one headscale accepts; HuJSON writes it.
type Policy struct {
	// Groups holds each group's members, indices into UserRefs.
	Groups [numGroups][]int
	// TagOwners holds each tag's owners: users, groups and tags.
	TagOwners [numTags][]Sel
	// Hosts holds how far each host is moved from its default prefix
	// (hostDefault), among the rule prefixes; zero is the default.
	Hosts [numHosts]int

	ACLs, Grants []Rule

	SSH           []SSHRule
	NodeAttrs     []NodeAttr
	AutoApprovers AutoApprovers
}

// Rule is an ACL or a grant; which is the list it is in.
type Rule struct {
	Src []Sel
	Dst []Dest

	// Proto is an ACL's protocol, an index into Protos.
	Proto int

	// IP, App and Via are a grant's.
	IP  []IP
	App []App
	// Via holds tags, indices into Tags.
	Via []int
}

// Dest is a destination; Ports, an index into Ports, is an ACL's.
type Dest struct {
	Sel   Sel
	Ports int
}

// IP is one entry of a grant's ip list: indices into Protos and Ports.
type IP struct {
	Proto, Ports int
}

// App is one app capability of a grant: indices into Apps and AppValues.
type App struct {
	Cap, Value int
}

// SSHRule is one rule of the ssh section.
type SSHRule struct {
	Check    bool
	Src, Dst []Sel
	// Users holds logins, indices into SSHUsers.
	Users []int
}

// NodeAttr grants node attributes, indices into Attrs, to its targets.
type NodeAttr struct {
	Targets []Sel
	Attrs   []int
}

// AutoApprovers is the autoApprovers section; approvers are users,
// groups and tags.
type AutoApprovers struct {
	Routes []RouteApproval
	Exit   []Sel
}

// RouteApproval approves Route, an index into Prefixes, for By.
type RouteApproval struct {
	Route int
	By    []Sel
}

// HostPrefix is the prefix host h names in p.
func (p Policy) HostPrefix(h int) int {
	return (hostDefault[h] + p.Hosts[h]) % numRulePrefixes
}

// RuleRef names a rule by its place in the document.
type RuleRef struct {
	Grant bool
	I     int
}

func (r RuleRef) String() string {
	if r.Grant {
		return fmt.Sprintf("grants[%d]", r.I)
	}

	return fmt.Sprintf("acls[%d]", r.I)
}

// List is the ACLs or the grants.
func (p Policy) List(grant bool) []Rule {
	if grant {
		return p.Grants
	}

	return p.ACLs
}

func ruleList(p *Policy, grant bool) *[]Rule {
	if grant {
		return &p.Grants
	}

	return &p.ACLs
}

// Rule returns the rule r names.
func (p Policy) Rule(r RuleRef) Rule { return p.List(r.Grant)[r.I] }

// Refs is every rule, ACLs first.
func (p Policy) Refs() []RuleRef {
	refs := make([]RuleRef, 0, len(p.ACLs)+len(p.Grants))
	for i := range p.ACLs {
		refs = append(refs, RuleRef{I: i})
	}

	for i := range p.Grants {
		refs = append(refs, RuleRef{Grant: true, I: i})
	}

	return refs
}

// selfRule reports whether r has an autogroup:self destination.
func (r Rule) selfRule() bool {
	return slices.ContainsFunc(r.Dst, func(d Dest) bool { return d.Sel.Kind == SelSelf })
}

// Selectors returns every selector the rules, via lists and ssh rules
// name, once each, in order of first appearance: what a selector table
// would hold.
func (p Policy) Selectors() []Sel {
	var out []Sel

	add := func(s Sel) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}

	for _, r := range slices.Concat(p.ACLs, p.Grants) {
		for _, s := range r.Src {
			add(s)
		}

		for _, d := range r.Dst {
			add(d.Sel)
		}

		for _, v := range r.Via {
			add(Sel{Kind: SelTag, I: v})
		}
	}

	for _, r := range p.SSH {
		for _, s := range slices.Concat(r.Src, r.Dst) {
			add(s)
		}
	}

	return out
}

// names is which groups, tags and hosts a policy names.
type names struct {
	groups [numGroups]bool
	tags   [numTags]bool
	hosts  [numHosts]bool
}

// referenced reports which groups, tags and hosts p names anywhere.
func (p Policy) referenced() names {
	var ns names

	mark := func(sels ...Sel) {
		for _, s := range sels {
			switch s.Kind { //nolint:exhaustive // only these kinds name a definition
			case SelGroup:
				ns.groups[s.I] = true
			case SelTag:
				ns.tags[s.I] = true
			case SelHost:
				ns.hosts[s.I] = true
			}
		}
	}

	for _, r := range slices.Concat(p.ACLs, p.Grants) {
		mark(r.Src...)

		for _, d := range r.Dst {
			mark(d.Sel)
		}

		for _, v := range r.Via {
			ns.tags[v] = true
		}
	}

	for _, r := range p.SSH {
		mark(r.Src...)
		mark(r.Dst...)
	}

	for _, a := range p.NodeAttrs {
		mark(a.Targets...)
	}

	for _, owners := range p.TagOwners {
		mark(owners...)
	}

	for _, ra := range p.AutoApprovers.Routes {
		mark(ra.By...)
	}

	mark(p.AutoApprovers.Exit...)

	return ns
}

// HuJSON writes p as the document headscale parses, one rule to a line.
// It defines every group, tag and host p refers to, and no others unless
// they have members or owners.
func (p Policy) HuJSON() []byte {
	ns := p.referenced()

	var sections []member

	var gs []member

	for g := range numGroups {
		if ns.groups[g] || len(p.Groups[g]) > 0 {
			refs := make([]string, len(p.Groups[g]))
			for i, m := range p.Groups[g] {
				refs[i] = UserRefs[m]
			}

			gs = append(gs, member{Groups[g], strs(refs)})
		}
	}

	if len(gs) > 0 {
		sections = append(sections, member{"groups", object(gs...)})
	}

	var ts []member

	for i := range numTags {
		if ns.tags[i] || len(p.TagOwners[i]) > 0 {
			ts = append(ts, member{Tags[i], strs(selStrings(p.TagOwners[i]))})
		}
	}

	if len(ts) > 0 {
		sections = append(sections, member{"tagOwners", object(ts...)})
	}

	var hs []member

	for h := range numHosts {
		if ns.hosts[h] {
			hs = append(hs, member{Hosts[h], quote(Prefixes[p.HostPrefix(h)].String())})
		}
	}

	if len(hs) > 0 {
		sections = append(sections, member{"hosts", object(hs...)})
	}

	acls := make([]string, len(p.ACLs))
	for i, r := range p.ACLs {
		acls[i] = r.json(false)
	}

	grants := make([]string, len(p.Grants))
	for i, r := range p.Grants {
		grants[i] = r.json(true)
	}

	// No rule at all is written as an empty acls list: without one,
	// headscale would allow everything.
	if len(acls) > 0 || len(grants) == 0 {
		sections = append(sections, member{"acls", lines(acls)})
	}

	if len(grants) > 0 {
		sections = append(sections, member{"grants", lines(grants)})
	}

	if len(p.SSH) > 0 {
		rs := make([]string, len(p.SSH))
		for i, r := range p.SSH {
			rs[i] = r.json()
		}

		sections = append(sections, member{"ssh", lines(rs)})
	}

	if len(p.NodeAttrs) > 0 {
		as := make([]string, len(p.NodeAttrs))
		for i, a := range p.NodeAttrs {
			as[i] = a.json()
		}

		sections = append(sections, member{"nodeAttrs", lines(as)})
	}

	if aa := p.AutoApprovers; len(aa.Routes) > 0 || len(aa.Exit) > 0 {
		sections = append(sections, member{"autoApprovers", aa.json()})
	}

	var b strings.Builder

	b.WriteString("{\n")

	for i, s := range sections {
		b.WriteString("  " + quote(s.key) + ": " + s.val)

		if i < len(sections)-1 {
			b.WriteByte(',')
		}

		b.WriteByte('\n')
	}

	b.WriteString("}\n")

	return []byte(b.String())
}

// GoString prints p as its document, so a counterexample can be pasted
// into a regression test.
func (p Policy) GoString() string { return string(p.HuJSON()) }

func (r Rule) json(grant bool) string {
	dsts := make([]string, len(r.Dst))

	if grant {
		for i, d := range r.Dst {
			dsts[i] = d.Sel.String()
		}

		ms := []member{{"src", strs(selStrings(r.Src))}, {"dst", strs(dsts)}}

		if len(r.IP) > 0 {
			ips := make([]string, len(r.IP))
			for i, ip := range r.IP {
				ips[i] = ip.String()
			}

			ms = append(ms, member{"ip", strs(ips)})
		}

		if len(r.App) > 0 {
			caps := make([]member, len(r.App))
			for i, a := range r.App {
				caps[i] = member{Apps[a.Cap], "[" + AppValues[a.Value] + "]"}
			}

			ms = append(ms, member{"app", object(caps...)})
		}

		if len(r.Via) > 0 {
			via := make([]string, len(r.Via))
			for i, v := range r.Via {
				via[i] = Tags[v]
			}

			ms = append(ms, member{"via", strs(via)})
		}

		return object(ms...)
	}

	for i, d := range r.Dst {
		dsts[i] = d.Sel.String() + ":" + Ports[d.Ports]
	}

	ms := []member{{"action", quote("accept")}}
	if r.Proto != 0 {
		ms = append(ms, member{"proto", quote(Protos[r.Proto])})
	}

	ms = append(ms, member{"src", strs(selStrings(r.Src))}, member{"dst", strs(dsts)})

	return object(ms...)
}

func (ip IP) String() string {
	switch {
	case ip.Proto == 0 && ip.Ports == 0:
		return "*"
	case ip.Proto == 0:
		return Ports[ip.Ports]
	}

	return Protos[ip.Proto] + ":" + Ports[ip.Ports]
}

func (r SSHRule) json() string {
	action := "accept"
	if r.Check {
		action = "check"
	}

	users := make([]string, len(r.Users))
	for i, u := range r.Users {
		users[i] = SSHUsers[u]
	}

	return object(
		member{"action", quote(action)},
		member{"src", strs(selStrings(r.Src))},
		member{"dst", strs(selStrings(r.Dst))},
		member{"users", strs(users)},
	)
}

func (a NodeAttr) json() string {
	attrs := make([]string, len(a.Attrs))
	for j, x := range a.Attrs {
		attrs[j] = Attrs[x]
	}

	return object(member{"target", strs(selStrings(a.Targets))}, member{"attr", strs(attrs)})
}

func (aa AutoApprovers) json() string {
	var ms []member

	if len(aa.Routes) > 0 {
		rs := make([]member, len(aa.Routes))
		for i, ra := range aa.Routes {
			rs[i] = member{Prefixes[ra.Route].String(), strs(selStrings(ra.By))}
		}

		ms = append(ms, member{"routes", object(rs...)})
	}

	if len(aa.Exit) > 0 {
		ms = append(ms, member{"exitNode", strs(selStrings(aa.Exit))})
	}

	return object(ms...)
}

// member is a key and its value, already JSON.
type member struct{ key, val string }

func object(ms ...member) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = quote(m.key) + ": " + m.val
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

func strs(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = quote(s)
	}

	return "[" + strings.Join(parts, ", ") + "]"
}

// lines is a list with one element to a line.
func lines(elems []string) string {
	if len(elems) == 0 {
		return "[]"
	}

	return "[\n    " + strings.Join(elems, ",\n    ") + "\n  ]"
}

func quote(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r > '~' || r == '"' || r == '\\' }) {
		return `"` + s + `"`
	}

	b, err := json.Marshal(s)
	if err != nil {
		return strconv.Quote(s)
	}

	return string(b)
}
