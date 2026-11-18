// Reference semantics: what a policy means for one topology, written from
// the policy language's documentation and from what Tailscale's hosted
// service was captured doing, and sharing no code with headscale's policy
// packages. Plain sets and loops, nothing cached or incremental, so that it
// can be read against the documentation. It answers four questions:
//
//   - access ([Ref.Rules]): the rules a node must enforce, one per policy
//     rule it serves, sources and destinations as addresses. The client's
//     own filter turns them into verdicts and app capabilities, so holding
//     production to them through [Compare] ignores how either side writes
//     its rules: merging, order, reduction, capability or address form;
//   - visibility ([Ref.Peers]): whom a node is shown as a peer;
//   - route access ([Ref.Routes]): which of a peer's routes a viewer gets;
//   - stamps ([Ref.Stamps]): the source selectors a node is stamped with in
//     capability mode.
//
// Every clause a plain reading of the documentation would not predict is
// marked "Quirk:" with its evidence. Where headscale is seen to disagree,
// the reference keeps its reading and names the clause [Contested].

package policymodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
)

// Doc is a policy document as the reference reads it: what decides
// access, visibility and stamps. SSH, nodeAttrs, tag owners and
// auto-approvers decide none of them.
type Doc struct {
	Groups map[string][]string
	Hosts  map[string]netip.Prefix
	// Rules are the ACLs, one per destination entry, then the grants, in
	// document order.
	Rules []DocRule
}

// DocRule is one grant, or one destination entry of an ACL, which
// means the same as a grant with that destination.
type DocRule struct {
	Src, Dst []string
	IP       []IPSpec
	App      tailcfg.PeerCapMap
	Via      []string
}

// IPSpec is protocols and ports; no protocols is the client's default
// set.
type IPSpec struct {
	Protos []int
	Ports  []tailcfg.PortRange
}

// ParseDoc reads a policy document written as plain JSON. A document
// with neither acls nor grants allows everything, as Tailscale's own
// default policy does.
func ParseDoc(b []byte) (Doc, error) {
	var raw struct {
		Groups map[string][]string `json:"groups"`
		Hosts  map[string]string   `json:"hosts"`
		ACLs   *[]struct {
			Proto    json.RawMessage `json:"proto"`
			Src, Dst []string
		} `json:"acls"`
		Grants *[]struct {
			Src, Dst, IP, Via []string
			App               map[string][]json.RawMessage
		} `json:"grants"`
	}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return Doc{}, err
	}

	if raw.ACLs == nil && raw.Grants == nil {
		return ParseDoc([]byte(`{"acls": [{"src": ["*"], "dst": ["*:*"]}]}`))
	}

	doc := Doc{Groups: raw.Groups, Hosts: map[string]netip.Prefix{}}

	for name, h := range raw.Hosts {
		p, err := parsePrefix(h)
		if err != nil {
			return Doc{}, fmt.Errorf("host %s: %w", name, err)
		}

		doc.Hosts[name] = p
	}

	for _, acl := range deref(raw.ACLs) {
		var proto string
		if json.Unmarshal(acl.Proto, &proto) != nil {
			proto = strings.Trim(string(acl.Proto), `"`)
		}

		protos, err := protoNumbers(proto)
		if err != nil {
			return Doc{}, err
		}

		for _, d := range acl.Dst {
			sel, portSpec, ok := strings.CutLast(d, ":")
			if !ok {
				return Doc{}, fmt.Errorf("%w: %q", errNoPorts, d)
			}

			ports, err := parsePorts(portSpec)
			if err != nil {
				return Doc{}, err
			}

			doc.Rules = append(doc.Rules, DocRule{Src: acl.Src, Dst: []string{sel}, IP: []IPSpec{{Protos: protos, Ports: ports}}})
		}
	}

	for _, g := range deref(raw.Grants) {
		r := DocRule{Src: g.Src, Dst: g.Dst, Via: g.Via}

		for _, s := range g.IP {
			spec, err := parseIPSpec(s)
			if err != nil {
				return Doc{}, err
			}

			r.IP = append(r.IP, spec)
		}

		for c, vs := range g.App {
			if r.App == nil {
				r.App = tailcfg.PeerCapMap{}
			}

			r.App[peercap.Cap(c)] = nil

			for _, v := range vs {
				r.App[peercap.Cap(c)] = append(r.App[peercap.Cap(c)], tailcfg.RawMessage(v))
			}
		}

		doc.Rules = append(doc.Rules, r)
	}

	return doc, nil
}

func deref[E any](s *[]E) []E {
	if s == nil {
		return nil
	}

	return *s
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}

	a, err := netip.ParseAddr(s)

	return netip.PrefixFrom(a, a.BitLen()), err
}

var errNoPorts = errors.New("acl destination has no ports")

// internetSel is autogroup:internet, which via grants read apart.
const internetSel = "autogroup:internet"

// ianaProtocols are the protocol names a policy may write, by number.
var ianaProtocols = map[string]int{
	"icmp": 1, "igmp": 2, "ipv4": 4, "ip-in-ip": 4, "tcp": 6, "egp": 8, "igp": 9,
	"udp": 17, "gre": 47, "esp": 50, "ah": 51, "ipv6-icmp": 58, "sctp": 132, "fc": 133,
}

func protoNumbers(p string) ([]int, error) {
	p = strings.ToLower(p)
	if p == "" || p == "*" {
		return nil, nil
	}

	if n, ok := ianaProtocols[p]; ok {
		return []int{n}, nil
	}

	n, err := strconv.Atoi(p)
	if err != nil {
		return nil, fmt.Errorf("protocol %q: %w", p, err)
	}

	return []int{n}, nil
}

// parsePorts reads "*", or ports and ranges separated by commas.
func parsePorts(s string) ([]tailcfg.PortRange, error) {
	if s == "*" {
		return []tailcfg.PortRange{tailcfg.PortRangeAny}, nil
	}

	var out []tailcfg.PortRange

	for part := range strings.SplitSeq(s, ",") {
		first, last, isRange := strings.Cut(part, "-")
		if !isRange {
			last = first
		}

		f, err := strconv.ParseUint(first, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("ports %q: %w", s, err)
		}

		l, err := strconv.ParseUint(last, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("ports %q: %w", s, err)
		}

		out = append(out, tailcfg.PortRange{First: uint16(f), Last: uint16(l)})
	}

	return out, nil
}

// parseIPSpec reads one entry of a grant's ip list: "*", ports, a
// protocol, or a protocol and ports.
func parseIPSpec(s string) (IPSpec, error) {
	if s == "*" {
		return IPSpec{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}}, nil
	}

	proto, ports, hasProto := strings.Cut(s, ":")
	if !hasProto {
		first, _, _ := strings.Cut(s, "-")

		_, err := strconv.Atoi(first)
		if err == nil {
			proto, ports = "", s
		} else {
			proto, ports = s, "*"
		}
	}

	protos, err := protoNumbers(proto)
	if err != nil {
		return IPSpec{}, err
	}

	pr, err := parsePorts(ports)

	return IPSpec{Protos: protos, Ports: pr}, err
}

// RefNode is a node as the reference reads it.
type RefNode struct {
	ID types.NodeID
	// User owns the node unless it is tagged; zero for no user, or for a
	// user the topology does not hold.
	User uint
	Tags []string
	// Addrs holds the node's own addresses.
	Addrs []netip.Addr
	// Announced and Approved are the routes the node advertises and the
	// routes approved for it.
	Announced, Approved []netip.Prefix
}

func (n RefNode) tagged() bool { return len(n.Tags) > 0 }

// ServedRoutes are the routes n serves: announced and approved, exit
// routes included.
func (n RefNode) ServedRoutes() []netip.Prefix { return n.routes() }

// owner is the user whose devices autogroup:self and the user's own
// selectors name n among, or zero.
func (n RefNode) owner() uint {
	if n.tagged() {
		return 0
	}

	return n.User
}

// routes are the routes n serves: announced and approved.
func (n RefNode) routes() []netip.Prefix {
	var out []netip.Prefix

	for _, p := range n.Approved {
		if slices.Contains(n.Announced, p) {
			out = append(out, p)
		}
	}

	return out
}

// subnets are n's routes but its exit routes.
func (n RefNode) subnets() []netip.Prefix {
	return slices.DeleteFunc(n.routes(), isExitRoute)
}

func (n RefNode) exit() bool { return slices.ContainsFunc(n.routes(), isExitRoute) }

func isExitRoute(p netip.Prefix) bool { return p.Bits() == 0 }

// Address ranges the meaning names.
var (
	// everything is what * names as a destination, and danger-all.
	everything = setOf(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))

	// tailnetRanges is what * names as a source: the shared address space
	// tailnet addresses come from, but the range Tailscale leaves to
	// ChromeOS's VMs, and the tailnet's IPv6 range.
	tailnetRanges = setMinus(
		setOf(netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")),
		setOf(netip.MustParsePrefix("100.115.92.0/23")))

	// internet is autogroup:internet: public IPv4, which leaves out the
	// private, shared and link-local ranges, and global unicast IPv6.
	internet = setMinus(
		setOf(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("2000::/3")),
		setOf(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("169.254.0.0/16")))
)

// Ref is a policy read against a topology.
type Ref struct {
	doc   Doc
	users []User
	nodes []RefNode
	// rules are the document's rules resolved to addresses.
	rules []refRule
	// without is the contested clauses left out.
	without Contested
}

// Contested is a clause of the reference that headscale is seen to
// disagree with: reported to the maintainer, not encoded. Either no
// capture decides, or one decides for the reference and headscale is
// believed wrong. A property asks for the reference without such a clause
// only to tell a difference that is exactly that clause from any other.
type Contested uint8

const (
	// OthersSelf: an autogroup:self rule's sides are addresses like any
	// other rule's: a node holding or routing one of the user's devices'
	// addresses is on them, takes the rule for what it routes, sees the
	// other side and gets routes by it. Headscale applies a user's self
	// rules only with one of the user's devices at one end: it sends them
	// to those devices and to exit nodes, gives routes by a viewer's own
	// user's, and links two nodes only when one is the user's.
	OthersSelf Contested = 1 << iota
	// ViaDestinations: a via grant reaches what its via routers route of
	// its destinations, * being everything. Headscale writes each
	// destination as it stands at a via router with a route overlapping
	// it, so the router takes it for its own address too, and reads * as
	// the tailnet's ranges.
	ViaDestinations
	// ExitDestinationRoutes: an exit node serving an internet-reaching
	// rule is on its destinations' side for route access too, and gets
	// the routes overlapping its sources, so that hosts behind a subnet
	// router can use it. Captured: routes-b18 gives the exit node those
	// routes. Headscale gives it none (believed wrong).
	ExitDestinationRoutes
	// AppWildcard: * in an app grant is everything as a destination, as
	// it is for the grant's ports: a viewer among its sources gets subnet
	// routes by it as by an app grant to the subnet (captured, via golden
	// v84), and a companion to * reaches the internet, so exit nodes see
	// its sources. Headscale reads * as the tailnet's ranges for app
	// capabilities, both ways.
	AppWildcard

	// AllContested is every contested clause.
	AllContested = OthersSelf | ViaDestinations | ExitDestinationRoutes | AppWildcard
)

// Without returns r with the contested clauses c left out.
func (r *Ref) Without(c Contested) *Ref { return newRef(r.doc, r.users, r.nodes, c) }

// refRule is one rule resolved to addresses: a grant or ACL entry, its
// autogroup:self part for one owner, or a companion of either.
type refRule struct {
	src, dst *netipx.IPSet
	// internet: a via grant's destinations include autogroup:internet,
	// which only its exit nodes serve.
	internet bool
	ip       []IPSpec
	app      tailcfg.PeerCapMap
	// via restricts the rule to routers holding one of these tags.
	via []string
	// owner is the user an autogroup:self part is for.
	owner uint
}

// companions are the app capabilities that imply a capability the other
// way: the destinations are granted the companion by the sources.
// Quirk: the hosted service writes these rules, captured in the grant
// goldens for drive and relay.
var companions = []struct{ of, companion peercap.Cap }{
	{"tailscale.com/cap/drive", "tailscale.com/cap/drive-sharer"},
	{"tailscale.com/cap/relay", "tailscale.com/cap/relay-target"},
}

// RefOf reads w's policy, as headscale is given it, against w's topology.
func RefOf(w World) *Ref {
	doc, err := ParseDoc(w.Policy.HuJSON())
	if err != nil {
		panic(fmt.Sprintf("the model writes a document it cannot read: %v", err))
	}

	nodes := make([]RefNode, len(w.Topology.Nodes))

	for i, n := range w.Topology.Nodes {
		rn := RefNode{ID: n.ID, Addrs: n.Addrs()}

		if _, ok := w.Topology.User(n.User); ok {
			rn.User = n.User
		}

		for _, t := range n.Tags {
			rn.Tags = append(rn.Tags, Tags[t])
		}

		for _, p := range n.Announced {
			rn.Announced = append(rn.Announced, Prefixes[p])
		}

		for _, p := range n.Approved {
			rn.Approved = append(rn.Approved, Prefixes[p])
		}

		nodes[i] = rn
	}

	return NewRef(doc, w.Topology.Users, nodes)
}

// NewRef reads doc against users and nodes.
func NewRef(doc Doc, users []User, nodes []RefNode) *Ref { return newRef(doc, users, nodes, 0) }

func newRef(doc Doc, users []User, nodes []RefNode, without Contested) *Ref {
	r := &Ref{doc: doc, users: users, nodes: nodes, without: without}

	for _, d := range doc.Rules {
		var dsts []string

		self, inet := false, false

		for _, t := range d.Dst {
			switch {
			case t == "autogroup:self":
				self = true
			case t == internetSel && len(d.Via) > 0:
				inet = true
			default:
				dsts = append(dsts, t)
			}
		}

		base := refRule{src: r.addrs(d.Src, true), dst: r.addrs(dsts, false), internet: inet, ip: d.IP, app: d.App, via: d.Via}

		if len(d.Via) > 0 {
			// Quirk: via restricts a grant's ip part only; its app part
			// reaches and shows what a grant without via would (the via
			// goldens v80-v91: every router of the destination, via tag or
			// not, sees the sources of an app grant through via).
			via, app := base, base
			via.app, app.ip, app.via = nil, nil, nil

			if without&ViaDestinations != 0 {
				via.dst = r.starAsTailnet(dsts)
			}

			r.rules = append(r.rules, via)
			base = app
		}

		if without&AppWildcard != 0 && len(d.App) > 0 {
			app := base
			app.ip, app.dst = nil, r.starAsTailnet(dsts)
			base.app = nil
			r.add(app, r.addrs(dsts, true), r.starAsTailnet(d.Src))
		}

		if len(dsts) > 0 || inet {
			r.add(base, r.addrs(dsts, true), r.addrs(d.Src, false))
		}

		if !self || len(d.Via) > 0 {
			continue
		}

		// autogroup:self: for each user, from the user's devices the
		// sources name to all of the user's devices. Quirk: a source names
		// a device when it holds one of the device's addresses, and the
		// device is then a source by every address it has (sameUserSources
		// in the compile; captured in the self goldens, which hold no
		// device with only one address in a source).
		for _, u := range r.owners() {
			var devices, named []RefNode

			for _, n := range nodes {
				if n.owner() == u {
					devices = append(devices, n)

					if slices.ContainsFunc(n.Addrs, base.src.Contains) {
						named = append(named, n)
					}
				}
			}

			if len(named) > 0 {
				self := base
				self.src, self.dst, self.internet, self.owner = addrsOf(named), addrsOf(devices), false, u
				r.add(self, self.dst, self.src)
			}
		}
	}

	return r
}

// starAsTailnet is what terms name as destinations, reading * as the
// tailnet's ranges: headscale's reading where a clause is contested.
func (r *Ref) starAsTailnet(terms []string) *netipx.IPSet {
	rest := slices.DeleteFunc(slices.Clone(terms), func(t string) bool { return t == "*" })
	if len(rest) == len(terms) {
		return r.addrs(terms, false)
	}

	var b netipx.IPSetBuilder

	b.AddSet(r.addrs(rest, false))
	b.AddSet(tailnetRanges)

	s, _ := b.IPSet()

	return s
}

// add adds rl and its companions, which run from asSrc to asDst: the
// rule's destinations read as sources and its sources as destinations.
func (r *Ref) add(rl refRule, asSrc, asDst *netipx.IPSet) {
	if len(rl.ip) == 0 && len(rl.app) == 0 {
		return
	}

	r.rules = append(r.rules, rl)

	for _, c := range companions {
		if _, ok := rl.app[c.of]; ok {
			r.rules = append(r.rules, refRule{src: asSrc, dst: asDst, app: tailcfg.PeerCapMap{c.companion: nil}, owner: rl.owner})
		}
	}
}

// owners are the users with an untagged device, in ID order.
func (r *Ref) owners() []uint {
	var out []uint

	for _, n := range r.nodes {
		if u := n.owner(); u != 0 && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}

	slices.Sort(out)

	return out
}

// identity reports whether a selector names nodes rather than addresses.
func identity(sel string) bool {
	return strings.HasPrefix(sel, "tag:") || strings.HasPrefix(sel, "group:") || strings.Contains(sel, "@") ||
		sel == "autogroup:member" || sel == "autogroup:tagged"
}

// member reports whether n is a member of the identity selector sel.
// Users and groups name untagged devices by their owner; tags name the
// devices tagged with them.
func (r *Ref) member(n RefNode, sel string) bool {
	switch {
	case sel == "autogroup:member":
		return !n.tagged()
	case sel == "autogroup:tagged":
		return n.tagged()
	case strings.HasPrefix(sel, "tag:"):
		return slices.Contains(n.Tags, sel)
	case strings.HasPrefix(sel, "group:"):
		return slices.ContainsFunc(r.doc.Groups[sel], func(tok string) bool { return n.owner() != 0 && slices.Contains(r.usersOf(tok), n.owner()) })
	case strings.Contains(sel, "@"):
		return n.owner() != 0 && slices.Contains(r.usersOf(sel), n.owner())
	}

	return false
}

// usersOf resolves a user token. A domain names every user whose e-mail
// is in it. Quirk: a token names the one user whose e-mail it is, or
// failing that the one user whose name it is less a trailing "@"; two
// users at either step name nobody (headscale's, issue #3513; the users
// goldens).
func (r *Ref) usersOf(tok string) []uint {
	if domain, ok := strings.CutPrefix(tok, "user:*@"); ok {
		var out []uint

		for _, u := range r.users {
			i := strings.LastIndex(u.Email, "@")
			if i >= 0 && strings.EqualFold(u.Email[i+1:], domain) {
				out = append(out, u.ID)
			}
		}

		return out
	}

	name := strings.TrimSuffix(tok, "@")
	if name == "" {
		return nil
	}

	for _, field := range []func(User) string{func(u User) string { return u.Email }, func(u User) string { return u.Name }} {
		var hits []uint

		for _, u := range r.users {
			if field(u) == name {
				hits = append(hits, u.ID)
			}
		}

		if len(hits) == 1 {
			return hits
		}

		if len(hits) > 1 {
			return nil
		}
	}

	return nil
}

// addrs is what terms name as addresses, as sources or as destinations.
func (r *Ref) addrs(terms []string, asSrc bool) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, t := range terms {
		switch {
		case t == "*" && asSrc:
			// Quirk: * as a source is the tailnet's ranges and every
			// approved subnet route, announced or not (the acl goldens).
			b.AddSet(tailnetRanges)

			for _, n := range r.nodes {
				for _, p := range n.Approved {
					if !isExitRoute(p) {
						b.AddPrefix(p)
					}
				}
			}
		case t == "*", t == "autogroup:danger-all":
			b.AddSet(everything)
		case t == internetSel:
			b.AddSet(internet)
		case identity(t):
			for _, n := range r.nodes {
				if r.member(n, t) {
					for _, a := range n.Addrs {
						b.Add(a)
					}
				}
			}
		default:
			p, ok := r.doc.Hosts[t]
			if !ok {
				var err error

				p, err = parsePrefix(t)
				if err != nil {
					continue
				}
			}

			b.AddPrefix(p)
		}
	}

	s, _ := b.IPSet()

	return s
}

// served is what n takes packets for: its own addresses and its routes.
func (n RefNode) served() *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, a := range n.Addrs {
		b.Add(a)
	}

	for _, p := range n.routes() {
		b.AddPrefix(p)
	}

	s, _ := b.IPSet()

	return s
}

// dstsAt is the part of rl's destinations that n takes packets for.
// A via rule reaches only the routers holding a via tag, for their
// routes, and autogroup:internet through via only exit nodes.
func (r *Ref) dstsAt(rl refRule, n RefNode) *netipx.IPSet {
	var b netipx.IPSetBuilder

	if len(rl.via) > 0 {
		if !slices.ContainsFunc(rl.via, func(t string) bool { return slices.Contains(n.Tags, t) }) {
			return &netipx.IPSet{}
		}

		for _, p := range n.subnets() {
			b.AddPrefix(p)
		}

		if r.without&ViaDestinations != 0 {
			b = netipx.IPSetBuilder{}

			for _, p := range rl.dst.Prefixes() {
				if slices.ContainsFunc(n.subnets(), p.Overlaps) {
					b.AddPrefix(p)
				}
			}

			b.Intersect(n.served())
		}
	} else {
		b.AddSet(n.served())
	}

	b.Intersect(rl.dst)

	if rl.internet {
		var exits netipx.IPSetBuilder

		for _, p := range n.routes() {
			if isExitRoute(p) {
				exits.AddPrefix(p)
			}
		}

		exits.Intersect(internet)
		s, _ := exits.IPSet()
		b.AddSet(s)
	}

	s, _ := b.IPSet()

	return s
}

// ownSelf reports whether rl counts at n with [OthersSelf] left out: it
// is no autogroup:self rule, or one for n's own user.
func (r *Ref) ownSelf(rl refRule, n RefNode) bool {
	return r.without&OthersSelf == 0 || rl.owner == 0 || rl.owner == n.owner()
}

func (r *Ref) node(id types.NodeID) (RefNode, bool) {
	i := slices.IndexFunc(r.nodes, func(n RefNode) bool { return n.ID == id })
	if i < 0 {
		return RefNode{}, false
	}

	return r.nodes[i], true
}

// Serves reports whether node id takes packets for a: one of its own
// addresses, or inside one of its routes.
func (r *Ref) Serves(id types.NodeID, a netip.Addr) bool {
	n, ok := r.node(id)

	return ok && n.served().Contains(a)
}

// What the reference leaves out of its domain: configurations headscale
// does not support, where its behaviour follows from how the code is
// built rather than from what a policy means. A property skips and counts
// them.
const (
	// OutsideAddress: a node holds an address outside the tailnet's
	// ranges, which headscale does not hand out. * then means one thing
	// for ports, another for app capabilities, and a third as an
	// autogroup:self source.
	OutsideAddress = "a node holds an address outside the tailnet"
	// SharedAddress: the receiver holds an address another node holds,
	// which headscale never hands out twice. Which node a packet for the
	// address reaches is not the policy's to say, and a destination granted
	// per device counts the address once per device holding it.
	SharedAddress = "the receiver shares an address"
)

// OutOfDomain returns why the reference does not speak for this world, or
// "" when it does.
func (r *Ref) OutOfDomain() string {
	for _, n := range r.nodes {
		if slices.ContainsFunc(n.Addrs, func(a netip.Addr) bool { return !tailnetRanges.Contains(a) }) {
			return OutsideAddress
		}
	}

	return ""
}

// ReceiverOutOfDomain returns why the reference does not speak for what
// node id accepts, or the routes it is given as a viewer, or "" when it
// does.
func (r *Ref) ReceiverOutOfDomain(id types.NodeID) string {
	if why := r.OutOfDomain(); why != "" {
		return why
	}

	n, _ := r.node(id)

	if slices.ContainsFunc(r.nodes, func(m RefNode) bool {
		return m.ID != id && slices.ContainsFunc(m.Addrs, func(a netip.Addr) bool { return slices.Contains(n.Addrs, a) })
	}) {
		return SharedAddress
	}

	return ""
}

// Rules are the rules node id must enforce, in document order: for each
// rule whose destinations it takes packets for, the rule's sources to
// those destinations, by addresses.
func (r *Ref) Rules(id types.NodeID) []tailcfg.FilterRule {
	n, ok := r.node(id)
	if !ok {
		return nil
	}

	var out []tailcfg.FilterRule

	for _, rl := range r.rules {
		if !r.ownSelf(rl, n) {
			continue
		}

		dst := r.dstsAt(rl, n)
		if len(dst.Prefixes()) == 0 || len(rl.src.Prefixes()) == 0 {
			continue
		}

		srcs := prefixStrings(rl.src.Prefixes())

		for _, spec := range rl.ip {
			fr := tailcfg.FilterRule{SrcIPs: srcs, IPProto: spec.Protos}

			for _, p := range dst.Prefixes() {
				for _, ports := range spec.Ports {
					fr.DstPorts = append(fr.DstPorts, tailcfg.NetPortRange{IP: p.String(), Ports: ports})
				}
			}

			out = append(out, fr)
		}

		// Quirk: app capabilities are granted at a node's own addresses,
		// never at addresses it routes, subnet or exit (the grant goldens
		// with * as destination at subnet routers; the via goldens v84-v104
		// with a subnet or a public prefix as destination).
		var own netipx.IPSetBuilder

		for _, a := range n.Addrs {
			own.Add(a)
		}

		own.Intersect(dst)

		if caps, _ := own.IPSet(); len(rl.app) > 0 && len(caps.Prefixes()) > 0 {
			out = append(out, tailcfg.FilterRule{SrcIPs: srcs, CapGrant: []tailcfg.CapGrant{{Dsts: caps.Prefixes(), CapMap: rl.app}}})
		}
	}

	return out
}

// Peers are the nodes node id is shown, in ID order. A node sees another
// when a rule has one on its sources' side and the other on its
// destinations' side, either way round; and every device of its own user.
// Quirk: an exit node also sees, one way, the sources of an app grant
// whose destinations reach the internet (captured: the grant goldens hold
// such pairs, where the sources do not see the exit node).
func (r *Ref) Peers(id types.NodeID) []types.NodeID {
	n, ok := r.node(id)
	if !ok {
		return nil
	}

	var out []types.NodeID

	for _, m := range r.nodes {
		if m.ID != id && r.sees(n, m) {
			out = append(out, m.ID)
		}
	}

	return out
}

func (r *Ref) sees(n, m RefNode) bool {
	if n.owner() != 0 && n.owner() == m.owner() {
		return true
	}

	for _, rl := range r.rules {
		if r.without&OthersSelf != 0 && rl.owner != 0 && n.owner() != rl.owner && m.owner() != rl.owner {
			continue
		}

		if rl.links(n, m) || rl.links(m, n) {
			return true
		}

		if len(rl.app) > 0 && n.exit() && rl.reachesInternet() && on(m, rl.src) {
			return true
		}
	}

	return false
}

// on reports whether n is on the side of a rule whose addresses are s: it
// holds one of them, or one of its subnet routes overlaps them. Quirk: a
// router whose route covers a node's address is on that node's side, and
// so is a node sharing its address (the goldens hold routers over
// tailnet addresses).
func on(n RefNode, s *netipx.IPSet) bool {
	return slices.ContainsFunc(n.Addrs, s.Contains) || slices.ContainsFunc(n.subnets(), s.OverlapsPrefix)
}

func (rl refRule) reachesInternet() bool { return rl.internet || rl.dst.Overlaps(internet) }

// onDst reports whether n is on rl's destinations' side: by address or
// route, or as an exit node when a port rule's destinations reach the
// internet. A via rule's destination side is its via routers that have
// an address.
func (rl refRule) onDst(n RefNode) bool {
	if len(rl.via) > 0 {
		return len(n.Addrs) > 0 && slices.ContainsFunc(rl.via, func(t string) bool { return slices.Contains(n.Tags, t) }) &&
			(slices.ContainsFunc(n.subnets(), rl.dst.OverlapsPrefix) || rl.internet && n.exit())
	}

	return on(n, rl.dst) || len(rl.ip) > 0 && n.exit() && rl.reachesInternet()
}

func (rl refRule) links(src, dst RefNode) bool { return on(src, rl.src) && rl.onDst(dst) }

// Routes are the routes of peer that viewer is given, in the peer's
// order: an exit route when the viewer may send packets to the internet,
// as a source of a port rule reaching it (an app grant does not: the via
// golden v104); a subnet route when the viewer is on one side of a rule and
// the route overlaps the other. Via grants are not read: they grant
// routes through steering, which the reference does not model.
func (r *Ref) Routes(viewer, peer types.NodeID) []netip.Prefix {
	v, ok := r.node(viewer)
	p, okp := r.node(peer)

	if !ok || !okp {
		return nil
	}

	var out []netip.Prefix

	for _, q := range p.routes() {
		keep := slices.ContainsFunc(r.rules, func(rl refRule) bool {
			if len(rl.via) > 0 || !r.ownSelf(rl, v) {
				return false
			}

			if isExitRoute(q) {
				return on(v, rl.src) && len(rl.ip) > 0 && rl.reachesInternet()
			}

			dstSide := rl.onDst(v)
			if r.without&ExitDestinationRoutes != 0 {
				dstSide = on(v, rl.dst)
			}

			return on(v, rl.src) && rl.dst.OverlapsPrefix(q) || dstSide && rl.src.OverlapsPrefix(q)
		})
		if keep {
			out = append(out, q)
		}
	}

	return out
}

// HasVia reports whether a rule is a via grant.
func (r *Ref) HasVia() bool {
	return slices.ContainsFunc(r.doc.Rules, func(d DocRule) bool { return len(d.Via) > 0 })
}

// StampPrefix is the namespace of the capabilities capability mode stamps
// nodes with, one per source selector a node is a member of; an
// autogroup:self rule's is "owner:" and the user's ID.
const StampPrefix = "https://headscale.net/cap/src/"

// Stamps are the source selectors node id is stamped with in capability
// mode, sorted: every identity selector it is a member of that is a
// source of a rule a client can match by capability, and its owner when
// such a rule is an autogroup:self rule with an identity source. A rule a
// client can match by capability has sources, destinations, no via, and
// an ip entry whose protocols the client checks capabilities for; app
// capabilities alone are not, since the client does not look them up by
// capability.
func (r *Ref) Stamps(id types.NodeID) []string {
	n, ok := r.node(id)
	if !ok {
		return nil
	}

	var out []string

	owner := false

	for _, d := range r.doc.Rules {
		if len(d.Via) > 0 || len(d.Src) == 0 || len(d.Dst) == 0 || !slices.ContainsFunc(d.IP, capMatched) {
			continue
		}

		for _, s := range d.Src {
			if identity(s) {
				owner = owner || slices.Contains(d.Dst, "autogroup:self")

				if r.member(n, s) {
					out = append(out, s)
				}
			}
		}
	}

	if owner && n.owner() != 0 {
		out = append(out, "owner:"+strconv.FormatUint(uint64(n.owner()), 10))
	}

	slices.Sort(out)

	return slices.Compact(out)
}

// capMatched reports whether the client matches spec's protocols by
// capability: TCP, UDP, SCTP and ICMP of either family, or its default.
func capMatched(spec IPSpec) bool {
	return !slices.ContainsFunc(spec.Protos, func(p int) bool { return !slices.Contains([]int{1, 6, 17, 58, 132}, p) })
}

// Netmap is what node id's client is told of itself and its peers in
// capability mode, by the reference: addresses, and stamps as
// capabilities.
func (r *Ref) Netmap(id types.NodeID) (tailcfg.NodeView, []tailcfg.NodeView) {
	render := func(n RefNode) tailcfg.NodeView {
		tn := &tailcfg.Node{ID: tailcfg.NodeID(n.ID), CapMap: tailcfg.NodeCapMap{}} //nolint:gosec // test IDs are small

		for _, a := range n.Addrs {
			tn.Addresses = append(tn.Addresses, netip.PrefixFrom(a, a.BitLen()))
		}

		for _, s := range r.Stamps(n.ID) {
			tn.CapMap[nodecap.Cap(StampPrefix+s)] = nil
		}

		return tn.View()
	}

	n, _ := r.node(id)

	ids := r.Peers(id)
	peers := make([]tailcfg.NodeView, 0, len(ids))

	for _, p := range ids {
		pn, _ := r.node(p)
		peers = append(peers, render(pn))
	}

	return render(n), peers
}

func setOf(ps ...netip.Prefix) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, p := range ps {
		b.AddPrefix(p)
	}

	s, _ := b.IPSet()

	return s
}

func setMinus(a, b *netipx.IPSet) *netipx.IPSet {
	var sb netipx.IPSetBuilder

	sb.AddSet(a)
	sb.RemoveSet(b)

	s, _ := sb.IPSet()

	return s
}

func addrsOf(nodes []RefNode) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, n := range nodes {
		for _, a := range n.Addrs {
			b.Add(a)
		}
	}

	s, _ := b.IPSet()

	return s
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}

	return out
}
