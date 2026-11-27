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
// the reference keeps its reading and names the clause [Contested]; none
// is open now.

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
	// Unavailable is a node offline or expired: no router an election
	// picks while another is available.
	Unavailable bool
}

func (n RefNode) tagged() bool { return len(n.Tags) > 0 }

// ServedRoutes are the routes n serves: announced and approved, exit
// routes included.
func (n RefNode) ServedRoutes() []netip.Prefix { return n.routes() }

// owner is the user whose devices autogroup:self and the user's own
// selectors name n among, or zero: a tagged device belongs to its tags.
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

func (n RefNode) subnets() []netip.Prefix { return slices.DeleteFunc(n.routes(), isExitRoute) }

func (n RefNode) exitRoutes() []netip.Prefix {
	return slices.DeleteFunc(n.routes(), func(p netip.Prefix) bool { return !isExitRoute(p) })
}

func (n RefNode) exit() bool { return len(n.exitRoutes()) > 0 }

func (n RefNode) hasTag(tags []string) bool {
	return slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(n.Tags, t) })
}

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

	// internet is the internet an exit node serves autogroup:internet for:
	// public IPv4, which leaves out the private, shared and link-local
	// ranges, and global unicast IPv6.
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
	// elections is the history elections read, if any (see
	// [Ref.WithElections]).
	elections *Elections
}

// Contested is a clause of the reference that headscale is seen to
// disagree with: reported to the maintainer, not encoded. Either no
// capture or document decides it, and the reference takes the plain
// reading; or one decides for the reference and headscale is believed
// wrong. Leaving a clause out restates headscale's behaviour in that
// clause's scope alone; a property asks for it only to tell a difference
// that is exactly that clause from any other.
//
// No clause is open: every one raised so far was settled against a capture
// of the hosted service. The mechanism stays for the next: declare the
// clause as a bit here, list and name it below, and branch on r.without
// where the readings part.
type Contested uint16

// ContestedClauses is every contested clause, in the order a property
// tries them; contestedNames their names, in the same order.
var (
	ContestedClauses = []Contested{}
	contestedNames   = []string{}
)

// FailsOpen reports whether headscale's side of c admits what the
// reference refuses.
func (c Contested) FailsOpen() bool { return false }

func (c Contested) String() string {
	var parts []string

	for i, k := range ContestedClauses {
		if c&k != 0 {
			parts = append(parts, contestedNames[i])
		}
	}

	return strings.Join(parts, " + ")
}

// Without returns r with the contested clauses c left out.
func (r *Ref) Without(c Contested) *Ref {
	out := newRef(r.doc, r.users, r.nodes, c)
	out.elections = r.elections

	return out
}

// dstTerm is one destination entry resolved: one node's address for an
// entry naming nodes, else all the entry names.
type dstTerm struct {
	set *netipx.IPSet
	// internet is set for autogroup:internet; star for *, which is sent
	// as one entry over both families.
	internet, star bool
}

// refRule is one rule resolved to addresses: a grant or ACL entry, its
// autogroup:self part for one owner, or a companion of either.
type refRule struct {
	src, dst *netipx.IPSet
	// terms are the destinations one entry at a time, as a node is sent
	// them; none stands for dst as one entry.
	terms []dstTerm
	// appDsts are the destination entries of an app grant, each once: a
	// node is granted the capability once for each that names it. None
	// stands for dst as one entry.
	appDsts []*netipx.IPSet
	// internet: a via rule names autogroup:internet, which only its exit
	// nodes serve; dst leaves it out.
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
// Quirk: the hosted service writes these rules (grant goldens k11, b3,
// f4 for drive; relay in the via goldens).
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
		rn := RefNode{ID: n.ID, Addrs: n.Addrs(), Unavailable: n.Offline || n.Expired}

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

		self := false

		for _, t := range d.Dst {
			if t == "autogroup:self" {
				self = true
			} else {
				dsts = append(dsts, t)
			}
		}

		// Quirk: autogroup:internet is an address set like any other: a
		// subnet router of a public prefix takes the rule, is on its side
		// and has the route given by it (routes-internet-public-subnet).
		base := refRule{src: r.srcAddrs(d.Src), dst: r.addrs(dsts, false), terms: r.terms(dsts), ip: d.IP, app: d.App}

		// Quirk: an entry the document repeats counts once
		// (grant-app-destination-repeated).
		for i, t := range dsts {
			if len(d.App) > 0 && !slices.Contains(dsts[:i], t) {
				base.appDsts = append(base.appDsts, r.addrs([]string{t}, false))
			}
		}

		if len(d.Via) > 0 {
			// Quirk: via restricts a grant's ip part only; its app part
			// reaches and shows what a grant without via would (via goldens
			// v80-v91: every router of the destination, via tag or not, sees
			// the sources of an app grant through via).
			via := base
			via.app, via.via = nil, d.Via
			// Quirk: through via, autogroup:internet is served by exit
			// nodes alone.
			via.internet = slices.Contains(dsts, internetSel)
			via.dst = r.addrs(slices.DeleteFunc(slices.Clone(dsts), func(t string) bool { return t == internetSel }), false)

			r.add(via, nil, nil)

			base.ip = nil
		}

		if len(dsts) > 0 {
			// A companion's destinations are the grant's sources as they
			// resolve: * the tailnet's ranges. Headscale's reading; no
			// capture holds a companion from an exit node's view.
			r.add(base, r.srcAddrs(dsts), r.starAsTailnet(d.Src))
		}

		if self {
			r.addSelf(base)
		}
	}

	return r
}

// addSelf adds rl's autogroup:self part: for each user, from the
// addresses rl's sources name among the user's devices to all of the
// user's devices. autogroup:self is "devices where the same user is
// authenticated on both the source and destination", tagged devices
// excluded (docs/ref/policy.md).
func (r *Ref) addSelf(rl refRule) {
	for _, u := range r.owners() {
		var devices []RefNode

		for _, n := range r.nodes {
			if n.owner() == u {
				devices = append(devices, n)
			}
		}

		var b netipx.IPSetBuilder

		b.AddSet(rl.src)
		b.Intersect(addrsOf(devices))

		named, _ := b.IPSet()
		if len(named.Prefixes()) == 0 {
			continue
		}

		self := rl
		self.src, self.dst, self.terms, self.appDsts, self.owner = named, addrsOf(devices), nodeTerms(devices), nil, u

		r.add(self, self.dst, self.src)
	}
}

// terms resolves destination entries one at a time.
func (r *Ref) terms(names []string) []dstTerm {
	var out []dstTerm

	for _, t := range names {
		if !identity(t) {
			out = append(out, dstTerm{set: r.addrs([]string{t}, false), internet: t == internetSel, star: t == "*"})

			continue
		}

		var members []RefNode

		for _, n := range r.nodes {
			if r.member(n, t) {
				members = append(members, n)
			}
		}

		out = append(out, nodeTerms(members)...)
	}

	return out
}

// nodeTerms is one term for each address of nodes.
func nodeTerms(nodes []RefNode) []dstTerm {
	var out []dstTerm

	for _, n := range nodes {
		for _, a := range n.Addrs {
			out = append(out, dstTerm{set: setOf(netip.PrefixFrom(a, a.BitLen()))})
		}
	}

	return out
}

// starAsTailnet is what terms name as destinations, reading * as the
// tailnet's ranges.
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
// devices tagged with them; autogroup:member is every untagged device and
// autogroup:tagged every tagged one (docs/ref/policy.md, Autogroups).
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

// usersOf resolves a user token as docs/ref/oidc.md ("Reference a user
// in the policy") says: the value is the token less the one "@" appended
// to a value that has none; it names the user with that provider
// identifier, failing that the one user with that e-mail, failing that
// the one user with that name; two at either of the last steps name
// nobody. A domain names every user whose e-mail is in it, domains
// compared without case (the users goldens hold one).
func (r *Ref) usersOf(tok string) []uint {
	if domain, ok := strings.CutPrefix(tok, "user:*@"); ok {
		var out []uint

		for _, u := range r.users {
			if _, d, ok := strings.Cut(u.Email, "@"); ok && strings.EqualFold(d, domain) {
				out = append(out, u.ID)
			}
		}

		return out
	}

	value := strings.TrimSuffix(tok, "@")
	if value == "" {
		return nil
	}

	for _, u := range r.users {
		if u.Provider != "" && u.Provider == value {
			return []uint{u.ID}
		}
	}

	for _, field := range []func(User) string{func(u User) string { return u.Email }, func(u User) string { return u.Name }} {
		var hits []uint

		for _, u := range r.users {
			if field(u) == value {
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

// srcAddrs is what terms name as sources. Quirk: * as a source adds
// every approved subnet route, announced or not (acl and grant goldens,
// e.g. grant-a1's 10.33.0.0/16; the owner-routes step capture for a route
// no longer announced).
func (r *Ref) srcAddrs(terms []string) *netipx.IPSet {
	if !slices.Contains(terms, "*") {
		return r.addrs(terms, true)
	}

	var b netipx.IPSetBuilder

	b.AddSet(r.addrs(terms, true))

	for _, n := range r.nodes {
		for _, p := range n.Approved {
			if !isExitRoute(p) {
				b.AddPrefix(p)
			}
		}
	}

	s, _ := b.IPSet()

	return s
}

// addrs is what terms name as addresses, as sources or as destinations.
func (r *Ref) addrs(terms []string, asSrc bool) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, t := range terms {
		switch {
		case t == "*" && asSrc:
			b.AddSet(tailnetRanges)
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

// served is what n takes packets for: its own addresses and its routes,
// an exit node's default routes whole (the client cuts its private
// ranges itself; the exit-node goldens agree).
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

// dstsAt is the part of rl's destinations that n is sent: a via rule's
// only at a node holding a via tag, for any route it serves, an exit
// route among them (grant-via-router-covered, grant-via-reach-a).
// Quirk: an entry that reaches what n serves is sent whole, not cut to it:
// a prefix wider than the route, the range of autogroup:internet a public
// route sits in (routes-destination-wider-than-route,
// routes-internet-public-subnet, grant-via-internet-one-family-exit). The
// client then also takes it for a route it announces unapproved.
func (r *Ref) dstsAt(rl refRule, n RefNode) *netipx.IPSet {
	via := len(rl.via) > 0
	if via && !n.hasTag(rl.via) {
		return &netipx.IPSet{}
	}

	terms := rl.terms
	if terms == nil {
		terms = []dstTerm{{set: rl.dst}}
	}

	var b netipx.IPSetBuilder

	reach := n.served()

	for _, term := range terms {
		if via && term.internet && !n.exit() {
			continue
		}

		if term.star {
			b.AddSet(term.set)

			continue
		}

		for _, rg := range term.set.Ranges() {
			if reach.OverlapsRange(rg) {
				b.AddRange(rg)
			}
		}
	}

	s, _ := b.IPSet()

	return s
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

// Served is every address node id takes packets for.
func (r *Ref) Served(id types.NodeID) *netipx.IPSet {
	n, _ := r.node(id)

	return n.served()
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
		// never at addresses it routes, subnet or exit (grant goldens a1,
		// a3, c1-c6, k11-k25 with * at subnet routers; via goldens v84-v104
		// with a subnet or a public prefix).
		entries := rl.appDsts
		if entries == nil {
			entries = []*netipx.IPSet{dst}
		}

		var grants []tailcfg.CapGrant

		for _, entry := range entries {
			var own []netip.Prefix

			for _, a := range n.Addrs {
				if entry.Contains(a) {
					own = append(own, netip.PrefixFrom(a, a.BitLen()))
				}
			}

			if len(own) > 0 {
				grants = append(grants, tailcfg.CapGrant{Dsts: own, CapMap: rl.app})
			}
		}

		if len(rl.app) > 0 && len(grants) > 0 {
			out = append(out, tailcfg.FilterRule{SrcIPs: srcs, CapGrant: grants})
		}
	}

	return out
}

// Peers are the nodes node id is shown, in ID order. A node sees another
// when a rule has one on its sources' side and the other on its
// destinations' side, either way round (the goldens' peer lists); and
// every device of its own user (ACL goldens: a user's two devices with no
// rule between them see each other).
// Quirk: an exit node also sees, one way, the sources of an app grant
// whose destinations reach the internet (grant goldens: the sources do
// not see the exit node).
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
		if r.links(rl, n, m) || r.links(rl, m, n) {
			return true
		}

		if r.oneWay(rl, n, m) || r.siblingSource(rl, n, m) || r.loneExitSource(rl, n, m) {
			return true
		}
	}

	return false
}

// loneExitSource reports whether n sees m, one way, as a node whose lone
// exit route covers a source of rl, a via grant n is a via router of.
// Quirk: an exit route approved without the other family's is none to the
// service: it reads it as a route over the sources it holds, and lists
// the node on the grant's via routers, which the node does not list back
// (grant-via-internet-one-family-exit, -bare, -untagged). A rule without
// via lists no such node.
func (r *Ref) loneExitSource(rl refRule, n, m RefNode) bool {
	exits := m.exitRoutes()

	return len(rl.via) > 0 && len(exits) == 1 && rl.src.OverlapsPrefix(exits[0]) && r.viaRouter(rl, n)
}

// siblingSource reports whether n sees m, one way, as a source of rl,
// another user's autogroup:self rule, that a subnet route of a device of
// n's user covers.
// Quirk: the service lists such a device on every device of the router's
// user, though it lists the router alone (acl-self-routed-by-other-user,
// -by-third-user, -wide-route); a device of that user the route does not
// cover is not listed.
func (r *Ref) siblingSource(rl refRule, n, m RefNode) bool {
	if rl.owner == 0 || n.owner() == 0 || n.owner() == rl.owner || !slices.ContainsFunc(m.Addrs, rl.src.Contains) {
		return false
	}

	return slices.ContainsFunc(r.nodes, func(router RefNode) bool {
		return router.owner() == n.owner() && slices.ContainsFunc(router.subnets(), func(q netip.Prefix) bool {
			return slices.ContainsFunc(m.Addrs, q.Contains)
		})
	})
}

// oneWay reports whether exit node n sees m only as a source of rl, an
// app grant reaching the internet.
func (r *Ref) oneWay(rl refRule, n, m RefNode) bool {
	return len(rl.app) > 0 && len(rl.via) == 0 && n.exit() && rl.reachesInternet() && on(m, rl.src)
}

// on reports whether n is on the side of a rule whose addresses are s: it
// holds one of them, or one of its subnet routes overlaps them, as a
// router takes packets for what it routes (goldens: routers of a
// destination prefix see its sources).
func on(n RefNode, s *netipx.IPSet) bool {
	return slices.ContainsFunc(n.Addrs, s.Contains) || slices.ContainsFunc(n.subnets(), s.OverlapsPrefix)
}

func (rl refRule) reachesInternet() bool { return rl.internet || rl.dst.Overlaps(internet) }

// onDst reports whether n is on rl's destinations' side: by address or
// route, or as an exit node when a port rule's destinations reach the
// internet (issue_3212 goldens b17, b18). A via rule's destination side is
// its via routers routing a destination.
func (r *Ref) onDst(rl refRule, n RefNode) bool {
	if len(rl.via) == 0 {
		return on(n, rl.dst) || len(rl.ip) > 0 && n.exit() && rl.reachesInternet()
	}

	return r.viaRouter(rl, n)
}

// viaRouter reports whether n is one of via rule rl's routers to its
// peers: it carries a via tag and a subnet route of it overlaps a
// destination, or it is an exit node and the rule names autogroup:internet
// or a public destination its exit route's family holds.
// Quirk: an exit node sent the rule for a private destination is shown
// nobody by it, and a node routing over a router's address is not linked
// with the router (grant-via-router-covered). An exit node of the other
// family than a public destination is sent no rule and linked with nobody.
func (r *Ref) viaRouter(rl refRule, n RefNode) bool {
	if !n.hasTag(rl.via) {
		return false
	}

	return slices.ContainsFunc(n.subnets(), rl.dst.OverlapsPrefix) || rl.internet && n.exit() ||
		slices.ContainsFunc(n.exitRoutes(), func(q netip.Prefix) bool { return publicIn(rl.dst, q) })
}

// publicIn reports whether set holds a public address inside q.
func publicIn(set *netipx.IPSet, q netip.Prefix) bool {
	var b netipx.IPSetBuilder

	b.AddSet(set)
	b.Intersect(internet)

	public, _ := b.IPSet()

	return public.OverlapsPrefix(q)
}

func (r *Ref) links(rl refRule, src, dst RefNode) bool { return on(src, rl.src) && r.onDst(rl, dst) }

// Routes are the routes of peer that viewer is given, in the peer's
// order: an exit route when the viewer may send packets to the internet,
// as a source of a port rule reaching it (an app grant does not: via
// golden v104); a subnet route when the viewer is on one side of a rule
// and the route overlaps the other (routes goldens; an exit node is a
// destination of an internet-reaching rule, routes-b18). A via grant
// gives routes to its via routers as destinations alone, whether or not a
// router is among its sources (grant-via-internet-exit-is-source); what it
// gives its sources is steering, which the reference does not model
// ([Ref.Steered]).
func (r *Ref) Routes(viewer, peer types.NodeID) []netip.Prefix {
	v, ok := r.node(viewer)
	p, okp := r.node(peer)

	if !ok || !okp {
		return nil
	}

	var out []netip.Prefix

	for _, q := range p.routes() {
		// Quirk: a node approved for one exit route alone is offered
		// nobody as an exit node (routes-exit-node-public-destination-b,
		// grant-via-internet-one-family-exit).
		if isExitRoute(q) && len(p.exitRoutes()) < 2 {
			continue
		}

		keep := slices.ContainsFunc(r.rules, func(rl refRule) bool {
			via := len(rl.via) > 0

			if isExitRoute(q) {
				return !via && on(v, rl.src) && len(rl.ip) > 0 && rl.reachesInternet()
			}

			return !via && on(v, rl.src) && rl.dst.OverlapsPrefix(q) || r.onDst(rl, v) && rl.src.OverlapsPrefix(q)
		})
		if keep {
			out = append(out, q)
		}
	}

	return out
}

// Steered reports whether the routes viewer is given of peer are via
// steering's to decide: viewer is a source of a via grant one of peer's
// routes reaches, an exit route through a destination on the internet.
func (r *Ref) Steered(viewer, peer types.NodeID) bool {
	v, _ := r.node(viewer)
	p, _ := r.node(peer)

	return slices.ContainsFunc(r.rules, func(rl refRule) bool {
		return len(rl.via) > 0 && on(v, rl.src) && slices.ContainsFunc(p.routes(), func(q netip.Prefix) bool {
			return !isExitRoute(q) && rl.dst.OverlapsPrefix(q) || rl.reachesInternet() && isExitRoute(q) || rl.internet && internet.OverlapsPrefix(q)
		})
	})
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
// capability. This is capability mode's design, which no capture holds.
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
