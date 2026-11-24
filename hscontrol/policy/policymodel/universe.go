// Package policymodel is test support for property tests of how headscale
// turns a policy and a set of nodes into filters, peers and routes: a
// typed model of those inputs and of edits to them, rapid generators that
// draw it valid by construction and shrink to readable cases, builders
// from the model to the real inputs, a classifier naming the shapes a
// drawn case contains, and the one oracle sharing nothing with headscale:
// the Tailscale client's own packet filter.
//
// A property draws a scenario, replays it against the system under test
// and the model together, and prints a minimised policy, node table and
// step list when it fails:
//
//	rapid.Check(t, func(t *rapid.T) {
//		s := policymodel.Scenarios(30).Draw(t, "scenario")
//		sys := newSystem(s.Start.Policy.HuJSON(), s.Start.Topology.Build)
//		w := s.Start
//		for i, st := range s.Steps {
//			next, change := w.Commit(st)
//			sys.commit(change, next)
//			if got, want := sys.answer(), model(next); got != want {
//				t.Fatalf("after step %d: %v, want %v", i+1, got, want)
//			}
//			w = next
//		}
//	})
//
// It must not import the code its properties check (policy/v2, state,
// mapper), and only tests may import it; TestImports holds both.
package policymodel

import (
	"fmt"
	"net/netip"
	"strings"
)

// The vocabulary is small and fixed so that drawn values collide: two
// rules naming one selector, a route over another node's address, two
// nodes on one address.

// UserRefs are the user tokens a policy names: by name, by e-mail, by
// e-mail domain, and by provider identifier, as headscale's OIDC
// documentation allows. Which user each resolves to depends on the
// topology: the provider identifier names whoever took ID 3 at an OIDC
// login, so nobody when that user is gone or was created through the API.
var UserRefs = []string{"alice@", "bob@example.com", "carol@example.org", "dave@", "user:*@example.com", providerPrefix + "3@"}

// refUsers counts the UserRefs naming at most one user by name or e-mail;
// the domain and the provider identifier come after.
const refUsers = 4

// providerRef is the UserRefs entry naming a user by provider identifier.
const providerRef = 5

// providerPrefix is the identity provider's issuer: an OIDC user's
// identifier is it followed by the user's ID, so identifiers are unique.
const providerPrefix = "https://idp.example.com/"

// defaultUsers is the identity of user i+1 before any draw changes it:
// two users created through the API, two who logged in through OIDC.
var defaultUsers = []User{
	{ID: 1, Name: "alice"},
	{ID: 2, Name: "bob", Email: "bob@example.com"},
	{ID: 3, Name: "carol", Email: "carol@example.org", Provider: providerPrefix + "3"},
	{ID: 4, Name: "dave", Email: "dave@example.com", Provider: providerPrefix + "4"},
}

// userNames and userEmails are what users are named and renamed. Users
// created through the API have names no other such user has; OIDC users
// take theirs from the identity provider, and may share one, which makes
// a token naming it ambiguous: it names nobody.
var (
	userNames  = []string{"erin", "alice", "bob", "carol", "dave"}
	userEmails = []string{"", "erin@example.com", "bob@example.com", "carol@example.org", "dave@example.com", "alice@example.org"}
)

// Groups, Tags and Hosts are the names a policy defines. Every one a
// document refers to is defined in it.
var (
	Groups = []string{"group:a", "group:b"}
	Tags   = []string{"tag:a", "tag:b", "tag:c"}
	Hosts  = []string{"h-net", "h-pub", "h-node"}
)

const (
	numGroups = 2
	numTags   = 3
	numHosts  = 3
)

// Prefixes serve rules, hosts, routes and auto-approvers. They cover node
// addresses (100.64.0.0/30 holds n1-n3, the /120 every node's own IPv6),
// overlap each other, touch (10.0.1.0/24 begins where 10.0.0.0/24 ends),
// reach public space in both families, and end in the two halves of an
// exit route.
var Prefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/24"),
	netip.MustParsePrefix("10.0.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/30"),
	netip.MustParsePrefix("100.64.0.2/32"),
	netip.MustParsePrefix("8.8.8.0/24"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/120"),
	netip.MustParsePrefix("fd00:1::/64"),
	netip.MustParsePrefix("10.0.1.0/24"),
	netip.MustParsePrefix("2001:4860::/32"),
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

const (
	// numRulePrefixes is how many Prefixes a rule or host may name: a grant
	// cannot name a default route, and a rule says autogroup:internet.
	numRulePrefixes = 9
	exit4, exit6    = 9, 10
	publicPrefix    = 4
	touching        = 7
	publicPrefix6   = 8
)

// hostDefault is the prefix each host names before a draw moves it:
// a subnet, public space, and one node's address.
var hostDefault = [numHosts]int{0, 4, 3}

// Protos are the protocols a rule names; "" is the default. The last
// three have no ports.
var Protos = []string{"", "tcp", "udp", "sctp", "icmp", "ipv6-icmp", "gre"}

const portedProtos = 4

// Ports are destination ports; a grant takes one range per entry, so the
// list is the ACLs' alone.
var Ports = []string{"*", "22", "80-443", "1", "65535", "22,443"}

const grantPorts = 5

// Apps are app capabilities: plain ones, and two the compile adds
// companions for. AppValues are the value lists one is granted: one value,
// then, from appSingles on, two, as long as each other and alike in the
// first, so that only what follows the first tells them apart.
var (
	Apps      = []string{"example.com/cap/x", "tailscale.com/cap/relay", "tailscale.com/cap/drive", "example.com/cap/y"}
	AppValues = [][]string{{`{}`}, {`{"role":"ops"}`}, {`{"role":"ops"}`, `{}`}, {`{"role":"ops"}`, `{"role":"dev"}`}}
)

const appSingles = 2

// SSHUsers are the logins an SSH rule grants.
var SSHUsers = []string{"root", "autogroup:nonroot", "localpart:*@example.com", "alice"}

// Attrs are the node attributes nodeAttrs grants; service-host makes a
// node a service host, which takes it out of capability form; disable-ipv4
// takes the node's IPv4 address from its own netmap and every peer's, and
// its peers' from its own.
var Attrs = []string{"randomize-client-port", "drive:share", "service-host", "disable-ipv4"}

const (
	attrServiceHost = 2
	attrDisableIPv4 = 3
)

// Node addresses. Node n owns 100.64.0.n and fd7a:115c:a1e0::n, so nodes
// are distinct unless a draw says otherwise; moved addresses are tailnet
// addresses no node owns.
var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

func ownAddr(family int, id uint64) netip.Addr {
	if family == 4 {
		return netip.AddrFrom4([4]byte{100, 64, byte(id >> 8), byte(id)}) //nolint:gosec // the low 16 bits of the ID
	}

	return netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: byte(id >> 8), 15: byte(id)}) //nolint:gosec // as above
}

func movedAddr(family int, id uint64) netip.Addr {
	if family == 4 {
		return netip.AddrFrom4([4]byte{100, 96, byte(id >> 8), byte(id)}) //nolint:gosec // as above
	}

	return netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 13: 1, 14: byte(id >> 8), 15: byte(id)}) //nolint:gosec // as above
}

// SelKind is what a selector names. The order is simplest first, since
// shrinking lowers it.
type SelKind uint8

const (
	SelAll       SelKind = iota // *
	SelUser                     // UserRefs[I]
	SelGroup                    // Groups[I]
	SelTag                      // Tags[I]
	SelMember                   // autogroup:member
	SelTagged                   // autogroup:tagged
	SelHost                     // Hosts[I]
	SelPrefix                   // Prefixes[I]
	SelSelf                     // autogroup:self; destinations only
	SelInternet                 // autogroup:internet; destinations only
	SelDangerAll                // autogroup:danger-all; sources only
)

// Sel is a selector: a kind and, for the kinds with a pool, an index into
// it.
type Sel struct {
	Kind SelKind
	I    int
}

func (s Sel) String() string {
	switch s.Kind {
	case SelAll:
		return "*"
	case SelUser:
		return UserRefs[s.I]
	case SelGroup:
		return Groups[s.I]
	case SelTag:
		return Tags[s.I]
	case SelMember:
		return "autogroup:member"
	case SelTagged:
		return "autogroup:tagged"
	case SelHost:
		return Hosts[s.I]
	case SelPrefix:
		return Prefixes[s.I].String()
	case SelSelf:
		return "autogroup:self"
	case SelInternet:
		return "autogroup:internet"
	case SelDangerAll:
		return "autogroup:danger-all"
	}

	return fmt.Sprintf("sel(%d,%d)", s.Kind, s.I)
}

func selStrings(sels []Sel) []string {
	out := make([]string, len(sels))
	for i, s := range sels {
		out[i] = s.String()
	}

	return out
}

func joinSels(sels []Sel) string { return "[" + strings.Join(selStrings(sels), " ") + "]" }

func routeStrings(idx []int) []string {
	out := make([]string, len(idx))
	for i, r := range idx {
		out[i] = Prefixes[r].String()
	}

	return out
}
