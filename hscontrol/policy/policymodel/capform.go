package policymodel

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// Capability form judged from the plain rules of its eligibility, not from
// headscale's decision: a source goes as cap: only for an identity
// selector (or an autogroup:self rule's owner), in a rule without app
// capabilities whose protocols the client matches by capability, to a
// receiver whose client applies capabilities and whose local nets are its
// own addresses, and only where no node outside the selector holds a
// member's address. Everything here reads the model world and the
// reference; headscale's facts, reasons and predicates are never asked,
// so a change to them that keeps them agreeing with each other is still
// judged.

// CapSourcePrefix is how a filter rule names a source capability.
const CapSourcePrefix = "cap:" + StampPrefix

// AddressFormReason returns why n must be sent every source as addresses
// in capability mode, or "" when it may be sent capabilities: its client
// does not apply them, or its local nets exceed its own addresses because
// it announces routes (approved or not), runs as an app connector or hosts
// a service IP.
func (v *View) AddressFormReason(n Node) string {
	switch {
	case n.Client != Official && n.Client != AppConnector:
		return "client"
	case len(n.Announced) > 0:
		return "routes"
	case n.Client == AppConnector:
		return "app-connector"
	case slices.Contains(v.ServiceHosts(), n.ID):
		return "service-host"
	}

	return ""
}

// CapSources are the source capabilities, as [StampPrefix] names them, a
// receiver sent capabilities must find among its rules' sources: for each
// rule without via with an ip entry the client matches by capability whose
// destinations reach node id, every identity source naming a node with an
// address; and for an autogroup:self rule, its owner's, when an identity
// source names id. A rule from autogroup:danger-all names every source
// already and leaves the identities out; an autogroup:self part does not.
// Sorted.
func (r *Ref) CapSources(id types.NodeID) []string {
	n, ok := r.node(id)
	if !ok || len(n.Addrs) == 0 {
		return nil
	}

	var out []string

	for _, d := range r.doc.Rules {
		if len(d.Via) > 0 || !slices.ContainsFunc(d.IP, capMatched) {
			continue
		}

		var dsts []string

		self, inet := false, false

		for _, t := range d.Dst {
			switch t {
			case "autogroup:self":
				self = true
			case internetSel:
				inet = true
			default:
				dsts = append(dsts, t)
			}
		}

		rl := refRule{dst: r.addrs(dsts, false), internet: inet}
		if (len(dsts) > 0 || inet) && len(r.dstsAt(rl, n).Prefixes()) > 0 && !slices.Contains(d.Src, "autogroup:danger-all") {
			for _, s := range d.Src {
				if identity(s) && len(r.addrs([]string{s}, true).Prefixes()) > 0 {
					out = append(out, s)
				}
			}
		}

		if self && n.owner() != 0 && slices.ContainsFunc(d.Src, func(s string) bool { return identity(s) && r.member(n, s) }) {
			out = append(out, ownerStamp(n.owner()))
		}
	}

	slices.Sort(out)

	return slices.Compact(out)
}

func ownerStamp(uid uint) string { return "owner:" + strconv.FormatUint(uint64(uid), 10) }

// sharedStamp reports whether a node outside what stamp s names holds an
// address of a node it names: the client asks one node per address, so s
// must go as addresses.
func (r *Ref) sharedStamp(s string) bool {
	in := func(n RefNode) bool { return r.member(n, s) }

	if uid, ok := strings.CutPrefix(s, "owner:"); ok {
		in = func(n RefNode) bool { return strconv.FormatUint(uint64(n.owner()), 10) == uid && n.owner() != 0 }
	}

	for _, m := range r.nodes {
		if !in(m) {
			continue
		}

		for _, o := range r.nodes {
			if !in(o) && slices.ContainsFunc(o.Addrs, func(a netip.Addr) bool { return slices.Contains(m.Addrs, a) }) {
				return true
			}
		}
	}

	return false
}

// FormJudge judges the form of the filters receivers are served or hold,
// and counts what it judged. The zero value is ready.
type FormJudge struct {
	// Filters counts the filters judged in capability mode by why their
	// receiver must be sent addresses, "" for one that may be sent
	// capabilities; Address those judged in address mode.
	Filters map[string]int
	Address int
	// WithCaps counts the capability-mode filters holding a cap: source,
	// Required those the reference required one in, and Mixed and
	// MultiCap the rules with a cap: source and an address source beside
	// it, and with two cap: sources.
	WithCaps, Required, Mixed, MultiCap int
	// ByRule counts the rules of receivers sent capabilities held to
	// addresses by their own kind: "cap-grant" and "portless".
	ByRule map[string]int
	// Shared counts the source capabilities held to addresses because a
	// node outside them holds a member's address.
	Shared int
}

func (j *FormJudge) String() string {
	return fmt.Sprintf("filters by receiver %v (address mode %d); with a cap: source %d, required %d; rules mixed %d, with several caps %d; held by rule %v; shared stamps %d",
		j.Filters, j.Address, j.WithCaps, j.Required, j.Mixed, j.MultiCap, j.ByRule, j.Shared)
}

// Check returns what is wrong with the form of rules, node id's filter in
// w, which ref reads, as served or as its client holds it; capMode is the
// source mode. In address mode no source is a capability. In capability
// mode: a receiver [View.AddressFormReason] names holds none; a rule
// granting app capabilities, or naming a protocol the client matches by
// address only, holds none; every cap: source is in the reserved
// namespace and names an identity or an owner no node outside shares an
// address with; and every capability [Ref.CapSources] lists is among the
// sources.
func (j *FormJudge) Check(w World, ref *Ref, id types.NodeID, rules []tailcfg.FilterRule, capMode bool) string {
	n, ok := w.Topology.Node(id)
	if !ok {
		return ""
	}

	if !capMode {
		j.Address++

		for _, r := range rules {
			if s := capSources(r); len(s) > 0 {
				return "address mode sends " + s[0]
			}
		}

		return ""
	}

	why := j.receiver(NewView(w), n)

	held, msg := j.sources(ref, id, why, rules)
	if msg != "" {
		return msg
	}

	if why != "" {
		j.countShared(ref, w)

		return ""
	}

	want := ref.CapSources(id)
	if len(want) > 0 {
		j.Required++
	}

	for _, s := range want {
		if !held[s] {
			return fmt.Sprintf("n%d, sent capabilities, enforces a rule from %s, and no rule it holds names %s%s (it holds %v)",
				id, s, CapSourcePrefix, s, slices.Sorted(maps.Keys(held)))
		}
	}

	return ""
}

// receiver counts n's filter by why n must be sent addresses and returns
// the reason [Check] holds it to.
func (j *FormJudge) receiver(v *View, n Node) string {
	why := v.AddressFormReason(n)

	if j.Filters == nil {
		j.Filters, j.ByRule = map[string]int{}, map[string]int{}
	}

	j.Filters[why]++

	return why
}

// sources holds each rule's cap: sources to the rule and to why, the
// receiver's reason, and returns the stamps they name.
func (j *FormJudge) sources(ref *Ref, id types.NodeID, why string, rules []tailcfg.FilterRule) (map[string]bool, string) {
	held := map[string]bool{}

	for _, r := range rules {
		caps := capSources(r)

		switch {
		case len(caps) == 0 && why == "" && len(r.CapGrant) > 0:
			j.ByRule["cap-grant"]++
		case len(caps) == 0 && why == "" && !capMatchedProtos(r.IPProto):
			j.ByRule["portless"]++
		case len(caps) == 0:
		case why != "":
			return nil, fmt.Sprintf("n%d must be sent addresses (%s), and is sent %s", id, why, caps[0])
		case len(r.CapGrant) > 0:
			return nil, "a rule granting app capabilities is sent with " + caps[0]
		case !capMatchedProtos(r.IPProto):
			return nil, fmt.Sprintf("a rule over protocols %v is sent with %s", r.IPProto, caps[0])
		}

		j.Mixed += b2i(len(caps) > 0 && len(caps) < len(r.SrcIPs))
		j.MultiCap += b2i(len(caps) > 1)

		for _, c := range caps {
			s, ok := strings.CutPrefix(c, CapSourcePrefix)
			if !ok || !identity(s) && !ownerName(s) {
				return nil, c + " names no identity or owner"
			}

			if ref.sharedStamp(s) {
				return nil, c + " is sent, and a node outside it holds a member's address"
			}

			held[s] = true
		}
	}

	j.WithCaps += b2i(len(held) > 0)

	return held, ""
}

// countShared counts the identity sources of w's rules held to addresses
// because a node outside them holds a member's address.
func (j *FormJudge) countShared(ref *Ref, w World) {
	if !SharesAddress(w) {
		return
	}

	for _, d := range ref.doc.Rules {
		for _, s := range d.Src {
			if identity(s) && ref.sharedStamp(s) {
				j.Shared++
			}
		}
	}
}

// capSources is r's sources that are capabilities.
func capSources(r tailcfg.FilterRule) []string {
	var out []string

	for _, s := range r.SrcIPs {
		if strings.HasPrefix(s, "cap:") {
			out = append(out, s)
		}
	}

	return out
}

func ownerName(s string) bool {
	uid, ok := strings.CutPrefix(s, "owner:")
	if !ok {
		return false
	}

	_, err := strconv.ParseUint(uid, 10, 64)

	return err == nil
}

// capMatchedProtos reports whether the client matches every protocol of a
// rule by capability: TCP, UDP, SCTP and ICMP of either family, or its
// default.
func capMatchedProtos(protos []int) bool { return capMatched(IPSpec{Protos: protos}) }

func b2i(b bool) int {
	if b {
		return 1
	}

	return 0
}

// IPv4Disabled reports whether nodeAttrs give n disable-ipv4. They grant
// by address, as for service hosts.
func (v *View) IPv4Disabled(n Node) bool {
	return slices.ContainsFunc(v.World.Policy.NodeAttrs, func(a NodeAttr) bool {
		return slices.Contains(a.Attrs, attrDisableIPv4) && v.holds(a.Targets, n)
	})
}

// HiddenAddrs are the node addresses node id's client is shown no node
// at under disable-ipv4: every IPv4 address when id has it, else the IPv4
// address of each node that has it. Sorted.
func HiddenAddrs(w World, id types.NodeID) []netip.Addr {
	v := NewView(w)
	self, ok := w.Topology.Node(id)
	all := ok && v.IPv4Disabled(self)

	var out []netip.Addr

	for _, n := range w.Topology.Nodes {
		if n.V4.IsValid() && (all || v.IPv4Disabled(n)) {
			out = append(out, n.V4)
		}
	}

	slices.SortFunc(out, netip.Addr.Compare)

	return slices.Compact(out)
}

// ShownAddrs are the addresses node viewer's client is shown node of
// holding: its own, less those disable-ipv4 hides. As the hosted service
// does: a node with it is shown no IPv4 address of its own or its peers',
// and its peers are shown none of its.
func ShownAddrs(w World, viewer, of types.NodeID) []netip.Addr {
	n, ok := w.Topology.Node(of)
	if !ok {
		return nil
	}

	hidden := HiddenAddrs(w, viewer)

	return slices.DeleteFunc(n.Addrs(), func(a netip.Addr) bool { return slices.Contains(hidden, a) })
}

// NotShown are the IPv4 addresses of w's nodes that no node of any of
// shown holds: what a client holding those nodes is shown no node at,
// disable-ipv4 having hidden them. Sorted.
func NotShown(w World, shown ...[]tailcfg.NodeView) []netip.Addr {
	held := map[netip.Addr]bool{}

	for _, ns := range shown {
		for _, n := range ns {
			for _, p := range n.Addresses().All() {
				held[p.Addr()] = true
			}
		}
	}

	var out []netip.Addr

	for _, n := range w.Topology.Nodes {
		if n.V4.IsValid() && !held[n.V4] {
			out = append(out, n.V4)
		}
	}

	slices.SortFunc(out, netip.Addr.Compare)

	return slices.Compact(out)
}

// SplitHidden takes out the differences on an address of hidden: a
// verdict from or to one, app capabilities from one.
func (r Report) SplitHidden(hidden []netip.Addr) (int, Report) {
	if len(hidden) == 0 {
		return 0, r
	}

	n := 0
	rest := r

	rest.Verdicts = slices.DeleteFunc(slices.Clone(r.Verdicts), func(d VerdictDiff) bool {
		in := slices.Contains(hidden, d.Probe.Src) || slices.Contains(hidden, d.Probe.Dst)
		n += b2i(in)

		return in
	})
	rest.Caps = slices.DeleteFunc(slices.Clone(r.Caps), func(d CapsDiff) bool {
		in := slices.Contains(hidden, d.Src) || slices.Contains(hidden, d.Dst)
		n += b2i(in)

		return in
	})

	return n, rest
}
