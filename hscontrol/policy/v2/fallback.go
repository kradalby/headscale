package v2

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/views"
)

// A filter rule may name a source "cap:<capability>": the receiving client
// finds the node holding the packet's source address among itself and its
// peers and accepts when that node's CapMap has the capability. Membership
// then travels on the peers, which every viewer is sent anyway, and a rule
// written that way stays the same while nodes come and go.
//
// This file decides, for every source of every rule a receiver is sent,
// whether it goes as a capability or as addresses, and why. Nothing else
// chooses address form: the cut asks [sourceForm], and address form is
// written only by functions that are handed the reason. Every reason has a
// row in [reasonDocs]; TestFallbackReasonsComplete holds the rows to the
// TODOs below, to their canaries and to the metric labels.

// SourceMode is how filter rules name the nodes a selector holds.
type SourceMode uint8

const (
	// AddressSources writes every source as addresses.
	AddressSources SourceMode = iota
	// CapabilitySources writes an identity source as the capability its
	// members are stamped with, wherever no fallback applies.
	CapabilitySources
)

// selectorCapPrefix is the namespace of the capabilities headscale stamps
// on nodes for the source selectors they hold. It is reserved: nodeAttrs
// cannot grant a capability in it and app grants cannot name one.
const selectorCapPrefix = "https://headscale.net/cap/src/"

// selectorCap is the capability the members of s are stamped with.
func selectorCap(s Selector) nodecap.Cap { return nodecap.Cap(selectorCapPrefix + s.Name) }

// ownerCap is the capability the owner nodes of user uid are stamped with,
// which an autogroup:self rule names. No alias is spelled "owner:".
func ownerCap(uid uint) nodecap.Cap {
	return nodecap.Cap(selectorCapPrefix + "owner:" + strconv.FormatUint(uint64(uid), 10))
}

// IsSourceCap reports whether c is in the reserved namespace of source
// capabilities, with or without its scheme.
func IsSourceCap(c string) bool {
	return strings.HasPrefix(c, selectorCapPrefix) ||
		strings.HasPrefix(c, strings.TrimPrefix(selectorCapPrefix, "https://"))
}

// ipReason is why a source goes as addresses instead of a capability.
// [sourceForm] returns the first that applies, in this order.
type ipReason uint8

const (
	// reasonNone: the source goes as a capability.
	reasonNone ipReason = iota

	// reasonAddressMode: policy.capability_sources is off. Permanent: it
	// is the opt-out.
	reasonAddressMode

	// TODO(capsrc/client): lift when every client headscale serves applies peers' node caps to cap: sources; canary TestTailscaleRustCapabilitySources
	// TODO(kradalby): capsrc/client: tailscale-rs hands its packet filter no
	// node capabilities; upstream: `TODO(npry): wire in nodecaps` in
	// Dataplane.process_inbound,
	// https://github.com/tailscale/tailscale-rs/blob/f9157a9938c8a33be31ef5146b310c30229321a9/ts_dataplane/src/lib.rs.
	// The Tailscale client matches capability sources since
	// https://github.com/tailscale/tailscale/pull/12543 and passes them to its
	// filter since https://github.com/tailscale/tailscale/pull/14067, whose
	// release is the floor officialClient checks; tracking
	// https://github.com/tailscale/tailscale/issues/12542.
	//
	// reasonClient: the receiving node's client is not known to apply
	// capability sources. tailscale-rs parses them but looks no caps up,
	// while reporting a current capability version.
	reasonClient

	// TODO(capsrc/local-nets): lift when the client checks a rule's destinations for capability sources on ICMP; canary TestCanaryICMPIgnoresDstsForCaps
	// TODO(kradalby): capsrc/local-nets: on ICMP the client accepts any
	// source holding a capability any rule names, without the rule's
	// destinations (matches.matchIPsOnly,
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/filter/match.go),
	// so only a node whose local nets are its own addresses is safe; local
	// nets come from the node's own preferences: advertised routes, app
	// connector, service IPs (LocalBackend.updateFilterLocked,
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/ipn/ipnlocal/local.go).
	// Tracking https://github.com/tailscale/tailscale/issues/12542. Lifting this also
	// sends via routers capability form, which capFormFor and the stamp
	// table cut no via rule for: they must first (TestFormShortcutsAgreeWithSourceForm
	// counts the premise breaking with this reason off).
	//
	// reasonLocalNets: the receiver handles more than its own addresses:
	// it announces routes (approved or not), is an app connector, or hosts
	// a service IP. The client accepts ICMP from any holder of a
	// capability its rules name, whatever their destinations.
	reasonLocalNets

	// TODO(capsrc/cap-grant): lift when CapsWithValues honours SrcCaps; canary TestCanaryCapsWithValuesIgnoresSrcCaps
	// TODO(kradalby): capsrc/cap-grant: the client grants app capabilities by
	// a rule's addresses only (Filter.CapsWithValues, and capMatchesFunc,
	// which keeps a capability rule's addresses alone, both in
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/filter/filter.go).
	// Tracking https://github.com/tailscale/tailscale/issues/12542; app capabilities:
	// https://tailscale.com/docs/features/access-control/grants.
	//
	// reasonCapGrant: the rule grants app capabilities, which the client
	// grants by address only.
	reasonCapGrant

	// TODO(capsrc/portless): lift when the client's path for protocols without ports honours SrcCaps; canary TestCanaryPortlessIgnoresSrcCaps
	// TODO(kradalby): capsrc/portless: the client matches a protocol without
	// ports by address only (matches.matchProtoAndIPsOnlyIfAllPorts,
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/filter/match.go,
	// reached from Filter.runIn4 and Filter.runIn6 in filter.go). Tracking
	// https://github.com/tailscale/tailscale/issues/12542.
	//
	// reasonPortless: the rule names a protocol other than TCP, UDP, SCTP
	// and ICMP, which the client matches by address only.
	reasonPortless

	// reasonLiteral: the source is an address, not a membership: *, a
	// host, a prefix, autogroup:internet, autogroup:danger-all. Permanent.
	reasonLiteral

	// TODO(capsrc/shared-address): lift when the client checks every node holding a source address; canary TestCanaryCapLookupOneNodePerAddress
	// TODO(kradalby): capsrc/shared-address: the client asks the one node its
	// netmap indexed last for an address (LocalBackend.srcIPHasCapForFilter,
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/ipn/ipnlocal/local.go,
	// through nodeBackend.NodeByAddr and updateNodeByAddrLocked in
	// node_backend.go), and a delta removal drops the address without
	// pointing it at its other holder (nodeBackend.UpdateNetmapDelta, same
	// file); upstream, on srcIPHasCapForFilter: `TODO(bradfitz): optimize
	// this later if/when it matters.` and `TODO(nickkhyl): move this into
	// [nodeBackend] along with [LocalBackend.updateFilterLocked].` Tracking
	// https://github.com/tailscale/tailscale/issues/12542; the lookup refuses unsigned peers
	// since https://github.com/tailscale/tailscale/pull/20513.
	//
	// reasonSharedAddress: a node outside the selector holds an address
	// of one of its members, or, for an autogroup:self rule, a node not
	// the owner's holds an address of one of the owner's nodes. The client
	// asks one node per address, whichever its netmap indexed last.
	reasonSharedAddress

	numReasons
)

// reasonKind is what lifting a reason takes.
type reasonKind uint8

const (
	kindNone reasonKind = iota
	// kindPermanent never lifts.
	kindPermanent
	// kindClient lifts when every supported client changes; a canary pins
	// the behaviour it rests on.
	kindClient
)

// reasonDoc is a reason's row in the fallback table.
type reasonDoc struct {
	// label names the reason in metrics and on the debug endpoint.
	label string
	kind  reasonKind
	// scope is what the reason sends as addresses.
	scope string
	// lift is when it can go; "never" for a permanent one.
	lift string
	// canary is the test pinning the client behaviour, for kindClient.
	canary string
}

var reasonDocs = [numReasons]reasonDoc{
	reasonNone: {label: "capability", kind: kindNone, scope: "the source goes as a capability"},
	reasonAddressMode: {
		label: "address-mode", kind: kindPermanent, scope: "every source of every node",
		lift: "never: policy.capability_sources is the opt-out",
	},
	reasonClient: {
		label: "client", kind: kindClient, scope: "every rule sent to a node whose client is not known to apply cap: sources",
		lift: "every client headscale serves applies peers' node caps to cap: sources", canary: "TestTailscaleRustCapabilitySources",
	},
	reasonLocalNets: {
		label: "local-nets", kind: kindClient, scope: "every rule sent to a node announcing routes, an app connector, or a service host",
		lift: "the client checks a rule's destinations for capability sources on ICMP", canary: "TestCanaryICMPIgnoresDstsForCaps",
	},
	reasonCapGrant: {
		label: "cap-grant", kind: kindClient, scope: "app capability rules and their companions",
		lift: "CapsWithValues honours SrcCaps", canary: "TestCanaryCapsWithValuesIgnoresSrcCaps",
	},
	reasonPortless: {
		label: "portless", kind: kindClient, scope: "rules naming a protocol other than TCP, UDP, SCTP and ICMP",
		lift: "the client's path for protocols without ports honours SrcCaps", canary: "TestCanaryPortlessIgnoresSrcCaps",
	},
	reasonLiteral: {
		label: "literal", kind: kindPermanent, scope: "*, hosts, prefixes, autogroup:internet, autogroup:danger-all",
		lift: "never: an address is not a membership",
	},
	reasonSharedAddress: {
		label: "shared-address", kind: kindClient, scope: "a selector a non-member shares a member's address with; an owner whose node shares an address with another user's",
		lift: "the client checks every node holding a source address", canary: "TestCanaryCapLookupOneNodePerAddress",
	},
}

// String returns the reason's label.
func (r ipReason) String() string {
	if r < numReasons {
		return reasonDocs[r].label
	}

	return "unknown"
}

// FallbackReasons returns the labels of the reasons a source goes as
// addresses, in decision order, for metrics.
func FallbackReasons() []string {
	out := make([]string, 0, numReasons-1)
	for r := reasonNone + 1; r < numReasons; r++ {
		out = append(out, r.String())
	}

	return out
}

// ReceiverFacts is what decides, beyond the policy, whether a node can be
// sent capability sources: what it announces, not what is approved, since
// the client builds its local nets from its own preferences; and what its
// client is. Reported by the node itself; a node that lies about them
// weakens only its own inbound filter.
type ReceiverFacts struct {
	// Announces: the node advertises routes, approved or not.
	Announces bool
	// AppConnector: the node runs as an app connector.
	AppConnector bool
	// ServiceHost: the node's capabilities name it a service host, whose
	// service IPs the client adds to its local nets.
	ServiceHost bool
	// Client: the node's client is known to apply capability sources.
	Client bool
}

// ReceiverFactsOf returns n's facts, with caps its policy capabilities.
func ReceiverFactsOf(n types.NodeView, caps tailcfg.NodeCapMap) ReceiverFacts {
	hi := n.Hostinfo()
	_, svc := caps[nodecap.ServiceHost]

	return ReceiverFacts{
		Announces:    hi.Valid() && hi.RoutableIPs().Len() > 0,
		AppConnector: hi.Valid() && hi.AppConnector().EqualBool(true),
		ServiceHost:  svc,
		Client:       officialClient(hi),
	}
}

// officialClient reports whether hi is the Tailscale client's own, which
// looks capability sources up: built with Go, a Tailscale release at or
// past the oldest headscale serves, and not tailscale-rs. Anything else is
// sent addresses: a client that parses cap: but looks nothing up drops
// every such rule.
func officialClient(hi tailcfg.HostinfoView) bool {
	if !hi.Valid() || strings.HasPrefix(hi.App(), "tailscale-rs") || !strings.HasPrefix(hi.GoVersion(), "go") {
		return false
	}

	major, minor, ok := releaseOf(hi.IPNVersion())
	if !ok {
		return false
	}

	floorMajor, floorMinor, _ := releaseOf(capver.TailscaleVersion(capver.MinSupportedCapabilityVersion))

	return major > floorMajor || major == floorMajor && minor >= floorMinor
}

// releaseOf parses the major and minor of a Tailscale version such as
// 1.84.0-t1234abcd-gabcdef or v1.84.
func releaseOf(v string) (int, int, bool) {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}

	return major, minor, major > 0
}

// Receivers holds every node's [ReceiverFacts]. Updating it recomputes
// only the nodes whose node or policy capabilities changed.
type Receivers struct {
	facts *graph.Map[types.NodeID, ReceiverFacts]
	nodes *NodeMap
	caps  *graph.Map[types.NodeID, tailcfg.NodeCapMap]

	// addressForm lists, sorted, the nodes some receiver-wide reason can
	// send every source as addresses, whichever reasons are in force: what
	// routing reads to name a node in address form without walking every
	// receiver. Shared; copied when a node enters or leaves it.
	addressForm []types.NodeID

	// kinds counts the nodes by their facts, so the census counts the
	// receivers by reason without visiting them.
	kinds [numFactKinds]int
}

// numFactKinds is how many distinct [ReceiverFacts] there are.
const numFactKinds = 16

// kind numbers f among the [ReceiverFacts] there are.
func (f ReceiverFacts) kind() int {
	k := 0

	for i, b := range [4]bool{f.Announces, f.AppConnector, f.ServiceHost, f.Client} {
		if b {
			k |= 1 << i
		}
	}

	return k
}

// factsOfKind is the inverse of [ReceiverFacts.kind].
func factsOfKind(k int) ReceiverFacts {
	return ReceiverFacts{Announces: k&1 != 0, AppConnector: k&2 != 0, ServiceHost: k&4 != 0, Client: k&8 != 0}
}

func sameFacts(a, b ReceiverFacts) bool { return a == b }

// mayBeAddressForm reports whether a receiver-wide reason can apply to a
// node with facts f: [receiverForm]'s conditions, before any is switched
// off.
func mayBeAddressForm(f ReceiverFacts) bool {
	return !f.Client || f.Announces || f.AppConnector || f.ServiceHost
}

// Update returns the facts of nodes with caps their policy capabilities.
func (r Receivers) Update(nodes *NodeMap, caps *graph.Map[types.NodeID, tailcfg.NodeCapMap]) Receivers {
	next := Receivers{facts: r.facts, nodes: nodes, caps: caps, addressForm: r.addressForm, kinds: r.kinds}
	if next.facts == nil {
		next.facts = graph.NewMap[types.NodeID](sameFacts, nil)
	}

	// A node whose node and capabilities both changed is in both lists;
	// visited twice, the census would count it twice.
	changed := slices.Concat(graph.Changes(r.nodes, nodes), graph.Changes(r.caps, caps))
	if len(changed) == 0 {
		return next
	}

	slices.Sort(changed)
	changed = slices.Compact(changed)

	e := next.facts.Edit()
	addr := next.addressForm
	owned := false

	for _, id := range changed {
		var (
			f      ReceiverFacts
			listed bool
		)

		if was, held := next.facts.Get(id); held {
			next.kinds[was.kind()]--
		}

		if n, ok := nodes.Get(id); ok {
			c, _ := caps.Get(id)
			f, listed = ReceiverFactsOf(n.View(), c), true
			e.Set(id, f)
			next.kinds[f.kind()]++
		} else {
			e.Delete(id)
		}

		i, held := slices.BinarySearch(addr, id)
		if want := listed && mayBeAddressForm(f); want != held {
			if !owned {
				addr, owned = slices.Clone(addr), true
			}

			if want {
				addr = slices.Insert(addr, i, id)
			} else {
				addr = slices.Delete(addr, i, i+1)
			}
		}
	}

	next.facts = e.Done()
	next.addressForm = slices.Clip(addr)

	return next
}

// Same reports whether a and b hold the same facts for every node.
func (r Receivers) Same(o Receivers) bool { return r.facts == o.facts }

// Of returns node id's facts; a node it does not hold has none, and so an
// unknown client.
func (r Receivers) Of(id types.NodeID) ReceiverFacts {
	f, _ := r.facts.Get(id)

	return f
}

// ChangedSince returns the nodes whose facts differ from old's: the nodes
// whose filter form can, and nothing else.
func (r Receivers) ChangedSince(old Receivers) []types.NodeID {
	return graph.Changes(old.facts, r.facts)
}

// filterForm is which of its two forms a receiver's filter is cut in;
// a receiver's facts choose it, through [receiverForm].
type filterForm uint8

const (
	// formAddress writes every source as addresses, as address mode does.
	formAddress filterForm = iota
	// formCapability writes each source as [sourceForm] decides.
	formCapability
	numForms
)

// formOf is the form a receiver-wide reason why sends.
func formOf(why ipReason) filterForm {
	if why == reasonNone {
		return formCapability
	}

	return formAddress
}

// recutReason is why a filter cut again in form, to compare it, goes as
// addresses under mode: the cut is the same whichever receiver-wide reason
// sent it, so in capability mode it names the first.
func recutReason(mode SourceMode, form filterForm) ipReason {
	switch {
	case form == formCapability:
		return reasonNone
	case mode != CapabilitySources:
		return reasonAddressMode
	}

	return reasonClient
}

// fallbacksOff holds the reasons a sensitivity test has switched off, to
// show what each prevents. Only tests that do not run in parallel set it.
var fallbacksOff [numReasons]bool

// applies reports whether reason r is in force where cond holds.
func applies(r ipReason, cond bool) bool { return cond && !fallbacksOff[r] }

// receiverForm is [sourceForm]'s part that reads the receiver alone: a
// reason here sends the receiver's whole filter as addresses, as address
// mode writes it.
func receiverForm(mode SourceMode, f ReceiverFacts) ipReason {
	switch {
	case applies(reasonAddressMode, mode != CapabilitySources):
		return reasonAddressMode
	case applies(reasonClient, !f.Client):
		return reasonClient
	case applies(reasonLocalNets, f.Announces || f.AppConnector || f.ServiceHost):
		return reasonLocalNets
	}

	return reasonNone
}

// How a session is sent its filter is decided here too: as named chunks
// (chunk.go), only to a client known to keep them per map session and to
// apply "*": null before the rest of a response; any other is sent the
// whole filter under "base", which every client handles and which a
// client that loses its chunks recovers from at the next change.

// deliveryReason is why a session is sent its whole filter under "base"
// instead of named chunks. [FilterDelivery] returns the first that applies.
type deliveryReason uint8

const (
	// deliveryChunks: the filter goes as named chunks.
	deliveryChunks deliveryReason = iota

	// deliveryOff: policy.filter_chunks is off. Permanent: it is the
	// opt-out.
	deliveryOff

	// TODO(capsrc/chunk-client): lift when every client headscale serves holds filter chunks per map session and rebuilds them whole when what applies them restarts; canary TestTailscaleRustFilterChunks
	// TODO(kradalby): capsrc/chunk-client: tailscale-rs keeps its chunks
	// for the runtime's life, not the map session's (the
	// PacketfilterUpdater actor in ts_runtime/src/packetfilter.rs outlives
	// the control stream, and only "*": null clears its state,
	// apply_update in ts_packetfilter/src/state.rs,
	// https://github.com/tailscale/tailscale-rs/blob/f9157a9938c8a33be31ef5146b310c30229321a9/ts_runtime/src/packetfilter.rs),
	// and when that actor panics and is restarted it replays only the last
	// update onto an empty state: with chunks it holds only what that
	// update carried until the next map session (fails closed, but an
	// outage), with the whole filter it recovers at the next change. A
	// client headscale does not recognise could do either. The Tailscale
	// client holds chunks per map session (mapSession.namedPacketFilters,
	// a new mapSession per long poll in Direct.sendMapRequest,
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/control/controlclient/direct.go)
	// and applies the clear first (mapSession.updateStateFromResponse in
	// map.go); TestCanaryClientChunkMerge pins it. No upstream issue:
	// nothing in tailscale-rs is wrong by its own contract, only unsafe
	// for an incremental sender.
	//
	// deliveryClient: the session's client is not known to handle named
	// chunks: anything but Tailscale's own client.
	deliveryClient

	numDeliveries
)

// deliveryDocs are the delivery reasons' rows, as [reasonDocs] are the
// source reasons'.
var deliveryDocs = [numDeliveries]reasonDoc{
	deliveryChunks: {label: "chunks", kind: kindNone, scope: "the filter goes as named chunks"},
	deliveryOff: {
		label: "chunks-off", kind: kindPermanent, scope: "every session, whole filter under \"base\"",
		lift: "never: policy.filter_chunks is the opt-out",
	},
	deliveryClient: {
		label: "chunk-client", kind: kindClient, scope: "every session of a node whose client is not known to handle named chunks",
		lift:   "every client headscale serves holds filter chunks per map session and rebuilds them whole when what applies them restarts",
		canary: "TestTailscaleRustFilterChunks",
	},
}

// Delivery is how a session is sent its filter: as named chunks, or whole
// under "base" for a reason.
type Delivery struct{ why deliveryReason }

// Chunked reports whether the filter goes as named chunks.
func (d Delivery) Chunked() bool { return d.why == deliveryChunks }

// String returns the delivery's label.
func (d Delivery) String() string {
	if d.why < numDeliveries {
		return deliveryDocs[d.why].label
	}

	return "unknown"
}

// deliveries counts [FilterDelivery]'s answers by reason.
var deliveries [numDeliveries]atomic.Uint64

// FilterDelivery decides how a session of a node whose client reported hi
// is sent its packet filter, chunks being policy.filter_chunks; it is the
// only place that does. Each call is counted: a session asks when it
// starts and when its node's client report changes.
func FilterDelivery(chunks bool, hi tailcfg.HostinfoView) Delivery {
	d := Delivery{deliveryChunks}

	switch {
	case !chunks:
		d.why = deliveryOff
	case !officialClient(hi):
		d.why = deliveryClient
	}

	deliveries[d.why].Add(1)

	return d
}

// FilterDeliveryCounts returns, by label, how often [FilterDelivery] chose
// each delivery since the process started.
func FilterDeliveryCounts() map[string]uint64 {
	out := make(map[string]uint64, numDeliveries)
	for d := range numDeliveries {
		out[Delivery{d}.String()] = deliveries[d].Load()
	}

	return out
}

// srcCapProtocols are the protocols the client matches capability sources
// for; a rule naming no protocol takes the client's defaults, all among
// them.
var srcCapProtocols = []int{ProtocolICMP, ProtocolTCP, ProtocolUDP, ProtocolIPv6ICMP, ProtocolSCTP}

// ruleForm is [sourceForm]'s part that reads the rule alone.
func ruleForm(capGrant bool, proto []int) ipReason {
	if applies(reasonCapGrant, capGrant) {
		return reasonCapGrant
	}

	if applies(reasonPortless, slices.ContainsFunc(proto, func(p int) bool { return !slices.Contains(srcCapProtocols, p) })) {
		return reasonPortless
	}

	return reasonNone
}

// sourceTraits is what decides a source's form beyond its rule and
// receiver.
type sourceTraits struct {
	kind SelectorKind
	// shared: a node outside the source holds an address of a member, or,
	// for a self rule, a node not the owner's holds an address of one of
	// the owner's nodes, or the source names only some of them.
	shared bool
}

// sourceForm returns why the source src of a rule, granting app
// capabilities when capGrant and over protocols proto, goes as addresses
// to a receiver with facts f under mode; reasonNone sends it as a
// capability. It is the only place that chooses.
func sourceForm(mode SourceMode, f ReceiverFacts, capGrant bool, proto []int, src sourceTraits) ipReason {
	if r := receiverForm(mode, f); r != reasonNone {
		return r
	}

	if r := ruleForm(capGrant, proto); r != reasonNone {
		return r
	}

	switch {
	case applies(reasonLiteral, !src.kind.HoldsNodes()):
		return reasonLiteral
	case applies(reasonSharedAddress, src.shared):
		return reasonSharedAddress
	}

	return reasonNone
}

// stampTable is which capabilities a template set's rules can name: the
// identity sources of every rule that can go in capability form for some
// receiver, and owners when an autogroup:self rule can. Via rules are left
// out: they reach via routers only, which announce routes.
type stampTable struct {
	sel   []bool
	owner bool
}

// stamps returns which capabilities t's rules can name, built once.
func (t *Templates) stamps() *stampTable {
	t.stampOnce.Do(func() {
		st := &stampTable{sel: make([]bool, t.table().Len())}

		for _, gt := range t.grants {
			if gt.none || gt.kind == grantVia {
				continue
			}

			app := gt.app != nil && ruleForm(true, nil) == reasonNone
			eligible := app || slices.ContainsFunc(gt.ip, func(ipr ipRule) bool { return ruleForm(false, ipr.proto) == reasonNone })

			if !eligible {
				continue
			}

			identity := false

			for _, id := range gt.srcs {
				if t.table().Selector(id).Kind.HoldsNodes() {
					st.sel[id] = true
					identity = true
				}
			}

			// A companion runs from the destinations.
			for _, id := range gt.dsts {
				if app && t.table().Selector(id).Kind.HoldsNodes() {
					st.sel[id] = true
				}
			}

			if gt.kind == grantSelf && identity {
				st.owner = true
			}
		}

		t.stampTab = st
	})

	return t.stampTab
}

// Stamps are the source capabilities one node holds, sorted. A value is
// shared by every node with the same role set and must not be modified.
type Stamps []nodecap.Cap

// stampMemo shares a role set's stamps across nodes and commits.
type stampMemo struct {
	m sync.Map // RoleSet -> Stamps
}

// StampsOf returns the source capabilities a node with role set rs holds
// under t: the identity selectors it is a member of that a rule can name,
// and its owner's capability when a self rule can. Membership, not
// holding a member's address: the client asks the node holding a source
// address, and a node is stamped only for what all of its addresses are
// sources of; [sourceForm] sends a selector as addresses wherever another
// node holds a member's address.
//
// No test tells membership from holding a member's address: they differ on
// a shared address only, whose selector [sourceForm] sends as addresses
// either way, so no client decision moves. Membership is kept as the
// notion that stays exact once that fallback lifts.
func (t *Templates) StampsOf(rs RoleSet) Stamps {
	if v, ok := t.stampCache.m.Load(rs); ok {
		return v.(Stamps) //nolint:forcetypeassert // only stamps are stored
	}

	st := t.stamps()

	var out Stamps

	for r := range rs.All() {
		if id, ok := r.Selector(); ok && int(id) < len(st.sel) && st.sel[id] {
			out = append(out, selectorCap(t.table().Selector(id)))
		}

		if uid, ok := r.Owner(); ok && st.owner {
			out = append(out, ownerCap(uid))
		}
	}

	slices.Sort(out)
	out = slices.Clip(slices.Compact(out))

	v, _ := t.stampCache.m.LoadOrStore(rs, out)

	return v.(Stamps) //nolint:forcetypeassert // only stamps are stored
}

// WithStamps returns caps with stamps added, without any capability of the
// reserved namespace caps carried; caps itself when there is nothing to
// add or drop.
func WithStamps(caps tailcfg.NodeCapMap, stamps Stamps) tailcfg.NodeCapMap {
	reserved := false

	for c := range caps {
		if IsSourceCap(string(c)) {
			reserved = true

			break
		}
	}

	if len(stamps) == 0 && !reserved {
		return caps
	}

	out := make(tailcfg.NodeCapMap, len(caps)+len(stamps))

	for c, v := range caps {
		if !IsSourceCap(string(c)) {
			out[c] = v
		}
	}

	for _, c := range stamps {
		out[c] = nil
	}

	return out
}

// FallbackCensus counts, per reason, the receivers whose whole filter goes
// as addresses and the rules with a source that does: what the fallbacks
// cost, for the debug endpoint and metrics. Index by [FallbackReasons]
// order, reasonNone first.
type FallbackCensus struct {
	// Receivers counts nodes by the reason their whole filter goes as
	// addresses; reasonNone counts the nodes sent capabilities.
	Receivers [numReasons]int
	// Rules counts, by reason, the rules a node sent capabilities can be
	// cut with a source in address form; an autogroup:self rule counts
	// once per owner. reasonNone counts the rules with none.
	Rules [numReasons]int
}

// Labelled returns the census as counts by reason label.
func (c FallbackCensus) Labelled() (map[string]int, map[string]int) {
	receivers, rules := map[string]int{}, map[string]int{}

	for r := range numReasons {
		receivers[r.String()] = c.Receivers[r]
		rules[r.String()] = c.Rules[r]
	}

	return receivers, rules
}

// formLog records, for one cut, the decision for every rule and source
// that went as addresses, so a test can tell an address source no decision
// covers. Only [sourceForm]'s callers in this file write it.
type formLog struct {
	// layout is the receiver's reason; a reason sends every rule as
	// addresses.
	layout ipReason
	// rules holds, per rule cut, the reasons its address sources were
	// written for.
	rules [][]ipReason
}

func (l *formLog) rule(reasons ...ipReason) {
	if l != nil {
		l.rules = append(l.rules, reasons)
	}
}

// addressCuts counts, by reason, the filters cut as address mode writes
// them, and addressRules the rules cut with sources as addresses into a
// filter otherwise in capability form.
var (
	addressCuts  [numReasons]atomic.Uint64
	addressRules [numReasons]atomic.Uint64
)

// AddressFormCounts returns, by reason label, the filters cut entirely as
// addresses and the rules cut with an address source into filters
// otherwise in capability form, since the process started.
func AddressFormCounts() (map[string]uint64, map[string]uint64) {
	filters, rules := map[string]uint64{}, map[string]uint64{}

	for r := reasonNone + 1; r < numReasons; r++ {
		filters[r.String()] = addressCuts[r].Load()
		rules[r.String()] = addressRules[r].Load()
	}

	return filters, rules
}

// addressSources returns srcs, sources written as addresses for why, and
// counts the rule.
func addressSources(why ipReason, srcs []string) []string {
	addressRules[why].Add(1)

	return srcs
}

// capInfo is what capability form needs beyond address form: which
// selectors and owners a node shares an address across, and each grant's
// sources as a receiver sent capabilities is sent them.
type capInfo struct {
	// shared marks, by selector, the identity selectors a node outside
	// holds a member's address of; ownerShared the owners one of whose
	// nodes shares an address with a node not theirs.
	shared      []bool
	ownerShared map[uint]bool
	grants      []grantCaps
}

// sharing is which identity selectors and owners nodes share an address
// across, see [capInfo].
type sharing struct {
	shared      []bool
	ownerShared map[uint]bool
}

// sharingScans counts the times sharing was found by sorting every node's
// addresses rather than carried over.
var sharingScans atomic.Uint64

// findSharing finds which selectors and owners the nodes of list, with
// posts their roles, share an address across.
func findSharing(list views.Slice[types.NodeView], posts Postings, selectors int) *sharing {
	sharingScans.Add(1)

	sh := &sharing{shared: make([]bool, selectors), ownerShared: map[uint]bool{}}

	for _, holders := range addressHolders(list) {
		count := map[SelectorID]int{}
		owners := map[uint]int{}

		for _, id := range holders {
			rs, _ := posts.byRole.In.Get(id)
			for r := range rs.All() {
				if sel, ok := r.Selector(); ok {
					count[sel]++
				}

				if uid, ok := r.Owner(); ok {
					owners[uid]++
				}
			}
		}

		for sel, n := range count {
			if n < len(holders) {
				sh.shared[sel] = true
			}
		}

		for uid, n := range owners {
			if n < len(holders) {
				sh.ownerShared[uid] = true
			}
		}
	}

	return sh
}

// grantCaps is a grant's sources in capability form.
type grantCaps struct {
	// srcs are its rules' sources: identity sources as capabilities, the
	// rest as addresses; nil when they come to nothing. reasons are why
	// the address sources among them are.
	srcs    []string
	reasons []ipReason

	// app and comp are the sources of its app capability rule and of its
	// companions, which run from its destinations; written on first use,
	// as they read the grant's addresses.
	appOnce   sync.Once
	app, comp formSources
}

// formSources are a rule's sources and why those written as addresses
// are.
type formSources struct {
	srcs    []string
	reasons []ipReason
}

// eligible is a receiver no receiver-wide reason sends addresses: what
// [Expansion.capForms] decides sources for, since a receiver it does not
// describe is cut in address form throughout.
var eligible = ReceiverFacts{Client: true}

// sharing returns which selectors and owners nodes share an address
// across: what the filters served give, else found from the list.
func (x *Expansion) sharing() *sharing {
	if x.share != nil {
		return x.share()
	}

	return findSharing(x.list, x.posts, x.table.Len())
}

// capForms returns what capability form needs, built once. Each grant's
// port rule sources read addresses only where a fallback writes them so.
func (x *Expansion) capForms() *capInfo {
	x.capsOnce.Do(func() {
		sh := x.sharing()
		ci := &capInfo{shared: sh.shared, ownerShared: sh.ownerShared, grants: make([]grantCaps, len(x.t.grants))}

		for g, gt := range x.t.grants {
			if gt.none || gt.kind == grantVia {
				continue
			}

			ports := x.selectorForms(gt.srcs, false, gt.wildcard, ci)
			ci.grants[g].srcs, ci.grants[g].reasons = ports.srcs, ports.reasons
		}

		x.caps = ci
	})

	return x.caps
}

// appForms returns the sources of grant g's app capability rule and its
// companions for a receiver sent capabilities, written once.
func (ci *capInfo) appForms(x *Expansion, g int) (formSources, formSources) {
	gc := &ci.grants[g]
	gc.appOnce.Do(func() { gc.app, gc.comp = x.appCaps(x.t.grants[g], x.grant(g), ci) })

	return gc.app, gc.comp
}

// appCaps decides each source of gt's app capability rule and companions
// for a receiver sent capabilities.
func (x *Expansion) appCaps(gt *GrantTemplate, ge *grantExpansion, ci *capInfo) (formSources, formSources) {
	if !ge.capGrant {
		return formSources{}, formSources{}
	}

	if why := ruleForm(true, nil); why != reasonNone {
		srcs := ge.srcStrs
		if srcs == nil {
			// The compile writes a capability rule from nobody with empty
			// sources, not none.
			srcs = []string{}
		}

		return formSources{srcs: srcs, reasons: []ipReason{why}}, formSources{srcs: ge.dstIPs, reasons: []ipReason{why}}
	}

	return x.selectorForms(gt.srcs, true, gt.wildcard, ci), x.selectorForms(gt.dsts, true, gt.dstWildcard, ci)
}

// selectorForms writes ids, the sources of a rule granting app
// capabilities when capGrant, for a receiver sent capabilities: each as
// [sourceForm] decides, the addresses sorted as address form writes them,
// then the capabilities. wildcard adds the approved subnet routes a *
// names.
func (x *Expansion) selectorForms(ids []SelectorID, capGrant, wildcard bool, ci *capInfo) formSources {
	var (
		fs    formSources
		addrs []string
		caps  []string
	)

	address := func(why ipReason, srcs ...string) {
		addrs = append(addrs, srcs...)

		if !slices.Contains(fs.reasons, why) {
			fs.reasons = append(fs.reasons, why)
		}
	}

	for _, id := range ids {
		s := x.table.Selector(id)

		why := sourceForm(CapabilitySources, eligible, capGrant, nil, sourceTraits{kind: s.Kind, shared: ci.shared[id]})
		switch {
		case why == reasonNone && s.Kind.HoldsNodes():
			caps = append(caps, capSourcePrefix+string(selectorCap(s)))
		case why == reasonNone:
			// A literal sent as a capability no node holds: only a test
			// switching the literal fallback off gets here.
			caps = append(caps, capSourcePrefix+selectorCapPrefix+s.Name)
		case s.Kind == SelectorDangerAll:
			address(why, "*")
		case s.Kind.HoldsNodes():
			address(why, x.res(id).Strings()...)
		default:
			if l := x.t.literals[id]; l.res != nil {
				address(why, l.res.Strings()...)
			}
		}
	}

	// * adds the approved subnet routes, which only an address names.
	if wildcard && len(x.routes) > 0 {
		if why := sourceForm(CapabilitySources, eligible, capGrant, nil, sourceTraits{kind: SelectorWildcard}); why != reasonNone {
			address(why, x.routes...)
		}
	}

	srcs := formatSources(addrs)
	if len(srcs) == 1 && srcs[0] == "*" {
		fs.srcs = srcs

		return fs
	}

	slices.Sort(caps)
	fs.srcs = append(srcs, slices.Compact(caps)...)

	return fs
}

// selfCapabilityOnly reports whether every autogroup:self rule of grant g
// cut for owner uid goes as the owner's capability, with named saying how
// many of the owner's nodes each source names: [Expansion.capFormSelf]'s
// decision, asked of every rule. Such rules read none of the owner's
// nodes but the receiver.
func (x *Expansion) selfCapabilityOnly(g int, uid uint, named []selfNaming) bool {
	gt := x.t.grants[g]

	// TODO(kradalby): overwake/self-owners-every-form: an app self grant is
	// declined outright, though capFormSelf cuts its rules as the owner's
	// capability when no fallback applies to them, so routing names its
	// owners in every form. Fixing it takes asking ruleForm and selfForm of
	// the app rule as capFormSelf does. Tolerated by
	// TestFormShortcutsAgreeWithSourceForm ("selfCapabilityOnly declines an
	// app self grant") and unmovedNamed in
	// TestFiltersChangedSoundPreciseAndCarried. No upstream reference:
	// headscale's own routing shortcut.
	if gt.app != nil {
		return false
	}

	for _, ipr := range gt.ip {
		if len(ipr.ports) == 0 {
			continue
		}

		for k, src := range x.srcIDs(g) {
			if named[k] != namedNone && x.selfForm(ipr.proto, src, uid, named[k] == namedAll) != reasonNone {
				return false
			}
		}
	}

	return true
}

// selfForm decides an autogroup:self rule's source src, which names some
// of owner uid's nodes, every one when all: an identity source naming every
// node of the owner, none of which shares an address with another node,
// goes as the owner's capability. Only an address another node holds names
// some of an owner's nodes and not all: membership is by user.
func (x *Expansion) selfForm(proto []int, src SelectorID, uid uint, all bool) ipReason {
	return sourceForm(CapabilitySources, eligible, false, proto, sourceTraits{
		kind:   x.table.Selector(src).Kind,
		shared: !all || x.capForms().ownerShared[uid],
	})
}

// selfNamed returns how many of owner uid's nodes each source of self
// grant g names, as [Expansion.selfRules] counts them by address: by
// membership where no node outside a source holds a member's address and
// none of the owner's shares one, which then decides it alike, so
// capability form need not resolve the sources.
func (x *Expansion) selfNamed(g int, uid uint) []selfNaming {
	ci := x.capForms()
	srcs := x.srcIDs(g)

	if ci.ownerShared[uid] || slices.ContainsFunc(srcs, func(id SelectorID) bool {
		return !x.table.Selector(id).Kind.HoldsNodes() || ci.shared[id]
	}) {
		return x.selfRules(g, uid).named
	}

	named := make([]selfNaming, len(srcs))
	owned := x.posts.Nodes(OwnerRole(uid))

	for k, src := range srcs {
		some, every := false, true

		for _, id := range owned {
			n, ok := x.node(id)
			if !ok {
				continue
			}

			rs, _ := x.posts.byRole.In.Get(id)
			in := len(n.IPs()) > 0 && rs.Has(SelectorRole(src))
			some = some || in
			every = every && (in || len(n.IPs()) == 0)
		}

		switch {
		case some && every:
			named[k] = namedAll
		case some:
			named[k] = namedSome
		}
	}

	return named
}

// addressHolders returns, for every address more than one node of nodes
// holds, its holders.
func addressHolders(nodes views.Slice[types.NodeView]) [][]types.NodeID {
	type held struct {
		ip netip.Addr
		id types.NodeID
	}

	all := make([]held, 0, 2*nodes.Len())

	for _, n := range nodes.All() {
		for _, ip := range n.IPs() {
			all = append(all, held{ip: ip, id: n.ID()})
		}
	}

	slices.SortFunc(all, func(a, b held) int {
		if c := a.ip.Compare(b.ip); c != 0 {
			return c
		}

		return cmp.Compare(a.id, b.id)
	})

	var out [][]types.NodeID

	for i := 0; i < len(all); {
		j := i + 1
		for j < len(all) && all[j].ip == all[i].ip {
			j++
		}

		if j-i > 1 {
			ids := make([]types.NodeID, 0, j-i)
			for _, h := range all[i:j] {
				ids = append(ids, h.id)
			}

			out = append(out, slices.Compact(ids))
		}

		i = j
	}

	return out
}

// addressPair reports whether a receiver sent capabilities is sent a rule
// of grant gt with a source written as addresses whatever its kind: an app
// capability rule and its companions, or a rule over a protocol without
// ports. Identity and literal sources of the grant's other rules are
// written in [capInfo]'s form, which routing compares apart. Only such a
// receiver's filter follows the addresses the grant's sources resolve to.
// A via grant never asks: routing returns before naming its receivers.
func addressPair(gt *GrantTemplate) bool {
	return gt.app != nil || slices.ContainsFunc(gt.ip, func(ipr ipRule) bool { return ruleForm(false, ipr.proto) != reasonNone })
}

// Census counts what the fallbacks of f send as addresses, with receivers
// every node's facts: the nodes whose whole filter does, by reason, and,
// for the nodes sent capabilities, the rules a source of which does. The
// rules are counted once per filters, from the last census counted before
// them where they follow it: then the self rules are counted again only for
// the owners whose nodes moved since, and a metrics scrape costs the
// grants and what moved, not the tailnet. In address mode it counts
// nothing: mode off does no work it did not do before.
func (f *Filters) Census(receivers Receivers) (FallbackCensus, error) {
	var c FallbackCensus

	if f.mode != CapabilitySources {
		return c, nil
	}

	f.censusOnce.Do(func() {
		var n *censusCount

		n, f.censusErr = f.countRules()
		if f.censusErr == nil {
			f.census.Rules = [numReasons]int(n.grants.plus(n.selfTotal, 1))
			f.counted.Store(n)
		}
	})

	c, err := f.census, f.censusErr
	if err != nil {
		return c, err
	}

	for k, n := range receivers.kinds {
		c.Receivers[receiverForm(f.mode, factsOfKind(k))] += n
	}

	return c, nil
}

// censusCount is a census of the rules: the grants' but the self rules,
// the self rules by owner and in all, and what those were counted under:
// each self grant's template, held weakly so an older document does not
// stay alive through the census, and the addresses shared.
type censusCount struct {
	grants     reasonCounts
	selfCounts *graph.Map[uint, reasonCounts]
	selfTotal  reasonCounts
	selfGrants []weak.Pointer[GrantTemplate]
	shared     *sharing
}

// selfGrantsOf is t's self grant templates by position, weakly.
func selfGrantsOf(t *Templates) []weak.Pointer[GrantTemplate] {
	out := make([]weak.Pointer[GrantTemplate], len(t.grants))

	for g, gt := range t.grants {
		if gt.kind == grantSelf {
			out[g] = weak.Make(gt)
		}
	}

	return out
}

// censusBase is a census some filters before f counted, and the owners
// whose nodes moved since, whose self rules f counts again.
type censusBase struct {
	of    *censusCount
	dirty *graph.Map[uint, struct{}]
}

// ownerCounts counts the censuses counted from every owner rather than
// carried over.
var ownerCounts atomic.Uint64

// reasonCounts counts rules by reason.
type reasonCounts [numReasons]int

// plus returns a with sign times b added.
func (a reasonCounts) plus(b reasonCounts, sign int) reasonCounts {
	for i := range a {
		a[i] += sign * b[i]
	}

	return a
}

func sameReasonCounts(a, b reasonCounts) bool { return a == b }

// followCensus gives f a base to count its census from: prev's census, or
// the one prev would count from, with the owners of moved, the nodes whose
// facts or roles moved since prev, marked. A self rule's form reads its
// owner's nodes, their roles, what they share and its template alone, so
// the base holds while the addresses shared are carried unchanged and no
// self grant's template moved; else f counts every owner.
func (f *Filters) followCensus(prev *Filters, moved []types.NodeID) {
	base := prev.censusFrom
	if n := prev.counted.Load(); n != nil {
		base = &censusBase{of: n, dirty: graph.NewMap[uint](graph.Same[struct{}], nil)}
	}

	if base == nil || f.shared.Load() == nil || f.shared.Load() != base.of.shared || !slices.Equal(base.of.selfGrants, selfGrantsOf(f.t)) {
		return
	}

	if len(moved) == 0 {
		f.censusFrom = base

		return
	}

	e := base.dirty.Edit()

	for _, id := range moved {
		for _, p := range [2]Postings{prev.posts, f.posts} {
			rs, _ := p.byRole.In.Get(id)
			for r := range rs.All() {
				if uid, ok := r.Owner(); ok {
					e.Set(uid, struct{}{})
				}
			}
		}
	}

	f.censusFrom = &censusBase{of: base.of, dirty: e.Done()}
}

// countRules counts the rules' census: from censusFrom, counting again
// the self rules of the owners marked there, else from every owner.
func (f *Filters) countRules() (*censusCount, error) {
	x, err := f.expansion()
	if err != nil {
		return nil, err
	}

	n := &censusCount{grants: f.countGrants(x), selfGrants: selfGrantsOf(f.t), shared: x.sharing()}

	if b := f.censusFrom; b != nil {
		n.selfTotal = b.of.selfTotal
		e := b.of.selfCounts.Edit()

		for uid := range b.dirty.All() {
			was, _ := b.of.selfCounts.Get(uid)
			is := x.selfCount(uid)

			n.selfTotal = n.selfTotal.plus(was, -1).plus(is, 1)

			if is == (reasonCounts{}) {
				e.Delete(uid)
			} else {
				e.Set(uid, is)
			}
		}

		n.selfCounts = e.Done()

		return n, nil
	}

	ownerCounts.Add(1)

	owners := map[uint]reasonCounts{}

	for _, uid := range x.ownerIDs() {
		if c := x.selfCount(uid); c != (reasonCounts{}) {
			owners[uid] = c
			n.selfTotal = n.selfTotal.plus(c, 1)
		}
	}

	n.selfCounts = graph.NewMap(sameReasonCounts, owners)

	return n, nil
}

// countGrants counts the rules of every grant but the self rules each
// owner is cut.
func (f *Filters) countGrants(x *Expansion) reasonCounts {
	var c FallbackCensus

	ci := x.capForms()

	for g, gt := range f.t.grants {
		switch {
		case gt.none:
			continue
		case gt.kind == grantVia:
			// Via rules reach only routers.
			c.Rules[reasonLocalNets] += len(gt.ip)

			continue
		}

		gc := &ci.grants[g]

		// A self grant's rules over its other destinations, if any.
		for _, ipr := range gt.ip {
			if len(gt.dsts) == 0 {
				break
			}

			if why := ruleForm(false, ipr.proto); why != reasonNone {
				c.Rules[why]++

				continue
			}

			if len(gc.reasons) == 0 {
				c.Rules[reasonNone]++
			}

			for _, why := range gc.reasons {
				c.Rules[why]++
			}
		}

		if gt.app != nil {
			c.Rules[reasonCapGrant]++
		}
	}

	return c.Rules
}

// selfCount counts the self rules owner uid is cut, by reason.
func (x *Expansion) selfCount(uid uint) reasonCounts {
	var n reasonCounts

	for g, gt := range x.t.grants {
		if gt.none || gt.kind != grantSelf {
			continue
		}

		named := x.selfNamed(g, uid)

		for _, ipr := range gt.ip {
			for k, src := range x.srcIDs(g) {
				switch {
				case named[k] == namedNone:
				case ruleForm(false, ipr.proto) != reasonNone:
					n[ruleForm(false, ipr.proto)]++
				default:
					n[x.selfForm(ipr.proto, src, uid, named[k] == namedAll)]++
				}
			}
		}
	}

	return n
}

// AgreesWithAddressForm returns how capForm, a receiver's filter in
// capability form, differs from ipForm, the same receiver's address form,
// once its capabilities are written as the addresses of their holders:
// compared as rule multisets, each rule's lists as sets, since capability
// form keeps each grant's rules apart where address form merges them.
func AgreesWithAddressForm(capForm, ipForm []tailcfg.FilterRule, holders func(nodecap.Cap) []netip.Addr) error {
	if slices.EqualFunc(capForm, ipForm, func(a, b tailcfg.FilterRule) bool { return reflect.DeepEqual(a, b) }) {
		return nil
	}

	got := ruleMultiset(expandFilter(capFilter{rules: capForm}, holders, reasonAddressMode))
	want := ruleMultiset(ipForm)

	if !slices.Equal(got, want) {
		return fmt.Errorf("%w:\naddress form    %v\ncapability form %v\nexpanded        %v", errCapForm, want, capForm, got)
	}

	return nil
}

var errCapForm = errors.New("capability form expands otherwise than address form")

// ruleMultiset writes rules as a multiset: each rule's lists sorted, app
// capability values as JSON, the rules in any order.
func ruleMultiset(rules []tailcfg.FilterRule) []string {
	out := make([]string, 0, len(rules))

	for _, r := range rules {
		// Sets: two nodes holding one address list it twice in address
		// form, once in capability form.
		srcs := slices.Compact(slices.Sorted(slices.Values(r.SrcIPs)))

		dsts := make([]string, 0, len(r.DstPorts))
		for _, d := range r.DstPorts {
			dsts = append(dsts, fmt.Sprintf("%s:%d-%d", d.IP, d.Ports.First, d.Ports.Last))
		}

		slices.Sort(dsts)
		dsts = slices.Compact(dsts)

		protos := slices.Compact(slices.Sorted(slices.Values(r.IPProto)))

		grants := make([]string, 0, len(r.CapGrant))

		for _, g := range r.CapGrant {
			ds := make([]string, 0, len(g.Dsts))
			for _, p := range g.Dsts {
				ds = append(ds, p.String())
			}

			slices.Sort(ds)
			ds = slices.Compact(ds)

			caps := make([]string, 0, len(g.CapMap))
			for c, vs := range g.CapMap {
				vals := make([]string, 0, len(vs))
				for _, v := range vs {
					vals = append(vals, compactJSON(v))
				}

				caps = append(caps, string(c)+"="+strings.Join(vals, ","))
			}

			slices.Sort(caps)
			grants = append(grants, strings.Join(ds, ",")+" "+strings.Join(caps, ";"))
		}

		slices.Sort(grants)
		grants = slices.Compact(grants)
		out = append(out, fmt.Sprintf("src=%v dst=%v proto=%v caps=%v", srcs, dsts, protos, grants))
	}

	slices.Sort(out)

	return out
}

// compactJSON writes a capability value as JSON with its keys sorted,
// whatever spacing and order it was given.
func compactJSON(m tailcfg.RawMessage) string {
	var v any

	err := json.Unmarshal([]byte(m), &v)
	if err != nil {
		return string(m)
	}

	b, err := json.Marshal(v)
	if err != nil {
		return string(m)
	}

	return string(b)
}
