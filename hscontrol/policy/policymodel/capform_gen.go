package policymodel

import (
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// Shapes for capability form: rules naming identities, which go as cap:
// sources, and scripted tours that flip one receiver in and out of every
// fallback in turn, so that each reason is met as a receiver's own fact
// and as a transition the receiver reads across.

// identityKinds are the source kinds a client matches by capability.
var identityKinds = []SelKind{SelUser, SelGroup, SelTag, SelMember, SelTagged}

// identitySrcs draws one to three identity sources.
var identitySrcs = rapid.SliceOfN(selGen(identityKinds), 1, 3)

// identitySources returns a rule's sources when ident: drawn identities,
// with the first general source after them when mixed, so a literal can
// sit beside them; else general.
func identitySources(ident, mixed bool, ids, general []Sel) []Sel {
	if !ident {
		return general
	}

	if mixed && len(general) > 0 && !slices.Contains(ids, general[0]) {
		return append(slices.Clone(ids), general[0])
	}

	return ids
}

// The fallbacks a form tour flips its receiver through, and two shapes
// beside them. Each is a step turning it on and a step turning it off, the
// receiver reading after both; tourValues is three steps.
const (
	tourAnnounce     = iota // announces a route, approved only if the auto-approvers approve it
	tourApproved            // announces a route and an admin approves it
	tourAppConnector        // runs as an app connector
	tourServiceHost         // nodeAttrs make it a service host
	tourUnknown             // its client reports no versions
	tourRS                  // its client is tailscale-rs
	tourCapGrant            // the rule it reads grants app capabilities too
	tourPortless            // the rule it reads goes over a protocol without ports
	tourValues              // app capability values that differ past the first
	tourNoIPv4              // nodeAttrs give it disable-ipv4: its client is shown no IPv4 address
	numTour
)

// tourStops draws which fallbacks a tour visits, in order.
var tourStops = rapid.SliceOfN(rapid.IntRange(0, numTour-1), 1, 4)

// formTour is a grant to an eligible node of w from identity sources that
// name another node, then the node flipped in and out of each fallback of
// stops, reading after every step. who picks the node and the grant's
// sources: one identity, an identity beside a host, two identities, or
// the members to their own devices. None when w has no eligible node with an address,
// or holds a token users made ambiguous, which no policy write gets past.
func formTour(w World, who int, stops []int) []Step {
	v := NewView(w)
	if len(v.AmbiguousRefs()) > 0 {
		return nil
	}

	var eligible []Node

	for _, n := range w.Topology.Nodes {
		if v.Eligible(n) && len(n.Addrs()) > 0 {
			eligible = append(eligible, n)
		}
	}

	if len(eligible) == 0 {
		return nil
	}

	n := eligible[who%len(eligible)]
	target, src := tourDest(v, n), tourSources(v, n, who/len(eligible)%4)

	dst := target
	if len(src) == 0 {
		dst, src = Sel{Kind: SelSelf}, []Sel{{Kind: SelMember}}
	}

	rule := Rule{Src: src, Dst: []Dest{{Sel: dst}}, IP: []IP{{}}}
	ref := RuleRef{Grant: true}
	read := []types.NodeID{n.ID}

	steps := []Step{{Edits: []Edit{AddRule{ref, rule}}, Reads: read}}
	cur := w.Apply(steps[0].Edits...)

	for _, stop := range stops {
		for _, edits := range tourFlip(cur, n, ref, target, stop) {
			steps = append(steps, Step{Edits: edits, Reads: read})
			cur = cur.Apply(edits...)
		}
	}

	return steps
}

// tourDest is a destination naming n: its tag, a token naming its user
// alone, or every member's device.
func tourDest(v *View, n Node) Sel {
	if n.Tagged() {
		return Sel{Kind: SelTag, I: n.Tags[0]}
	}

	for ref := range UserRefs {
		if ids := v.RefUsers(ref); len(ids) == 1 && ids[0] == n.User {
			return Sel{Kind: SelUser, I: ref}
		}
	}

	return Sel{Kind: SelMember}
}

// tourSources are identity sources naming a node of v other than n with
// an address, by variant: one, one beside the host h-net, or two; or none,
// for an untagged n, for the members to their own devices.
func tourSources(v *View, n Node, variant int) []Sel {
	var other Node

	for _, m := range v.nodes {
		if m.ID != n.ID && len(m.Addrs()) > 0 {
			other = m

			break
		}
	}

	ident := Sel{Kind: SelMember}

	switch {
	case other.Tagged():
		ident = Sel{Kind: SelTag, I: other.Tags[0]}
	case other.ID != 0:
		for ref := range UserRefs {
			if ids := v.RefUsers(ref); len(ids) == 1 && ids[0] == other.User {
				ident = Sel{Kind: SelUser, I: ref}

				break
			}
		}
	}

	second := Sel{Kind: SelTagged}
	if ident.Kind == SelTag || ident.Kind == SelTagged {
		second = Sel{Kind: SelMember}
	}

	switch variant {
	case 1:
		return []Sel{ident, {Kind: SelHost}}
	case 2:
		return []Sel{ident, second}
	case 3:
		if !n.Tagged() {
			return nil
		}
	}

	return []Sel{ident}
}

// tourFlip is the edits turning fallback stop on at n and off again, one
// list a step, in w with the tour's grant at ref; target names n. None
// where w cannot take them: no route left to announce.
func tourFlip(w World, n Node, ref RuleRef, target Sel, stop int) [][]Edit {
	route := slices.IndexFunc([]int{0, 6, touching}, func(r int) bool { return !slices.Contains(n.Announced, r) })
	routes := []int{[]int{0, 6, touching}[max(route, 0)]}
	official := SetClient{n.ID, Official}

	switch stop {
	case tourAnnounce:
		if route < 0 {
			return nil
		}

		return [][]Edit{{Announce{n.ID, routes}}, {Withdraw{n.ID, routes}}}
	case tourApproved:
		if route < 0 {
			return nil
		}

		return [][]Edit{{Announce{n.ID, routes}, Approve{n.ID, routes}}, {Withdraw{n.ID, routes}, Unapprove{n.ID, routes}}}
	case tourAppConnector:
		return [][]Edit{{SetClient{n.ID, AppConnector}}, {official}}
	case tourServiceHost, tourNoIPv4:
		attr := attrServiceHost
		if stop == tourNoIPv4 {
			attr = attrDisableIPv4
		}

		attrs := w.Policy.NodeAttrs
		with := append(slices.Clone(attrs), NodeAttr{Targets: []Sel{target}, Attrs: []int{attr}})

		return [][]Edit{{SetNodeAttrs{with}}, {SetNodeAttrs{attrs}}}
	case tourUnknown:
		return [][]Edit{{SetClient{n.ID, Unknown}}, {official}}
	case tourRS:
		return [][]Edit{{SetClient{n.ID, TailscaleRS}}, {official}}
	case tourCapGrant:
		return [][]Edit{{SetApp{ref, []App{{Cap: 0, Value: 1}}}}, {SetApp{ref, nil}}}
	case tourPortless:
		gre := slices.Index(Protos, "gre")

		return [][]Edit{{SetIP{ref, []IP{{Proto: gre}}}}, {SetIP{ref, []IP{{}}}}}
	case tourValues:
		apps := []App{{Cap: 0, Value: appSingles}}

		return [][]Edit{{SetApp{ref, apps}}, {SetApp{ref, valuesTail(apps)}}, {SetApp{ref, nil}}}
	}

	return nil
}

// doubleGrants: one scenario in so many ends with [doubleGrant].
const doubleGrants = 2

// doubleGrant is steps on an online node of w that holds its own IPv4
// address and its own IPv6 one: a grant with two app capabilities, one
// key carrying two values, whose two destinations both name the
// receiver but differently — one whole, one its IPv4 address alone — so
// the rule its filter is cut from carries two CapGrant entries that
// differ; then the second destination moves to the receiver's IPv6
// alone and back, and the values change past the first, the receiver
// reading after every step. A chunk name that encodes only the first
// CapGrant of a rule keeps its name across the destination move while
// the rule changes. None when w holds a token users made ambiguous, or
// no online node holds both of its own addresses.
func doubleGrant(w World, who int) []Step {
	v := NewView(w)
	if len(v.AmbiguousRefs()) > 0 {
		return nil
	}

	var online []Node

	for _, n := range w.Topology.Nodes {
		// The receiver's own addresses, which 100.64.0.0/30 and
		// fd7a:115c:a1e0::/120 hold for the first nodes.
		if !n.Offline && n.V4 == ownAddr(4, uint64(n.ID)) && n.V6 == ownAddr(6, uint64(n.ID)) {
			online = append(online, n)
		}
	}

	if len(online) == 0 {
		return nil
	}

	n := online[who%len(online)]

	// dst names the receiver whole; part names its IPv4 address alone,
	// and part6 its IPv6 one: the receiver's cut of the rule carries one
	// whole CapGrant entry and one partial, either family.
	dst := Sel{Kind: SelMember}
	if n.Tagged() {
		dst = Sel{Kind: SelTag, I: n.Tags[0]}
	}

	part := Sel{Kind: SelPrefix, I: 2}

	src := tourSources(v, n, who/len(online)%4)
	if len(src) == 0 {
		src = []Sel{{Kind: SelMember}}
	}

	apps := []App{{Cap: 0, Value: appSingles}, {Cap: 1, Value: appSingles}}
	ref := RuleRef{Grant: true, I: len(w.Policy.Grants)}
	read := []types.NodeID{n.ID}

	return []Step{
		{Edits: []Edit{AddRule{ref, Rule{Src: src, Dst: []Dest{{Sel: dst}, {Sel: part}}, App: apps}}}, Reads: read},
		{Edits: []Edit{SetSel{ref, true, 1, Sel{Kind: SelPrefix, I: 5}}}, Reads: read},
		{Edits: []Edit{SetSel{ref, true, 1, part}}, Reads: read},
		{Edits: []Edit{SetApp{ref, valuesTail(apps)}}, Reads: read},
	}
}

// valuesTail is apps with each capability's values traded for the list
// as long and alike in the first value, differing past it, where there is
// one.
func valuesTail(apps []App) []App {
	out := slices.Clone(apps)

	for i, a := range out {
		switch a.Value {
		case 1, 3:
			out[i].Value = 2
		case 2:
			out[i].Value = 3
		}
	}

	return out
}
