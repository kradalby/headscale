// Invariants on what headscale emits, over generated scenarios: every
// served filter parses in the client's own parser, is well formed, names
// capability sources only from the reserved namespace and only for
// selectors the policy can stamp, and nothing a policy can say puts a
// capability of that namespace on a node but the stamping.

package v2

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/wgengine/filter"
)

// ruleDefect returns how rules, served to a node in mode, are malformed:
// the client's parser refuses them; a rule grants nothing, or names no
// source but as a capability rule from nobody (the compile writes those
// so); a source repeats in a rule; a destination is not an address; a
// cap: source outside the reserved namespace, or in address mode at all.
func ruleDefect(rules []tailcfg.FilterRule, mode SourceMode) string {
	_, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		return "the client's parser refuses the filter: " + err.Error()
	}

	for i, r := range rules {
		switch {
		case len(r.DstPorts) == 0 && len(r.CapGrant) == 0:
			return fmt.Sprintf("rule %d grants nothing", i)
		case len(r.SrcIPs) == 0 && len(r.CapGrant) == 0:
			return fmt.Sprintf("rule %d names no source", i)
		case len(r.CapGrant) == 0 && len(slices.Compact(slices.Sorted(slices.Values(r.SrcIPs)))) != len(r.SrcIPs):
			// A companion rule repeats its sources where the document
			// repeats a destination; that one ruleQuirks counts.
			//
			// TODO(kradalby): policy/app-values-repeated: the same root as
			// the repeated app values reference_test.go allows: a grant is
			// written once per destination entry. Fold it into that
			// decision.
			return fmt.Sprintf("rule %d repeats a source: %v", i, r.SrcIPs)
		}

		for _, d := range r.DstPorts {
			if d.IP != "*" && !isAddress(d.IP) {
				return fmt.Sprintf("rule %d's destination %q is not an address", i, d.IP)
			}
		}

		for _, src := range r.SrcIPs {
			c, ok := strings.CutPrefix(src, capSourcePrefix)

			switch {
			case !ok:
			case mode != CapabilitySources:
				return fmt.Sprintf("rule %d names %s in address mode", i, src)
			case !strings.HasPrefix(c, selectorCapPrefix):
				return fmt.Sprintf("rule %d names %s, outside the reserved namespace", i, src)
			}
		}
	}

	return ""
}

func isAddress(s string) bool {
	_, errAddr := netip.ParseAddr(s)
	_, errPrefix := netip.ParsePrefix(s)

	if errAddr == nil || errPrefix == nil {
		return true
	}

	from, to, ok := strings.Cut(s, "-")
	if !ok {
		return false
	}

	_, errFrom := netip.ParseAddr(from)
	_, errTo := netip.ParseAddr(to)

	return errFrom == nil && errTo == nil
}

// tokenDefect returns a cap: source of rules that names no capability the
// templates can stamp: a selector the policy does not use as a source a
// capability form can name, or an owner without a self rule that can.
func tokenDefect(rules []tailcfg.FilterRule, t *Templates) string {
	st := t.stamps()

	for _, r := range rules {
		for _, src := range r.SrcIPs {
			c, ok := strings.CutPrefix(src, capSourcePrefix+selectorCapPrefix)
			if !ok {
				continue
			}

			if strings.HasPrefix(c, "owner:") {
				if !st.owner {
					return src + " names an owner, and no self rule can"
				}

				continue
			}

			if s, ok := t.table().Lookup(c); !ok || !s.Kind.HoldsNodes() || !st.sel[s.ID] {
				return src + " names no source selector the policy can stamp"
			}
		}
	}

	return ""
}

// reservedCap reports whether c is in the namespace of source
// capabilities, with or without its scheme, as the documentation of the
// namespace reads (ErrCapReserved), not as headscale's IsSourceCap does.
func reservedCap(c string) bool {
	return strings.HasPrefix(c, "https://headscale.net/cap/src/") || strings.HasPrefix(c, "headscale.net/cap/src/")
}

// stampDefect returns a capability of the reserved namespace node id is
// rendered with that is not one of its stamps.
func stampDefect(sv *served, id types.NodeID) string {
	rs, _ := sv.roles.Of(id)
	stamps := sv.t.StampsOf(rs)

	for _, self := range []bool{true, false} {
		for c := range sv.render(id, self).CapMap().All() {
			if reservedCap(string(c)) && !slices.Contains(stamps, c) {
				return fmt.Sprintf("n%d is rendered (to itself %t) with %s, which it is not stamped with (%v)", id, self, c, stamps)
			}
		}
	}

	return ""
}

// TestServedFiltersWellFormed holds, after every step of each scenario,
// every node's filter as served in both modes (address mode, and the form
// its facts send it in capability mode) to ruleDefect and tokenDefect, its
// rendered capabilities to stampDefect, and the policy's own node
// capabilities to the reserved namespace: none in it. It counts rules
// repeated whole within one filter, which the format allows. Oracle: the
// client's parser and the namespace rules; nothing of the cut.
func TestServedFiltersWellFormed(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")
		shapes.add(s)

		var (
			st  *stage
			err error
		)

		w := s.Start
		steps := append([]policymodel.Step{{}}, s.Steps...)

		for i, step := range steps {
			next, change := w.Commit(step)

			st, err = stageAt(st, next, change)
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i, stableError(err))
			}

			for id, caps := range st.pm.NodeCapMaps() {
				for c := range caps {
					if reservedCap(string(c)) {
						t.Fatalf("after step %d the policy grants n%d %s, in the reserved namespace", i, id, c)
					}
				}
			}

			for _, n := range st.list {
				for _, m := range []SourceMode{AddressSources, CapabilitySources} {
					f, facts := st.ip, ReceiverFacts{}
					if m == CapabilitySources {
						f, facts = st.cap, st.recv.Of(n.ID)
					}

					rules, err := f.ForNode(n.ID, facts)
					if err != nil {
						t.Fatalf("after step %d n%d: %v", i, n.ID, err)
					}

					if msg := ruleDefect(rules, m); msg != "" {
						t.Fatalf("after step %d n%d, mode %d, is served %s: %s", i, n.ID, m, rulesJSON(rules, nil), msg)
					}

					if msg := tokenDefect(rules, st.t); msg != "" {
						t.Fatalf("after step %d n%d is served %s: %s", i, n.ID, rulesJSON(rules, nil), msg)
					}

					ruleQuirks(rules, m, &tally)

					tally.add(fmt.Sprintf("filters judged, mode %d", m))
				}

				if msg := stampDefect(st.served, n.ID); msg != "" {
					t.Fatalf("after step %d: %s", i, msg)
				}
			}

			w = next
		}
	})

	t.Logf("well formed: %v", &tally)
	shapes.log(t, "well formed")
}

// hostileCaps are capabilities a document may try to put on a node, or
// grant, that look like the reserved namespace: case variants, other
// schemes, the cap: prefix, doubled and encoded separators, padding, and
// the exact names stamps take (filled in from the document).
var hostileCaps = []string{
	"https://headscale.net/cap/src/group:a",
	"HTTPS://HEADSCALE.NET/CAP/SRC/group:a",
	"https://Headscale.net/cap/src/group:a",
	"https://headscale.net/CAP/SRC/group:a",
	"http://headscale.net/cap/src/group:a",
	"cap:https://headscale.net/cap/src/group:a",
	"https://headscale.net//cap/src/group:a",
	"https://headscale.net/cap/src%2Fgroup:a",
	" https://headscale.net/cap/src/group:a",
	"headscale.net/cap/src/group:a",
	"https://headscale.net/cap/src/owner:1",
	"https://headscale.net/cap/src",
	"https://headscale.net/cap/src/*",
	"stamp-of-first-selector",
}

// hostileDoc is w's document with one more nodeAttrs entry granting every
// node c, or one more grant naming c as an app capability, and the
// capability as written.
func hostileDoc(w policymodel.World, c string, app bool) ([]byte, string) {
	var doc map[string]any

	err := json.Unmarshal(w.Policy.HuJSON(), &doc)
	if err != nil {
		panic(err)
	}

	if c == "stamp-of-first-selector" {
		c = selectorCapPrefix + "*"
		if sels := w.Policy.Selectors(); len(sels) > 0 {
			c = selectorCapPrefix + sels[0].String()
		}
	}

	all := []any{"*"}

	if app {
		grants, _ := doc["grants"].([]any)
		doc["grants"] = append(grants, map[string]any{"src": all, "dst": all, "app": map[string]any{c: []any{map[string]any{}}}})
	} else {
		attrs, _ := doc["nodeAttrs"].([]any)
		doc["nodeAttrs"] = append(attrs, map[string]any{"target": all, "attr": []any{c}})
	}

	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}

	return b, c
}

// servedDoc is what headscale serves for doc over w's users and nodes,
// from scratch: [serve] for a document the model does not describe.
func servedDoc(doc []byte, w policymodel.World) (*served, error) {
	users, nodes := w.Topology.Build()

	sv := &served{w: w, users: users, list: nodes}

	nm := map[types.NodeID]*types.Node{}
	for _, n := range nodes {
		nm[n.ID] = n
	}

	sv.nm = graph.NewMap(graph.Same[*types.Node], nm)

	var err error

	sv.pm, err = NewPolicyManager(doc, users, nodes.ViewSlice())
	if err != nil {
		return nil, err
	}

	sv.sel = SelectorsFor(nil, sv.pm)
	sv.us = NewUserSets(nil, sv.sel, users)
	sv.roles = Roles{}.Update(sv.us, sv.nm, nil)
	sv.posts = Postings{}.Update(sv.roles)
	sv.t = BuildTemplates(nil, sv.sel)
	sv.appr = SubnetApprovals{}.Update(sv.nm)
	sv.sides = UpdateSides(Sides{}, sv.t, sv.roles, sv.posts, sv.appr, sv.nm)
	sv.peers = RolePeers(nil, sv.sides)
	sv.caps = graph.NewMap(sameCapMaps, sv.pm.NodeCapMaps())
	sv.recv = Receivers{}.Update(sv.nm, sv.caps)
	sv.ip = NewFiltersFor(AddressSources, sv.t, sv.posts, sv.appr, nodes.ViewSlice())
	sv.cap = NewFiltersFor(CapabilitySources, sv.t, sv.posts, sv.appr, nodes.ViewSlice())

	return sv, nil
}

// TestReservedNamespaceOnlyStamped writes into drawn documents one more
// nodeAttrs entry granting every node, or one more grant naming as an app
// capability, a capability that looks like the reserved namespace
// (hostileCaps), and holds that headscale either refuses the document or
// serves no node a reserved capability but its stamps (stampDefect), no
// filter a cap: source it did not write from a selector (tokenDefect),
// and that the capability, wherever it lands, changes no verdict of any
// node's capability-form filter through the client: the same with every
// node's capabilities rendered as served and with the planted one taken
// out. Oracle: the client's filter and its capability lookup; the
// namespace rules.
func TestReservedNamespaceOnlyStamped(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		w := policymodel.Worlds().Draw(t, "world")
		spelling := rapid.IntRange(0, len(hostileCaps)-1).Draw(t, "spelling")
		app := rapid.Bool().Draw(t, "as an app capability")

		shapes.add(policymodel.Scenario{Start: w})

		doc, c := hostileDoc(w, hostileCaps[spelling], app)

		sv, err := servedDoc(doc, w)
		if err != nil {
			tally.add(fmt.Sprintf("refused %q app=%t", c, app))

			return
		}

		tally.add(fmt.Sprintf("accepted %q app=%t", c, app))

		ref := policymodel.RefOf(w)
		if ref.OutOfDomain() != "" {
			return
		}

		for _, n := range w.Topology.Nodes {
			if msg := stampDefect(sv, n.ID); msg != "" {
				t.Fatalf("document %s: %s", doc, msg)
			}

			rules, err := sv.cap.ForNode(n.ID, sv.recv.Of(n.ID))
			if err != nil {
				t.Fatalf("n%d: %v", n.ID, err)
			}

			if msg := tokenDefect(rules, sv.t); msg != "" {
				t.Fatalf("document %s: n%d is served %s: %s", doc, n.ID, rulesJSON(rules, nil), msg)
			}

			planted, clean := hostileViews(sv, n, w, c)

			if rep := policymodel.CompareViews(rules, planted, clean); !rep.Equivalent() {
				t.Fatalf("document %s: n%d's filter %s answers otherwise with the planted capability (reference) than without (candidate): %s", doc, n.ID, rulesJSON(rules, nil), rep)
			}
		}
	})

	t.Logf("namespace: %v", &tally)
	shapes.log(t, "namespace")
}

// hostileViews are n's client views with peers and itself rendered as
// served, and with the planted capability c taken out of every node.
func hostileViews(sv *served, n policymodel.Node, w policymodel.World, c string) (policymodel.ClientView, policymodel.ClientView) {
	render := func(id types.NodeID, self bool, drop bool) tailcfg.NodeView {
		v := sv.render(id, self)
		if !drop {
			return v
		}

		// The exact stamp spelling, were it accepted, plants a capability
		// the node may hold as its own stamp: that one stays.
		rs, _ := sv.roles.Of(id)
		if slices.Contains(sv.t.StampsOf(rs), nodecap.Cap(c)) {
			return v
		}

		tn := v.AsStruct()
		delete(tn.CapMap, nodecap.Cap(c))

		return tn.View()
	}

	views := func(drop bool) policymodel.ClientView {
		ids := sv.peersOf(n.ID)

		peers := make([]tailcfg.NodeView, 0, len(ids))
		for _, p := range ids {
			peers = append(peers, render(p, false, drop))
		}

		caps := policymodel.NewNetmapCaps(render(n.ID, true, drop), peers)

		return policymodel.ModelView(n, w, &caps, nil)
	}

	return views(false), views(true)
}

// ruleQuirks counts what the format allows that a rule list need not
// hold: a rule repeated whole, and a capability rule repeating a source.
func ruleQuirks(rules []tailcfg.FilterRule, m SourceMode, tally *changeTally) {
	seen := map[string]bool{}

	for _, r := range rules {
		b := jsonString(r)
		if seen[b] {
			tally.add(fmt.Sprintf("rule repeated whole, mode %d", m))
		}

		seen[b] = true

		if len(slices.Compact(slices.Sorted(slices.Values(r.SrcIPs)))) != len(r.SrcIPs) {
			tally.add(fmt.Sprintf("capability rule repeating a source, mode %d", m))
		}
	}
}
