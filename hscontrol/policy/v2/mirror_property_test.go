// Properties holding every place that restates a fallback decision,
// rather than asking sourceForm, to the decision: routing and cutting
// take such shortcuts so they need not build what they will not send. A
// shortcut that says "capability form" where the cut writes addresses
// leaves a receiver holding a stale address list. The oracle is
// sourceForm (fallback.go), or the slow path the shortcut stands for.

package v2

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"pgregory.net/rapid"
)

// fallbackSets are the fallback configurations the shortcuts are held to:
// none switched off, and each reason off alone. Tests switch reasons off
// to show what each prevents; a shortcut must follow the decision whatever
// is switched off.
var fallbackSets = func() [][]ipReason {
	// The client reason decides nothing for an official client, which
	// every shortcut here is asked about but the via premise's.
	out := [][]ipReason{nil}
	for r := reasonLocalNets; r < numReasons; r++ {
		out = append(out, []ipReason{r})
	}

	return out
}()

// withFallbacksOff runs f with the reasons off switched off.
func withFallbacksOff(off []ipReason, f func()) {
	saved := fallbacksOff

	defer func() { fallbacksOff = saved }()

	fallbacksOff = [numReasons]bool{}
	for _, r := range off {
		fallbacksOff[r] = true
	}

	f()
}

// TestMayBeAddressFormCoversReceiverForm holds the address-form index's
// predicate, over every receiver's facts and every set of reasons
// switched off, to the decision it restates: a node receiverForm can send
// addresses is in the index (routing names address-form receivers only
// through it), and with nothing switched off exactly those are. And the
// census's numbering of facts kinds is a bijection. Exhaustive: the space
// is sixteen facts by every subset of the reasons.
func TestMayBeAddressFormCoversReceiverForm(t *testing.T) {
	for k := range numFactKinds {
		f := factsOfKind(k)
		if f.kind() != k {
			t.Fatalf("facts kind %d reads back as %d", k, f.kind())
		}

		for mask := range 1 << (numReasons - 1) {
			var off []ipReason

			for r := reasonAddressMode; r < numReasons; r++ {
				if mask&(1<<(r-1)) != 0 {
					off = append(off, r)
				}
			}

			withFallbacksOff(off, func() {
				why := receiverForm(CapabilitySources, f)

				if why != reasonNone && !mayBeAddressForm(f) {
					t.Errorf("facts %+v with %v off: receiverForm sends addresses (%s), the address-form index leaves the node out", f, off, why)
				}

				if len(off) == 0 && (why != reasonNone) != mayBeAddressForm(f) {
					t.Errorf("facts %+v: receiverForm %s, the address-form index says %t", f, why, mayBeAddressForm(f))
				}
			})
		}
	}
}

// TestFormShortcutsAgreeWithSourceForm holds, over the worlds of drawn
// scenarios built from scratch, the last of each also under every
// configuration of fallbackSets,
// each shortcut that restates a form decision to the decision or to the
// slow path it stands for:
//
//   - addressPair(grant), routing's "a receiver sent capabilities reads
//     this grant's sources as addresses": true wherever sourceForm sends
//     some rule of the grant as addresses whatever its source (an app
//     capability rule or a companion, an ip rule over a protocol without
//     ports);
//   - selfCapabilityOnly(grant, owner): true only if capFormSelf, cut for
//     each of the owner's nodes, writes every self rule as the owner's
//     capability; and true wherever it does, but for grants with an app
//     capability, which it declines outright;
//   - selfNamed's shortcut by membership: equal to the naming
//     selfRules(grant, owner) reads off addresses;
//   - dstPorts by role: equal to dstPorts by address, for every rule and
//     receiver;
//   - the stamp table: a selector is stamped exactly when some rule can
//     send it as a capability, as sourceForm decides for an unshared
//     identity source; owners exactly when a self grant's can; and every
//     cap: token a capability-form cut writes names a stamped selector or
//     owner;
//   - recutReason's premise: a node's address form is the same cut
//     whichever receiver-wide reason sent it;
//   - the premise capFormFor and the stamp table skip via grants on: a node
//     sent capability form has no route a via rule could reach it through.
//     It holds only while the local-nets reason stands (counted apart).
//
// Oracle: sourceForm and the slow paths, in the same package; they share
// the cut's inputs (expansion, postings, sharing).
func TestFormShortcutsAgreeWithSourceForm(t *testing.T) {
	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")
		shapes.add(s)

		worlds := s.Worlds()

		for i, w := range worlds {
			// Every world as served; the last also with each reason off.
			sets := fallbackSets[:1]
			if i == len(worlds)-1 {
				sets = fallbackSets
			}

			for _, off := range sets {
				var msg string

				withFallbacksOff(off, func() { msg = shortcutsDiffer(w, off, &tally) })

				if msg != "" {
					t.Fatalf("after step %d, %v switched off: %s", i, off, msg)
				}
			}
		}
	})

	t.Logf("shortcuts: %v", &tally)
	shapes.log(t, "shortcuts")
}

// shortcutsDiffer builds w from scratch, with fallbacksOff as the caller
// set it, and returns the first shortcut that disagrees with the decision.
func shortcutsDiffer(w policymodel.World, off []ipReason, tally *changeTally) string {
	st, err := stageAt(nil, w, policymodel.Change{})
	if err != nil {
		return "the policy is refused: " + stableError(err)
	}

	x, err := st.cap.expansion()
	if err != nil {
		return "the templates do not expand: " + err.Error()
	}

	for _, check := range []func(*stage, *Expansion, *changeTally) string{
		addressPairDiffers, selfShortcutsDiffer, dstPortsDiffer, stampTableDiffers, recutDiffers,
	} {
		if msg := check(st, x, tally); msg != "" {
			return msg
		}
	}

	if msg := viaPremiseDiffers(st); msg != "" {
		if slices.Contains(off, reasonLocalNets) {
			tally.add("via premise broken with local-nets off")

			return ""
		}

		return msg
	}

	return ""
}

// identityTraits is an unshared identity source: what sourceForm decides
// for a rule's own reasons alone.
var identityTraits = sourceTraits{kind: SelectorGroup}

// shortcutMode is the mode every shortcut held here serves.
var shortcutMode = CapabilitySources

func addressPairDiffers(st *stage, _ *Expansion, tally *changeTally) string {
	for g, gt := range st.t.grants {
		if gt.none || gt.kind == grantVia {
			continue
		}

		var why []string

		if gt.app != nil {
			if r := sourceForm(shortcutMode, eligible, true, nil, identityTraits); r != reasonNone {
				why = append(why, "the app rule goes as addresses ("+r.String()+")")
			}
		}

		for _, ipr := range gt.ip {
			if r := sourceForm(shortcutMode, eligible, false, ipr.proto, identityTraits); r != reasonNone {
				why = append(why, fmt.Sprintf("the ip rule over %v goes as addresses (%s)", ipr.proto, r))
			}
		}

		switch pair := addressPair(gt); {
		case len(why) > 0 && !pair:
			return fmt.Sprintf("grant %d: %s whatever its source, and addressPair says no rule does: %s", g, strings.Join(why, "; "), grantJSON(gt))
		case len(why) == 0 && pair:
			tally.add("addressPair true where no rule goes as addresses")
		case pair:
			tally.add("addressPair true and needed")
		}
	}

	return ""
}

// selfShortcutsDiffer holds selfNamed to selfRules' naming, and
// selfCapabilityOnly to what capFormSelf cuts for each of the owner's
// nodes.
func selfShortcutsDiffer(st *stage, x *Expansion, tally *changeTally) string {
	for g, gt := range st.t.grants {
		if gt.none || gt.kind != grantSelf {
			continue
		}

		for _, uid := range x.ownerIDs() {
			named := x.selfNamed(g, uid)
			if want := x.selfRules(g, uid).named; !slices.Equal(named, want) {
				return fmt.Sprintf("grant %d, owner %d: selfNamed's shortcut names %v, the rules by address %v: %s", g, uid, named, want, grantJSON(gt))
			}

			only := x.selfCapabilityOnly(g, uid, named)
			cut, capable := false, true

			for _, id := range st.posts.Nodes(OwnerRole(uid)) {
				n, ok := x.node(id)
				if !ok || len(n.IPs()) == 0 {
					continue
				}

				cut = true
				owner := capSourcePrefix + string(ownerCap(uid))

				for _, fr := range x.capFormSelf(nil, g, gt, newReceiver(n)) {
					if !slices.Equal(fr.rule.SrcIPs, []string{owner}) {
						capable = false

						if only {
							return fmt.Sprintf("grant %d, owner %d: selfCapabilityOnly says every self rule goes as the owner's capability, n%d is cut %v: %s",
								g, uid, id, fr.rule.SrcIPs, grantJSON(gt))
						}
					}
				}
			}

			switch {
			case !cut:
			case capable && !only && gt.app == nil:
				return fmt.Sprintf("grant %d, owner %d: capFormSelf writes every self rule as the owner's capability, selfCapabilityOnly says otherwise: %s", g, uid, grantJSON(gt))
			case capable && !only:
				// TODO(kradalby): overwake/self-owners-every-form: delete this
				// case, so an app self grant cut as capabilities must be
				// reported so, when selfCapabilityOnly in fallback.go stops
				// declining every app self grant.
				tally.add("selfCapabilityOnly declines an app self grant cut as capabilities")
			case only:
				tally.add("selfCapabilityOnly true and cut so")
			}
		}
	}

	return ""
}

// dstPortsDiffer holds dstPorts by role to dstPorts by address, for every
// port rule and receiver.
func dstPortsDiffer(st *stage, x *Expansion, tally *changeTally) string {
	for g, gt := range st.t.grants {
		if gt.none || gt.kind == grantVia {
			continue
		}

		for _, n := range st.list {
			rc := newReceiver(n.View())

			for _, ipr := range gt.ip {
				byRole, byAddr := x.dstPorts(gt, ipr.ports, rc, true), x.dstPorts(gt, ipr.ports, rc, false)
				if !reflect.DeepEqual(byRole, byAddr) {
					return fmt.Sprintf("grant %d to n%d: dstPorts by role %v, by address %v: %s", g, n.ID, byRole, byAddr, grantJSON(gt))
				}

				if len(byAddr) > 0 {
					tally.add("dstPorts compared, reached")
				}
			}
		}
	}

	return ""
}

// stampTableDiffers holds the stamp table to sourceForm, and every cap:
// token of every capability-form cut to the table.
func stampTableDiffers(st *stage, x *Expansion, tally *changeTally) string {
	table := st.sel.table
	want := make([]bool, table.Len())
	owner := false

	for _, gt := range st.t.grants {
		if gt.none || gt.kind == grantVia {
			continue
		}

		capable := slices.ContainsFunc(gt.ip, func(ipr ipRule) bool {
			return sourceForm(shortcutMode, eligible, false, ipr.proto, identityTraits) == reasonNone
		})
		app := gt.app != nil && sourceForm(shortcutMode, eligible, true, nil, identityTraits) == reasonNone

		for _, id := range gt.srcs {
			if table.Selector(id).Kind.HoldsNodes() && (capable || app) {
				want[id] = true

				if gt.kind == grantSelf {
					owner = true
				}
			}
		}

		for _, id := range gt.dsts {
			if table.Selector(id).Kind.HoldsNodes() && app {
				want[id] = true
			}
		}
	}

	got := st.t.stamps()
	if !slices.Equal(got.sel, want) || got.owner != owner {
		return fmt.Sprintf("the stamp table stamps %v (owners %t), sourceForm says %v (owners %t)", stamped(table, got.sel), got.owner, stamped(table, want), owner)
	}

	for _, n := range st.list {
		for _, rule := range x.capFormFor(n.View(), nil) {
			for _, src := range rule.SrcIPs {
				c, ok := strings.CutPrefix(src, capSourcePrefix)
				if !ok {
					continue
				}

				tally.add("cap: token checked against the stamp table")

				name, ok := strings.CutPrefix(c, selectorCapPrefix)
				if !ok {
					return fmt.Sprintf("n%d is cut %s, outside the reserved namespace", n.ID, src)
				}

				if strings.HasPrefix(name, "owner:") {
					switch {
					case owner:
					case fallbacksOff[reasonLiteral]:
						// A self rule from a literal source cut as the owner's
						// capability, which only switching the permanent
						// literal reason off writes; the stamp table restates
						// that reason (it stamps owners for identity sources).
						tally.add("owner token unstamped with literal off")
					default:
						return fmt.Sprintf("n%d is cut %s, and no owner is stamped", n.ID, src)
					}

					continue
				}

				s, ok := table.Lookup(name)
				if ok && !s.Kind.HoldsNodes() && fallbacksOff[reasonLiteral] {
					// A literal sent as a capability nobody holds, as the
					// literal reason switched off writes it.
					continue
				}

				if !ok || !got.sel[s.ID] {
					return fmt.Sprintf("n%d is cut %s, which no node is stamped with", n.ID, src)
				}
			}
		}
	}

	return ""
}

func stamped(table *SelectorTable, sel []bool) []string {
	var out []string

	for id, on := range sel {
		if on {
			out = append(out, table.Selector(SelectorID(id)).Name) //nolint:gosec // a selector ID
		}
	}

	return out
}

// recutDiffers holds recutReason's premise: an address-form cut is the
// same whichever receiver-wide reason sent it.
func recutDiffers(st *stage, x *Expansion, _ *changeTally) string {
	for _, n := range st.list {
		want := x.cutIn(n.View(), formAddress, recutReason(CapabilitySources, formAddress), nil)

		for _, why := range []ipReason{reasonAddressMode, reasonClient, reasonLocalNets} {
			if got := x.cutIn(n.View(), formAddress, why, nil); !reflect.DeepEqual(got, want) {
				return fmt.Sprintf("n%d's address form sent for %s is %s, for %s %s", n.ID, why, rulesJSON(got, nil), recutReason(CapabilitySources, formAddress), rulesJSON(want, nil))
			}
		}
	}

	return ""
}

// viaPremiseDiffers returns a node sent capability form that a via rule
// could reach: one serving a route.
func viaPremiseDiffers(st *stage) string {
	for _, n := range st.list {
		nv := n.View()

		if receiverForm(CapabilitySources, st.recv.Of(n.ID)) == reasonNone && (nv.IsExitNode() || len(nv.SubnetRoutes()) > 0) {
			return fmt.Sprintf("n%d is sent capability form, which cuts no via rule, yet serves %v", n.ID, nv.AllApprovedRoutes())
		}
	}

	return ""
}
