package v2

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// propertySteps is how long a drawn scenario may be here, the length
// builders run.
const propertySteps = 10

// TestGeneratedPoliciesCompile holds policymodel's idea of a valid input
// to headscale's write boundary: the start's policy and every policy a
// step writes pass the checks State.SetPolicy makes (it compiles, and no
// user token in it answers to two users), and every world's policy, also
// those users changed under, compiles every node's filter and SSH policy.
// A failure means the model, not headscale, is wrong.
func TestGeneratedPoliciesCompile(t *testing.T) {
	t.Parallel()

	gen := policymodel.Scenarios(propertySteps)

	rapid.Check(t, func(t *rapid.T) {
		s := gen.Draw(t, "scenario")

		requireWritable(t, 0, "the start", s.Start)

		w := s.Start
		for i, st := range s.Steps {
			for _, e := range st.Edits {
				next := w.Apply(e)
				if string(next.Policy.HuJSON()) != string(w.Policy.HuJSON()) {
					requireWritable(t, i+1, e.String(), next)
				}

				w = next
			}
		}

		for i, w := range s.Worlds() {
			users, nodes := w.Topology.Build()

			pm, err := NewPolicyManager(w.Policy.HuJSON(), users, nodes.ViewSlice())
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i, stableError(err))
			}

			for _, n := range nodes {
				_, err := pm.FilterForNode(n.View())
				if err != nil {
					t.Fatalf("after step %d n%d's filter does not compile: %s", i, n.ID, stableError(err))
				}

				_, err = pm.SSHPolicy("https://headscale.example.com", n.View())
				if err != nil {
					t.Fatalf("after step %d n%d's SSH policy does not compile: %s", i, n.ID, stableError(err))
				}
			}
		}
	})
}

// requireWritable fails unless w's policy, written with w's users and
// nodes, passes State.SetPolicy's checks: it compiles, and no user token
// in it answers to two users. The policy's own tests are the only other
// check, and no generated document has any.
func requireWritable(t *rapid.T, step int, what string, w policymodel.World) {
	t.Helper()

	users, nodes := w.Topology.Build()

	pm, err := NewPolicyManager(w.Policy.HuJSON(), users, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("step %d (%s): the policy write is refused: %s", step, what, stableError(err))
	}

	if tokens, _ := pm.AmbiguousUserReferences(); len(tokens) > 0 {
		t.Fatalf("step %d (%s): the policy write holds tokens several users answer to: %v", step, what, tokens)
	}
}

// TestModelMatchesProduction holds every answer the model and its
// classifier take from headscale's semantics to headscale's own, on every
// world of a drawn scenario: who a node is (tagged without a user, an
// exit node, an official client), which nodes nodeAttrs makes service
// hosts and which can be sent capability sources, which routes the
// auto-approvers approve, which addresses each user token names, which
// tokens are ambiguous, and, across a policy-only step, whether the
// selector table is kept. It is the guard for every shape the classifier
// computes from them.
func TestModelMatchesProduction(t *testing.T) {
	t.Parallel()

	gen := policymodel.Scenarios(propertySteps)

	rapid.Check(t, func(t *rapid.T) {
		s := gen.Draw(t, "scenario")

		var prev *Selectors

		for i, w := range s.Worlds() {
			users, nodes := w.Topology.Build()

			pm, err := NewPolicyManager(w.Policy.HuJSON(), users, nodes.ViewSlice())
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i, stableError(err))
			}

			v := policymodel.NewView(w)

			if msg := nodeFactsDiffer(w, v, pm, nodes); msg != "" {
				t.Fatalf("after step %d %s", i, msg)
			}

			if msg := userRefsDiffer(v, pm, users, nodes); msg != "" {
				t.Fatalf("after step %d %s", i, msg)
			}

			sel := SelectorsFor(prev, pm)

			if i > 0 && policyOnly(s.Steps[i-1]) {
				before, after := s.Worlds()[i-1].Policy.Selectors(), w.Policy.Selectors()
				if kept := sel.table == prev.table; kept != sameSels(before, after) {
					t.Fatalf("step %d (%s): headscale keeps its selector table %t; the model's selectors went from %v to %v", i, s.Steps[i-1], kept, before, after)
				}
			}

			prev = sel
		}
	})
}

func nodeFactsDiffer(w policymodel.World, v *policymodel.View, pm *PolicyManager, nodes types.Nodes) string {
	caps := pm.NodeCapMaps()

	for j, n := range nodes {
		m := w.Topology.Nodes[j]
		facts := ReceiverFactsOf(n.View(), caps[n.ID])
		_, svc := caps[n.ID][nodecap.ServiceHost]

		switch {
		case n.IsTagged() != m.Tagged() || n.IsTagged() && n.UserID != nil:
			return fmt.Sprintf("n%d is tagged %t with user %v, the model says tagged %t", n.ID, n.IsTagged(), n.UserID, m.Tagged())
		case n.IsExitNode() != m.Exit():
			return fmt.Sprintf("n%d is an exit node %t, the model says %t", n.ID, n.IsExitNode(), m.Exit())
		case facts.Client != (m.Client == policymodel.Official || m.Client == policymodel.AppConnector):
			return fmt.Sprintf("n%d (%s) reads as an official client %t", n.ID, m.Client, facts.Client)
		case svc != slices.Contains(v.ServiceHosts(), n.ID):
			return fmt.Sprintf("n%d is a service host %t, the model says otherwise", n.ID, svc)
		case hasCap(caps[n.ID], types.NodeAttrDisableIPv4) != v.IPv4Disabled(m):
			return fmt.Sprintf("n%d has disable-ipv4 %t, the model says %t", n.ID, !v.IPv4Disabled(m), v.IPv4Disabled(m))
		case (facts.Client && !facts.Announces && !facts.AppConnector && !facts.ServiceHost) != v.Eligible(m):
			return fmt.Sprintf("n%d's facts %+v disagree with the model's eligibility", n.ID, facts)
		}

		for _, r := range m.Announced {
			if got, want := pm.NodeCanApproveRoute(n.View(), policymodel.Prefixes[r]), v.Approvable(m, r); got != want {
				return fmt.Sprintf("n%d may have %s auto-approved %t, the model says %t", n.ID, policymodel.Prefixes[r], got, want)
			}
		}
	}

	return ""
}

func userRefsDiffer(v *policymodel.View, pm *PolicyManager, users types.Users, nodes types.Nodes) string {
	tokens, _ := pm.AmbiguousUserReferences()

	refs := v.AmbiguousRefs()

	model := make([]string, 0, len(refs))
	for _, ref := range refs {
		model = append(model, policymodel.UserRefs[ref])
	}

	slices.Sort(model)

	if !slices.Equal(tokens, model) {
		return fmt.Sprintf("the ambiguous tokens are %v, the model says %v", tokens, model)
	}

	for ref, tok := range policymodel.UserRefs {
		u := Username(tok)
		got, _ := u.resolve(nil, users, nodes.ViewSlice())

		var b netipx.IPSetBuilder

		for _, n := range v.MembersOf(policymodel.Sel{Kind: policymodel.SelUser, I: ref}) {
			for _, a := range n.Addrs() {
				b.Add(a)
			}
		}

		want, _ := b.IPSet()
		if !got.Equal(want) {
			return fmt.Sprintf("%s names %v, the model says %v", tok, got.Prefixes(), want.Prefixes())
		}
	}

	return ""
}

func policyOnly(st policymodel.Step) bool {
	if len(st.Edits) == 0 {
		return false
	}

	for _, e := range st.Edits {
		switch e.(type) {
		case policymodel.Join, policymodel.Leave, policymodel.Retag, policymodel.SetAddr, policymodel.SwapAddrs,
			policymodel.Announce, policymodel.Withdraw, policymodel.Approve, policymodel.Unapprove,
			policymodel.SetClient, policymodel.SetExpired, policymodel.SetOnline,
			policymodel.AddUser, policymodel.DeleteUser, policymodel.RenameUser, policymodel.SetEmail:
			return false
		}
	}

	return true
}

func sameSels(a, b []policymodel.Sel) bool {
	return !slices.ContainsFunc(a, func(s policymodel.Sel) bool { return !slices.Contains(b, s) }) &&
		!slices.ContainsFunc(b, func(s policymodel.Sel) bool { return !slices.Contains(a, s) })
}

// productionShape is a shape only headscale can count, measured over
// generated scenarios from its own counters: the plan alone cannot say
// where a merged rule lands or whose cover moved.
type productionShape struct {
	name, why string
	min       float64
}

var productionShapes = []productionShape{
	{"own-anchored", "a merged rule placed by an own rule that reaches nothing (FilterShapes.OwnAnchored)", 0.02},
	{"router-cover-moved-by-policy", "a policy-only step moving a router's cover (Sides.RoutersMovedSince)", 0.025},
	{"one-way-peers", "a node seeing another that does not see it (RolePeers)", 0.035},
}

// productionSamples is how many generated scenarios TestProductionShapesReached
// counts over.
const productionSamples = 400

// TestProductionShapesReached counts, over generated scenarios, the
// shapes only headscale can name, from its own counters, and fails when
// the generators stop reaching one. Run with -v for the counts.
func TestProductionShapesReached(t *testing.T) {
	t.Parallel()

	got := map[string]int{}
	gen := policymodel.Scenarios(propertySteps)

	for i := range productionSamples {
		for _, name := range productionShapesOf(t, gen.Example(i)) {
			got[name]++
		}
	}

	var table strings.Builder

	for _, sh := range productionShapes {
		fmt.Fprintf(&table, "%-30s %4d %4.0f  %s\n", sh.name, got[sh.name], sh.min*productionSamples, sh.why)

		if floor := int(sh.min * productionSamples); got[sh.name] < floor {
			t.Errorf("%s in %d of %d scenarios, floor %d", sh.name, got[sh.name], productionSamples, floor)
		}
	}

	t.Logf("scenarios out of %d containing each shape:\n%s", productionSamples, table.String())
}

// productionShapesOf names the production shapes s reaches.
func productionShapesOf(t *testing.T, s policymodel.Scenario) []string {
	t.Helper()

	var out []string

	add := func(name string) {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}

	worlds := s.Worlds()

	for i, w := range worlds {
		users, nodes := w.Topology.Build()

		pm, err := NewPolicyManager(w.Policy.HuJSON(), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("scenario %#v: the policy is refused: %v", s, err)
		}

		nm := nodeMapOf(nodes)
		x, _ := expansionOf(t, pm, users, nm)

		var shapes FilterShapes
		for _, n := range nodes {
			x.capFilterFor(n.View(), &shapes)
		}

		if shapes.OwnAnchored > 0 {
			add("own-anchored")
		}

		m := newSideModel(t, pm, users, nodes)
		if oneWay(m.peers, nodes) {
			add("one-way-peers")
		}

		if i == 0 || !policyOnly(s.Steps[i-1]) {
			continue
		}

		before := worlds[i-1]
		bu, bn := before.Topology.Build()

		bpm, err := NewPolicyManager(before.Policy.HuJSON(), bu, bn.ViewSlice())
		if err != nil {
			t.Fatal(err)
		}

		bm := newSideModel(t, bpm, bu, bn)
		cover := bm.sides.RouteCover()

		_, ok := bm.edit(t, NewUserSets(nil, bm.t.sel, bu), w.Policy.HuJSON())
		if ok && len(bm.sides.RoutersMovedSince(cover)) > 0 {
			add("router-cover-moved-by-policy")
		}
	}

	return out
}

func oneWay(peers *PeerClasses, nodes types.Nodes) bool {
	for _, n := range nodes {
		for _, p := range peers.Peers(n.ID) {
			if p != n.ID && !slices.Contains(peers.Peers(p), n.ID) {
				return true
			}
		}
	}

	return false
}

// TestInvalidPoliciesRefused holds each of policymodel's invalid-on-purpose
// documents to a refusal for the reason its defect names.
func TestInvalidPoliciesRefused(t *testing.T) {
	t.Parallel()

	want := map[policymodel.Defect]error{
		policymodel.DefectReservedAttr:        ErrCapReserved,
		policymodel.DefectReservedApp:         ErrCapReserved,
		policymodel.DefectSelfSource:          ErrAutogroupSelfSrc,
		policymodel.DefectUndefinedTag:        ErrTagNotDefined,
		policymodel.DefectUndefinedGroup:      ErrGroupNotDefined,
		policymodel.DefectUndefinedHost:       ErrHostNotDefined,
		policymodel.DefectDefaultRouteDst:     ErrGrantDefaultRouteCIDR,
		policymodel.DefectAppToInternet:       ErrGrantAppWithAutogroupInternet,
		policymodel.DefectPortsOnICMP:         ErrProtocolNoSpecificPorts,
		policymodel.DefectFunnelAttr:          ErrNodeAttrUnsupported,
		policymodel.DefectViaInACL:            ErrUnknownField,
		policymodel.DefectSSHWildcardSource:   ErrSSHSrcNotAllowed,
		policymodel.DefectTagStartsWithDigit:  ErrTagNameMustStartWithLetter,
		policymodel.DefectGrantWithoutIPOrApp: ErrGrantMissingIPOrApp,
	}

	rapid.Check(t, func(t *rapid.T) {
		iv := policymodel.InvalidPolicies().Draw(t, "invalid")

		_, err := NewPolicyManager(iv.HuJSON(), nil, types.Nodes{}.ViewSlice())

		switch {
		case err == nil:
			t.Fatalf("%s is accepted", iv.Defect)
		case !errors.Is(err, want[iv.Defect]):
			t.Fatalf("%s is refused for another reason: %s", iv.Defect, stableError(err))
		}
	})
}

// stableError is err's text with its lines sorted: validation collects
// some errors by ranging over maps, and a message that varies between
// runs stops rapid shrinking.
func stableError(err error) string {
	lines := strings.Split(err.Error(), "\n")
	slices.Sort(lines)

	return strings.Join(lines, "\n")
}

func hasCap(caps tailcfg.NodeCapMap, c nodecap.Cap) bool {
	_, ok := caps[c]

	return ok
}
