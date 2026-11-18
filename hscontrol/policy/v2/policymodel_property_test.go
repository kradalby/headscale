package v2

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg/nodecap"
)

// TestGeneratedPoliciesCompile holds policymodel's idea of a valid input
// to headscale's: every policy its scenarios hold, before and after each
// step, parses and compiles against the topology of that moment, every
// node's filter and SSH policy compile, and the nodes are what the model
// says they are. A failure means the model, not headscale, is wrong.
func TestGeneratedPoliciesCompile(t *testing.T) {
	t.Parallel()

	gen := policymodel.Scenarios(30)

	rapid.Check(t, func(t *rapid.T) {
		s := gen.Draw(t, "scenario")

		for i, w := range s.Worlds() {
			users, nodes := w.Topology.Build()

			pm, err := NewPolicyManager(w.Policy.HuJSON(), users, nodes.ViewSlice())
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i, stableError(err))
			}

			caps := pm.NodeCapMaps()
			v := policymodel.NewView(w)

			for j, n := range nodes {
				_, err := pm.FilterForNode(n.View())
				if err != nil {
					t.Fatalf("after step %d n%d's filter does not compile: %s", i, n.ID, stableError(err))
				}

				_, err = pm.SSHPolicy("https://headscale.example.com", n.View())
				if err != nil {
					t.Fatalf("after step %d n%d's SSH policy does not compile: %s", i, n.ID, stableError(err))
				}

				m := w.Topology.Nodes[j]
				facts := ReceiverFactsOf(n.View(), caps[n.ID])
				_, svc := caps[n.ID][nodecap.ServiceHost]

				switch {
				case n.IsTagged() != m.Tagged():
					t.Fatalf("after step %d n%d is tagged %t, the model says %t", i, n.ID, n.IsTagged(), m.Tagged())
				case n.IsExitNode() != m.Exit():
					t.Fatalf("after step %d n%d is an exit node %t, the model says %t", i, n.ID, n.IsExitNode(), m.Exit())
				case facts.Client != (m.Client == policymodel.Official || m.Client == policymodel.AppConnector):
					t.Fatalf("after step %d n%d (%s) reads as an official client %t", i, n.ID, m.Client, facts.Client)
				case svc != slices.Contains(v.ServiceHosts(), n.ID):
					t.Fatalf("after step %d n%d is a service host %t, the model says otherwise", i, n.ID, svc)
				case (facts.Client && !facts.Announces && !facts.AppConnector && !facts.ServiceHost) != v.Eligible(m):
					t.Fatalf("after step %d n%d's facts %+v disagree with the model's eligibility", i, n.ID, facts)
				}
			}
		}
	})
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
