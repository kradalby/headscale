package v2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestIncrementalDuplicateAppGrantInvalidatesFilter(t *testing.T) {
	nodes := scanManyRulesNodes(2).ViewSlice()
	before := []byte(`{"grants":[{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[]}}]}`)
	after := []byte(`{"grants":[{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[]}},{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[]}}]}`)
	old, err := NewPolicyManager(before, nil, nodes)
	require.NoError(t, err)
	_, err = old.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	next, err := NewPolicyManagerFrom(old, after, nil, nodes)
	require.NoError(t, err)
	fresh, err := NewPolicyManager(after, nil, nodes)
	require.NoError(t, err)
	// Compilation itself agrees; the warmed reduced filter is stale.
	wantGlobal, _ := fresh.Filter()
	gotGlobal, _ := next.Filter()
	require.Equal(t, wantGlobal, gotGlobal)

	cold, err := NewPolicyManager(before, nil, nodes)
	require.NoError(t, err)
	coldNext, err := NewPolicyManagerFrom(cold, after, nil, nodes)
	require.NoError(t, err)
	coldRules, err := coldNext.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	got, err := next.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	want, err := fresh.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	require.Equal(t, want, coldRules)

	changed, all := next.FilterChangedNodes(old)
	t.Logf("rules fresh=%d incremental=%d notifications=%v all=%t destination=%d", len(want), len(got), changed, all, types.NodeID(2))
	require.Equal(t, want, got)
}

func TestIncrementalAppGrantOrderInvalidatesFilter(t *testing.T) {
	nodes := scanManyRulesNodes(2).ViewSlice()
	before := []byte(`{"grants":[{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[{"role":"read"}]}},{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[{"role":"write"}]}}]}`)
	after := []byte(`{"grants":[{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[{"role":"write"}]}},{"src":["100.64.0.0"],"dst":["100.64.0.1"],"app":{"example.com/cap":[{"role":"read"}]}}]}`)
	old, err := NewPolicyManager(before, nil, nodes)
	require.NoError(t, err)
	_, err = old.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	next, err := NewPolicyManagerFrom(old, after, nil, nodes)
	require.NoError(t, err)
	fresh, err := NewPolicyManager(after, nil, nodes)
	require.NoError(t, err)
	cold, err := NewPolicyManager(before, nil, nodes)
	require.NoError(t, err)
	coldNext, err := NewPolicyManagerFrom(cold, after, nil, nodes)
	require.NoError(t, err)
	coldRules, err := coldNext.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	got, err := next.FilterForNode(nodes.At(1))
	require.NoError(t, err)
	want, err := fresh.FilterForNode(nodes.At(1))
	require.NoError(t, err)

	// Pin input order independently of the incremental/fresh comparison.
	require.Len(t, want, 2)

	for i, role := range []tailcfg.RawMessage{`{"role":"write"}`, `{"role":"read"}`} {
		require.Len(t, want[i].CapGrant, 1)
		require.Equal(t, []tailcfg.RawMessage{role}, want[i].CapGrant[0].CapMap["example.com/cap"])
	}

	wantGlobal, _ := fresh.Filter()
	gotGlobal, _ := next.Filter()
	require.Equal(t, wantGlobal, gotGlobal)
	require.Equal(t, want, coldRules)
	require.ElementsMatch(t, want, got, "only order changed, not payloads or multiplicity")

	// Exact filter convergence requires invalidation even for a pure reorder.
	changed, all := next.FilterChangedNodes(old)
	if !all {
		assert.Contains(t, changed, nodes.At(1).ID(), "the destination must receive its reordered filter")
	}

	require.Equal(t, want, got, "a warmed filter must preserve the new policy's grant order")
}
