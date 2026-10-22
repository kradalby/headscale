package state

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/stretchr/testify/require"
)

// TestReloadPolicyRebuildsPeerMapOnChangeOnly covers the peer-map rebuilds
// of a policy write. The API handlers apply a policy with [State.SetPolicy],
// store it and then call [State.ReloadPolicy]; the O(n^2) rebuild must run
// once for that, not once per step. A reload that is the first to see a new
// policy (SIGHUP, a policy stored by another path) must still rebuild.
//
// The graph recomputes each derived cell at most once per commit, so the
// commits a write makes bound its rebuilds.
func TestReloadPolicyRebuildsPeerMapOnChangeOnly(t *testing.T) {
	const (
		denyAll  = `{"grants": []}`
		allowAll = `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`
	)

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	nodes := database.CreateRegisteredNodesForTest(database.CreateUserForTest("reload-user"), 2, "reload-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// rebuilds reports how many commits fn made and whether the last one
	// recompiled the policy.
	rebuilds := func(fn func()) (uint64, bool) {
		t.Helper()

		before := s.Snapshot().Rev()

		fn()

		after := s.Snapshot()

		return after.Rev() - before, after.PolicyRev() == after.Rev() && after.Rev() != before
	}

	// write is the sequence of the SetPolicy API handlers.
	write := func(pol string) func() {
		return func() {
			_, err := s.SetPolicy([]byte(pol))
			require.NoError(t, err)

			_, err = s.SetPolicyInDB(pol)
			require.NoError(t, err)

			require.NoError(t, s.ReloadPolicy())
		}
	}
	reload := func() { require.NoError(t, s.ReloadPolicy()) }
	peers := func() int { return s.ListPeers(nodes[0].ID).Len() }

	require.Equal(t, 1, peers(), "no policy: allow all")

	commits, compiled := rebuilds(write(denyAll))
	require.EqualValues(t, 1, commits, "a changed policy is rebuilt once per write")
	require.True(t, compiled)
	require.Zero(t, peers())

	commits, _ = rebuilds(write(denyAll))
	require.Zero(t, commits, "the same policy again needs no rebuild")
	require.Zero(t, peers())

	commits, compiled = rebuilds(write(allowAll))
	require.EqualValues(t, 1, commits)
	require.True(t, compiled)
	require.Equal(t, 1, peers())

	// A reload that finds a policy the world has not seen yet.
	_, err = s.SetPolicyInDB(denyAll)
	require.NoError(t, err)

	commits, compiled = rebuilds(reload)
	require.EqualValues(t, 1, commits, "a reload that changes the policy rebuilds")
	require.True(t, compiled)
	require.Zero(t, peers())

	commits, _ = rebuilds(reload)
	require.Zero(t, commits, "a reload of the current policy does not")
}
