package mapper

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestAddConnectionWithLimit_StopsOldest(t *testing.T) {
	h := NewHub()

	var stopped []int

	sessions := make([]*Session, 0, maxConcurrentMapSessionsPerNode+3)
	for i := range maxConcurrentMapSessionsPerNode + 3 {
		sessions = append(sessions, h.Join(1, func() { stopped = append(stopped, i) }))
	}

	require.Equal(t, []int{0, 1, 2}, stopped)
	require.Equal(t, maxConcurrentMapSessionsPerNode, h.Connected()[1])
	h.wake(true, nil)

	for i, sess := range sessions {
		_, retained := h.sessions[1][sess]
		require.Equal(t, i >= 3, retained, "newest streams are retained in deterministic admission order")
		require.Equal(t, i < 3, sess.left)

		if retained {
			require.Len(t, sess.wakes, 1, "every surviving stream receives updates")
		} else {
			require.Empty(t, sess.wakes, "evicted streams receive no new updates")
		}
	}
}

func TestComputePeerDiff(t *testing.T) {
	ids := func(v ...tailcfg.NodeID) []tailcfg.NodeID { return v }
	for _, tt := range []struct {
		name                   string
		tracked, current, want []tailcfg.NodeID
	}{
		{"no_changes", ids(1, 2, 3), ids(1, 2, 3), nil},
		{"one_removed", ids(1, 2, 3), ids(1, 3), ids(2)},
		{"multiple_removed", ids(1, 2, 3, 4, 5), ids(2, 4), ids(1, 3, 5)},
		{"all_removed", ids(1, 2, 3), nil, ids(1, 2, 3)},
		{"peers_added_no_removal", ids(1), ids(1, 2, 3), nil},
		{"empty_tracked", nil, ids(1, 2, 3), nil},
		{"both_empty", nil, nil, nil},
		{"disjoint_sets", ids(1, 2, 3), ids(4, 5, 6), ids(1, 2, 3)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			build := func(ids []tailcfg.NodeID) *netMap {
				e := newPeerMap().Edit()
				for _, id := range ids {
					e.Set(id, &tailcfg.Node{ID: id})
				}

				return &netMap{peers: e.Done()}
			}
			_, removed := peerChanges(build(tt.tracked), build(tt.current))
			require.ElementsMatch(t, tt.want, removed)
		})
	}
}

func TestUpdateSentPeers(t *testing.T) {
	h := NewHub()
	sess := h.Join(1, func() {})

	for _, tt := range []struct {
		name string
		ids  []types.NodeID
		rev  uint64
	}{
		{"full_peer_list_replaces_all", []types.NodeID{1, 2, 3}, 1},
		{"incremental_add_via_PeersChanged", []types.NodeID{1, 2, 3, 4}, 2},
		{"incremental_remove_via_PeersRemoved", []types.NodeID{1, 3, 4}, 3},
		{"empty_full_peer_list_clears_all", nil, 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h.mayHavePeers(sess, 1, sentView{ids: tt.ids, rev: tt.rev})
			h.setLastPeers(sess, 1, sentView{ids: tt.ids, rev: tt.rev})
			require.Equal(t, tt.ids, h.lastPeers(1))
		})
	}

	h.setLastPeers(sess, 1, sentView{ids: []types.NodeID{99}, rev: 1})
	require.Empty(t, h.lastPeers(1), "late stale delivery cannot restore removed peers")
}

func TestMultiChannelSend_SSHPolicyOnlyWhenChanged(t *testing.T) {
	ssh := func(user string) *tailcfg.SSHPolicy {
		if user == "" {
			return &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}
		}

		return &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{SSHUsers: map[string]string{user: user}, Action: &tailcfg.SSHAction{Accept: true}}}}
	}

	for _, tt := range []struct {
		name, old, next string
		none, want      bool
	}{
		{"unchanged empty", "", "", false, false},
		{"unchanged rules", "root", "root", false, false},
		{"rules removed", "root", "", false, true},
		{"rules changed", "root", "alice", false, true},
		{"none delivered yet", "", "", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old, next := testNetMap(), testNetMap()

			old.ssh, next.ssh = ssh(tt.old), ssh(tt.next)
			if tt.none {
				old.ssh = nil
			}

			next.filter = []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.1"}}}
			sharedSSH := next.ssh
			out := diff(old, next, &frameCache{})
			require.Len(t, out, 1)
			require.Equal(t, next.filter, out[0].PacketFilters["base"], "other changed fields survive policy stripping")

			if tt.want {
				require.Same(t, next.ssh, out[0].SSHPolicy)
			} else {
				require.Nil(t, out[0].SSHPolicy)
			}

			require.Same(t, sharedSSH, next.ssh, "diff cannot replace the shared rendered policy pointer")
		})
	}
}

func TestMultiChannelSend_SSHPolicyPerConnection(t *testing.T) {
	old, newer, next := testNetMap(), testNetMap(), testNetMap()
	newer.self, next.self = old.self, old.self
	old.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{SSHUsers: map[string]string{"root": "root"}}}}
	newer.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{SSHUsers: map[string]string{"alice": "alice"}}}}
	next.ssh = newer.ssh
	require.Empty(t, diff(newer, next, &frameCache{}))
	out := diff(old, next, &frameCache{})
	require.Len(t, out, 1)
	require.Same(t, next.ssh, out[0].SSHPolicy)
}

func TestSendSkipsResponseLeftEmptyByStripping(t *testing.T) {
	old, next := testNetMap(), testNetMap()
	old.self = &tailcfg.Node{ID: 1}
	next.self = &tailcfg.Node{ID: 1}
	old.ssh = &tailcfg.SSHPolicy{}
	next.ssh = &tailcfg.SSHPolicy{}
	require.Empty(t, diff(old, next, &frameCache{}), "identical self and SSH leave no frame, including ControlTime-only frames")
}
