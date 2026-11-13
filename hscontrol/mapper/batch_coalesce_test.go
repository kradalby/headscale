package mapper

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestProcessBatchedChangesCoalescesWhenInFlight(t *testing.T) {
	h := NewHub()
	defer h.Close()

	sess := h.Join(1, func() {})
	for range 10000 {
		h.wake(true, nil)
	}

	require.Len(t, sess.wakes, 1, "commits pending behind an initial write cost one wake")
	<-sess.Wakes()
	h.wake(true, nil)
	require.Len(t, sess.wakes, 1, "the next committed snapshot is scheduled after draining")
}

func TestProcessBatchedChangesSkipsNodesWithoutConnection(t *testing.T) {
	h := NewHub()
	defer h.Close()

	sess := h.Join(1, func() {})
	h.Leave(sess)
	h.wake(false, map[types.NodeID]struct{}{1: {}})
	require.Empty(t, sess.wakes, "an offline node accumulates no work")
	require.Empty(t, h.sessions)
}

func TestAppendPendingStaysBoundedWhileInFlight(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	st := NewStream(cfg, h, ids[0], capVer)
	full, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(full[0])

	sess := h.Join(ids[0], func() {})
	for i := range 3000 {
		h.wake(true, nil)
		h.mayHavePeers(sess, ids[0], sentView{ids: []types.NodeID{ids[1]}, rev: uint64(i + 1)})
	}

	require.Len(t, sess.wakes, 1)
	require.LessOrEqual(t, len(h.sentPeers[ids[0]].attempts), maxPeerAttempts)
	_, err = s.RenameNode(ids[1], "coalesced")
	require.NoError(t, err)
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	for _, resp := range out {
		client.apply(resp)
	}

	fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, client.sameAs(newModelClient(fresh[0])))
}

func TestAppendPendingBoundsFoldedPatches(t *testing.T) {
	h := NewHub()
	defer h.Close()

	h.maxHistoryIDs = 64

	sess := h.Join(1, func() {})
	for i := range 3000 {
		h.mayHavePeers(sess, 1, sentView{ids: []types.NodeID{types.NodeID(i + 2)}, rev: uint64(i + 1)})
		h.wake(true, nil)
	}

	require.LessOrEqual(t, h.retained, h.maxHistoryIDs)
	require.Len(t, sess.wakes, 1)
	require.LessOrEqual(t, len(h.lastPeers(1)), h.maxHistoryIDs+maxPeerAttempts)
	// Pings remain separate from coalesced snapshot work.
	require.True(t, h.Ping(1, &tailcfg.PingRequest{}))
	require.Len(t, sess.pings, 1)
}
