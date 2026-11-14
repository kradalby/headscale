package mapper

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// Every stream writes Initial before reading Wakes. The one buffered wake
// preserves changes that arrive while its initial write is blocked.
func TestUnreadyConnectionDefersBroadcastsUntilInitialMap(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	h.Watch(s)
	sess := h.Join(ids[0], func() {})
	st := NewStream(cfg, h, ids[0], capVer)
	st.Attach(sess)

	before := s.Snapshot()
	s.Connect(ids[1])

	first, err := st.Initial(before)
	require.NoError(t, err)
	require.NotNil(t, first[0].Node, "initial frame must carry self even if a commit is pending")
	st.Delivered()
	waitWake(t, sess)

	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.True(t, mentions(out, ids[1]), "pending change reaches stream after initial delivery")
}

func TestUnreadyConnectionBesideReadyOneHoldsBroadcasts(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	h.Watch(s)
	ready := NewStream(cfg, h, ids[0], capVer)
	ready.Attach(h.Join(ids[0], func() {}))
	_, err := ready.Initial(s.Snapshot())
	require.NoError(t, err)
	ready.Delivered()

	pendingSession := h.Join(ids[0], func() {})
	pending := NewStream(cfg, h, ids[0], capVer)
	pending.Attach(pendingSession)

	before := s.Snapshot()
	gen := s.Connect(ids[1])
	require.NotZero(t, gen)

	updated, err := ready.Update(s.Snapshot())
	require.NoError(t, err)
	require.True(t, mentions(updated, ids[1]))

	first, err := pending.Initial(before)
	require.NoError(t, err)
	require.NotNil(t, first[0].Node)
	pending.Delivered()
	waitWake(t, pendingSession)

	out, err := pending.Update(s.Snapshot())
	require.NoError(t, err)
	require.True(t, mentions(first, ids[1]), "pending initial refreshes to the snapshot another stream observed")
	require.Empty(t, out, "the refreshed initial already carries the committed online state")
}

// The graph coalesces commits into the latest snapshot: intermediate presence
// flips are not an event log. Frames that are emitted remain ordered per stream.
func TestHeldChangesKeepOrderWhenStreamTurnsReady(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	h.Watch(s)
	sess := h.Join(ids[0], func() {})
	st := NewStream(cfg, h, ids[0], capVer)
	st.Attach(sess)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])
	gen := s.Connect(ids[1])
	require.NotZero(t, gen)

	_, err = s.RenameNode(ids[1], "between-presence-flips")
	require.NoError(t, err)
	require.NoError(t, s.Disconnect(ids[1], gen))
	gen = s.Connect(ids[1])
	require.NotZero(t, gen)
	st.Delivered()
	waitWake(t, sess)

	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	for _, resp := range out {
		client.apply(resp)
	}

	fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, client.sameAs(newModelClient(fresh[0])), "coalesced online/offline/rename commits converge without stale rollback")

	peer, ok := st.sent.peer(ids[1].NodeID())
	require.True(t, ok)
	require.True(t, *peer.Online)
	require.Equal(t, "between-presence-flips.headscale.test.", peer.Name)
}

func TestSyncInitialMapNoPhantomPeersOnTimeout(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)

	h := NewHub()
	defer h.Close()

	st := NewStream(cfg, h, ids[0], capVer)
	first, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.False(t, mentions(first, ids[2]))
	// The initial write fails without Delivered; subsequent revocation still
	// removes every peer that write might have exposed, and no hidden node.
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))
	retry := NewStream(cfg, h, ids[0], capVer)
	out, err := retry.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, out[1].PeersRemoved)
	require.False(t, mentions(out, ids[2]))
	retry.Delivered()
	require.NotContains(t, h.lastPeers(ids[0]), ids[1])
}

func TestInitialMapCarriesDebugConfigOnEveryStream(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg, s, ids := streamTestState(t, "", func(c *types.Config) { c.LogTail.Enabled = enabled })

		h := NewHub()
		defer h.Close()

		for range 2 {
			out, err := NewStream(cfg, h, ids[0], capVer).Initial(s.Snapshot())
			require.NoError(t, err)

			if enabled {
				require.Nil(t, out[0].Debug)
			} else {
				require.Equal(t, &tailcfg.Debug{DisableLogTail: true}, out[0].Debug)
			}
		}
	}
}

func waitWake(t *testing.T, sess *Session) {
	t.Helper()

	select {
	case <-sess.Wakes():
	case <-time.After(5 * time.Second):
		t.Fatal("stream missed committed snapshot")
	}
}
