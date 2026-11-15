package state

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/internal/propcheck"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type worldModelSnapshot struct {
	snap    *Snapshot
	model   propcheck.World
	touched map[types.NodeID]bool
}

func worldModelKeys(t *rapid.T) ([]key.NodePublic, []key.MachinePublic) {
	t.Helper()

	nodes := make([]key.NodePublic, 5)
	machines := make([]key.MachinePublic, 5)

	for i := range nodes {
		require.NoError(t, nodes[i].UnmarshalText(fmt.Appendf(nil, "nodekey:%064x", i)))
		require.NoError(t, machines[i].UnmarshalText(fmt.Appendf(nil, "mkey:%064x", i)))
	}

	return nodes, machines
}

func checkWorldModelHistory(t *rapid.T, history []worldModelSnapshot, old int) {
	t.Helper()

	latest := history[len(history)-1].snap
	before := history[old].snap

	want := map[types.NodeID]bool{}
	for _, entry := range history[old+1:] {
		maps.Copy(want, entry.touched)
	}

	keys, complete := latest.NodesTouchedSince(before.NodesVersion())
	require.True(t, complete, "bounded model history must fit the edit log")

	got := map[types.NodeID]bool{}
	for _, id := range keys {
		got[id] = true
	}

	require.Equal(t, want, got, "NodesTouchedSince")

	change := latest.Since(before)
	require.False(t, change.Resync)

	got = map[types.NodeID]bool{}
	for _, id := range change.Nodes {
		got[id] = true
	}

	require.Equal(t, want, got, "Since must include deleted and reverted writes")

	if latest.Rev() > before.Rev()+1 && latest.PeersRev() != before.PeersRev() {
		require.True(t, change.Global, "skipped peer transitions must wake intermediate readers")
	}
}

//nolint:gocyclo // Keep the generated operation and its reference transition together.
func TestWorldMutationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodeKeys, machineKeys := worldModelKeys(t)
		m := propcheck.World{
			Nodes: map[types.NodeID]*types.Node{},
			Users: []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}},
		}
		w, err := newWorld(nil, m.Users, nil, types.DNSView{})
		require.NoError(t, err)

		history := make([]worldModelSnapshot, 1, 61)
		history[0] = worldModelSnapshot{snap: w.snapshot(), model: m}
		checkWorldReference(t, m, w.snapshot(), nodeKeys, machineKeys)
		require.True(t, w.snapshot().Since(nil).Global)

		for range rapid.IntRange(1, 60).Draw(t, "steps") {
			m = m.Clone()
			before := w.snapshot()
			touched := map[types.NodeID]bool{}
			commit := false
			id := types.NodeID(rapid.Uint64Range(1, 8).Draw(t, "id"))
			name := rapid.SampledFrom([]string{"", "node", "NODE", "web", "web-1", "db"}).Draw(t, "name")

			op := rapid.SampledFrom([]string{"put", "delete", "ownership", "keys", "rename", "user", "batch", "noop", "copy", "payload", "stale"}).Draw(t, "op")
			switch op {
			case "put":
				u := m.Users[rapid.IntRange(0, 1).Draw(t, "owner")]
				ip := netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id))

				n := &types.Node{
					ID: id, UserID: new(u.ID), User: &u, IPv4: &ip,
					GivenName: name, Hostname: name, Hostinfo: &tailcfg.Hostinfo{},
					NodeKey:    nodeKeys[rapid.IntRange(0, 4).Draw(t, "node-key")],
					MachineKey: machineKeys[rapid.IntRange(0, 4).Draw(t, "machine-key")],
				}
				if rapid.Bool().Draw(t, "tagged") {
					n.Tags = []string{"tag:srv"}
				}

				got := w.PutNode(*n)
				n.GivenName = m.Name(id, name)
				m.Put(n)
				require.Equal(t, n, got.AsStruct())

				touched[id], commit = true, true
			case "delete":
				w.DeleteNode(id)

				if m.Nodes[id] != nil {
					m.Delete(id)
					touched[id], commit = true, true
				}
			case "ownership", "keys", "payload":
				u := m.Users[rapid.IntRange(0, 1).Draw(t, "owner")]
				tagged := rapid.Bool().Draw(t, "tagged")
				keepCreator := rapid.Bool().Draw(t, "keep-creator")
				k := rapid.IntRange(0, 4).Draw(t, "key")
				edit := func(n *types.Node) {
					switch op {
					case "ownership":
						n.UserID, n.User, n.Tags = new(u.ID), &u, nil
						if tagged {
							n.Tags = []string{"tag:srv"}
							if !keepCreator {
								n.UserID, n.User = nil, nil
							}
						}
					case "keys":
						n.NodeKey, n.MachineKey = nodeKeys[k], machineKeys[k]
					case "payload":
						n.Hostname, n.GivenName = name, name
						n.Hostinfo.Hostname = name
					}
				}
				prev, next, ok := w.UpdateNodeDiff(id, edit)
				require.Equal(t, m.Nodes[id] != nil, ok)

				if n := m.Nodes[id]; n != nil {
					require.Equal(t, n, prev.AsStruct())
					updated := n.Clone()
					edit(updated)

					if updated.GivenName != n.GivenName {
						updated.GivenName = m.Name(id, updated.GivenName)
					}

					m.Put(updated)
					require.Equal(t, updated, next.AsStruct())

					touched[id], commit = true, true
				}
			case "rename":
				label := rapid.SampledFrom([]string{"web", "WEB", "web-1", "node", "", "bad label", strings.Repeat("x", 64)}).Draw(t, "label")

				var want error

				switch {
				case m.Nodes[id] == nil:
					want = ErrNodeNotFound
				case label == "" || label == "bad label" || len(label) > 63:
					want = ErrGivenNameInvalid
				case m.Name(id, label) != label:
					want = ErrGivenNameTaken
				}

				got, err := w.SetGivenName(id, label)
				if want != nil {
					require.ErrorIs(t, err, want)
				} else {
					require.NoError(t, err)

					n := m.Nodes[id].Clone()
					n.GivenName = label
					m.Put(n)
					require.Equal(t, n, got.AsStruct())

					touched[id], commit = true, true
				}
			case "user":
				i := rapid.IntRange(0, 1).Draw(t, "user")
				name := rapid.SampledFrom([]string{"", "Alice", "Renamed"}).Draw(t, "display-name")

				updated := m.Users[i]
				if rapid.Bool().Draw(t, "login-name") {
					updated.Name = fmt.Sprintf("user%d-%s", i, name)
				} else {
					updated.DisplayName = name
				}

				if m.Users[i] != updated {
					m.Users[i] = updated
					commit = true

					for id, n := range m.Nodes {
						if n.User != nil && n.User.ID == m.Users[i].ID {
							touched[id] = true
						}
					}

					m.SetUsers(m.Users)
				}

				require.NoError(t, w.SetUsers(m.Users))
			case "batch":
				ids := rapid.SliceOfNDistinct(rapid.Uint64Range(1, 8), 0, 8, func(id uint64) uint64 { return id }).Draw(t, "batch")
				parity := rapid.Uint64Range(0, 2).Draw(t, "accept-parity")
				updates := map[types.NodeID]UpdateNodeFunc{}

				for _, raw := range ids {
					id := types.NodeID(raw)

					updates[id] = func(n *types.Node) { n.Hostname = name }
					if n := m.Nodes[id]; n != nil && uint64(id)%2 == parity {
						n = n.Clone()
						n.Hostname = name
						m.Nodes[id], touched[id], commit = n, true, true
					}
				}

				applied := w.UpdateNodesIf(updates, func(n *types.Node) bool { return uint64(n.ID)%2 == parity })
				require.Equal(t, commit, applied)
			case "noop":
				w.UpdateNodes(nil)
				require.NoError(t, w.SetUsers(slices.Clone(m.Users)))
				require.False(t, w.UpdateNodesIf(map[types.NodeID]UpdateNodeFunc{id: func(*types.Node) { t.Fatal("rejected callback ran") }}, func(*types.Node) bool { return false }))
			case "copy":
				_, ok := w.UpdateNode(id, func(*types.Node) {})
				require.Equal(t, m.Nodes[id] != nil, ok)

				if ok {
					// An identical node copy is still a published write.
					touched[id], commit = true, true
				}
			case "stale":
				old := history[rapid.IntRange(0, len(history)-1).Draw(t, "stale-snapshot")].model.Nodes[id]
				if old != nil {
					n := old.Clone()
					got := w.PutNode(*n)

					n.GivenName = m.Name(id, n.GivenName)
					if n.User != nil {
						for _, u := range m.Users {
							if u.ID == n.User.ID {
								n.User = u.Clone()
							}
						}
					}

					m.Put(n)
					require.Equal(t, n, got.AsStruct())

					touched[id], commit = true, true
				}
			}

			after := w.snapshot()

			wantRev := before.Rev()
			if commit {
				wantRev++
			}

			require.Equal(t, wantRev, after.Rev(), "operation %s", op)
			history = append(history, worldModelSnapshot{snap: after, model: m, touched: touched})
			checkWorldReference(t, m, after, nodeKeys, machineKeys)
			old := rapid.IntRange(0, len(history)-1).Draw(t, "retained")
			checkWorldReference(t, history[old].model, history[old].snap, nodeKeys, machineKeys)
			checkWorldModelHistory(t, history, old)
			checkWorldModelHistory(t, history, len(history)-2)
		}

		for i, old := range history {
			checkWorldReference(t, old.model, old.snap, nodeKeys, machineKeys)
			checkWorldModelHistory(t, history, i)
		}
	})
}

// The map retains at least 256 edits and trims its chain after 512. Keep
// cursors on both sides of that boundary, including writes reverted to their
// original value and a node which exists only in an intermediate snapshot.
func TestWorldHistoryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		w, err := newWorld(nil, nil, nil, types.DNSView{})
		require.NoError(t, err)

		n := types.Node{ID: 1, GivenName: "one", Hostname: "before", Tags: []string{"tag:srv"}, Hostinfo: &tailcfg.Hostinfo{}}
		w.PutNode(n)
		first := w.snapshot()
		cursor := first.NodesVersion()

		w.PutNode(types.Node{ID: 2, GivenName: "two", Tags: []string{"tag:srv"}, Hostinfo: &tailcfg.Hostinfo{}})
		w.DeleteNode(2)
		coalesced := w.snapshot().Since(first)
		require.True(t, coalesced.Global)
		require.Contains(t, coalesced.Nodes, types.NodeID(2))

		var recent *Snapshot

		for step := range rapid.IntRange(513, 530).Draw(t, "writes") {
			if step == 500 {
				recent = w.snapshot()
			}

			value := rapid.SampledFrom([]string{"before", "after", ""}).Draw(t, "hostname")

			w.UpdateNode(1, func(n *types.Node) { n.Hostname = value })
		}

		w.UpdateNode(1, func(n *types.Node) { n.Hostname = "before" })
		latest := w.snapshot()
		_, complete := latest.NodesTouchedSince(cursor)
		require.False(t, complete)

		change := latest.Since(first)
		require.True(t, change.Resync)
		require.True(t, change.Global)

		keys, complete := latest.NodesTouchedSince(recent.NodesVersion())
		require.True(t, complete)
		require.NotEmpty(t, keys)

		for _, id := range keys {
			require.Equal(t, types.NodeID(1), id)
		}

		require.False(t, latest.Since(recent).Resync)
		require.False(t, latest.Since(recent).Global, "payload-only skipped commits stay local")
		require.Equal(t, n, *first.ListNodes().At(0).AsStruct())
		require.Equal(t, n, *latest.ListNodes().At(0).AsStruct())
		checkPeersMatchFullBuild(t, latest)
	})
}

func checkWorldReference(t *rapid.T, m propcheck.World, snap *Snapshot, nodeKeys []key.NodePublic, machineKeys []key.MachinePublic) {
	propcheck.CheckWorld(t, m, snap, propcheck.WorldProbes{
		IDs: []types.NodeID{1, 2, 3, 4, 5, 6, 7, 8}, UserIDs: []types.UserID{0, 1, 2, 3}, NodeKeys: nodeKeys, MachineKeys: machineKeys,
	})
	checkPeersMatchFullBuild(t, snap)
}

func TestWorldReferenceOwnership(t *testing.T) {
	m := propcheck.World{Nodes: map[types.NodeID]*types.Node{}, Users: []types.User{{ID: 1, Name: "one"}}}
	n := &types.Node{ID: 1, GivenName: "Name", UserID: new(uint(1)), User: &types.User{ID: 1}, Tags: []string{"tag:srv"}, Hostinfo: &tailcfg.Hostinfo{Hostname: "first"}}
	m.Put(n)
	n.Hostinfo.Hostname, n.Tags[0] = "mutated", "tag:other"
	require.Equal(t, "first", m.Nodes[1].Hostinfo.Hostname)
	require.Equal(t, []string{"tag:srv"}, []string(m.Nodes[1].Tags))
	require.Equal(t, "name-1", m.Name(2, "name"))
	clone := m.Clone()
	users := []types.User{{ID: 1, Name: "renamed"}}
	m.SetUsers(users)
	users[0].Name = "mutated"
	require.Equal(t, "renamed", m.Nodes[1].User.Name)
	require.Equal(t, "one", clone.Nodes[1].User.Name)
	m.Delete(1)
	require.Contains(t, clone.Nodes, types.NodeID(1))
}
