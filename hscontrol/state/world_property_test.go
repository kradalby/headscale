package state

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// worldModel deliberately uses full scans and owned records, not graph indexes
// or the world's change predicates. Nodes are replaced, never edited in place.
type worldModel struct {
	nodes map[types.NodeID]*types.Node
	users []types.User
}

type worldModelSnapshot struct {
	snap    *Snapshot
	model   worldModel
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

func (m worldModel) name(id types.NodeID, base string) string {
	if base == "" {
		base = "node"
	}

	for suffix := 0; ; suffix++ {
		candidate := base
		if suffix > 0 {
			candidate = fmt.Sprintf("%s-%d", base, suffix)
		}

		busy := false
		for other, n := range m.nodes {
			busy = busy || other != id && strings.EqualFold(n.GivenName, candidate)
		}

		if !busy {
			return candidate
		}
	}
}

func (m worldModel) check(t *rapid.T, snap *Snapshot, nodeKeys []key.NodePublic, machineKeys []key.MachinePublic) {
	t.Helper()

	require.Equal(t, m.users, snap.Users())
	require.NoError(t, snap.PolicyErr())

	ids := slices.Sorted(maps.Keys(m.nodes))
	got := snap.ListNodes()
	require.Equal(t, len(ids), got.Len())

	for i, id := range ids {
		require.Equal(t, id, got.At(i).ID())
		require.Equal(t, m.nodes[id], got.At(i).AsStruct(), "node %d", id)
	}

	for id := types.NodeID(1); id <= 8; id++ {
		n, ok := snap.GetNode(id)
		require.Equal(t, m.nodes[id] != nil, ok)

		if ok {
			require.Equal(t, m.nodes[id], n.AsStruct())
		}
	}

	for uid := types.UserID(0); uid <= 3; uid++ {
		want := []types.NodeID{}

		for _, id := range ids {
			n := m.nodes[id]
			if len(n.Tags) == 0 && n.UserID != nil && types.UserID(*n.UserID) == uid {
				want = append(want, id)
			}
		}

		gotIDs := []types.NodeID{}
		for _, n := range snap.ListNodesByUser(uid).All() {
			gotIDs = append(gotIDs, n.ID())
			require.Equal(t, m.nodes[n.ID()], n.AsStruct())
		}

		require.Equal(t, want, gotIDs, "user %d", uid)
	}

	for _, k := range nodeKeys {
		var want types.NodeID
		for id, n := range m.nodes {
			if n.NodeKey == k && id > want {
				want = id // Re-registration explicitly chooses the highest ID.
			}
		}

		n, ok := snap.GetNodeByNodeKey(k)
		require.Equal(t, want != 0, ok)

		if ok {
			require.Equal(t, m.nodes[want], n.AsStruct())
		}
	}

	for _, k := range machineKeys {
		want := map[types.UserID][]types.NodeID{}

		for _, id := range ids {
			n := m.nodes[id]
			if n.MachineKey != k {
				continue
			}

			var uid types.UserID
			if len(n.Tags) == 0 && n.UserID != nil {
				uid = types.UserID(*n.UserID)
			}

			want[uid] = append(want[uid], id)
		}

		got := snap.GetNodesByMachineKeyAllUsers(k)
		require.Len(t, got, len(want))

		for uid, candidates := range want {
			n, ok := got[uid]
			require.True(t, ok)
			// Multiple registrations for one owner have no documented winner.
			require.Contains(t, candidates, n.ID())
			require.Equal(t, m.nodes[n.ID()], n.AsStruct())
		}
	}

	checkPeersMatchFullBuild(t, snap)
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
		m := worldModel{
			nodes: map[types.NodeID]*types.Node{},
			users: []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}},
		}
		w, err := newWorld(nil, m.users, nil, types.DNSView{})
		require.NoError(t, err)

		history := make([]worldModelSnapshot, 1, 61)
		history[0] = worldModelSnapshot{snap: w.snapshot(), model: m}
		m.check(t, w.snapshot(), nodeKeys, machineKeys)
		require.True(t, w.snapshot().Since(nil).Global)

		for range rapid.IntRange(1, 60).Draw(t, "steps") {
			m.nodes = maps.Clone(m.nodes)
			m.users = slices.Clone(m.users)
			before := w.snapshot()
			touched := map[types.NodeID]bool{}
			commit := false
			id := types.NodeID(rapid.Uint64Range(1, 8).Draw(t, "id"))
			name := rapid.SampledFrom([]string{"", "node", "NODE", "web", "web-1", "db"}).Draw(t, "name")

			op := rapid.SampledFrom([]string{"put", "delete", "ownership", "keys", "rename", "user", "batch", "noop", "copy", "payload", "stale"}).Draw(t, "op")
			switch op {
			case "put":
				u := m.users[rapid.IntRange(0, 1).Draw(t, "owner")]
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
				n.GivenName = m.name(id, name)
				m.nodes[id] = n
				require.Equal(t, n, got.AsStruct())

				touched[id], commit = true, true
			case "delete":
				w.DeleteNode(id)

				if m.nodes[id] != nil {
					delete(m.nodes, id)
					touched[id], commit = true, true
				}
			case "ownership", "keys", "payload":
				u := m.users[rapid.IntRange(0, 1).Draw(t, "owner")]
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
				require.Equal(t, m.nodes[id] != nil, ok)

				if n := m.nodes[id]; n != nil {
					require.Equal(t, n, prev.AsStruct())
					updated := n.Clone()
					edit(updated)

					if updated.GivenName != n.GivenName {
						updated.GivenName = m.name(id, updated.GivenName)
					}

					m.nodes[id] = updated
					require.Equal(t, updated, next.AsStruct())

					touched[id], commit = true, true
				}
			case "rename":
				label := rapid.SampledFrom([]string{"web", "WEB", "web-1", "node", "", "bad label", strings.Repeat("x", 64)}).Draw(t, "label")

				var want error

				switch {
				case m.nodes[id] == nil:
					want = ErrNodeNotFound
				case label == "" || label == "bad label" || len(label) > 63:
					want = ErrGivenNameInvalid
				case m.name(id, label) != label:
					want = ErrGivenNameTaken
				}

				got, err := w.SetGivenName(id, label)
				if want != nil {
					require.ErrorIs(t, err, want)
				} else {
					require.NoError(t, err)

					n := m.nodes[id].Clone()
					n.GivenName = label
					m.nodes[id] = n
					require.Equal(t, n, got.AsStruct())

					touched[id], commit = true, true
				}
			case "user":
				i := rapid.IntRange(0, 1).Draw(t, "user")
				name := rapid.SampledFrom([]string{"", "Alice", "Renamed"}).Draw(t, "display-name")

				updated := m.users[i]
				if rapid.Bool().Draw(t, "login-name") {
					updated.Name = fmt.Sprintf("user%d-%s", i, name)
				} else {
					updated.DisplayName = name
				}

				if m.users[i] != updated {
					m.users[i] = updated
					commit = true

					for id, n := range m.nodes {
						if n.User != nil && n.User.ID == m.users[i].ID {
							n = n.Clone()
							n.User = m.users[i].Clone()
							m.nodes[id], touched[id] = n, true
						}
					}
				}

				require.NoError(t, w.SetUsers(m.users))
			case "batch":
				ids := rapid.SliceOfNDistinct(rapid.Uint64Range(1, 8), 0, 8, func(id uint64) uint64 { return id }).Draw(t, "batch")
				parity := rapid.Uint64Range(0, 2).Draw(t, "accept-parity")
				updates := map[types.NodeID]UpdateNodeFunc{}

				for _, raw := range ids {
					id := types.NodeID(raw)

					updates[id] = func(n *types.Node) { n.Hostname = name }
					if n := m.nodes[id]; n != nil && uint64(id)%2 == parity {
						n = n.Clone()
						n.Hostname = name
						m.nodes[id], touched[id], commit = n, true, true
					}
				}

				applied := w.UpdateNodesIf(updates, func(n *types.Node) bool { return uint64(n.ID)%2 == parity })
				require.Equal(t, commit, applied)
			case "noop":
				w.UpdateNodes(nil)
				require.NoError(t, w.SetUsers(slices.Clone(m.users)))
				require.False(t, w.UpdateNodesIf(map[types.NodeID]UpdateNodeFunc{id: func(*types.Node) { t.Fatal("rejected callback ran") }}, func(*types.Node) bool { return false }))
			case "copy":
				_, ok := w.UpdateNode(id, func(*types.Node) {})
				require.Equal(t, m.nodes[id] != nil, ok)

				if ok {
					// An identical node copy is still a published write.
					touched[id], commit = true, true
				}
			case "stale":
				old := history[rapid.IntRange(0, len(history)-1).Draw(t, "stale-snapshot")].model.nodes[id]
				if old != nil {
					n := old.Clone()
					got := w.PutNode(*n)

					n.GivenName = m.name(id, n.GivenName)
					if n.User != nil {
						for _, u := range m.users {
							if u.ID == n.User.ID {
								n.User = u.Clone()
							}
						}
					}

					m.nodes[id] = n
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
			m.check(t, after, nodeKeys, machineKeys)
			old := rapid.IntRange(0, len(history)-1).Draw(t, "retained")
			history[old].model.check(t, history[old].snap, nodeKeys, machineKeys)
			checkWorldModelHistory(t, history, old)
			checkWorldModelHistory(t, history, len(history)-2)
		}

		for i, old := range history {
			old.model.check(t, old.snap, nodeKeys, machineKeys)
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
