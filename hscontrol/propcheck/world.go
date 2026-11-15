package propcheck

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// World deliberately uses full scans and owned records, never graph indexes.
// Callers advance it from generated inputs, not production snapshots.
type World struct {
	Nodes map[types.NodeID]*types.Node
	Users []types.User
}

func (m *World) Clone() World {
	out := World{Nodes: make(map[types.NodeID]*types.Node, len(m.Nodes)), Users: slices.Clone(m.Users)}
	for id, n := range m.Nodes {
		out.Nodes[id] = n.Clone()
	}

	return out
}

// Put owns its input, allocates its name, and refreshes the embedded user.
func (m *World) Put(input *types.Node) {
	n := input.Clone()

	n.GivenName = m.Name(n.ID, n.GivenName)
	if n.User != nil {
		for _, u := range m.Users {
			if u.ID == n.User.ID {
				n.User = u.Clone()
			}
		}
	}

	m.Nodes[n.ID] = n
}

func (m *World) Delete(id types.NodeID) { delete(m.Nodes, id) }

func (m *World) SetUsers(users []types.User) {
	m.Users = slices.Clone(users)
	for id, n := range m.Nodes {
		if n.User != nil {
			for _, u := range users {
				if u.ID == n.User.ID {
					n = n.Clone()
					n.User = u.Clone()
					m.Nodes[id] = n
				}
			}
		}
	}
}

// WorldSnapshot is the read contract; the model never imports its implementation.
type WorldSnapshot interface {
	Users() []types.User
	PolicyErr() error
	ListNodes() views.Slice[types.NodeView]
	ListNodesByUser(uid types.UserID) views.Slice[types.NodeView]
	GetNode(id types.NodeID) (types.NodeView, bool)
	GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool)
	GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView
}

type WorldProbes struct {
	IDs         []types.NodeID
	UserIDs     []types.UserID
	NodeKeys    []key.NodePublic
	MachineKeys []key.MachinePublic
}

func (m *World) Name(id types.NodeID, base string) string {
	if base == "" {
		base = "node"
	}

	for suffix := 0; ; suffix++ {
		candidate := base
		if suffix > 0 {
			candidate = fmt.Sprintf("%s-%d", base, suffix)
		}

		busy := false
		for other, n := range m.Nodes {
			busy = busy || other != id && strings.EqualFold(n.GivenName, candidate)
		}

		if !busy {
			return candidate
		}
	}
}

func CheckWorld(t require.TestingT, m World, snap WorldSnapshot, probes WorldProbes) {
	require.Equal(t, m.Users, snap.Users())
	require.NoError(t, snap.PolicyErr())

	ids := slices.Sorted(maps.Keys(m.Nodes))
	got := snap.ListNodes()
	require.Equal(t, len(ids), got.Len())

	for i, id := range ids {
		require.Equal(t, id, got.At(i).ID())
		require.Equal(t, m.Nodes[id], got.At(i).AsStruct(), "node %d", id)
	}

	for _, id := range probes.IDs {
		n, ok := snap.GetNode(id)
		require.Equal(t, m.Nodes[id] != nil, ok)

		if ok {
			require.Equal(t, m.Nodes[id], n.AsStruct())
		}
	}

	for _, uid := range probes.UserIDs {
		want := []types.NodeID{}

		for _, id := range ids {
			n := m.Nodes[id]
			if len(n.Tags) == 0 && n.UserID != nil && types.UserID(*n.UserID) == uid {
				want = append(want, id)
			}
		}

		gotIDs := []types.NodeID{}
		for _, n := range snap.ListNodesByUser(uid).All() {
			gotIDs = append(gotIDs, n.ID())
			require.Equal(t, m.Nodes[n.ID()], n.AsStruct())
		}

		require.Equal(t, want, gotIDs, "user %d", uid)
	}

	for _, k := range probes.NodeKeys {
		var want types.NodeID
		for id, n := range m.Nodes {
			if n.NodeKey == k && id > want {
				want = id // Re-registration explicitly chooses the highest ID.
			}
		}

		n, ok := snap.GetNodeByNodeKey(k)
		require.Equal(t, want != 0, ok)

		if ok {
			require.Equal(t, m.Nodes[want], n.AsStruct())
		}
	}

	for _, k := range probes.MachineKeys {
		want := map[types.UserID][]types.NodeID{}

		for _, id := range ids {
			n := m.Nodes[id]
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
			require.Equal(t, m.Nodes[n.ID()], n.AsStruct())
		}
	}
}
