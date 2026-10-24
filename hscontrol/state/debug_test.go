package state

import (
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestDebugNodeStore(t *testing.T) {
	tests := []struct {
		name     string
		nodes    []types.Node
		contains []string
	}{
		{
			name: "empty",
			contains: []string{
				"=== Node State Debug Information ===",
				"Total Nodes: 0",
				"Users with Nodes: 0",
			},
		},
		{
			name: "with data",
			nodes: []types.Node{
				createTestNode(1, 1, "user1", "node1"),
				createTestNode(2, 2, "user2", "node2"),
			},
			contains: []string{
				"Total Nodes: 2",
				"Users with Nodes: 2",
				"Peer Relationships:",
				"Node 1 (node1): 1 peers",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{world: newTestWorld(t, tt.nodes...)}

			debugStr := s.DebugNodeStore()

			for _, expected := range tt.contains {
				assert.Contains(t, debugStr, expected,
					"Debug string should contain: %s\nActual debug:\n%s", expected, debugStr)
			}
		})
	}
}

func TestDebugRegistrationCache(t *testing.T) {
	s := &State{
		authCacheMaxEntries: defaultRegisterCacheMaxEntries,
		authCache: expirable.NewLRU[types.AuthID, *types.AuthRequest](
			defaultRegisterCacheMaxEntries, nil, time.Minute),
	}
	s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest())

	info := s.DebugRegistrationCache()

	assert.Equal(t, "expirable-lru", info["type"])
	assert.Equal(t, defaultRegisterCacheMaxEntries, info["max_entries"])
	assert.Equal(t, 1, info["current_len"])
}
