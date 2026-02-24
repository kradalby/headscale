package state

import (
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStateForSSHCheck() *State {
	return &State{
		sshCheckAuth: make(map[sshCheckPair]time.Time),
	}
}

func TestSSHCheckAuthGlobal(t *testing.T) {
	s := newTestStateForSSHCheck()

	src := types.NodeID(1)
	dst := types.NodeID(2)
	otherDst := types.NodeID(3)
	otherSrc := types.NodeID(4)

	// No record initially
	_, ok := s.SSHCheckAuthTime(src, dst, false)
	require.False(t, ok)

	// Record global auth
	s.RecordSSHCheckAuth(src, dst, false)

	// Same src, same dst: found
	authTime, ok := s.SSHCheckAuthTime(src, dst, false)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now(), authTime, time.Second)

	// Same src, different dst: also found (global covers any dst)
	authTime2, ok := s.SSHCheckAuthTime(src, otherDst, false)
	require.True(t, ok)
	assert.Equal(t, authTime, authTime2)

	// Different src: not found
	_, ok = s.SSHCheckAuthTime(otherSrc, dst, false)
	require.False(t, ok)
}

func TestSSHCheckAuthSpecific(t *testing.T) {
	s := newTestStateForSSHCheck()

	src := types.NodeID(1)
	dst := types.NodeID(2)
	otherDst := types.NodeID(3)

	// Record specific auth
	s.RecordSSHCheckAuth(src, dst, true)

	// Same src+dst: found
	_, ok := s.SSHCheckAuthTime(src, dst, true)
	require.True(t, ok)

	// Same src, different dst: not found
	_, ok = s.SSHCheckAuthTime(src, otherDst, true)
	require.False(t, ok)
}

func TestSSHCheckAuthClear(t *testing.T) {
	s := newTestStateForSSHCheck()

	// Record both types
	s.RecordSSHCheckAuth(types.NodeID(1), types.NodeID(2), false)
	s.RecordSSHCheckAuth(types.NodeID(1), types.NodeID(2), true)

	// Both exist
	_, ok := s.SSHCheckAuthTime(types.NodeID(1), types.NodeID(2), false)
	require.True(t, ok)

	_, ok = s.SSHCheckAuthTime(types.NodeID(1), types.NodeID(2), true)
	require.True(t, ok)

	// Clear
	s.ClearSSHCheckAuth()

	// Both gone
	_, ok = s.SSHCheckAuthTime(types.NodeID(1), types.NodeID(2), false)
	require.False(t, ok)

	_, ok = s.SSHCheckAuthTime(types.NodeID(1), types.NodeID(2), true)
	require.False(t, ok)
}

func TestSSHCheckAuthConcurrent(t *testing.T) {
	s := newTestStateForSSHCheck()

	var wg sync.WaitGroup

	for i := range 100 {
		wg.Go(func() {
			src := types.NodeID(uint64(i % 10))   //nolint:gosec
			dst := types.NodeID(uint64(i%5 + 10)) //nolint:gosec

			s.RecordSSHCheckAuth(src, dst, i%2 == 0)
			s.SSHCheckAuthTime(src, dst, i%2 == 0)
		})
	}

	wg.Wait()

	// Clear concurrently with reads
	wg.Add(2)

	go func() {
		defer wg.Done()

		s.ClearSSHCheckAuth()
	}()

	go func() {
		defer wg.Done()

		s.SSHCheckAuthTime(types.NodeID(1), types.NodeID(2), false)
	}()

	wg.Wait()
}
