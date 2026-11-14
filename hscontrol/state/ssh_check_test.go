package state

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func newTestStateForSSHCheck(t *testing.T) *State {
	t.Helper()

	s := newRetagTestState(t)

	user := s.CreateUserForTest("ssh-user")
	for i := range 10 {
		node := s.CreateRegisteredNodeForTest(user, fmt.Sprintf("ssh-node-%d", i))
		node.User = user
		s.world.PutNode(*node)
	}

	return s
}

func TestSSHCheckAuth(t *testing.T) {
	s := newTestStateForSSHCheck(t)

	src := types.NodeID(1)
	dst := types.NodeID(2)
	otherDst := types.NodeID(3)
	otherSrc := types.NodeID(4)

	// No record initially
	_, ok := s.GetLastSSHAuth(src, dst)
	require.False(t, ok)

	// Record auth for (src, dst)
	s.SetLastSSHAuth(src, dst)

	// Same src+dst: found
	authTime, ok := s.GetLastSSHAuth(src, dst)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now(), authTime, time.Second)

	// Same src, different dst: not found (auth is per-pair)
	_, ok = s.GetLastSSHAuth(src, otherDst)
	require.False(t, ok)

	// Different src: not found
	_, ok = s.GetLastSSHAuth(otherSrc, dst)
	require.False(t, ok)
}

func TestSSHCheckAuthClear(t *testing.T) {
	s := newTestStateForSSHCheck(t)

	s.SetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	s.SetLastSSHAuth(types.NodeID(1), types.NodeID(3))

	_, ok := s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	require.True(t, ok)

	_, ok = s.GetLastSSHAuth(types.NodeID(1), types.NodeID(3))
	require.True(t, ok)

	// Clear
	s.ClearSSHCheckAuth()

	_, ok = s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	require.False(t, ok)

	_, ok = s.GetLastSSHAuth(types.NodeID(1), types.NodeID(3))
	require.False(t, ok)
}

func TestSSHCheckAuthConcurrent(t *testing.T) {
	s := newTestStateForSSHCheck(t)

	var wg sync.WaitGroup

	for i := range 100 {
		wg.Go(func() {
			src := types.NodeID(uint64(i % 10))   //nolint:gosec
			dst := types.NodeID(uint64(i%5 + 10)) //nolint:gosec

			s.SetLastSSHAuth(src, dst)
			s.GetLastSSHAuth(src, dst)
		})
	}

	wg.Wait()

	// Clear concurrently with reads
	wg.Go(func() {
		s.ClearSSHCheckAuth()
	})

	wg.Go(func() {
		s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	})

	wg.Wait()
}

func TestSSHCheckAuthFollowsSourceOwner(t *testing.T) {
	for _, tt := range []struct {
		name   string
		tagged bool
		kept   bool
	}{
		{"convert", false, false},
		{"retag", true, false},
		{"user_change", false, false},
		{"delete", false, false},
		{"destination_change", false, true},
		{"rekey", false, true},
		{"same_tags", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStateForSSHCheck(t)
			_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:ci":["ssh-user@"],"tag:ops":["ssh-user@"]}}`))
			require.NoError(t, err)

			src, dst := types.NodeID(1), types.NodeID(2)
			if tt.tagged {
				_, err = s.SetNodeTags(src, []string{"tag:ci", "tag:ops"})
				require.NoError(t, err)
			}

			s.SetLastSSHAuth(src, dst)
			at, ok := s.GetLastSSHAuth(src, dst)
			require.True(t, ok)

			switch tt.name {
			case "convert", "destination_change":
				id := src
				if tt.name == "destination_change" {
					id = dst
				}

				_, err = s.SetNodeTags(id, []string{"tag:ci"})
				require.NoError(t, err)
			case "retag":
				_, err = s.SetNodeTags(src, []string{"tag:ops"})
				require.NoError(t, err)
			case "user_change":
				other := s.CreateUserForTest("other-user")
				_, ok = s.world.UpdateNode(src, func(n *types.Node) {
					n.UserID = &other.ID
					n.User = other
				})
				require.True(t, ok)
			case "delete":
				node, ok := s.GetNodeByID(src)
				require.True(t, ok)

				err = s.DeleteNode(node)
				require.NoError(t, err)
			case "rekey":
				_, ok = s.world.UpdateNode(src, func(n *types.Node) { n.NodeKey = key.NewNode().Public() })
				require.True(t, ok)
			case "same_tags":
				_, ok = s.world.UpdateNode(src, func(n *types.Node) {
					n.Tags = []string{"tag:ops", "tag:ci"}
				})
				require.True(t, ok)
			}

			last, ok := s.GetLastSSHAuth(src, dst)
			assert.Equal(t, tt.kept, ok)

			if tt.kept {
				assert.Equal(t, at, last)
			} else {
				assert.True(t, last.IsZero())
			}
		})
	}
}

func TestSSHCheckAuthExpiresWithSource(t *testing.T) {
	s := newTestStateForSSHCheck(t)
	src, dst, other := types.NodeID(1), types.NodeID(2), types.NodeID(3)
	s.SetLastSSHAuth(src, dst)
	s.SetLastSSHAuth(src, other)
	s.SetLastSSHAuth(dst, src)
	s.SetLastSSHAuth(dst, other)
	node, ok := s.GetNodeByID(src)
	require.True(t, ok)

	expiry := time.Now()
	_, err := s.SetNodeExpiry(src, &expiry)
	require.NoError(t, err)

	for _, destination := range []types.NodeID{dst, other} {
		_, ok = s.GetLastSSHAuth(src, destination)
		assert.False(t, ok)
	}

	for _, destination := range []types.NodeID{src, other} {
		_, ok = s.GetLastSSHAuth(dst, destination)
		assert.True(t, ok)
	}

	userID := types.UserID(node.UserID().Get())
	pak, err := s.CreatePreAuthKey(&userID, true, false, nil, nil)
	require.NoError(t, err)
	reauthenticated, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname()},
		Expiry:   time.Now().Add(24 * time.Hour),
	}, node.MachineKey())
	require.NoError(t, err)
	require.Equal(t, src, reauthenticated.ID())
	require.False(t, reauthenticated.IsExpired())

	for _, destination := range []types.NodeID{dst, other} {
		_, ok = s.GetLastSSHAuth(src, destination)
		assert.False(t, ok, "pre-auth key relogin must require a new SSH check")
	}
}

func TestSSHCheckAuthKeepsApprovalOnExpiryExtension(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)

	zero := time.Time{}
	for name, expiry := range map[string]*time.Time{
		"future": &future, "disabled": nil, "zero": &zero,
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStateForSSHCheck(t)
			src, dst := types.NodeID(1), types.NodeID(2)
			s.SetLastSSHAuth(src, dst)
			before, ok := s.GetLastSSHAuth(src, dst)
			require.True(t, ok)

			_, err := s.SetNodeExpiry(src, expiry)
			require.NoError(t, err)

			after, ok := s.GetLastSSHAuth(src, dst)
			require.True(t, ok)
			assert.Equal(t, before, after)
		})
	}
}

func TestSSHCheckAuthExpiresWithinBatch(t *testing.T) {
	s := newTestStateForSSHCheck(t)
	src, dst := types.NodeID(1), types.NodeID(2)
	s.SetLastSSHAuth(src, dst)
	_, approved := s.GetLastSSHAuth(src, dst)
	require.True(t, approved)

	node, ok := s.GetNodeByID(src)
	require.True(t, ok)

	userID := types.UserID(node.UserID().Get())
	pak, err := s.CreatePreAuthKey(&userID, true, false, nil, nil)
	require.NoError(t, err)

	// Hold graph publication while expiry takes the row lock. Reauth must
	// wait for expiry's memory+SQL write, rather than publish a provisional identity.
	entered, release := make(chan struct{}), make(chan struct{})

	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()

	go s.world.UpdateNode(dst, func(*types.Node) {
		close(entered)
		<-release
	})

	<-entered

	expiry := time.Now()
	expiryDone := make(chan error, 1)

	go func() {
		_, err := s.SetNodeExpiry(src, &expiry)
		expiryDone <- err
	}()

	waitParkedOnWriteQueue(t, "SetNodeExpiry")

	regDone := make(chan error, 1)

	var approvalAtReauth, expiredAtReauth bool

	renewalKey := key.NewNode().Public()

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("observe_ssh_renewal", func(tx *gorm.DB) {
		candidate, ok := tx.Statement.Dest.(*types.Node)
		if tx.Statement.Table != "nodes" || !ok || candidate.ID != src || candidate.NodeKey != renewalKey {
			return
		}

		current, ok := s.GetNodeByID(src)
		expiredAtReauth = ok && current.IsExpired()
		_, approvalAtReauth = s.GetLastSSHAuth(src, dst)
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("observe_ssh_renewal") })

	go func() {
		_, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  renewalKey,
			Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname()},
			Expiry:   time.Now().Add(24 * time.Hour),
		}, node.MachineKey())
		regDone <- err
	}()

	buf := make([]byte, 1<<20)

	require.Eventually(t, func() bool {
		n := runtime.Stack(buf, true)
		for n == len(buf) {
			buf = make([]byte, len(buf)*2)
			n = runtime.Stack(buf, true)
		}

		for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
			if strings.Contains(g, ".reregisterNodeWithPAK(") && strings.Contains(g, "(*rowLocks).lock(") {
				return true
			}
		}

		return false
	}, 5*time.Second, time.Millisecond)

	select {
	case err := <-regDone:
		require.NoError(t, err)
		t.Fatal("reauth completed before the pending expiry released its row")
	default:
	}

	releaseOnce()
	require.NoError(t, <-expiryDone)
	require.NoError(t, <-regDone)
	assert.True(t, expiredAtReauth, "reauth sees the committed expiry before renewing it")
	assert.False(t, approvalAtReauth, "expiry already revoked the human approval before renewal")

	renewed, ok := s.GetNodeByID(src)
	require.True(t, ok)
	require.False(t, renewed.IsExpired(), "precondition: the relogin renewed the node")

	_, ok = s.GetLastSSHAuth(src, dst)
	assert.False(t, ok, "expiry must forget the approval")
}
