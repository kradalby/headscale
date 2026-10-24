package state

import (
	"bytes"
	"database/sql"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
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

// TestSetPolicyRejectsWhatFailsAsPublished sets a document that compiles
// against the users SetPolicy checked it with but not against those of the
// commit publishing it: a second "persist-user", added in between, makes
// its nodeAttrs target ambiguous. SetPolicy must return the error, publish
// no snapshot, and leave the stored source and the live filter as they
// were.
func TestSetPolicyRejectsWhatFailsAsPublished(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)

	var (
		before      *Snapshot
		src         []byte
		filter      policy.PolicyManager
		interleaved bool
	)

	s.world.beforePolicyCommit = func() {
		dup := types.User{Name: "persist-user", ProviderIdentifier: sql.NullString{String: "oidc|dup", Valid: true}}
		require.NoError(t, s.db.DB.Create(&dup).Error)
		require.NoError(t, s.refreshUsers())

		before = s.Snapshot()
		src, filter = before.PolicySource(), before.Policy()
		interleaved = true
	}

	_, err = s.SetPolicy([]byte(`{
		"acls":[{"action":"accept","src":["persist-user@"],"dst":["persist-user@:22"]}],
		"nodeAttrs":[{"target":["persist-user@"],"attr":["custom:x"]}]}`))
	require.Error(t, err, "a policy whose published compile fails must be rejected")
	require.True(t, interleaved, "test sanity: the document passed its checks before the users changed")

	after := s.Snapshot()
	assert.Equal(t, before.Rev(), after.Rev(), "a refused document is never published, not even briefly")
	assert.Equal(t, string(src), string(after.PolicySource()))

	node, ok := after.GetNode(nodeID)
	require.True(t, ok)

	was, err := filter.FilterForNode(node)
	require.NoError(t, err)

	is, err := after.Policy().FilterForNode(node)
	require.NoError(t, err)
	assert.Equal(t, was, is, "the live filter must stay the last good one")
}

// TestSetPolicyEnforcesPolicyTests sets documents whose tests, sshTests or
// both fail, through State.SetPolicy: each is refused, and the stored
// source, the live filter and SSH policy stay as they were. The base keeps
// passing tests of both kinds, so a refusal is only the failing block.
func TestSetPolicyEnforcesPolicyTests(t *testing.T) {
	const (
		rules = `"acls":[{"action":"accept","src":["persist-user@"],"dst":["persist-user@:22"]}],
			"ssh":[{"action":"accept","src":["persist-user@"],"dst":["autogroup:self"],"users":["root"]}]`
		aclOK  = `{"src":"persist-user@","accept":["persist-user@:22"]}`
		aclBad = `{"src":"persist-user@","accept":["persist-user@:80"]}`
		sshOK  = `{"src":"persist-user@","dst":["persist-user@"],"accept":["root"]}`
		sshBad = `{"src":"persist-user@","dst":["persist-user@"],"accept":["ubuntu"]}`
	)

	doc := func(acl, ssh string) []byte {
		return []byte(`{` + rules + `,"tests":[` + acl + `],"sshTests":[` + ssh + `]}`)
	}

	for name, pol := range map[string][]byte{
		"acl":  doc(aclBad, sshOK),
		"ssh":  doc(aclOK, sshBad),
		"both": doc(aclBad, sshBad),
	} {
		t.Run(name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			_, err := s.SetPolicy(doc(aclOK, sshOK))
			require.NoError(t, err, "the base document's tests pass")

			before := s.Snapshot()
			node, ok := before.GetNode(nodeID)
			require.True(t, ok)

			wasFilter, err := before.Policy().FilterForNode(node)
			require.NoError(t, err)

			wasSSH, err := s.SSHPolicy(node)
			require.NoError(t, err)

			_, err = s.SetPolicy(pol)
			require.Error(t, err, "failing policy tests must refuse the document")

			after := s.Snapshot()
			assert.Equal(t, before.Rev(), after.Rev(), "a document failing its tests is never published, not even briefly")
			assert.Equal(t, string(before.PolicySource()), string(after.PolicySource()))

			isFilter, err := after.Policy().FilterForNode(node)
			require.NoError(t, err)
			assert.Equal(t, wasFilter, isFilter)

			isSSH, err := s.SSHPolicy(node)
			require.NoError(t, err)
			assert.Equal(t, wasSSH, isSSH)
		})
	}
}

// TestSetPolicyUnchangedDocumentIsANoOp re-sets the live document after a
// node change made its tests fail: the document is already live, so the
// write changes nothing and returns no error, which lets a reload of it go
// on to auto-approval as boot does.
func TestSetPolicyUnchangedDocumentIsANoOp(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	pol := []byte(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["persist-user@:22"]}],
		"tests":[{"src":"persist-user@","accept":["persist-user@:22"]}]}`)

	_, err := s.SetPolicy(pol)
	require.NoError(t, err)

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.NoError(t, s.DeleteNode(node))
	require.Error(t, policyTestsFail(s.Snapshot().Policy()), "test sanity: the document's tests now fail")

	changed, err := s.SetPolicy(pol)
	require.NoError(t, err, "an unchanged document is already live")
	assert.False(t, changed)

	// The second of two identical writes that both passed the check above
	// reaches the world, which must commit nothing.
	before := s.Snapshot()
	changed, err = s.world.SetPolicy(bytes.Clone(pol), (*Snapshot).PolicyErr)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, before.Rev(), s.Snapshot().Rev(), "an unchanged document is not recompiled")
}

// TestSetPolicyTestsSeeThePublishedNodes changes the nodes a document's
// tests read after they passed and before the commit publishing it. The
// commit refuses, and the document is tested again against the nodes it
// would be published with; once the nodes have moved on every attempt
// outside the world's lock, the commit runs the tests itself.
func TestSetPolicyTestsSeeThePublishedNodes(t *testing.T) {
	pol := []byte(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["persist-user@:22"]}],
		"tests":[{"src":"persist-user@","accept":["persist-user@:22"]}]}`)

	for _, tt := range []struct {
		name     string
		deleteAt int // the attempt deleting the node the tests need; 0 never
		publish  bool
	}{
		{name: "deleted before the first publish", deleteAt: 1},
		{name: "moved on every attempt", publish: true},
		{name: "deleted on the last attempt", deleteAt: policyAttempts},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			attempts := 0
			s.world.beforePolicyCommit = func() {
				attempts++

				node, ok := s.GetNodeByID(nodeID)
				require.True(t, ok)

				if attempts == tt.deleteAt {
					require.NoError(t, s.DeleteNode(node))

					return
				}

				// A new address is a change the policy reads, and one the
				// tests survive.
				n := node.AsStruct()
				n.IPv4 = new(netip.AddrFrom4([4]byte{100, 64, 9, byte(attempts)})) //nolint:gosec // small
				s.PutNodeInStoreForTest(*n)
			}

			changed, err := s.SetPolicy(pol)
			if !tt.publish {
				require.Error(t, err, "tests failing against the published nodes must refuse the document")
				assert.False(t, changed)
				assert.Empty(t, s.Snapshot().PolicySource())

				return
			}

			require.NoError(t, err)
			assert.True(t, changed)
			assert.Equal(t, policyAttempts, attempts, "test sanity: every attempt saw its nodes move")
			assert.Equal(t, string(pol), string(s.Snapshot().PolicySource()))
		})
	}
}

// TestSetPolicyIdenticalWritesCommitOnce sets one new document from several
// writers at once, released together just before publishing: one commits,
// the rest find it live.
func TestSetPolicyIdenticalWritesCommitOnce(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	const writers = 8

	var (
		arrived atomic.Int32
		release = make(chan struct{})
		wg      sync.WaitGroup
		commits atomic.Int32
	)

	s.world.beforePolicyCommit = func() {
		if arrived.Add(1) == writers {
			close(release)
		}

		<-release
	}

	pol := []byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)
	before := s.Snapshot().Rev()

	errs := make(chan error, writers)

	for range writers {
		wg.Go(func() {
			changed, err := s.SetPolicy(pol)
			errs <- err

			if changed {
				commits.Add(1)
			}
		})
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	assert.EqualValues(t, 1, commits.Load(), "one writer publishes the document")
	assert.Equal(t, before+1, s.Snapshot().Rev(), "and only one commit is made")
}

func TestUserMutationReportsPolicyCompileFailure(t *testing.T) {
	for _, mode := range []string{"create", "update"} {
		t.Run(mode, func(t *testing.T) {
			_, s, _ := persistTestSetup(t)
			_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["*:22"]}]}`))
			require.NoError(t, err)

			good := s.Snapshot().Policy()
			if mode == "create" {
				_, err = s.CreateUser(types.User{Name: "persist-user", ProviderIdentifier: sql.NullString{String: "oidc|duplicate", Valid: true}})
			} else {
				other, createErr := s.CreateUser(types.User{Name: "other", ProviderIdentifier: sql.NullString{String: "oidc|other", Valid: true}})
				require.NoError(t, createErr)

				good = s.Snapshot().Policy()
				_, err = s.UpdateUser(types.UserID(other.ID), func(u *types.User) error { u.Name = "persist-user"; return nil })
			}

			require.Error(t, err)
			require.Error(t, s.Snapshot().PolicyErr())
			require.Same(t, good, s.Snapshot().Policy(), "keep the last valid policy")
		})
	}
}
