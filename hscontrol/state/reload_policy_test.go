package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

var errIdenticalPolicyStore = errors.New("identical policy store failure")

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

	// Two users: a user's own devices stay peers under any policy.
	nodes := append(
		database.CreateRegisteredNodesForTest(database.CreateUserForTest("reload-user"), 1, "reload-node"),
		database.CreateRegisteredNodesForTest(database.CreateUserForTest("reload-other"), 1, "reload-other")...,
	)
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

// TestSetPolicyRejectsWhatFailsAsPublished sets a document that passes its
// checks against the users SetPolicy checked it with but not against those
// of the commit publishing it: a second "persist-user", added in between,
// makes the name it lists ambiguous. SetPolicy must return the error, publish
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
	require.Error(t, policyRefusal(s.Snapshot().Policy()), "test sanity: the document's tests now fail")

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

// TestUserMutationDropsAmbiguousName pins that a user created or renamed to a
// name the policy lists is stored, and the policy recompiles with that name
// granting nothing rather than failing the write and freezing the policy,
// with a warning naming the token.
func TestUserMutationDropsAmbiguousName(t *testing.T) {
	for _, mode := range []string{"create", "update"} {
		t.Run(mode, func(t *testing.T) {
			_, s, _ := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["*:22"]}]}`))
			require.NoError(t, err)

			rules, _ := s.Snapshot().Policy().Filter()
			require.NotEmpty(t, rules, "precondition: persist-user@ has a node")

			var logged bytes.Buffer

			previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
			log.Logger = zerolog.New(&logged)

			zerolog.SetGlobalLevel(zerolog.WarnLevel)

			t.Cleanup(func() {
				log.Logger = previousLogger

				zerolog.SetGlobalLevel(previousLevel)
			})

			if mode == "create" {
				_, err = s.CreateUser(types.User{Name: "persist-user", ProviderIdentifier: sql.NullString{String: "oidc|duplicate", Valid: true}})
			} else {
				other, createErr := s.CreateUser(types.User{Name: "other", ProviderIdentifier: sql.NullString{String: "oidc|other", Valid: true}})
				require.NoError(t, createErr)

				_, err = s.UpdateUser(types.UserID(other.ID), func(u *types.User) error { u.Name = "persist-user"; return nil })
			}

			require.NoError(t, err)
			require.NoError(t, s.Snapshot().PolicyErr())

			rules, _ = s.Snapshot().Policy().Filter()
			assert.Empty(t, rules, "an ambiguous name grants nothing")
			assert.Contains(t, logged.String(), `"level":"warn"`, "the operator learns a name went ambiguous")
			assert.Contains(t, logged.String(), "persist-user", "the warning names the token")
		})
	}
}

// TestAmbiguousNameWarnsOnTransition refreshes the users repeatedly while a
// policy name stays ambiguous: the operator is warned when it becomes
// ambiguous, not on every registration's refresh after that.
func TestAmbiguousNameWarnsOnTransition(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["*:22"]}]}`))
	require.NoError(t, err)

	var logged bytes.Buffer

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&logged)

	zerolog.SetGlobalLevel(zerolog.WarnLevel)

	t.Cleanup(func() {
		log.Logger = previousLogger

		zerolog.SetGlobalLevel(previousLevel)
	})

	warnings := func() int { return strings.Count(logged.String(), "policy names users ambiguously") }

	twin, err := s.CreateUser(types.User{Name: "persist-user", ProviderIdentifier: sql.NullString{String: "oidc|twin", Valid: true}})
	require.NoError(t, err)
	require.Equal(t, 1, warnings(), "the name becoming ambiguous is reported")

	for range 3 {
		require.NoError(t, s.refreshUsers())
	}

	assert.Equal(t, 1, warnings(), "an unchanged ambiguity is reported again on every refresh")

	_, err = s.UpdateUser(types.UserID(twin.ID), func(u *types.User) error { u.Name = "persist-twin"; return nil })
	require.NoError(t, err)

	_, err = s.CreateUser(types.User{Name: "persist-user", ProviderIdentifier: sql.NullString{String: "oidc|again", Valid: true}})
	require.NoError(t, err)
	assert.Equal(t, 2, warnings(), "a name becoming ambiguous again is reported again")
}

// captureWarnings counts the ambiguity warnings the logger sees.
func captureWarnings(t *testing.T) func() int {
	t.Helper()

	var logged bytes.Buffer

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&logged)

	zerolog.SetGlobalLevel(zerolog.WarnLevel)

	t.Cleanup(func() {
		log.Logger = previousLogger

		zerolog.SetGlobalLevel(previousLevel)
	})

	return func() int { return strings.Count(logged.String(), "policy names users ambiguously") }
}

// TestAmbiguousWarningIdentityIsTheSet pins that the warning is keyed on
// which names are ambiguous, not on how the validator happens to order its
// report: groups are a map, so the same set can be reported in any order.
func TestAmbiguousWarningIdentityIsTheSet(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.CreateUser(types.User{Name: "other-user"})
	require.NoError(t, err)

	_, err = s.SetPolicy([]byte(`{"groups":{"group:first":["persist-user@"],"group:second":["other-user@"]},"acls":[{"action":"accept","src":["group:first","group:second"],"dst":["*:22"]}]}`))
	require.NoError(t, err)

	warnings := captureWarnings(t)

	twins := 0

	twin := func(name string) *types.User {
		twins++

		u, err := s.CreateUser(types.User{Name: name, ProviderIdentifier: sql.NullString{String: fmt.Sprintf("oidc|twin-%d", twins), Valid: true}})
		require.NoError(t, err)

		return u
	}

	first := twin("persist-user")

	require.Equal(t, 1, warnings())

	twin("other-user")
	require.Equal(t, 2, warnings(), "the second name joining the set is reported")

	for i := range 48 {
		_, err = s.CreateUser(types.User{Name: fmt.Sprintf("unrelated-%d", i)})
		require.NoError(t, err)
	}

	require.Equal(t, 2, warnings(), "unrelated users do not change the ambiguity set")

	_, err = s.UpdateUser(types.UserID(first.ID), func(u *types.User) error { u.Name = "persist-twin"; return nil })
	require.NoError(t, err)
	require.Equal(t, 3, warnings(), "a name leaving the set changes it")

	twin("persist-user")
	require.Equal(t, 4, warnings(), "a name becoming ambiguous again is reported again")
}

// TestUserRefreshValidatesOnIdentityChangeOnly counts validations: every
// registration refreshes the users, and only a change to what a policy name
// resolves by can make a name ambiguous. The warning's deduplication would
// hide a validation made on every refresh, so the count is the oracle.
func TestUserRefreshValidatesOnIdentityChangeOnly(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["*:22"]}]}`))
	require.NoError(t, err)

	user, err := s.CreateUser(types.User{Name: "other-user"})
	require.NoError(t, err)

	validations := 0
	s.beforeAmbiguityCheck = func() { validations++ }

	update := func(f func(*types.User)) {
		t.Helper()

		_, err := s.UpdateUser(types.UserID(user.ID), func(u *types.User) error { f(u); return nil })
		require.NoError(t, err)
	}

	require.NoError(t, s.refreshUsers())
	assert.Equal(t, 0, validations, "an identical user list is not validated")

	update(func(u *types.User) { u.DisplayName = "Other User" })
	assert.Equal(t, 0, validations, "a field the policy does not resolve by is not validated")

	update(func(u *types.User) { u.Name = "renamed-user" })
	assert.Equal(t, 1, validations, "a renamed user is validated")

	update(func(u *types.User) { u.Email = "other@example.com" })
	assert.Equal(t, 2, validations, "a changed email is validated")
}

// TestBootWarnedAmbiguityIsNotRepeated pins that the ambiguity warned about
// at boot is known to the first user change after it: one that keeps the
// same names ambiguous says nothing new.
func TestBootWarnedAmbiguityIsNotRepeated(t *testing.T) {
	dbPath, _ := ambiguousNameSetup(t)

	warnings := captureWarnings(t)
	s := persistTestReopen(t, dbPath)

	require.Equal(t, 1, warnings(), "boot warns about the stored ambiguity")

	// Another user's name changes, which a refresh validates again.
	bob, err := s.GetUserByName("bob")
	require.NoError(t, err)

	_, err = s.RenameUser(types.UserID(bob.ID), "robert")
	require.NoError(t, err)
	require.Equal(t, 1, warnings(), "the same ambiguity is not warned about twice")
}

// ambiguousNameSetup stores a policy granting alice@ and bob@ access to
// carol@, with a second "alice" from another issuer already in the database.
// It returns the database path and the node of each user.
func ambiguousNameSetup(t *testing.T) (string, map[string]types.NodeID) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"

	database, err := db.NewHeadscaleDatabase(persistTestConfig(dbPath))
	require.NoError(t, err)

	ids := map[string]types.NodeID{}
	for _, name := range []string{"alice", "bob", "carol"} {
		ids[name] = database.CreateRegisteredNodeForTest(database.CreateUserForTest(name), name+"-node").ID
	}

	_, err = database.SetPolicy(`{"acls":[{"action":"accept","src":["alice@","bob@"],"dst":["carol@:*"]}]}`)
	require.NoError(t, err)

	require.NoError(t, database.DB.Create(&types.User{
		Name:               "alice",
		ProviderIdentifier: sql.NullString{String: "https://idp.example|alice", Valid: true},
	}).Error)
	require.NoError(t, database.Close())

	return dbPath, ids
}

// TestAmbiguousNameBoots pins that a duplicate user in the database does not
// keep the server from starting: the stored policy compiles, the ambiguous
// name grants nothing and the rest of the policy is served.
func TestAmbiguousNameBoots(t *testing.T) {
	dbPath, ids := ambiguousNameSetup(t)

	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err, "a duplicate user must not block boot")
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Snapshot().PolicyErr())

	peers := s.Snapshot().ListPeerIDs(ids["carol"])
	assert.Contains(t, peers, ids["bob"], "an unambiguous name is served")
	assert.NotContains(t, peers, ids["alice"], "an ambiguous name grants nothing")
}

// TestSetPolicyRefusesAmbiguousName pins that a document naming a user several
// users answer to is refused when it is set, as at upstream, while one that
// does not is accepted; the check also holds when the duplicate appears only
// before the last, in-lock attempt.
func TestSetPolicyRefusesAmbiguousName(t *testing.T) {
	const (
		namesAlice = `{"acls":[{"action":"accept","src":["alice@"],"dst":["carol@:*"]}]}`
		namesBob   = `{"acls":[{"action":"accept","src":["bob@"],"dst":["carol@:*"]}]}`
	)

	t.Run("duplicate present", func(t *testing.T) {
		dbPath, _ := ambiguousNameSetup(t)
		s := persistTestReopen(t, dbPath)
		before := s.Snapshot().PolicySource()

		_, err := s.SetPolicy([]byte(namesAlice))
		require.ErrorIs(t, err, policyv2.ErrMultipleUsersFound)
		assert.Equal(t, string(before), string(s.Snapshot().PolicySource()))

		_, err = s.SetPolicy([]byte(namesBob))
		require.NoError(t, err)
	})

	t.Run("duplicate before the last attempt", func(t *testing.T) {
		_, s, nodeID := persistTestSetup(t)
		t.Cleanup(func() { _ = s.Close() })

		_, err := s.CreateUser(types.User{Name: "alice"})
		require.NoError(t, err)

		before := s.Snapshot().PolicySource()
		attempts := 0
		s.world.beforePolicyCommit = func() {
			attempts++
			if attempts == policyAttempts {
				_, err := s.CreateUser(types.User{Name: "alice", ProviderIdentifier: sql.NullString{String: "oidc|alice", Valid: true}})
				require.NoError(t, err)

				return
			}

			// Moved nodes send SetPolicy to its next attempt.
			node, ok := s.GetNodeByID(nodeID)
			require.True(t, ok)

			n := node.AsStruct()
			n.IPv4 = new(netip.MustParseAddr(fmt.Sprintf("100.64.9.%d", attempts)))
			s.PutNodeInStoreForTest(*n)
		}

		_, err = s.SetPolicy([]byte(namesAlice))
		require.ErrorIs(t, err, policyv2.ErrMultipleUsersFound)
		assert.Equal(t, policyAttempts, attempts, "test sanity: the duplicate appeared before the last attempt")
		assert.Equal(t, string(before), string(s.Snapshot().PolicySource()))
	})
}

// TestSetPolicyUnchangedClearsSSHCheckAuth re-applies the live document, as
// a reload or a policy set of the same file does: the check-mode approvals
// an operator expects that to revoke must be gone, as upstream clears them
// after every successful set.
func TestSetPolicyUnchangedClearsSSHCheckAuth(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	doc := []byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)

	_, err := s.SetPolicy(doc)
	require.NoError(t, err)

	s.SetLastSSHAuth(1, 2)

	_, ok := s.GetLastSSHAuth(1, 2)
	require.True(t, ok, "test sanity: the approval is recorded")

	changed, err := s.SetPolicy(doc)
	require.NoError(t, err)
	assert.False(t, changed, "test sanity: the document is unchanged")

	_, ok = s.GetLastSSHAuth(1, 2)
	assert.False(t, ok, "re-applying the policy keeps a check-mode approval")
}

func TestPolicyStorageDeadlineReleasesGraph(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	initial := []byte(`{"grants":[]}`)
	stored, err := s.UpdatePolicy(t.Context(), initial)
	require.NoError(t, err)
	require.NotNil(t, stored)
	s.SetLastSSHAuth(id, 0)
	approved, ok := s.GetLastSSHAuth(id, 0)
	require.True(t, ok)

	before := s.Snapshot()
	sqlDB, err := s.db.DB.DB()
	require.NoError(t, err)
	conn, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)

	closeConn := sync.OnceFunc(func() { require.NoError(t, conn.Close()) })
	defer closeConn()

	waitingBefore := sqlDB.Stats().WaitCount
	done := make(chan error, 1)

	candidate := []byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`)
	go func() { _, err := s.UpdatePolicy(t.Context(), candidate); done <- err }()

	require.Eventually(t, func() bool { return sqlDB.Stats().WaitCount > waitingBefore }, time.Second, time.Millisecond, "policy storage must wait for the held connection")

	writerEntered, writerRelease, writerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})

	releaseWriter := sync.OnceFunc(func() { close(writerRelease) })
	defer releaseWriter()

	go func() {
		s.world.UpdateNode(id, func(n *types.Node) { close(writerEntered); <-writerRelease; n.Hostname = "after-policy-timeout" })
		close(writerDone)
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.NotErrorIs(t, err, ErrInvalidPolicy)
	case <-time.After(policyPersistTimeout + time.Second):
		t.Fatal("policy storage did not honor its deadline")
	}

	select {
	case <-writerEntered:
	case <-time.After(time.Second):
		t.Fatal("queued graph writer did not resume")
	}

	after := s.Snapshot()
	assert.Equal(t, before.Rev(), after.Rev(), "failed storage publishes no revision")
	assert.Equal(t, initial, after.PolicySource())
	assert.Same(t, before.Policy(), after.Policy())
	assert.Equal(t, before.DERPMap(), after.DERPMap())

	stillApproved, ok := s.GetLastSSHAuth(id, 0)
	require.True(t, ok)
	assert.Equal(t, approved, stillApproved)
	releaseWriter()
	<-writerDone
	closeConn()

	row, err := s.GetPolicy()
	require.NoError(t, err)
	assert.Equal(t, string(initial), row.Data)
	_, err = s.UpdatePolicy(t.Context(), candidate)
	require.NoError(t, err)
	assert.Equal(t, candidate, s.Snapshot().PolicySource())
}

func TestUpdatePolicyRequestCancellationKeepsPublishedPolicy(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	initial := []byte(`{"grants":[]}`)
	stored, err := s.UpdatePolicy(t.Context(), initial)
	require.NoError(t, err)
	s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "cancel-policy", RegionName: "Unchanged relay"},
	}})
	s.SetLastSSHAuth(id, 0)
	approval, ok := s.GetLastSSHAuth(id, 0)
	require.True(t, ok)

	before := s.Snapshot()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var reachedStorage, candidateWasPrivate bool

	require.NoError(t, s.db.DB.Callback().Create().Before("gorm:create").Register("cancel_policy_request", func(tx *gorm.DB) {
		if tx.Statement.Table != "policies" || reachedStorage {
			return
		}

		reachedStorage = true
		candidateWasPrivate = bytes.Equal(initial, s.Snapshot().PolicySource())

		cancel()
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Create().Remove("cancel_policy_request") })

	candidate := []byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`)
	_, err = s.UpdatePolicy(ctx, candidate)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrInvalidPolicy)
	require.True(t, reachedStorage, "the request must reach candidate persistence before cancellation")
	assert.True(t, candidateWasPrivate)

	after := s.Snapshot()
	assert.Equal(t, before.Rev(), after.Rev())
	assert.Equal(t, initial, after.PolicySource())
	assert.Same(t, before.Policy(), after.Policy())
	assert.Equal(t, before.DERPMap(), after.DERPMap())

	stillApproved, ok := s.GetLastSSHAuth(id, 0)
	require.True(t, ok)
	assert.Equal(t, approval, stillApproved)

	row, err := s.GetPolicy()
	require.NoError(t, err)
	assert.Equal(t, stored.ID, row.ID)
	assert.Equal(t, string(initial), row.Data)

	var rows int64
	require.NoError(t, s.db.DB.Unscoped().Model(&types.Policy{}).Count(&rows).Error)
	assert.EqualValues(t, 1, rows)
	next, err := s.UpdatePolicy(t.Context(), candidate)
	require.NoError(t, err)
	require.NotNil(t, next)
	assert.Greater(t, next.ID, stored.ID)
	assert.Equal(t, candidate, s.Snapshot().PolicySource())
	row, err = s.GetPolicy()
	require.NoError(t, err)
	assert.Equal(t, next.ID, row.ID)
	assert.Equal(t, string(candidate), row.Data)
}

type afterPolicyCommitPool struct {
	gorm.ConnPool

	after func()
}

func (p *afterPolicyCommitPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	beginner, ok := p.ConnPool.(gorm.TxBeginner)
	if !ok {
		return nil, gorm.ErrInvalidTransaction
	}

	tx, err := beginner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &afterPolicyCommitTx{Tx: tx, after: p.after}, nil
}

type afterPolicyCommitTx struct {
	gorm.Tx

	after func()
}

func (tx *afterPolicyCommitTx) Commit() error {
	err := tx.Tx.Commit()
	if err == nil {
		tx.after()
	}

	return err
}

func TestUpdatePolicyPublishesAfterCommittedRequestCancellation(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	initial := []byte(`{"grants":[]}`)
	first, err := s.UpdatePolicy(t.Context(), initial)
	require.NoError(t, err)
	s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		900: {RegionID: 900, RegionCode: "before-commit", RegionName: "Original relay"},
	}})
	s.SetLastSSHAuth(id, 0)
	_, approved := s.GetLastSSHAuth(id, 0)
	require.True(t, approved)

	before := s.Snapshot()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var (
		committedSnapshot *Snapshot
		approvedAtCommit  bool
	)

	pool := s.db.DB.ConnPool
	wrapped := &afterPolicyCommitPool{ConnPool: pool, after: func() {
		// The real Commit has succeeded, but its nil result has not returned
		// to policy acceptance, so publication must still be the old snapshot.
		committedSnapshot = s.Snapshot()
		_, approvedAtCommit = s.GetLastSSHAuth(id, 0)

		cancel()
	}}
	s.db.DB.ConnPool = wrapped
	s.db.DB.Statement.ConnPool = wrapped

	restorePool := func() {
		s.db.DB.ConnPool = pool
		s.db.DB.Statement.ConnPool = pool
	}
	defer restorePool()

	candidate := []byte(`{
		"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}],
		"derpMap":{"OmitDefaultRegions":true,"Regions":{"901":{
			"RegionID":901,"RegionCode":"after-commit","RegionName":"Committed relay",
			"Nodes":[{"Name":"901a","RegionID":901,"HostName":"127.0.0.1","DERPPort":-1}]
		}}}
	}`)
	stored, err := s.UpdatePolicy(ctx, candidate)

	restorePool()
	require.NoError(t, err, "incoming cancellation cannot veto an already committed policy")
	require.NotNil(t, stored)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.NotNil(t, committedSnapshot, "the real successful Commit must run the cancellation callback")
	assert.Equal(t, before.Rev(), committedSnapshot.Rev())
	assert.Equal(t, initial, committedSnapshot.PolicySource())
	assert.Same(t, before.Policy(), committedSnapshot.Policy())
	assert.Equal(t, before.DERPMap(), committedSnapshot.DERPMap())
	assert.True(t, approvedAtCommit)

	after := s.Snapshot()
	assert.Equal(t, before.Rev()+1, after.Rev())
	assert.Equal(t, candidate, after.PolicySource())
	assert.NotSame(t, before.Policy(), after.Policy())
	require.NoError(t, after.PolicyErr())
	require.NotNil(t, after.DERPMap())
	assert.NotContains(t, after.DERPMap().Regions, tailcfg.DERPRegionID(900))
	require.Contains(t, after.DERPMap().Regions, tailcfg.DERPRegionID(901))
	assert.Equal(t, "Committed relay", after.DERPMap().Regions[901].RegionName)
	assert.Contains(t, before.DERPMap().Regions, tailcfg.DERPRegionID(900))

	_, stillApproved := s.GetLastSSHAuth(id, 0)
	assert.False(t, stillApproved, "a changed committed policy clears the old SSH approval")
	assert.Greater(t, stored.ID, first.ID)

	row, err := s.GetPolicy()
	require.NoError(t, err)
	assert.Equal(t, stored.ID, row.ID)
	assert.Equal(t, string(candidate), row.Data)

	var rows int64
	require.NoError(t, s.db.DB.Unscoped().Model(&types.Policy{}).Count(&rows).Error)
	assert.EqualValues(t, 1, rows)
}

func TestIdenticalPolicyWritePersistsWithoutPublication(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	document := []byte(`{"grants":[]}`)
	first, err := s.UpdatePolicy(t.Context(), document)
	require.NoError(t, err)
	s.SetLastSSHAuth(id, 0)
	approval, ok := s.GetLastSSHAuth(id, 0)
	require.True(t, ok)

	before := s.Snapshot()

	sub := s.Subscribe()
	defer sub.Close()

	second, err := s.UpdatePolicy(t.Context(), document)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Greater(t, second.ID, first.ID)
	assert.Equal(t, before.Rev(), s.Snapshot().Rev())

	select {
	case <-sub.C:
		t.Fatal("identical write woke a subscriber")
	default:
	}

	afterApproval, ok := s.GetLastSSHAuth(id, 0)
	require.True(t, ok)
	assert.Equal(t, approval, afterApproval)
	require.NoError(t, s.db.DB.Callback().Create().Before("gorm:create").Register("fail_identical_policy", func(tx *gorm.DB) {
		if tx.Statement.Table == "policies" {
			_ = tx.AddError(errIdenticalPolicyStore)
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Create().Remove("fail_identical_policy") })
	_, err = s.UpdatePolicy(t.Context(), document)
	require.ErrorIs(t, err, errIdenticalPolicyStore)
	require.NotErrorIs(t, err, ErrInvalidPolicy)
	assert.Equal(t, before.Rev(), s.Snapshot().Rev())
	afterApproval, ok = s.GetLastSSHAuth(id, 0)
	require.True(t, ok)
	assert.Equal(t, approval, afterApproval)

	select {
	case <-sub.C:
		t.Fatal("failed identical write woke a subscriber")
	default:
	}
}

func TestValidatePolicyUsesOneWorldSnapshot(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	ip := node.IPv4().Get().String()
	document := []byte(fmt.Sprintf(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["%s:*"]}],"tests":[{"src":"persist-user@","accept":["%s:22"]}]}`, ip, ip))
	require.NoError(t, s.ValidatePolicy(document))
	// A committed user row is waiting for its graph publication.
	require.NoError(t, s.db.DB.Model(&types.User{}).Where("id = ?", node.User().ID()).Update("name", "database-only-name").Error)
	before := s.Snapshot()
	require.NoError(t, s.ValidatePolicy(document), "validation uses the still-authoritative graph user and node together")
	assert.Equal(t, before.Rev(), s.Snapshot().Rev())
	require.NoError(t, s.refreshUsers())
	require.ErrorIs(t, s.ValidatePolicy(document), ErrInvalidPolicy, "after publication the old user reference is no longer valid")
}

func TestUpdatePolicyDriftRefusalIsInvalidPolicy(t *testing.T) {
	for _, identical := range []bool{false, true} {
		t.Run(fmt.Sprintf("identical=%t", identical), func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)

			ip := node.IPv4().Get().String()
			candidate := []byte(fmt.Sprintf(`{"acls":[{"action":"accept","src":["persist-user@"],"dst":["%s:*"]}],"tests":[{"src":"persist-user@","accept":["%s:22"]}]}`, ip, ip))

			initial := []byte(`{"grants":[]}`)
			if identical {
				initial = candidate
			}

			stored, err := s.UpdatePolicy(t.Context(), initial)
			require.NoError(t, err)

			var afterDrift *Snapshot

			s.world.beforePolicyCommit = sync.OnceFunc(func() {
				users := s.Snapshot().Users()
				duplicate := users[0]
				duplicate.ID += 100
				users = append(slices.Clone(users), duplicate)
				require.NoError(t, s.world.SetUsers(users))
				afterDrift = s.Snapshot()
			})
			_, err = s.UpdatePolicy(t.Context(), candidate)
			require.ErrorIs(t, err, ErrInvalidPolicy)
			require.NotNil(t, afterDrift)
			assert.Equal(t, afterDrift.Rev(), s.Snapshot().Rev(), "refusal creates no extra publication")
			assert.Equal(t, initial, s.Snapshot().PolicySource())
			row, err := s.GetPolicy()
			require.NoError(t, err)
			assert.Equal(t, stored.ID, row.ID, "refused candidate creates no durable policy row")

			var count int64
			require.NoError(t, s.db.DB.Model(&types.Policy{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})
	}
}
