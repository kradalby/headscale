package state

import (
	"errors"
	"maps"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// persistTestSetup pre-creates a sqlite database on disk with a single
// registered node, then constructs a State that loads it. The on-disk
// path is returned so the test can close the State and re-open one
// against the same file to simulate a server restart. The caller owns
// the returned State and must Close it; persistTestReopen handles the
// second State's lifecycle for the restart simulation.
func persistTestSetup(t *testing.T) (string, *State, types.NodeID) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("persist-user")
	node := database.CreateRegisteredNodeForTest(user, "persist-node")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)

	return dbPath, s, node.ID
}

// persistTestReopen constructs a fresh State pointed at the same
// sqlite file and registers a cleanup to close it at the end of the
// test. Use it to simulate a server restart after the first State has
// been explicitly closed by the caller.
func persistTestReopen(t *testing.T, dbPath string) *State {
	t.Helper()

	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	return s
}

func persistTestConfig(dbPath string) *types.Config {
	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	return &types.Config{
		Database: types.DatabaseConfig{
			Type: types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{
				Path: dbPath,
			},
		},
		PrefixV4:     &prefixV4,
		PrefixV6:     &prefixV6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
	}
}

// TestPersistEmptyApprovedRoutes covers the State.SetApprovedRoutes
// path. The gRPC handler builds the slice via append from a nil
// declaration, so when the operator passes `-r ""` the persist layer
// receives a nil []netip.Prefix. GORM's struct Updates skips nil
// slices, so the column would stay populated with the previously
// approved routes and a restart would re-apply them.
func TestPersistEmptyApprovedRoutes(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	route := netip.MustParsePrefix("10.0.0.0/8")

	_, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{route})
	require.NoError(t, err)

	gotAfterApprove, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{route}, gotAfterApprove.ApprovedRoutes.List(),
		"approved_routes should hold the seeded route")

	var noRoutes []netip.Prefix

	_, err = s.SetApprovedRoutes(nodeID, noRoutes)
	require.NoError(t, err)

	gotAfterClear, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, gotAfterClear.ApprovedRoutes,
		"approved_routes should be empty after rejecting all routes, got %v",
		gotAfterClear.ApprovedRoutes)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	nv, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok, "node should be loaded from DB after restart")
	assert.Empty(t, nv.AsStruct().ApprovedRoutes,
		"after restart, memory should reflect the cleared routes")
}

// TestPersistEmptyTags exercises the same persist path for the tags
// column. State.SetNodeTags rejects an empty slice at the API level
// (tags are one-way), so the test drives the bug surface directly via
// world + persistNode, which is the same code path the public
// SetApprovedRoutes call exercises.
func TestPersistEmptyTags(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = []string{"tag:test"}
	})
	require.True(t, ok)

	seeded, ok := s.Snapshot().GetNode(nodeID)
	require.True(t, ok)

	_, err := s.persistNode(seeded)
	require.NoError(t, err)

	gotAfterSeed, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []string{"tag:test"}, gotAfterSeed.Tags.List(),
		"tags should hold the seeded value")

	cleared, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = nil
	})
	require.True(t, ok)

	_, err = s.persistNode(cleared)
	require.NoError(t, err)

	gotAfterClear, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, gotAfterClear.Tags,
		"tags should be empty after clear, got %v", gotAfterClear.Tags)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	nv, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, nv.AsStruct().Tags,
		"after restart, memory should reflect the cleared tags")
}

// TestPersistEmptyEndpoints covers the endpoints column. Endpoints
// arrive via MapRequest in production; the test reaches the persist
// layer directly because the bug is in serialization, not in
// upstream parsing.
func TestPersistEmptyEndpoints(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	endpoint := netip.MustParseAddrPort("198.51.100.1:41641")

	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Endpoints = []netip.AddrPort{endpoint}
	})
	require.True(t, ok)

	seeded, ok := s.Snapshot().GetNode(nodeID)
	require.True(t, ok)

	_, err := s.persistNode(seeded)
	require.NoError(t, err)

	gotAfterSeed, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []netip.AddrPort{endpoint}, gotAfterSeed.Endpoints.List(),
		"endpoints should hold the seeded value")

	cleared, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Endpoints = nil
	})
	require.True(t, ok)

	_, err = s.persistNode(cleared)
	require.NoError(t, err)

	gotAfterClear, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, gotAfterClear.Endpoints,
		"endpoints should be empty after clear, got %v", gotAfterClear.Endpoints)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	nv, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, nv.AsStruct().Endpoints,
		"after restart, memory should reflect the cleared endpoints")
}

// TestRegistrationRejectsNodeKeyClaimedByAnotherMachine proves a new
// registration cannot claim a NodeKey already bound to a different machine.
// NodeKeys are public (peers learn them from the netmap), so without this
// check an authenticated party can register a node carrying a victim's
// NodeKey. That poisons the NodeKey index (a map keyed on NodeKey,
// last writer wins), so the victim's MapRequest resolves to the attacker's
// node and is rejected by getAndValidateNode's MachineKey check (noise.go) —
// a denial of service against the victim. getAndValidateNode already enforces
// a 1:1 NodeKey<->MachineKey binding at poll time; this enforces the same
// invariant at registration time.
func TestRegistrationRejectsNodeKeyClaimedByAnotherMachine(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("nk-user")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	sharedNodeKey := key.NewNode()

	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        sharedNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "victim",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// A different machine tries to register carrying the victim's NodeKey.
	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        sharedNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "attacker",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.Error(t, err,
		"registering a NodeKey already bound to another machine must be rejected")
}

// TestRegistrationKeepsRequestTagsIntact guards the node's reported
// Hostinfo.RequestTags against the in-place sort/compact that derives the
// approved tag set: the two must not share a backing array.
func TestRegistrationKeepsRequestTagsIntact(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("tagger")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{"tagOwners":{"tag:a":["tagger@"],"tag:b":["tagger@"]}}`))
	require.NoError(t, err)

	node, err := s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "node",
		Hostinfo:       &tailcfg.Hostinfo{RequestTags: []string{"tag:b", "tag:a", "tag:a"}},
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"tag:a", "tag:b"}, node.Tags().AsSlice())
	assert.Equal(t, []string{"tag:b", "tag:a", "tag:a"}, node.Hostinfo().RequestTags().AsSlice(),
		"reported RequestTags rewritten by tag approval")
}

// TestReauthRejectsNodeKeyClaimedByAnotherMachine proves the re-auth/update
// path enforces the same 1:1 NodeKey<->MachineKey binding as the create path
// (TestRegistrationRejectsNodeKeyClaimedByAnotherMachine) and the poll path
// (getAndValidateNode). Without it, a node re-authenticating could rotate its
// NodeKey to a victim's, poisoning the NodeKey index so the victim's
// MapRequest resolves to the attacker's node and is rejected — a DoS.
func TestReauthRejectsNodeKeyClaimedByAnotherMachine(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	attacker := database.CreateUserForTest("attacker")
	victim := database.CreateUserForTest("victim")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	victimNodeKey := key.NewNode()
	attackerMachine := key.NewMachine()

	// Victim's node holds victimNodeKey.
	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *victim,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        victimNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "victim",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// Attacker registers its own node.
	attackerNode, err := s.createAndSaveNewNode(newNodeParams{
		User:           *attacker,
		MachineKey:     attackerMachine.Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "attacker",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// Attacker re-authenticates its own node but supplies the victim's NodeKey.
	_, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode: attackerNode,
		RegData: &types.RegistrationData{
			MachineKey: attackerMachine.Public(),
			NodeKey:    victimNodeKey.Public(),
			Hostname:   "attacker",
			Hostinfo:   &tailcfg.Hostinfo{},
		},
		ValidHostinfo:  &tailcfg.Hostinfo{},
		Hostname:       "attacker",
		User:           attacker,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.Error(t, err,
		"re-auth claiming a NodeKey bound to another machine must be rejected")
}

// TestReauthPreservesEndpointsWhenClientOmitsThem proves the re-auth/update
// path keeps a node's live WireGuard endpoints when the originating
// RegisterRequest carried none. Web/OIDC relogins report endpoints via
// MapRequest, not register, so RegData.Endpoints is empty; wiping the stored
// endpoints would advertise the re-keyed node to peers endpoint-less, which
// drives head/unstable tailscale clients into one-way disco-deafness.
func TestReauthPreservesEndpointsWhenClientOmitsThem(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("user")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	machine := key.NewMachine()
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.5:41641"),
		netip.MustParseAddrPort("10.0.0.5:41641"),
	}

	// Node is registered and has reported live endpoints (as after its first
	// MapRequest).
	node, err := s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     machine.Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "node",
		Endpoints:      endpoints,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)
	require.Equal(t, endpoints, node.Endpoints().AsSlice(),
		"precondition: node has live endpoints")

	// Node re-authenticates, rotating its NodeKey. The RegisterRequest carries
	// no endpoints.
	updated, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode: node,
		RegData: &types.RegistrationData{
			MachineKey: machine.Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "node",
			Hostinfo:   &tailcfg.Hostinfo{},
			Endpoints:  nil,
		},
		ValidHostinfo:  &tailcfg.Hostinfo{},
		Hostname:       "node",
		User:           user,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	assert.Equal(t, endpoints, updated.Endpoints().AsSlice(),
		"re-auth without reported endpoints must preserve the node's live endpoints")
}

// TestPreAuthKeyReauthRejectsNodeKeyClaimedByAnotherMachine is the pre-auth-key
// analogue of TestReauthRejectsNodeKeyClaimedByAnotherMachine: re-registering
// via a pre-auth key must enforce the same 1:1 NodeKey<->MachineKey binding the
// auth path and poll-time validation enforce, so a node cannot rotate its key
// to a victim's and poison the NodeKey index.
func TestPreAuthKeyReauthRejectsNodeKeyClaimedByAnotherMachine(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	attacker := s.CreateUserForTest("attacker")
	victim := s.CreateUserForTest("victim")

	victimMachine := key.NewMachine()
	victimNodeKey := key.NewNode()
	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *victim,
		MachineKey:     victimMachine.Public(),
		NodeKey:        victimNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "victim",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// Attacker registers its own node with a reusable pre-auth key.
	pak, err := s.CreatePreAuthKey(attacker.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	attackerMachine := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "attacker"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	_, err = s.HandleNodeFromPreAuthKey(regReq, attackerMachine.Public())
	require.NoError(t, err)

	// Attacker re-registers its own node but supplies the victim's NodeKey.
	attack := regReq
	attack.NodeKey = victimNodeKey.Public()
	_, err = s.HandleNodeFromPreAuthKey(attack, attackerMachine.Public())
	require.ErrorIs(t, err, ErrNodeKeyInUse,
		"pre-auth-key re-registration claiming another machine's NodeKey must be rejected")

	// The victim still owns its NodeKey.
	owner, ok := s.GetNodeByNodeKey(victimNodeKey.Public())
	require.True(t, ok)
	require.Equal(t, victimMachine.Public(), owner.MachineKey(),
		"victim's NodeKey index entry must be untouched")
}

var (
	errInjectedNodeUpdate = errors.New("injected node update failure")
	errInjectedNodeDelete = errors.New("injected node delete failure")
)

func TestDeleteNodeKeepsStoreOnDBFailure(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").
		Register("fail_node_delete", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeDelete)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove("fail_node_delete") })

	err := s.DeleteNode(node)
	require.NoError(t, s.db.DB.Callback().Delete().Remove("fail_node_delete"))
	require.ErrorIs(t, err, errInjectedNodeDelete)

	_, ok = s.GetNodeByID(nodeID)
	assert.True(t, ok, "a database failure must leave the in-memory node available")

	_, err = s.db.GetNodeByID(nodeID)
	assert.NoError(t, err, "a failed deletion must leave the durable node row available")
}

// TestPreAuthKeyReauthRevertsMemoryOnDBFailure ensures a failed database
// write during pre-auth-key re-registration does not leave memory
// holding a node key that was never persisted: a restart would reload the old
// row and the client's current key would no longer resolve, locking it out.
func TestPreAuthKeyReauthRevertsMemoryOnDBFailure(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("reauth-user")

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "reauth-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	node, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	origNodeKey := node.NodeKey()

	// Fail the node row update so the re-registration's database write errors
	// after memory has already been mutated. A session connects during
	// the write; the rollback must not undo it.
	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				s.Connect(node.ID())

				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))

	reReg := regReq
	reReg.NodeKey = key.NewNode().Public() // rotate -> memory mutation, then DB write fails
	_, err = s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))
	require.Error(t, err, "re-registration must fail when the database write fails")

	got, ok := s.GetNodeByID(node.ID())
	require.True(t, ok)
	require.Equal(t, origNodeKey, got.NodeKey(),
		"memory must revert to the persisted node key when the write fails")

	online, known := got.IsOnline().GetOk()
	require.True(t, known)
	require.True(t, online, "rollback dropped the session that connected during the write")
}

// TestConcurrentPreAuthKeyRegistrationSameMachineKey ensures concurrent
// registrations of the same machine key resolve to a single node. Without
// serialising the find-then-create section, each request sees "no existing
// node" and creates its own, leaving duplicate nodes and IP allocations for
// one machine.
func TestConcurrentPreAuthKeyRegistrationSameMachineKey(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("concurrent-user")

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()

	const n = 12

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, n)

	for range n {
		wg.Go(func() {
			regReq := tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "concurrent-node"},
				Expiry:   time.Now().Add(24 * time.Hour),
			}

			<-start

			_, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
			errs <- err
		})
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, 1, s.ListNodes().Len(),
		"concurrent registrations of one machine key must yield a single node")
}

// TestUpdatePolicyManagerUsersUnchangedKeepsSnapshot ensures re-sending the
// same user list commits nothing, so it neither recompiles the policy nor
// wakes a map stream, while a real user change recompiles.
func TestUpdatePolicyManagerUsersUnchangedKeepsSnapshot(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.UpdatePolicyManagerUsersForTest())

	before := s.Snapshot()

	require.NoError(t, s.UpdatePolicyManagerUsersForTest())
	require.Equal(t, before.Rev(), s.Snapshot().Rev(),
		"unchanged users must not publish a snapshot")

	_, err := s.CreateUser(types.User{Name: "second"})
	require.NoError(t, err)
	require.NotEqual(t, before.PolicyRev(), s.Snapshot().PolicyRev(),
		"a user change must recompile the policy")
}

// TestSingleUsePreAuthKeyUsedInMemory asserts that consuming a single-use
// key marks it used in both the database and the node's cached AuthKey, on
// first registration and when re-registering with a fresh single-use key.
func TestSingleUsePreAuthKeyUsedInMemory(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"

	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("single-use")
	machine := key.NewMachine()

	register := func(t *testing.T) types.NodeView {
		t.Helper()

		pak, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
		require.NoError(t, err)

		node, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: "single-use"},
			Expiry:   time.Now().Add(24 * time.Hour),
		}, machine.Public())
		require.NoError(t, err)

		cached, ok := s.GetNodeByID(node.ID())
		require.True(t, ok)
		require.True(t, cached.AuthKey().Valid())
		assert.Equal(t, pak.ID, cached.AuthKey().ID())
		assert.True(t, cached.AuthKey().Used(), "in-memory copy must be marked used")

		stored, err := s.db.GetPreAuthKeyByID(pak.ID)
		require.NoError(t, err)
		assert.True(t, stored.Used, "database row must be marked used")

		return cached
	}

	first := register(t)
	second := register(t)
	assert.Equal(t, first.ID(), second.ID(), "second key re-registers the same node")
}

// TestAdminNodeWritesRecompileOnlyPolicyInputs proves each admin node write
// is one commit, so every map stream re-renders it and the O(n^2) peer build
// runs at most once, and recompiles the policy only when it moved something
// the policy reads.
func TestAdminNodeWritesRecompileOnlyPolicyInputs(t *testing.T) {
	taggingPolicy := `{
		"tagOwners": {"tag:ci": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`

	tests := []struct {
		name        string
		policy      string
		setup       func(t *testing.T, s *State, nodeID types.NodeID)
		run         func(t *testing.T, s *State, nodeID types.NodeID)
		wantCompile bool
	}{
		{
			name: "RenameNode is no policy input",
			run: func(t *testing.T, s *State, nodeID types.NodeID) {
				t.Helper()

				nv, err := s.RenameNode(nodeID, "renamed")
				require.NoError(t, err)
				require.Equal(t, "renamed", nv.GivenName())
			},
		},
		{
			name:   "SetNodeTags with a real tag assignment is a policy input",
			policy: taggingPolicy,
			run: func(t *testing.T, s *State, nodeID types.NodeID) {
				t.Helper()

				nv, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
				require.NoError(t, err)
				require.True(t, nv.IsTagged())
			},
			wantCompile: true,
		},
		{
			name:   "SetNodeTags re-applying identical tags is no policy input",
			policy: taggingPolicy,
			setup: func(t *testing.T, s *State, nodeID types.NodeID) {
				t.Helper()

				_, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
				require.NoError(t, err)
			},
			run: func(t *testing.T, s *State, nodeID types.NodeID) {
				t.Helper()

				_, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
				require.NoError(t, err)
			},
		},
		{
			name: "SetApprovedRoutes of an unannounced route is no policy input",
			run: func(t *testing.T, s *State, nodeID types.NodeID) {
				t.Helper()

				_, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			if tt.policy != "" {
				_, err := s.SetPolicy([]byte(tt.policy))
				require.NoError(t, err)
			}

			if tt.setup != nil {
				tt.setup(t, s, nodeID)
			}

			before := s.Snapshot()

			tt.run(t, s, nodeID)

			after := s.Snapshot()
			assert.Equal(t, before.Rev()+1, after.Rev(), "the write must be one commit")
			assert.Equal(t, tt.wantCompile, after.PolicyRev() != before.PolicyRev(), "policy recompiled")
			checkPeersMatchFullBuild(t, after)
		})
	}
}

// TestConcurrentTagWritesBothReachPolicy runs two SetNodeTags on different
// nodes at once. Each commit compiles against the nodes of its own
// snapshot, so the later one must hold both tags and its peers must match
// a full build.
func TestConcurrentTagWritesBothReachPolicy(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	nodes := database.CreateRegisteredNodesForTest(database.CreateUserForTest("pb-user"), 3, "pb-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{
		"tagOwners": {"tag:a": ["pb-user@"], "tag:b": ["pb-user@"]},
		"acls": [{"action": "accept", "src": ["tag:a"], "dst": ["tag:b:*"]}]
	}`))
	require.NoError(t, err)

	tags := [2]string{"tag:a", "tag:b"}

	for round := range 20 {
		var (
			wg   sync.WaitGroup
			errs [2]error
		)

		for i := range 2 {
			wg.Go(func() {
				_, errs[i] = s.SetNodeTags(nodes[1+i].ID, []string{tags[(i+round)%2]})
			})
		}

		wg.Wait()

		snap := s.Snapshot()

		for i := range 2 {
			require.NoError(t, errs[i])

			nv, ok := snap.GetNode(nodes[1+i].ID)
			require.True(t, ok)
			require.Equal(t, []string{tags[(i+round)%2]}, nv.Tags().AsSlice(), "round %d writer %d", round, i)
		}

		require.Contains(t, snap.ListPeerIDs(nodes[1].ID), nodes[2].ID, "round %d: tag:a reaches tag:b", round)
		checkPeersMatchFullBuild(t, snap)
	}
}

// TestFailedPersistKeepsPolicyMove proves a policy move made by a write whose
// database persist failed still reaches the compiled policy. Memory is
// written first, so clients are served the move; an identical retry then
// only has to persist it.
func TestFailedPersistKeepsPolicyMove(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{
		"tagOwners": {"tag:ci": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]
	}`))
	require.NoError(t, err)

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("fail_node_update") })

	before := s.Snapshot()

	_, err = s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.ErrorIs(t, err, errInjectedNodeUpdate)
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))

	failed := s.Snapshot()
	nv, ok := failed.GetNode(nodeID)
	require.True(t, ok)
	assert.True(t, nv.IsTagged(), "memory keeps the write the database lost")
	assert.NotEqual(t, before.PolicyRev(), failed.PolicyRev(),
		"the policy must be compiled with the write the database lost")

	row, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, row.Tags, "precondition: the database lost the write")

	_, err = s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.NoError(t, err)

	row, err = s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Equal(t, []string{"tag:ci"}, row.Tags.List(), "the retry must persist the write")
}

// TestReloadPolicyKeepsApprovalOnAutoApproveFailure covers a policy reload
// whose route auto-approval fails to persist. Memory is written first, so
// the approval and the policy compiled with it are served despite the
// error.
func TestReloadPolicyKeepsApprovalOnAutoApproveFailure(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.9.0.0/24")
	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	})
	require.True(t, ok)

	_, err := s.db.SetPolicy(`{
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"autoApprovers": {"routes": {"10.9.0.0/24": ["persist-user@"]}}
	}`)
	require.NoError(t, err)

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("fail_node_update") })

	before := s.Snapshot()

	err = s.ReloadPolicy()
	require.ErrorIs(t, err, errInjectedNodeUpdate)

	after := s.Snapshot()
	approved, ok := after.GetNode(nodeID)
	require.True(t, ok)
	require.Contains(t, approved.ApprovedRoutes().AsSlice(), route,
		"memory holds the approval the database write lost")
	assert.Contains(t, approved.SubnetRoutes(), route)
	assert.NotEqual(t, before.PolicyRev(), after.PolicyRev(),
		"the policy must be compiled with the approved route")
}

// TestBackfillNodeIPsRecompilesPolicy pins that assigning a missing address
// recompiles the policy: the address is a policy input, and peers would
// otherwise only learn it from whichever unrelated write next recompiled.
func TestBackfillNodeIPsRecompilesPolicy(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	nodes := database.CreateRegisteredNodesForTest(database.CreateUserForTest("bf-user"), 2, "bf-node")
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", nodes[0].ID).Update("ipv4", nil).Error)
	// Backfill copies the stored Hostinfo, which a registered client always has.
	require.NoError(t, database.DB.Model(&types.Node{}).Where("1 = 1").Update("host_info", "{}").Error)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	before := s.Snapshot()

	backfilled, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, backfilled)

	after := s.Snapshot()
	nv, ok := after.GetNode(nodes[0].ID)
	require.True(t, ok)
	assert.True(t, nv.IPv4().Valid(), "backfill must assign the missing address")
	assert.NotEqual(t, before.PolicyRev(), after.PolicyRev(), "backfill must recompile the policy")
	checkPeersMatchFullBuild(t, after)
}

// TestBackfillNodeIPsSurvivesConcurrentPersist guards the backfill against a
// node persist landing between its database write and the memory reload:
// that persist writes the old addresses back and the backfill is lost.
func TestBackfillNodeIPsSurvivesConcurrentPersist(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	require.NoError(t, s.Close())

	// Dropping the IPv6 prefix gives the backfill work to do.
	cfg := persistTestConfig(dbPath)
	cfg.PrefixV6 = nil

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, nv.IPv6().Valid(), "precondition: node has an IPv6 address")

	// The backfill reads the nodes table twice: inside its write, then to
	// reload memory. Persist the node just before the reload.
	var reads atomic.Int32

	persisted := make(chan struct{})

	require.NoError(t, s.db.DB.Callback().Query().Before("gorm:query").
		Register("persist_before_reload", func(tx *gorm.DB) {
			if tx.Statement.Table != "nodes" || reads.Add(1) != 2 {
				return
			}

			go func() {
				_, _ = s.persistNode(nv)

				close(persisted)
			}()

			// Give an unserialised persist time to land before the reload.
			select {
			case <-persisted:
			case <-time.After(200 * time.Millisecond):
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Query().Remove("persist_before_reload") })

	_, err = s.BackfillNodeIPs()
	require.NoError(t, err)
	<-persisted

	nv, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.False(t, nv.IPv6().Valid(), "memory kept the removed IPv6 address")

	dbNode, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Nil(t, dbNode.IPv6, "database kept the removed IPv6 address")
}

// TestConcurrentDeletesShareACommit deletes two nodes while a commit is in
// flight: both deletions must land in the next commit together. Holding
// persistMu across the world write would serialise them into a commit
// each, so under churn every delete would wait out its own.
func TestConcurrentDeletesShareACommit(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("delete-batch-user")
	nodes := database.CreateNodesForTest(user, 2, "delete-batch-node")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	inCommit, release := make(chan struct{}), make(chan struct{})

	go s.world.update(func(*nodeEdit) {
		close(inCommit)
		<-release
	})

	<-inCommit

	before := s.Snapshot().Rev()

	var wg sync.WaitGroup

	for _, n := range nodes {
		node, ok := s.GetNodeByID(n.ID)
		require.True(t, ok)

		wg.Go(func() { assert.NoError(t, s.DeleteNode(node)) })
	}

	// Both deletions wait behind the commit in flight.
	require.Eventually(t, func() bool {
		s.world.writeMu.Lock()
		defer s.world.writeMu.Unlock()

		return len(s.world.writes) == 2
	}, 5*time.Second, time.Millisecond, "both deletions must queue for the next commit")

	close(release)
	wg.Wait()

	// The held commit changed nothing, so it published no revision.
	assert.Equal(t, before+1, s.Snapshot().Rev(), "both deletions commit together")
}

// TestAuthReauthRevertsMemoryOnDBFailure fails the database write of an
// interactive re-auth: memory must keep the persisted node key and owner,
// as the pre-auth-key path does, so a restart does not change what clients
// already saw.
func TestAuthReauthRevertsMemoryOnDBFailure(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("auth-reauth-user")
	machine := key.NewMachine()

	node, err := s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     machine.Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "auth-reauth-node",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))

	_, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode: node,
		RegData: &types.RegistrationData{
			MachineKey: machine.Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "renamed",
			Hostinfo:   &tailcfg.Hostinfo{},
		},
		ValidHostinfo:  &tailcfg.Hostinfo{Hostname: "renamed"},
		Hostname:       "renamed",
		User:           user,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))
	require.Error(t, err, "re-auth must fail when the database write fails")

	got, ok := s.GetNodeByID(node.ID())
	require.True(t, ok)
	assert.Equal(t, node.NodeKey(), got.NodeKey(), "memory must keep the persisted node key")
	assert.Equal(t, node.Hostname(), got.Hostname(), "and the persisted hostname")
}

// reauthEntryPoints prepares a re-authentication of node, with a fresh
// node key, through each way a node re-authenticates: interactively and by
// pre-auth key. The returned func runs it, touching the database only
// after its memory write.
var reauthEntryPoints = map[string]func(t *testing.T, s *State, node types.NodeView) func() error{
	"interactive": func(_ *testing.T, s *State, node types.NodeView) func() error {
		return func() error {
			_, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
				ExistingNode: node,
				RegData: &types.RegistrationData{
					MachineKey: node.MachineKey(),
					NodeKey:    key.NewNode().Public(),
					Hostname:   "reauth",
					Expiry:     new(time.Now().Add(time.Hour)),
				},
				ValidHostinfo: &tailcfg.Hostinfo{Hostname: "reauth"},
				Hostname:      "reauth",
				User:          node.User().AsStruct(),
			})

			return err
		}
	},
	"pre-auth key": func(t *testing.T, s *State, node types.NodeView) func() error {
		t.Helper()

		uid := types.UserID(node.User().ID())
		created, err := s.CreatePreAuthKey(&uid, true, false, nil, nil)
		require.NoError(t, err)

		pak, err := s.GetPreAuthKey(created.Key)
		require.NoError(t, err)

		return func() error {
			hi := &tailcfg.Hostinfo{Hostname: "reauth"}
			_, err := s.reregisterNodeWithPAK(node, pak, tailcfg.RegisterRequest{
				NodeKey:  key.NewNode().Public(),
				Expiry:   time.Now().Add(time.Hour),
				Hostinfo: hi,
			}, node.MachineKey(), "reauth", hi)

			return err
		}
	},
}

// expiryWaits reports whether a SetNodeExpiry is blocked on persistMu or,
// past its memory write, on the database connection.
func expiryWaits() bool {
	buf := make([]byte, 1<<20)

	n := runtime.Stack(buf, true)
	for n == len(buf) {
		buf = make([]byte, 2*len(buf))
		n = runtime.Stack(buf, true)
	}

	for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
		if !strings.Contains(g, ".SetNodeExpiry(") {
			continue
		}

		onLock := strings.Contains(g, "[sync.Mutex.Lock") && !strings.Contains(g, "(*world).update(")
		if onLock || strings.Contains(g, "database/sql.(*DB).conn(") {
			return true
		}
	}

	return false
}

// TestAdminExpiryDuringReauthReachesTheRow expires a node while a
// re-authentication that succeeds sits between its memory write and its
// row write, the single database connection held so the admin's write
// could slip in first: the row must end as memory does, or a restart
// brings the revoked node back unexpired. Who gets the connection first is
// random, so each entry point runs several times.
func TestAdminExpiryDuringReauthReachesTheRow(t *testing.T) {
	for name, reauthWith := range reauthEntryPoints {
		t.Run(name, func(t *testing.T) {
			for range 10 {
				_, s, id := persistTestSetup(t)

				node, ok := s.GetNodeByID(id)
				require.True(t, ok)

				run := reauthWith(t, s, node)

				sqlDB, err := s.db.DB.DB()
				require.NoError(t, err)

				held, err := sqlDB.Conn(t.Context())
				require.NoError(t, err)

				reauth := make(chan error, 1)

				go func() { reauth <- run() }()

				require.Eventually(t, func() bool {
					n, _ := s.GetNodeByID(id)

					return n.NodeKey() != node.NodeKey()
				}, 5*time.Second, time.Millisecond, "test sanity: the re-auth wrote memory")

				admin := make(chan error, 1)

				go func() {
					_, err := s.SetNodeExpiry(id, new(time.Now().Add(-time.Hour)))
					admin <- err
				}()

				// Serialised, the expiry waits for persistMu; unserialised,
				// it lands in memory and queues for the connection.
				require.Eventually(t, expiryWaits, 5*time.Second, time.Millisecond)
				require.NoError(t, held.Close())
				require.NoError(t, <-reauth)
				require.NoError(t, <-admin)

				got, ok := s.GetNodeByID(id)
				require.True(t, ok)
				require.True(t, got.IsExpired(), "the later expiry stands")

				durable, err := s.DB().GetNodeByID(id)
				require.NoError(t, err)
				require.Equal(t, got.IsExpired(), durable.IsExpired(), "the row a restart loads matches memory")

				require.NoError(t, s.Close())
			}
		})
	}
}

// TestAuthReauthRollbackKeepsLaterAdminWrites fails a re-auth's database
// write, interactive or by pre-auth key, while an admin expires or retags
// the node in between: the rollback must keep the admin's value, which it
// persisted itself, and restore only what the failed write set. An expiry
// waits for the re-auth instead; it must still stand afterwards.
func TestAuthReauthRollbackKeepsLaterAdminWrites(t *testing.T) {
	admins := map[string]struct {
		write func(t *testing.T, s *State, id types.NodeID)
		// waits is set for a write that serialises with the re-auth.
		waits bool
	}{
		"expiry": {waits: true, write: func(t *testing.T, s *State, id types.NodeID) {
			t.Helper()

			_, err := s.SetNodeExpiry(id, new(time.Now().Add(-time.Hour)))
			assert.NoError(t, err)
		}},
		"retag": {waits: true, write: func(t *testing.T, s *State, id types.NodeID) {
			t.Helper()

			_, err := s.SetNodeTags(id, []string{"tag:admin"})
			assert.NoError(t, err)
		}},
	}

	for reauthName, reauthWith := range reauthEntryPoints {
		for adminName, admin := range admins {
			t.Run(reauthName+"/"+adminName, func(t *testing.T) {
				testReauthRollbackKeepsAdminWrite(t, reauthWith, admin.write, admin.waits)
			})
		}
	}
}

func testReauthRollbackKeepsAdminWrite(
	t *testing.T,
	reauthWith func(t *testing.T, s *State, node types.NodeView) func() error,
	admin func(t *testing.T, s *State, id types.NodeID),
	waits bool,
) {
	t.Helper()

	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:admin":["persist-user@"]},
		"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	// The re-auth's update waits, then fails; the admin's passes.
	entered, release := make(chan struct{}), make(chan struct{})

	var paused atomic.Bool

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("pause_reauth", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" && paused.CompareAndSwap(false, true) {
			close(entered)
			<-release

			_ = tx.AddError(errInjectedNodeUpdate)
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("pause_reauth") })

	reauth := make(chan error, 1)

	run := reauthWith(t, s, node)

	go func() { reauth <- run() }()

	<-entered

	adminDone := make(chan struct{})

	go func() {
		defer close(adminDone)

		admin(t, s, id)
	}()

	// A retag is live at once, its database write waiting for the
	// re-auth's transaction; an expiry waits for the whole re-auth.
	landed := func() bool {
		n, _ := s.GetNodeByID(id)

		return n.IsExpired() || n.IsTagged()
	}

	var want types.NodeView

	if waits {
		assert.Never(t, landed, 100*time.Millisecond, time.Millisecond, "the admin write waits for the re-auth")
	} else {
		require.Eventually(t, landed, 5*time.Second, time.Millisecond, "test sanity: the admin write is live")

		want, _ = s.GetNodeByID(id)
	}

	close(release)
	require.ErrorIs(t, <-reauth, errInjectedNodeUpdate)
	<-adminDone

	if waits {
		require.True(t, landed(), "the admin's write lands after the re-auth")

		want, _ = s.GetNodeByID(id)
	}

	got, ok := s.GetNodeByID(id)
	require.True(t, ok)
	assert.Equal(t, node.NodeKey(), got.NodeKey(), "the failed write's node key is undone")
	assert.Equal(t, want.IsExpired(), got.IsExpired(), "the admin's expiry stands")
	assert.Equal(t, want.Tags().AsSlice(), got.Tags().AsSlice(), "the admin's tags stand")

	durable, err := s.DB().GetNodeByID(id)
	require.NoError(t, err)
	assert.Equal(t, durable.IsExpired(), got.IsExpired(), "memory matches the row a restart loads")
	assert.Equal(t, []string(durable.Tags), got.Tags().AsSlice())
	assert.Equal(t, durable.NodeKey, got.NodeKey())
}

// TestReauthRollbackKeepsSameBatchWrite batches a write with a re-auth into
// one commit and fails the re-auth's database write. Its rollback compares
// against the node as the re-auth left it, so the batched write, published
// in the same snapshot, keeps its value; an admin retag cannot join the
// batch at all, as it waits for the re-auth.
func TestReauthRollbackKeepsSameBatchWrite(t *testing.T) {
	for name, reauthWith := range reauthEntryPoints {
		for kind, batched := range map[string]func(s *State, id types.NodeID) error{
			"hostinfo": func(s *State, id types.NodeID) error {
				s.world.UpdateNode(id, func(n *types.Node) {
					n.Hostinfo = &tailcfg.Hostinfo{Hostname: n.Hostname, OS: "batched"}
				})

				return nil
			},
			"retag": func(s *State, id types.NodeID) error {
				_, err := s.SetNodeTags(id, []string{"tag:admin"})

				return err
			},
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				_, s, id := persistTestSetup(t)
				t.Cleanup(func() { _ = s.Close() })

				_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:admin":["persist-user@"]},
					"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
				require.NoError(t, err)

				node, ok := s.GetNodeByID(id)
				require.True(t, ok)

				run := reauthWith(t, s, node)

				var failed atomic.Bool

				require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("fail_reauth_once", func(tx *gorm.DB) {
					if tx.Statement.Table == "nodes" && failed.CompareAndSwap(false, true) {
						_ = tx.AddError(errInjectedNodeUpdate)
					}
				}))
				t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("fail_reauth_once") })

				// Hold a commit so the re-auth and the batched write queue
				// behind it and commit together.
				entered, release, held := make(chan struct{}), make(chan struct{}), make(chan struct{})

				go func() {
					defer close(held)

					s.world.update(func(*nodeEdit) { close(entered); <-release })
				}()

				<-entered

				var releaseOnce sync.Once

				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); <-held })

				queued := func() int {
					s.world.writeMu.Lock()
					defer s.world.writeMu.Unlock()

					return len(s.world.writes)
				}

				reauth := make(chan error, 1)

				go func() { reauth <- run() }()

				require.Eventually(t, func() bool { return queued() == 1 }, 5*time.Second, time.Millisecond)

				other := make(chan error, 1)

				go func() { other <- batched(s, id) }()

				if kind == "retag" {
					assert.Never(t, func() bool { return queued() == 2 }, 100*time.Millisecond, time.Millisecond,
						"a retag waits for the re-auth instead of joining its batch")
				} else {
					require.Eventually(t, func() bool { return queued() == 2 }, 5*time.Second, time.Millisecond)
				}

				releaseOnce.Do(func() { close(release) })
				require.ErrorIs(t, <-reauth, errInjectedNodeUpdate)
				require.NoError(t, <-other)

				live, ok := s.GetNodeByID(id)
				require.True(t, ok)
				assert.Equal(t, node.NodeKey(), live.NodeKey(), "the failed re-auth's key is rolled back")

				durable, err := s.DB().GetNodeByID(id)
				require.NoError(t, err)

				if kind == "retag" {
					assert.Equal(t, []string{"tag:admin"}, live.Tags().AsSlice(), "the admin's retag stands")
					assert.Equal(t, []string{"tag:admin"}, []string(durable.Tags), "and reaches the row")
				} else {
					require.True(t, live.Hostinfo().Valid(), "the batched write keeps its value")
					assert.Equal(t, "batched", live.Hostinfo().OS(), "the batched write keeps its value")
				}
			})
		}
	}
}

// TestReauthRollbackKeepsAConcurrentUserRename renames the node's owner
// while a re-auth waits on its database write, which then fails: the
// rollback must keep the renamed user, as nothing refreshes a node's user
// again once the user list is current. Retagged covers a re-auth that took
// the node from its owner, whose rollback hands it back.
func TestReauthRollbackKeepsAConcurrentUserRename(t *testing.T) {
	retagged := func(_ *testing.T, s *State, node types.NodeView) func() error {
		return func() error {
			_, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
				ExistingNode: node,
				RegData: &types.RegistrationData{
					MachineKey: node.MachineKey(),
					NodeKey:    key.NewNode().Public(),
					Hostname:   "reauth",
					Hostinfo:   &tailcfg.Hostinfo{RequestTags: []string{"tag:admin"}},
				},
				ValidHostinfo: &tailcfg.Hostinfo{Hostname: "reauth"},
				Hostname:      "reauth",
				User:          node.User().AsStruct(),
			})

			return err
		}
	}

	entries := maps.Clone(reauthEntryPoints)
	entries["retagged"] = retagged

	for name, reauthWith := range entries {
		t.Run(name, func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:admin":["persist-user@"]},
				"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
			require.NoError(t, err)

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)

			run := reauthWith(t, s, node)

			// The rename pauses after listing the users, the re-auth inside
			// its row write.
			listed, letRefresh := make(chan struct{}), make(chan struct{})
			inWrite, letFail := make(chan struct{}), make(chan struct{})

			var (
				listedOnce, wroteOnce atomic.Bool
				refreshOnce, failOnce sync.Once
			)

			t.Cleanup(func() {
				refreshOnce.Do(func() { close(letRefresh) })
				failOnce.Do(func() { close(letFail) })
			})

			require.NoError(t, s.db.DB.Callback().Query().After("gorm:query").Register("pause_user_list", func(tx *gorm.DB) {
				_, isList := tx.Statement.Dest.(*[]types.User)
				if tx.Statement.Table == "users" && isList && listedOnce.CompareAndSwap(false, true) {
					close(listed)
					<-letRefresh
				}
			}))
			require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("fail_reauth_write", func(tx *gorm.DB) {
				if tx.Statement.Table == "nodes" && wroteOnce.CompareAndSwap(false, true) {
					close(inWrite)
					<-letFail

					_ = tx.AddError(errInjectedNodeUpdate)
				}
			}))
			t.Cleanup(func() {
				_ = s.db.DB.Callback().Query().Remove("pause_user_list")
				_ = s.db.DB.Callback().Update().Remove("fail_reauth_write")
			})

			renamed := make(chan error, 1)

			go func() {
				_, err := s.RenameUser(types.UserID(node.User().ID()), "renamed-user")
				renamed <- err
			}()

			<-listed

			reauth := make(chan error, 1)

			go func() { reauth <- run() }()

			<-inWrite
			refreshOnce.Do(func() { close(letRefresh) })
			require.NoError(t, <-renamed)

			failOnce.Do(func() { close(letFail) })
			require.ErrorIs(t, <-reauth, errInjectedNodeUpdate)

			live, ok := s.GetNodeByID(id)
			require.True(t, ok)
			require.True(t, live.User().Valid(), "the node is the user's again")
			assert.Equal(t, "renamed-user", live.User().Name(), "the rollback keeps the rename")

			require.NoError(t, s.refreshUsers())

			again, _ := s.GetNodeByID(id)
			assert.Equal(t, "renamed-user", again.User().Name(), "and nothing refreshes a stale one later")
		})
	}
}
