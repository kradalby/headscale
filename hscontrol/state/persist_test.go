package state

import (
	"errors"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

	// Fail the node row update. A session connects during the transaction;
	// refusing the registration must not undo it.
	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				s.Connect(node.ID())

				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))

	reReg := regReq
	reReg.NodeKey = key.NewNode().Public() // The failed transaction must not publish this rotation.
	_, err = s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))
	require.Error(t, err, "re-registration must fail when the database write fails")

	got, ok := s.GetNodeByID(node.ID())
	require.True(t, ok)
	require.Equal(t, origNodeKey, got.NodeKey(),
		"memory must keep the persisted node key when the write fails")

	online, known := got.IsOnline().GetOk()
	require.True(t, known)
	require.True(t, online, "failed auth must keep the session that connected during the write")
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
// pre-auth key. The returned func runs the staged transaction and publication.
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

func TestReauthPublishesOnlyAfterCommit(t *testing.T) {
	for _, path := range []string{"interactive", "pre-auth key"} {
		for _, succeeds := range []bool{false, true} {
			name := "failure"
			if succeeds {
				name = "success"
			}

			t.Run(path+"/"+name, func(t *testing.T) {
				_, s, id := persistTestSetup(t)
				t.Cleanup(func() { _ = s.Close() })

				_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:auth":["persist-user@"]}}`))
				require.NoError(t, err)
				_, err = s.SetNodeExpiry(id, new(time.Now().Add(-time.Hour)))
				require.NoError(t, err)
				s.Connect(id)
				node, ok := s.GetNodeByID(id)
				require.True(t, ok)

				created, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:auth"})
				require.NoError(t, err)
				pak, err := s.GetPreAuthKey(created.Key)
				require.NoError(t, err)

				if path == "pre-auth key" && !succeeds {
					// Lose the credential CAS after the auth lookup read an unused key.
					require.NoError(t, s.db.Write(func(tx *gorm.DB) error {
						return db.UsePreAuthKey(tx, &types.PreAuthKey{ID: pak.ID})
					}))
				}

				sub := s.Subscribe()
				defer sub.Close()

				before := s.Snapshot().Rev()
				keyAfter := key.NewNode().Public()
				checked := 0

				require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("observe_auth", func(tx *gorm.DB) {
					if tx.Statement.Table != "nodes" && tx.Statement.Table != "credentials" {
						return
					}

					checked++
					live, found := s.GetNodeByID(id)
					assert.True(t, found)
					assert.Equal(t, pakFieldsOf(node.AsStruct()), pakFieldsOf(live.AsStruct()), "uncommitted identity must stay private")
					assert.Equal(t, before, s.Snapshot().Rev(), "staging must not publish a graph revision")
					_, found = s.GetNodeByNodeKey(keyAfter)
					assert.False(t, found, "uncommitted node key must not authenticate")

					select {
					case <-sub.C:
						t.Error("staging woke graph subscribers")
					default:
					}

					if path == "interactive" && !succeeds {
						_ = tx.AddError(errInjectedNodeUpdate)
					}
				}))
				t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("observe_auth") })

				hi := &tailcfg.Hostinfo{Hostname: "reauth", RequestTags: []string{"tag:auth"}}
				if path == "interactive" {
					_, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
						ExistingNode: node,
						RegData: &types.RegistrationData{
							MachineKey: node.MachineKey(), NodeKey: keyAfter, Hostinfo: hi,
						},
						ValidHostinfo: hi, Hostname: hi.Hostname, User: node.User().AsStruct(),
					})
				} else {
					_, err = s.reregisterNodeWithPAK(node, pak, tailcfg.RegisterRequest{
						NodeKey: keyAfter, Hostinfo: hi,
					}, node.MachineKey(), hi.Hostname, hi)
				}

				require.Positive(t, checked, "the test must reach the transaction")

				live, ok := s.GetNodeByID(id)
				require.True(t, ok)

				if succeeds {
					require.NoError(t, err)
					assert.Equal(t, keyAfter, live.NodeKey())
					assert.Equal(t, []string{"tag:auth"}, live.Tags().AsSlice())
					assert.False(t, live.UserID().Valid())
					assert.False(t, live.Expiry().Valid())
					assert.True(t, live.IsOnline().Get(), "committed reauth revives a connected expired node")
					assert.Equal(t, before+1, s.Snapshot().Rev(), "publish the committed identity once")
				} else {
					if path == "interactive" {
						require.ErrorIs(t, err, errInjectedNodeUpdate)
					} else {
						require.ErrorIs(t, err, types.PAKError("authkey already used"))
					}

					assert.Equal(t, pakFieldsOf(node.AsStruct()), pakFieldsOf(live.AsStruct()))
					assert.Equal(t, before, s.Snapshot().Rev(), "failed auth needs no rollback publication")
					assert.False(t, live.IsOnline().Get(), "failed auth leaves the connected node expired")
				}

				durable, err := s.db.GetNodeByID(id)
				require.NoError(t, err)
				assert.Equal(t, pakFieldsOf(durable), pakFieldsOf(live.AsStruct()))
			})
		}
	}
}

func TestReauthPublicationKeepsConcurrentMapUpdate(t *testing.T) {
	for name, reauthWith := range reauthEntryPoints {
		for _, keepHostname := range []bool{false, true} {
			caseName := "changed hostname"
			if keepHostname {
				caseName = "unchanged hostname"
			}

			t.Run(name+"/"+caseName, func(t *testing.T) {
				dbPath, s, id := persistTestSetup(t)
				t.Cleanup(func() { _ = s.Close() })

				node, ok := s.GetNodeByID(id)
				require.True(t, ok)
				run := reauthWith(t, s, node)

				req := tailcfg.MapRequest{
					NodeKey: node.NodeKey(), DiscoKey: key.NewDisco().Public(),
					Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:4242")},
					Hostinfo:  &tailcfg.Hostinfo{Hostname: "concurrent", OS: "linux", NetInfo: &tailcfg.NetInfo{PreferredDERP: 7}},
				}
				if keepHostname {
					req.Hostinfo.Hostname = node.Hostname()
				}

				updated := make(chan error, 1)

				var (
					concurrent types.NodeView
					once       sync.Once
				)

				require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("map_during_auth", func(tx *gorm.DB) {
					if tx.Statement.Table != "nodes" {
						return
					}

					once.Do(func() {
						s.Connect(id)
						go func() { updated <- s.UpdateNodeFromMapRequest(id, req) }()

						require.Eventually(t, func() bool {
							concurrent, _ = s.GetNodeByID(id)
							return concurrent.Hostinfo().Valid() && concurrent.Hostinfo().OS() == "linux"
						}, 5*time.Second, time.Millisecond, "map updates must progress during the auth transaction")
					})
				}))
				t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("map_during_auth") })

				require.NoError(t, run())
				require.NoError(t, <-updated)

				live, ok := s.GetNodeByID(id)
				require.True(t, ok)
				assert.Equal(t, req.DiscoKey, live.DiscoKey())
				assert.NotEqual(t, node.NodeKey(), live.NodeKey(), "the old stream must not undo committed reauth")
				assert.Equal(t, req.Endpoints, live.Endpoints().AsSlice())
				assert.Equal(t, req.Hostinfo, live.Hostinfo().AsStruct())
				assert.Equal(t, req.Hostinfo.Hostname, live.Hostname())
				assert.Equal(t, concurrent.LastSeen(), live.LastSeen())
				assert.Equal(t, concurrent.ActiveSessions(), live.ActiveSessions())
				assert.True(t, live.IsOnline().Get())

				durable, err := s.db.GetNodeByID(id)
				require.NoError(t, err)
				assert.Equal(t, live.NodeKey(), durable.NodeKey)
				assert.Equal(t, req.Endpoints, []netip.AddrPort(durable.Endpoints))
				assert.Equal(t, req.Hostinfo, durable.Hostinfo)
				assert.Equal(t, req.Hostinfo.Hostname, durable.Hostname)

				req.NodeKey = live.NodeKey()
				require.NoError(t, s.UpdateNodeFromMapRequest(id, req))
				require.NoError(t, s.Close())
				reopened := persistTestReopen(t, dbPath)
				reloaded, ok := reopened.GetNodeByID(id)
				require.True(t, ok)
				assert.Equal(t, req.Hostinfo.Hostname, reloaded.Hostname())
				assert.Equal(t, req.Hostinfo, reloaded.Hostinfo().AsStruct())
			})
		}
	}
}

func TestConcurrentReauthCannotClaimSameNodeKey(t *testing.T) {
	for _, path := range []string{"interactive", "pre-auth key"} {
		t.Run(path, func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			first, ok := s.GetNodeByID(id)
			require.True(t, ok)

			second, err := s.createAndSaveNewNode(newNodeParams{
				User: *first.User().AsStruct(), MachineKey: key.NewMachine().Public(),
				NodeKey: key.NewNode().Public(), Hostname: "second",
			})
			require.NoError(t, err)

			uid := types.UserID(first.User().ID())
			created, err := s.CreatePreAuthKey(&uid, true, false, nil, nil)
			require.NoError(t, err)
			pak, err := s.GetPreAuthKey(created.Key)
			require.NoError(t, err)

			claimed := key.NewNode().Public()
			done := make(chan error, 2)

			s.persistMu.Lock()

			unlock := sync.OnceFunc(s.persistMu.Unlock)
			defer unlock()

			for _, node := range []types.NodeView{first, second} {
				go func() {
					hi := &tailcfg.Hostinfo{Hostname: node.Hostname()}

					var err error
					if path == "interactive" {
						_, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
							ExistingNode:  node,
							RegData:       &types.RegistrationData{MachineKey: node.MachineKey(), NodeKey: claimed},
							ValidHostinfo: hi, Hostname: hi.Hostname, User: node.User().AsStruct(),
						})
					} else {
						_, err = s.reregisterNodeWithPAK(node, pak, tailcfg.RegisterRequest{NodeKey: claimed},
							node.MachineKey(), hi.Hostname, hi)
					}

					done <- err
				}()
			}
			// Both requests must have reached persistence before either proceeds.
			require.Eventually(t, func() bool {
				// The dump grows until it fits: a cut dump can miss a
				// parked registration and under-count the waiters.
				buf := make([]byte, 64<<10)

				n := runtime.Stack(buf, true)
				for n == len(buf) {
					buf = make([]byte, 2*len(buf))
					n = runtime.Stack(buf, true)
				}

				waiting := 0

				for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
					if strings.Contains(g, "[sync.Mutex.Lock") &&
						(strings.Contains(g, ".applyAuthNodeUpdate(") || strings.Contains(g, ".reregisterNodeWithPAK(")) {
						waiting++
					}
				}

				return waiting == 2
			}, 5*time.Second, time.Millisecond)
			unlock()

			a, b := <-done, <-done
			if a == nil {
				require.ErrorIs(t, b, ErrNodeKeyInUse)
			} else {
				require.ErrorIs(t, a, ErrNodeKeyInUse)
				require.NoError(t, b)
			}
		})
	}
}

// TestConcurrentFreshJoinsCommitTogether pins that a fresh join does not
// serialise the whole tailnet behind persistMu: distinct machines joining
// concurrently must all queue their PutNode into one held batch, as any other
// burst of world writes does. A global persistMu held across each join's
// INSERT and publish would leave the burst stuck behind the first join's
// commit and defeat the group-commit batching the world documents.
func TestConcurrentFreshJoinsCommitTogether(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	user := node.User().AsStruct()

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })

	var wg sync.WaitGroup

	t.Cleanup(func() { unblock(); wg.Wait() })

	wg.Go(func() {
		s.world.update(func(*nodeEdit) { close(entered); <-release })
	})
	<-entered

	const joins = 8

	done := make(chan error, joins)
	for range joins {
		go func() {
			_, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "batched-join"},
			}, key.NewMachine().Public())
			done <- err
		}()
	}

	// Every join must reach the held batch while the leader is parked:
	// the burst costs one commit, not one per join.
	require.Eventually(t, func() bool {
		s.world.writeMu.Lock()
		defer s.world.writeMu.Unlock()

		return len(s.world.writes) == joins
	}, 5*time.Second, time.Millisecond, "fresh joins must batch, not serialise behind the first join")

	unblock()
	wg.Wait()

	for range joins {
		require.NoError(t, <-done)
	}

	assert.Zero(t, s.claimLocks.Size(), "claim locks must not outlive their registrations")
}

func TestFreshRegistrationCannotRaceNodeKeyClaim(t *testing.T) {
	for _, firstPath := range []string{"fresh", "interactive", "pre-auth key"} {
		t.Run(firstPath, func(t *testing.T) {
			dbPath, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)

			user := node.User().AsStruct()
			uid := types.UserID(user.ID)
			created, err := s.CreatePreAuthKey(&uid, true, false, nil, nil)
			require.NoError(t, err)
			pak, err := s.GetPreAuthKey(created.Key)
			require.NoError(t, err)

			claimed := key.NewNode().Public()
			fresh := func() error {
				_, err := s.createAndSaveNewNode(newNodeParams{
					User: *user, MachineKey: key.NewMachine().Public(), NodeKey: claimed,
					Hostname: "fresh", Hostinfo: &tailcfg.Hostinfo{Hostname: "fresh"},
				})

				return err
			}

			sqlDB, err := s.db.DB.DB()
			require.NoError(t, err)
			held, err := sqlDB.Conn(t.Context())
			require.NoError(t, err)

			release := sync.OnceFunc(func() { assert.NoError(t, held.Close()) })
			defer release()

			waits := sqlDB.Stats().WaitCount
			done := make(chan error, 2)

			go func() {
				hi := &tailcfg.Hostinfo{Hostname: node.Hostname()}

				var err error

				switch firstPath {
				case "fresh":
					err = fresh()
				case "interactive":
					_, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
						ExistingNode: node, RegData: &types.RegistrationData{MachineKey: node.MachineKey(), NodeKey: claimed},
						ValidHostinfo: hi, Hostname: hi.Hostname, User: user,
					})
				case "pre-auth key":
					_, err = s.reregisterNodeWithPAK(node, pak, tailcfg.RegisterRequest{NodeKey: claimed}, node.MachineKey(), hi.Hostname, hi)
				}

				done <- err
			}()

			require.Eventually(t, func() bool { return sqlDB.Stats().WaitCount > waits }, 5*time.Second, time.Millisecond)

			go func() { done <- fresh() }()

			require.Eventually(t, func() bool {
				if sqlDB.Stats().WaitCount > waits+1 {
					return true
				}

				// The dump grows until it fits: a cut dump can miss the
				// parked claim and lose the race it is probing.
				buf := make([]byte, 64<<10)

				n := runtime.Stack(buf, true)
				for n == len(buf) {
					buf = make([]byte, 2*len(buf))
					n = runtime.Stack(buf, true)
				}

				for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
					if strings.Contains(g, "[sync.Mutex.Lock") && strings.Contains(g, ".createAndSaveNewNode(") {
						return true
					}
				}

				return false
			}, 5*time.Second, time.Millisecond, "both claims must reach their persistence wait")
			release()

			a, b := <-done, <-done
			if a == nil {
				require.ErrorIs(t, b, ErrNodeKeyInUse)
			} else {
				require.ErrorIs(t, a, ErrNodeKeyInUse)
				require.NoError(t, b)
			}

			rows, err := s.db.ListNodes()
			require.NoError(t, err)

			var holders []types.NodeID

			for _, row := range rows {
				if row.NodeKey == claimed {
					holders = append(holders, row.ID)
				}
			}

			require.Len(t, holders, 1, "only one durable claim may survive")

			winner, ok := s.GetNodeByNodeKey(claimed)
			require.True(t, ok)
			assert.Equal(t, holders[0], winner.ID())
			require.NoError(t, s.Close())
			reopened := persistTestReopen(t, dbPath)
			reloaded, ok := reopened.GetNodeByNodeKey(claimed)
			require.True(t, ok)
			assert.Equal(t, winner.MachineKey(), reloaded.MachineKey())
		})
	}
}

func TestReauthRejectsDeletedRowBeforePublication(t *testing.T) {
	for name, reauthWith := range reauthEntryPoints {
		t.Run(name, func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)
			run := reauthWith(t, s, node)
			// DeleteNode releases persistMu before removing the graph node.
			require.NoError(t, s.db.DeleteNode(node.AsStruct()))
			before := s.Snapshot().Rev()

			require.ErrorIs(t, run(), ErrNodeNotInNodeStore)
			assert.Equal(t, before, s.Snapshot().Rev())
			_, err := s.db.GetNodeByID(id)
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		})
	}
}

func TestReauthPublicationExpiresPastSweepWatermark(t *testing.T) {
	for name, reauthWith := range reauthEntryPoints {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, s, id := persistTestSetup(t)
				t.Cleanup(func() { _ = s.Close() })

				_, err := s.SetNodeExpiry(id, new(time.Now().Add(2*time.Hour)))
				require.NoError(t, err)
				s.Connect(id)
				node, ok := s.GetNodeByID(id)
				require.True(t, ok)
				require.True(t, node.IsOnline().Get())
				run := reauthWith(t, s, node)
				watermark := time.Now()

				require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("delay_auth_expiry", func(tx *gorm.DB) {
					if tx.Statement.Table != "nodes" {
						return
					}

					<-time.After(90 * time.Minute)

					var expired bool

					watermark, expired = s.ExpireExpiredNodes(watermark)
					assert.False(t, expired, "the still-private earlier expiry is invisible to the sweep")
					<-time.After(time.Hour)
				}))
				t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("delay_auth_expiry") })
				require.NoError(t, run())

				_, expired := s.ExpireExpiredNodes(watermark)
				assert.False(t, expired, "the new expiry predates the last sweep")

				live, ok := s.GetNodeByID(id)
				require.True(t, ok)
				assert.True(t, live.IsExpired())
				assert.False(t, live.IsOnline().Get(), "publication must not retain expired online state")
			})
		})
	}
}

func BenchmarkPublishRegistrationUnchangedOwner(b *testing.B) {
	for _, count := range []int{1, 100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			users := make([]types.User, count)
			for i := range users {
				users[i] = types.User{ID: uint(i + 1), Name: "user" + strconv.Itoa(i)}
			}

			owner := &users[count-1]
			node := &types.Node{ID: 1, NodeKey: key.NewNode().Public(), UserID: &owner.ID, User: owner, LastSeen: new(time.Now())}
			w, err := newWorld(types.Nodes{node}, users, nil, types.DNSView{})
			require.NoError(b, err)

			s := &State{world: w}
			candidate := node.Clone()

			s.persistMu.Lock()
			defer s.persistMu.Unlock()

			b.ReportAllocs()

			for b.Loop() {
				_, err := s.publishRegistration(node, candidate)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPublishRegistrationChangedOwner covers the merge branch the
// unchanged-owner benchmark skips: a candidate carrying a different owner
// re-resolves it against the snapshot's user list, so its cost follows that
// list, not the tailnet's node count. The candidate alternates between two
// owners near the end of the list each iteration, so the re-resolve branch
// and its full scan run on every operation, not just the first.
func BenchmarkPublishRegistrationChangedOwner(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			users := make([]types.User, count)
			for i := range users {
				users[i] = types.User{ID: uint(i + 1), Name: "user" + strconv.Itoa(i)}
			}

			owner := &users[count-1]
			node := &types.Node{ID: 1, NodeKey: key.NewNode().Public(), UserID: &owner.ID, User: owner, LastSeen: new(time.Now())}
			w, err := newWorld(types.Nodes{node}, users, nil, types.DNSView{})
			require.NoError(b, err)

			s := &State{world: w}
			candidate := node.Clone()

			owners := [2]*types.User{&users[count-2], owner}

			s.persistMu.Lock()
			defer s.persistMu.Unlock()

			b.ReportAllocs()

			var i int

			for b.Loop() {
				newOwner := owners[i%2]
				i++

				candidate.UserID = &newOwner.ID
				candidate.User = newOwner

				_, err := s.publishRegistration(node, candidate)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestReauthPublicationUsesCurrentOwner(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:auth":["persist-user@"]}}`))
	require.NoError(t, err)

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	user := node.User().AsStruct()
	node, err = s.SetNodeTags(id, []string{"tag:auth"})
	require.NoError(t, err)

	// A user rename has committed, but its graph refresh lands during reauth.
	renamed := *user
	renamed.Name = "renamed-owner"
	require.NoError(t, s.db.DB.Model(&renamed).Update("name", renamed.Name).Error)
	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("refresh_owner", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			require.NoError(t, s.world.SetUsers([]types.User{renamed}))
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("refresh_owner") })

	got, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode:  node,
		RegData:       &types.RegistrationData{MachineKey: node.MachineKey(), NodeKey: key.NewNode().Public()},
		ValidHostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname()}, Hostname: node.Hostname(),
		User: user, IsConvertFromTag: true, RegisterMethod: util.RegisterMethodOIDC,
	})
	require.NoError(t, err)
	require.False(t, got.IsTagged())
	assert.Equal(t, renamed.Name, got.User().Name())
	require.NoError(t, s.refreshUsers())
	got, ok = s.GetNodeByID(id)
	require.True(t, ok)
	assert.Equal(t, renamed.Name, got.User().Name(), "an unchanged user list will not repair a stale owner")
}

func TestReauthAuthorizesBeforeConcurrentPolicyChange(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:auth":["persist-user@"]}}`))
	require.NoError(t, err)

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)
	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").Register("change_policy", func(tx *gorm.DB) {
		if tx.Statement.Table == "nodes" {
			// Removing a tag owner does not revoke a grant already authorised.
			_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:auth":[]}}`))
			assert.NoError(t, err)

			live, found := s.GetNodeByID(id)
			assert.True(t, found)
			assert.False(t, live.IsTagged(), "the authorised candidate still waits for commit")
		}
	}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("change_policy") })

	hi := &tailcfg.Hostinfo{Hostname: node.Hostname(), RequestTags: []string{"tag:auth"}}
	got, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode:  node,
		RegData:       &types.RegistrationData{MachineKey: node.MachineKey(), NodeKey: key.NewNode().Public(), Hostinfo: hi},
		ValidHostinfo: hi, Hostname: node.Hostname(), User: node.User().AsStruct(),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"tag:auth"}, got.Tags().AsSlice())
	assert.False(t, s.Snapshot().Policy().UserCanHaveTag(node.User(), "tag:auth"))
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
// re-authentication that succeeds waits for its transaction, the single
// database connection held so the admin's write
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

				waits := sqlDB.Stats().WaitCount
				reauth := make(chan error, 1)

				go func() { reauth <- run() }()

				require.Eventually(t, func() bool {
					return sqlDB.Stats().WaitCount > waits
				}, 5*time.Second, time.Millisecond, "test sanity: the re-auth is waiting for its transaction")

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
// the node. Both admin writes wait for the re-auth's private candidate to
// be discarded, then their values must remain in memory and the database.
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

	// Both a retag and an expiry wait for the whole re-auth under persistMu.
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
	assert.Equal(t, node.NodeKey(), got.NodeKey(), "the failed write must not publish its node key")
	assert.Equal(t, want.IsExpired(), got.IsExpired(), "the admin's expiry stands")
	assert.Equal(t, want.Tags().AsSlice(), got.Tags().AsSlice(), "the admin's tags stand")

	durable, err := s.DB().GetNodeByID(id)
	require.NoError(t, err)
	assert.Equal(t, durable.IsExpired(), got.IsExpired(), "memory matches the row a restart loads")
	assert.Equal(t, []string(durable.Tags), got.Tags().AsSlice())
	assert.Equal(t, durable.NodeKey, got.NodeKey())
}

// TestReauthRollbackKeepsSameBatchWrite batches a Hostinfo write with
// re-auth staging, then fails the re-auth's database write. Discarding the
// private candidate must keep the batched Hostinfo; an admin retag cannot
// join the batch because it waits for the whole re-auth under persistMu.
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

				// Hold a commit so staging and the Hostinfo write queue together;
				// an admin retag waits for the re-auth instead.
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
				assert.Equal(t, node.NodeKey(), live.NodeKey(), "the failed re-auth's key must not publish")

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
// while a re-auth waits on its database write, which then fails. Discarding
// the private candidate must keep the renamed user, as an unchanged user
// list will not refresh it again. Retagged covers a failed candidate that
// would have removed user ownership.
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
			require.True(t, live.User().Valid(), "the node must keep its user ownership")
			assert.Equal(t, "renamed-user", live.User().Name(), "failed auth must keep the rename")

			require.NoError(t, s.refreshUsers())

			again, _ := s.GetNodeByID(id)
			assert.Equal(t, "renamed-user", again.User().Name(), "and nothing refreshes a stale one later")
		})
	}
}

// TestNewStateBoundsStoredClientReport covers legacy reports before they reach peers.
func TestNewStateBoundsStoredClientReport(t *testing.T) {
	endpoints := make([]netip.AddrPort, types.MaxEndpoints+1)
	for i := range endpoints {
		endpoints[i] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i))
	}

	routes := make([]netip.Prefix, types.MaxRoutableIPs+1)
	for i := range routes {
		routes[i] = netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, byte(i >> 8), byte(i)}), 64)
	}

	for _, tt := range []struct {
		name          string
		hostname      string
		endpoints     []netip.AddrPort
		routes        []netip.Prefix
		wantHostname  string
		wantEndpoints []netip.AddrPort
		wantRoutes    []netip.Prefix
	}{
		{
			name:          "at limits",
			hostname:      strings.Repeat("h", types.MaxHostnameLength),
			endpoints:     endpoints[:types.MaxEndpoints],
			routes:        routes[:types.MaxRoutableIPs],
			wantHostname:  strings.Repeat("h", types.MaxHostnameLength),
			wantEndpoints: endpoints[:types.MaxEndpoints],
			wantRoutes:    routes[:types.MaxRoutableIPs],
		},
		{
			name:          "over limits",
			hostname:      strings.Repeat("h", types.MaxHostnameLength+1),
			endpoints:     endpoints,
			routes:        routes,
			wantHostname:  strings.Repeat("h", types.MaxHostnameLength),
			wantEndpoints: endpoints[:types.MaxEndpoints],
			wantRoutes:    routes[:types.MaxRoutableIPs],
		},
		{
			name:     "multibyte hostname and zoned endpoint",
			hostname: strings.Repeat("h", types.MaxHostnameLength-1) + "é",
			endpoints: []netip.AddrPort{
				netip.MustParseAddrPort("[fe80::1%eth0]:41641"), endpoints[0],
			},
			wantHostname:  strings.Repeat("h", types.MaxHostnameLength-1),
			wantEndpoints: endpoints[:1],
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := t.TempDir() + "/headscale.db"
			cfg := persistTestConfig(dbPath)
			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			user := database.CreateUserForTest("bound-user")
			node := database.CreateRegisteredNodeForTest(user, "bounded")
			err = database.DB.Model(node).Select("Hostname", "Endpoints", "Hostinfo").
				Updates(&types.Node{
					Hostname:  tt.hostname,
					Endpoints: tt.endpoints,
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: tt.hostname, RoutableIPs: tt.routes,
						NetInfo: &tailcfg.NetInfo{PreferredDERP: 1, DERPLatency: map[string]float64{"1-v4": 0.01}},
					},
				}).Error
			require.NoError(t, err)
			require.NoError(t, database.Close())

			s, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			nv, ok := s.GetNodeByID(node.ID)
			require.True(t, ok)
			require.True(t, nv.Hostinfo().Valid())
			assert.Equal(t, tailcfg.DERPRegionID(1), nv.Hostinfo().NetInfo().PreferredDERP())
			assert.Nil(t, nv.Hostinfo().AsStruct().NetInfo.DERPLatency)
			assert.Equal(t, tt.wantHostname, nv.Hostname())
			assert.Equal(t, tt.wantHostname, nv.Hostinfo().Hostname())
			assert.Equal(t, tt.wantEndpoints, nv.Endpoints().AsSlice())
			assert.Equal(t, tt.wantRoutes, nv.Hostinfo().RoutableIPs().AsSlice())

			err = s.UpdateNodeFromMapRequest(node.ID, tailcfg.MapRequest{
				NodeKey: nv.NodeKey(), DiscoKey: key.NewDisco().Public(),
			})
			require.NoError(t, err)

			reported, ok := s.GetNodeByID(node.ID)
			require.True(t, ok)
			assert.Equal(t, tt.wantEndpoints, reported.Endpoints().AsSlice(), "peers are sent the bounded endpoints")

			row, err := s.DB().GetNodeByID(node.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.wantHostname, row.Hostname, "the next persist rewrites the row")
			assert.True(t, slices.Equal(tt.wantEndpoints, row.Endpoints), "persisted endpoints match the bounded report")
			assert.Equal(t, tt.wantRoutes, row.Hostinfo.RoutableIPs)
		})
	}
}

func TestNewStateDiscardsOversizedHostinfo(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	err := s.DB().DB.Model(&types.Node{ID: nodeID}).Select("Hostinfo").
		Updates(&types.Node{Hostinfo: &tailcfg.Hostinfo{
			OSVersion: strings.Repeat("v", types.MaxHostinfoSize),
		}}).Error
	require.NoError(t, err)
	require.NoError(t, s.Close())

	nv, ok := persistTestReopen(t, dbPath).GetNodeByID(nodeID)
	require.True(t, ok)
	assert.False(t, nv.Hostinfo().Valid(),
		"oversized Hostinfo is dropped until the node reports again")
}

// TestBootKeepsHostinfoTheMapPathStored pins that the startup check keeps
// what the map path accepted. A report without NetInfo keeps the stored one,
// so a stored Hostinfo can combine fields from two reports.
func TestBootKeepsHostinfoTheMapPathStored(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	for _, hi := range []*tailcfg.Hostinfo{
		{
			Hostname: nv.Hostname(),
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				LinkType:      strings.Repeat("l", 60<<10),
			},
		},
		{Hostname: nv.Hostname(), OSVersion: strings.Repeat("v", 60<<10)},
	} {
		req := tailcfg.MapRequest{
			NodeKey: nv.NodeKey(), DiscoKey: nv.DiscoKey(), Hostinfo: hi,
		}
		require.NoError(t, types.ValidateHostinfo(req.Hostinfo))

		err := s.UpdateNodeFromMapRequest(nodeID, req)
		require.NoError(t, err)
	}

	require.NoError(t, s.Close())

	reloaded, ok := persistTestReopen(t, dbPath).GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, reloaded.Hostinfo().Valid(),
		"the startup check must keep a Hostinfo the map path stored")
	assert.Equal(t, tailcfg.DERPRegionID(1),
		reloaded.Hostinfo().NetInfo().PreferredDERP())

	osVersionLen := len(reloaded.Hostinfo().OSVersion())
	assert.Equal(t, 60<<10, osVersionLen)
}

// TestSetNodeExpiryRejectsUnencodableExpiry proves an admin cannot store a key
// expiry that every map carrying the node would fail to encode.
func TestSetNodeExpiryRejectsUnencodableExpiry(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	beyond, err := time.Parse(time.RFC3339, "9999-12-31T23:59:59-23:59")
	require.NoError(t, err)

	before := s.Snapshot().Rev()

	_, err = s.SetNodeExpiry(nodeID, &beyond)
	require.ErrorIs(t, err, types.ErrExpiryOutOfRange)
	require.Equal(t, before, s.Snapshot().Rev(),
		"a refused expiry must not reach the world")

	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	_, err = s.SetNodeExpiry(nodeID, &latest)
	require.NoError(t, err)
}

// TestAuthPathRejectsUnencodableExpiry proves an expiry handed to the auth
// path, such as an OIDC token's, cannot store what SetNodeExpiry refuses.
func TestAuthPathRejectsUnencodableExpiry(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("auth-path-user")
	nodeKey := key.NewNode().Public()
	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    nodeKey,
		Hostname:   "auth-path-node",
	})))

	// How go-oidc reads an exp claim in the year 10000.
	beyond := time.Unix(253402300800, 0)

	_, err := s.HandleNodeFromAuthPath(
		authID, types.UserID(user.ID), &beyond, util.RegisterMethodOIDC,
	)
	require.ErrorIs(t, err, types.ErrExpiryOutOfRange)

	_, found := s.GetNodeByNodeKey(nodeKey)
	require.False(t, found, "a refused expiry must not create a node")
}

// TestAcceptedExpirySurvivesRestart proves an accepted expiry that is already in
// the year 10000 in its own zone is stored so SQLite can load it at the next
// start. go-oidc reads a token's exp in the server's zone, east of UTC here.
func TestAcceptedExpirySurvivesRestart(t *testing.T) {
	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	east := latest.In(time.FixedZone("", 60*60))

	dbPath, s, adminID := persistTestSetup(t)

	_, err := s.SetNodeExpiry(adminID, &east)
	require.NoError(t, err)

	user := s.CreateUserForTest("oidc-user")
	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "oidc-node",
	})))

	oidcNode, err := s.HandleNodeFromAuthPath(
		authID, types.UserID(user.ID), &east, util.RegisterMethodOIDC,
	)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	s = persistTestReopen(t, dbPath)

	for _, id := range []types.NodeID{adminID, oidcNode.ID()} {
		nv, ok := s.GetNodeByID(id)
		require.True(t, ok)
		assert.True(t, latest.Equal(nv.Expiry().Get()), "node %d", id)
	}
}

// TestLoadedExpiryIsUTC proves an expiry the database returns in another zone is
// served in UTC. PostgreSQL returns the server's zone, where the latest accepted
// expiry is in the year 10000 and cannot be encoded.
func TestLoadedExpiryIsUTC(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	require.NoError(t, s.Close())

	expiry := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)

	database, err := db.NewHeadscaleDatabase(persistTestConfig(dbPath))
	require.NoError(t, err)
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", nodeID).
		Update("expiry", expiry.In(time.FixedZone("", 60*60))).Error)
	require.NoError(t, database.Close())

	s = persistTestReopen(t, dbPath)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	got := nv.Expiry().Get()
	assert.True(t, expiry.Equal(got))
	assert.Equal(t, time.UTC, got.Location())
}
