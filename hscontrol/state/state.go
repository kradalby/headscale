// Package state provides core state management for Headscale,
// coordinating between subsystems like database, IP allocation,
// policy management, and DERP routing.
//
// The central type [State] owns the control plane as a dataflow graph
// (world.go): nodes, users, policy and DERP map as inputs, the compiled
// policy, peer visibility and HA primaries derived from them, all read
// through one consistent [Snapshot]. It also owns a [pingTracker] for
// [tailcfg.PingRequest] correlation. Cross-subsystem operations (node
// updates, policy evaluation, IP allocation) go through [State] rather
// than directly to the database.
package state

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/multierr"
	"tailscale.com/util/truncate"
)

const (
	// registerCacheExpiration defines how long node registration entries remain in cache.
	registerCacheExpiration = time.Minute * 15

	// Cap pending requests as well as the interactive handler's per-request payload.
	defaultRegisterCacheMaxEntries = 1024

	authCacheSSHReserve = 64
)

// ErrUnsupportedPolicyMode is returned for invalid policy modes. Valid modes are "file" and "db".
var ErrUnsupportedPolicyMode = errors.New("unsupported policy mode")

// ErrNodeNotFound is returned when a node cannot be found by its ID.
var ErrNodeNotFound = errors.New("node not found")

// ErrInvalidNodeView is returned when an invalid node view is provided.
var ErrInvalidNodeView = errors.New("invalid node view provided")

// ErrNodeNotInNodeStore is returned when a node is gone from the latest
// snapshot, deleted while the caller worked on it.
var ErrNodeNotInNodeStore = errors.New("node no longer exists")

// ErrNodeKeyChanged rejects a map request authenticated before reauthentication.
var ErrNodeKeyChanged = errors.New("node key changed since map request authentication")

// ErrNodeNameNotUnique is returned when a node name is not unique.
var ErrNodeNameNotUnique = errors.New("node name is not unique")

// nodeUpdateColumns lists all Node columns that should be written
// during a struct-based GORM Updates() call.  Listing them explicitly
// forces GORM to include nil/zero-value fields (e.g. UserID=nil when
// converting a user-owned node to tagged) that struct-based Updates()
// would otherwise silently skip.
//
// Excluded columns:
//   - AuthKeyID, AuthKey: prevents GORM from persisting stale
//     PreAuthKey references after a key has been deleted (#2862).
//   - User: GORM association, not a real column.
//   - IsOnline: runtime-only field (gorm:"-").
//
// Expiry is included here but may be omitted at call sites that must
// not touch it (see persistNode).
var nodeUpdateColumns = []string{
	"MachineKey",
	"NodeKey",
	"DiscoKey",
	"Endpoints",
	"Hostinfo",
	"IPv4",
	"IPv6",
	"Hostname",
	"GivenName",
	"UserID",
	"RegisterMethod",
	"Tags",
	"Expiry",
	"LastSeen",
	"ApprovedRoutes",
	"UpdatedAt",
}

// ErrRegistrationExpired is returned when a registration has expired.
var ErrRegistrationExpired = errors.New("registration expired")

var ErrAuthCacheFull = errors.New("the pending authentication cache is full")

var ErrAuthCacheEntryExists = errors.New("authentication request already exists")

var ErrAuthCacheClosed = errors.New("authentication cache closed")

var ErrAuthRequestFinished = errors.New("authentication request already finished")

var ErrInvalidPolicy = errors.New("invalid policy")

// invalidPolicyError marks a refusal as [ErrInvalidPolicy] and keeps the
// reason's own text, which API answers show as is.
type invalidPolicyError struct{ reason error }

func (e invalidPolicyError) Error() string   { return e.reason.Error() }
func (e invalidPolicyError) Unwrap() []error { return []error{ErrInvalidPolicy, e.reason} }

// ValidatePolicy compiles a candidate policy against the live users and
// nodes without storing it: the acl/validate endpoint's backing. A document
// the live path would refuse is rejected here for the same reasons.
func (s *State) ValidatePolicy(pol []byte) error {
	users, err := s.ListAllUsers()
	if err != nil {
		return fmt.Errorf("loading users: %w", err)
	}

	snap := s.Snapshot()
	nodes := snap.ListNodes()

	pm, err := policy.NewPolicyManager(pol, users, nodes)
	if err != nil {
		return invalidPolicyError{err}
	}

	// The write path refuses a document whose tests or sshTests fail; the
	// validate answer must agree with it, or a policy set would refuse
	// what validate blessed.
	testErr := policyTestsFail(pm)
	if testErr != nil {
		return invalidPolicyError{testErr}
	}

	// SSH rules compile per node, so a server without nodes cannot catch
	// every case here.
	if nodes.Len() > 0 {
		_, err = pm.SSHPolicy(s.cfg.ServerURL, nodes.At(0))
		if err != nil {
			return invalidPolicyError{fmt.Errorf("verifying SSH rules: %w", err)}
		}
	}

	return nil
}

// ErrNodeKeyInUse is returned when a registration or re-auth claims a NodeKey
// already bound to a different machine, enforcing the 1:1 NodeKey<->MachineKey
// binding.
var ErrNodeKeyInUse = errors.New("node key already in use by another machine")

// ErrAmbiguousNodeOwnership is returned when a machine key maps to a set of
// nodes from which the correct one to update or convert cannot be determined:
// multiple user-owned candidates for a tagged conversion, or a tagged node and
// a user-owned node coexisting (impossible per validateNodeOwnership). The
// registration is rejected rather than mutating an arbitrarily-picked node.
var ErrAmbiguousNodeOwnership = errors.New("machine key maps to ambiguous node ownership")

// sshCheckPair identifies a (source, destination) node pair for
// SSH check auth tracking.
type sshCheckPair struct {
	Src types.NodeID
	Dst types.NodeID
}

// State manages Headscale's core state, coordinating between database, policy management,
// IP allocation, and DERP routing. All methods are thread-safe.
//
// Reads go through a [Snapshot], in which nodes, users, the compiled policy,
// peers and primaries all belong to the same commit.
type State struct {
	// onNodeDeleted runs after a node deletion; see [State.OnNodeDeleted].
	onNodeDeleted atomic.Pointer[func(types.NodeID)]

	// cfg holds the current Headscale configuration
	cfg *types.Config

	// world is the in-memory control plane; the database is its durable copy.
	world *world

	// subsystem keeping state
	// db provides persistent storage and database operations
	db *hsdb.HSDatabase
	// ipAlloc manages IP address allocation for nodes
	ipAlloc *hsdb.IPAllocator

	// authCache holds any pending authentication requests from either auth
	// type (Web and OIDC). It is a bounded LRU keyed by AuthID; oldest
	// entries are evicted once the size cap is reached, and entries that
	// time out have their auth verdict resolved with ErrRegistrationExpired
	// via the eviction callback so any waiting goroutines wake.
	authCache *expirable.LRU[types.AuthID, *types.AuthRequest]

	authCacheMaxEntries     int
	authCacheRegularEntries atomic.Int64
	authCacheMu             sync.Mutex
	authCacheClosed         bool

	// pings tracks pending ping requests and their response channels.
	pings *pingTracker

	// sshCheckAuth tracks when source nodes last completed SSH check auth.
	//
	// For rules without explicit checkPeriod (default 12h), auth covers any
	// destination — keyed by (src, Dst=0) where 0 is a sentinel meaning "any".
	// Ref: "Once re-authenticated to a destination, the user can access the
	// device and any other device in the tailnet without re-verification
	// for the next 12 hours." — https://tailscale.com/docs/features/tailscale-ssh
	//
	// For rules with explicit checkPeriod, auth covers only that specific
	// destination — keyed by (src, dst).
	// Ref: "If a different check period is specified for the connection,
	// then the user can access specifically this device without
	// re-verification for the duration of the check period."
	//
	// Ref: https://github.com/tailscale/tailscale/issues/10480
	// Ref: https://github.com/tailscale/tailscale/issues/7125
	sshCheckAuth map[sshCheckPair]time.Time
	sshCheckMu   sync.RWMutex

	// persistMu serialises node-row persistence and deletion so the database
	// always converges on the in-memory node rather than being clobbered by a
	// stale caller snapshot or resurrected by an update racing with deletion.
	persistMu sync.Mutex
	// connectMu excludes session admission (State.Connect, its only reader)
	// from a lifetime delete in flight: a Connect arriving while the row is
	// being removed must wait or find the node gone, never acquire a live
	// epoch for it. It is never acquired under persistMu — a session parked
	// on its batched world write must not stall every persist behind a
	// delete waiting that session out — and a delete waiting behind
	// registration SQL must not block admission, so the GC decides the
	// node's lifetime first and only then takes it.
	connectMu sync.RWMutex

	// beforeAuthWrite, for tests, runs just before a re-auth writes the
	// node: where a check made ahead of the write would already be stale.
	beforeAuthWrite func()

	// beforeLogoutWrite, for tests, interposes an admin write between
	// LogoutNode's unlocked checks and its locked re-decision.
	beforeLogoutWrite func()

	// usersMu serialises listing users and handing them to the world, so a
	// slow refresh cannot replace a newer user list with an older one.
	usersMu sync.Mutex

	// registerLocks serialises registration per machine key so concurrent
	// registrations of the same machine resolve to a single node instead of
	// racing the find-then-create section and each creating their own.
	registerLocks *xsync.Map[key.MachinePublic, *registrationLock]

	// claimLocks serialises NodeKey claims per key across fresh
	// registrations and re-authentications, so two writers cannot both
	// insert or rotate onto the same NodeKey. Unrelated claims stay
	// concurrent: fresh joins batch into one commit instead of queueing
	// behind each other on persistMu.
	claimLocks *xsync.Map[key.NodePublic, *registrationLock]
}

type registrationLock struct {
	mu sync.Mutex
	// refs includes waiters, so releasing an owner cannot replace their lock.
	refs int
}

// lockRegistration serialises registration for a single machine key and
// returns the unlock function.
func (s *State) lockRegistration(machineKey key.MachinePublic) func() {
	return lockKeyed(s.registerLocks, machineKey)
}

// lockNodeKey serialises writes claiming a single NodeKey — a fresh
// registration inserting it or a re-auth rotating onto it — and returns the
// unlock function.
func (s *State) lockNodeKey(nodeKey key.NodePublic) func() {
	return lockKeyed(s.claimLocks, nodeKey)
}

// lockKeyed serialises access per key with a refcounted lock: entries are
// dropped once every holder and waiter is gone, so the maps never grow with
// the machines or keys a tailnet has seen.
func lockKeyed[K comparable](locks *xsync.Map[K, *registrationLock], lockKey K) func() {
	lock, _ := locks.Compute(lockKey, func(lock *registrationLock, loaded bool) (*registrationLock, xsync.ComputeOp) {
		if !loaded {
			lock = &registrationLock{}
		}

		lock.refs++

		return lock, xsync.UpdateOp
	})
	lock.mu.Lock()

	return func() {
		lock.mu.Unlock()
		locks.Compute(lockKey, func(lock *registrationLock, _ bool) (*registrationLock, xsync.ComputeOp) {
			lock.refs--
			if lock.refs == 0 {
				return nil, xsync.DeleteOp
			}

			return lock, xsync.CancelOp
		})
	}
}

// NewState creates and initializes a new [State] instance, setting up the database,
// IP allocator, DERP map, policy manager, and loading existing users and nodes.
func NewState(cfg *types.Config) (*State, error) {
	cacheExpiration := cmp.Or(cfg.Tuning.RegisterCacheExpiration, registerCacheExpiration)

	cacheMaxEntries := defaultRegisterCacheMaxEntries
	if cfg.Tuning.RegisterCacheMaxEntries > 0 {
		cacheMaxEntries = cfg.Tuning.RegisterCacheMaxEntries
	}

	db, err := hsdb.NewHeadscaleDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("initializing database: %w", err)
	}

	ipAlloc, err := hsdb.NewIPAllocator(db, cfg.PrefixV4, cfg.PrefixV6, cfg.IPAllocation)
	if err != nil {
		return nil, fmt.Errorf("initializing IP allocator: %w", err)
	}

	nodes, err := db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes: %w", err)
	}

	// On startup, all nodes should be marked as offline until they reconnect
	// This ensures we don't have stale online status from previous runs
	for _, node := range nodes {
		node.IsOnline = new(false)

		// PostgreSQL returns the server's zone, where the latest accepted
		// expiry is in the year 10000 and cannot be encoded.
		if node.Expiry != nil {
			node.Expiry = new(node.Expiry.UTC())
		}

		// Legacy reports must pass the same checks before entering the world.
		// The next persist rewrites trimmed or discarded metadata.
		if len(node.Hostname) > types.MaxHostnameLength {
			log.Warn().Uint64(zf.NodeID, node.ID.Uint64()).Msg("trimming oversized stored hostname")
			node.Hostname = strings.Clone(truncate.String(node.Hostname, types.MaxHostnameLength))
		}

		node.Endpoints = slices.DeleteFunc(node.Endpoints, func(ep netip.AddrPort) bool {
			return ep.Addr().Zone() != ""
		})
		node.Endpoints = slices.Clone(node.Endpoints[:min(len(node.Endpoints), types.MaxEndpoints)])

		if hi := node.Hostinfo; hi != nil {
			if hi.NetInfo != nil {
				hi.NetInfo.DERPLatency = nil
			}

			if len(hi.Hostname) > types.MaxHostnameLength {
				hi.Hostname = strings.Clone(truncate.String(hi.Hostname, types.MaxHostnameLength))
			}

			if len(hi.RoutableIPs) > types.MaxRoutableIPs {
				log.Warn().Uint64(zf.NodeID, node.ID.Uint64()).Msgf(
					"too many stored routes, keeping the first %d", types.MaxRoutableIPs)
				hi.RoutableIPs = slices.Clone(hi.RoutableIPs[:types.MaxRoutableIPs])
			}
		}

		err := types.ValidateHostinfo(node.Hostinfo)
		if err != nil {
			log.Warn().Uint64(zf.NodeID, node.ID.Uint64()).Err(err).Msg("discarding stored Hostinfo until the node reports again")
			node.Hostinfo = nil
		}
	}

	users, err := db.ListUsers(nil)
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	pol, err := hsdb.PolicyBytes(db.DB, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	w, err := newWorld(nodes, users, pol, cfg.DNSView())
	if err != nil {
		return nil, fmt.Errorf("initializing policy manager: %w", err)
	}

	w.batchSize, w.batchTimeout = cfg.Tuning.NodeStoreBatchSize, cfg.Tuning.NodeStoreBatchTimeout
	w.servesRoute = cfg.ServesRoute
	// The stored policy's tests are checked once at boot, and by
	// [State.SetPolicy] for each changed document; a node change
	// recompiles the policy without them. A failure here only warns: a stale stored policy (a
	// user deleted while the server was down) must not block boot.
	if t, ok := w.snapshot().Policy().(policyTester); ok {
		if err := t.RunTests(); err != nil { //nolint:noinlineerr // warn and continue
			log.Warn().Err(err).Msg("policy tests failed at boot; server starting anyway, fix the policy and reload")
		}

		if err := t.RunSSHTests(); err != nil { //nolint:noinlineerr // warn and continue
			log.Warn().Err(err).Msg("policy sshTests failed at boot; server starting anyway, fix the policy and reload")
		}
	}

	s := &State{
		cfg:                 cfg,
		authCacheMaxEntries: cacheMaxEntries,

		db:      db,
		ipAlloc: ipAlloc,
		world:   w,
		pings:   newPingTracker(),

		sshCheckAuth:  make(map[sshCheckPair]time.Time),
		registerLocks: xsync.NewMap[key.MachinePublic, *registrationLock](),
		claimLocks:    xsync.NewMap[key.NodePublic, *registrationLock](),

		beforeAuthWrite: func() {},
	}

	// Last: NewLRU starts the TTL sweeper goroutine, which only Close stops.
	// The cache carries the SSH reserve; an evicted regular entry releases
	// its slot, and eviction wakes the waiter.
	s.authCache = expirable.NewLRU[types.AuthID, *types.AuthRequest](
		cacheMaxEntries+authCacheSSHReserve,
		func(_ types.AuthID, rn *types.AuthRequest) {
			if !rn.IsSSHCheck() {
				s.authCacheRegularEntries.Add(-1)
			}

			rn.FinishAuth(types.AuthVerdict{Err: ErrRegistrationExpired})
		},
		cacheExpiration,
	)

	// Surface nodes whose stored data would break map generation (e.g. an
	// invalid given name from a legacy row) so an operator can fix them. This
	// only logs; it never mutates a node's stored name at boot.
	s.logNodeHealth()

	return s, nil
}

// Close gracefully shuts down the [State] instance and releases all resources.
func (s *State) Close() error {
	s.pings.drain()

	s.authCacheMu.Lock()
	s.authCacheClosed = true
	s.authCacheMu.Unlock()

	// Purge before Close: Close stops the sweeper, so anything still cached
	// would never expire and its WaitForAuth caller would hang.
	s.authCache.Purge()
	s.authCache.Close()

	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	return nil
}

// Snapshot returns the latest consistent view of the control plane. Take
// one per operation when several reads must agree.
func (s *State) Snapshot() *Snapshot {
	return s.world.snapshot()
}

// Subscribe returns a subscription woken after every commit to the control
// plane; read [State.Snapshot] after each wake-up.
func (s *State) Subscribe() *graph.Subscription {
	return s.world.g.Subscribe()
}

// SetDERPMap updates the DERP relay configuration.
func (s *State) SetDERPMap(dm *tailcfg.DERPMap) {
	s.world.SetDERPMap(dm)
}

// DERPMap returns the current DERP relay configuration for peer-to-peer connectivity.
func (s *State) DERPMap() tailcfg.DERPMapView {
	return s.Snapshot().DERPMap().View()
}

// SetExtraRecords publishes the extra DNS records and wakes map streams in
// the same graph commit.
func (s *State) SetExtraRecords(records []tailcfg.DNSRecord) {
	s.world.SetExtraRecords(records)
}

// ReloadPolicy reloads the access control policy and re-runs route
// auto-approval. The policy is already swapped when auto-approval fails.
func (s *State) ReloadPolicy() error {
	pol, err := hsdb.PolicyBytes(s.db.DB, s.cfg)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	policyChanged, err := s.SetPolicy(pol)
	if err != nil {
		return fmt.Errorf("setting policy: %w", err)
	}

	// Always call autoApproveNodes during policy reload, regardless of whether
	// the policy content has changed. This ensures that routes are re-evaluated
	// when they might have been manually disabled but could now be auto-approved
	// with the current policy.
	approved, err := s.autoApproveNodes()
	if err != nil {
		return fmt.Errorf("auto approving nodes: %w", err)
	}

	if approved > 0 || policyChanged {
		log.Info().
			Bool("policy.changed", policyChanged).
			Int("route.changes", approved).
			Msg("Policy reload completed with changes")
	}

	return nil
}

// CreateUser creates a new user and refreshes the users the policy reads.
func (s *State) CreateUser(user types.User) (*types.User, error) {
	if err := s.db.DB.Save(&user).Error; err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("creating user: %w", err)
	}

	err := s.refreshUsers()
	if err != nil {
		return &user, fmt.Errorf("updating policy manager after user creation: %w", err)
	}

	log.Info().Str(zf.UserName, user.Name).Msg("user created")

	return &user, nil
}

// UpdateUser modifies an existing user using the provided update function within a transaction.
func (s *State) UpdateUser(userID types.UserID, updateFn func(*types.User) error) (*types.User, error) {
	user, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		user, err := hsdb.GetUserByID(tx, userID)
		if err != nil {
			return nil, err
		}

		if err := updateFn(user); err != nil { //nolint:noinlineerr
			return nil, err
		}

		// Use Updates() to only update modified fields, preserving unchanged values.
		err = tx.Updates(user).Error
		if err != nil {
			return nil, fmt.Errorf("updating user: %w", err)
		}

		return user, nil
	})
	if err != nil {
		return nil, err
	}

	err = s.refreshUsers()
	if err != nil {
		return user, fmt.Errorf("updating policy manager after user update: %w", err)
	}

	return user, nil
}

// DeleteUser permanently removes a user and all associated data (nodes, API keys, etc).
// This operation is irreversible.
// It also refreshes the users the policy reads so ACL policies referencing
// the deleted user are re-evaluated immediately, fixing issue #2967.
func (s *State) DeleteUser(userID types.UserID) error {
	err := s.db.DestroyUser(userID)
	if err != nil {
		return err
	}

	err = s.refreshUsers()
	if err != nil {
		return fmt.Errorf("updating policy after user deletion: %w", err)
	}

	return nil
}

// RenameUser changes a user's name. The new name must be unique.
func (s *State) RenameUser(userID types.UserID, newName string) (*types.User, error) {
	return s.UpdateUser(userID, func(user *types.User) error {
		user.Name = newName
		return nil
	})
}

// GetUserByID retrieves a user by ID.
func (s *State) GetUserByID(userID types.UserID) (*types.User, error) {
	return s.db.GetUserByID(userID)
}

// GetUserByName retrieves a user by name.
func (s *State) GetUserByName(name string) (*types.User, error) {
	return s.db.GetUserByName(name)
}

// GetUserByOIDCIdentifier retrieves a user by their OIDC identifier.
func (s *State) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return s.db.GetUserByOIDCIdentifier(id)
}

// ListUsersWithFilter retrieves users matching the specified filter criteria.
func (s *State) ListUsersWithFilter(filter *types.User) ([]types.User, error) {
	return s.db.ListUsers(filter)
}

// ListAllUsers retrieves all users in the system.
func (s *State) ListAllUsers() ([]types.User, error) {
	return s.db.ListUsers(nil)
}

// refreshUsers hands the database's user list to the world, which
// recompiles the policy and refreshes the user every node carries.
func (s *State) refreshUsers() error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	users, err := s.ListAllUsers()
	if err != nil {
		return fmt.Errorf("listing users for policy update: %w", err)
	}

	return s.world.SetUsers(users)
}

// persistNode writes the node's database row, re-reading the
// authoritative in-memory copy first.
func (s *State) persistNode(node types.NodeView) (types.NodeView, error) {
	if !node.Valid() {
		return types.NodeView{}, ErrInvalidNodeView
	}

	// Memory is the source of truth and every caller updates it before
	// persisting. Re-read the authoritative node under persistMu and write
	// that, rather than the caller's `node` view which may have been captured
	// earlier (e.g. at the top of UpdateNodeFromMapRequest) and gone stale
	// behind a concurrent admin write such as SetNodeTags. Serialising the
	// read+write keeps the database row converging on memory instead of
	// reverting it to an out-of-date column set.
	//
	// The same re-read also guards against the node having been deleted (e.g.
	// ephemeral logout) between the caller's update and this persist: a missing
	// node means we must not re-insert it.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	return s.persistNodeLocked(node)
}

// persistNodeLocked is [State.persistNode] for a caller holding persistMu.
func (s *State) persistNodeLocked(node types.NodeView) (types.NodeView, error) {
	fresh, exists := s.Snapshot().GetNode(node.ID())
	if !exists {
		log.Warn().
			EmbedObject(node).
			Bool("is_ephemeral", node.IsEphemeral()).
			Msg("Node no longer exists in memory, skipping database persist to prevent race condition")

		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, node.ID())
	}

	nodePtr := fresh.AsStruct()

	// Explicitly select all node columns so GORM includes nil/zero-value
	// fields (e.g. UserID=nil when converting a user-owned node to tagged).
	// Omit "Expiry" here: expiry is only updated through explicit
	// SetNodeExpiry calls or re-registration, not during MapRequest updates.
	result := s.db.DB.Select(nodeUpdateColumns).Omit("Expiry").Updates(nodePtr)
	if result.Error != nil {
		return types.NodeView{}, fmt.Errorf("saving node: %w", result.Error)
	}

	// The lifetime deletes drop the row before the world node, so a write
	// landing in that window matches zero rows. SQLite and Postgres both
	// count matched rows even when values are unchanged; report the row
	// gone instead of a no-op dressed as success.
	if result.RowsAffected == 0 {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, node.ID())
	}

	return fresh, nil
}

// DeleteNode permanently removes a node and cleans up associated resources.
func (s *State) DeleteNode(node types.NodeView) error {
	outcome, fresh, err := s.deleteNodeRow(node)
	if err != nil {
		return err
	}

	// The database is the durable source of truth. Only remove the in-memory
	// node after its row is gone so a failed database write cannot make a live
	// node look deleted until the next restart. persistMu stays out of this
	// write: a persist that still finds the node updates no row and reports
	// ErrNodeNotInNodeStore (persistNodeLocked), and holding it would keep
	// concurrent deletes out of one group commit. The window between the row
	// delete and this write is deliberate and short.
	//
	// The row write's own winner owns the teardown — a second one could free
	// a reallocated address — but a winner that died before removing the
	// world node would orphan it in peers' maps until restart, and the world
	// delete is idempotent, so every delete completes it.
	s.world.DeleteNode(node.ID())

	if outcome == deleteDroppedRow {
		s.finishNodeDeletion(fresh)
	}

	return nil
}

// deleteNodeRow re-reads the node under the row write's lock and drops the
// row, reporting what it found. The re-read is what makes the teardown free
// the addresses the delete actually saw: the caller's view can go stale
// behind the lock (an address backfill landing in between would otherwise be
// freed from the stale addresses and leak until restart). The lock is scoped
// with a deferred unlock, so a panic in the driver or a callback cannot leak
// it for the life of the process. The outcome is meaningful only when the
// error is nil.
func (s *State) deleteNodeRow(node types.NodeView) (deleteOutcome, types.NodeView, error) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	current, ok := s.GetNodeByID(node.ID())
	if !ok {
		// The world node is gone while the row may not be (test setups and
		// duplicate deletes); the row write still goes through the caller's view.
		current = node
	}

	err := s.db.DeleteNode(current.AsStruct())
	if err != nil {
		// Both spellings mean another delete already dropped the row: its
		// caller owns the teardown, and this one must not run it again.
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, hsdb.ErrNodeNotFound) {
			return deleteAlreadyGone, types.NodeView{}, nil
		}

		return deleteRefused, types.NodeView{}, err
	}

	return deleteDroppedRow, current, nil
}

// deleteOutcome says what a delete's row write found. It is meaningful only
// when the accompanying error is nil.
type deleteOutcome int

const (
	// deleteRefused: nothing was written — the lifetime re-check refused,
	// or the row write failed. The zero value, so a caller that reads the
	// outcome before the error can never be told it owns a teardown.
	deleteRefused deleteOutcome = iota
	// deleteDroppedRow: this caller deleted the row and owns the teardown.
	deleteDroppedRow
	// deleteAlreadyGone: another delete had already dropped the row.
	deleteAlreadyGone
)

// DeleteEphemeralNode removes a node only if it is still ephemeral and idle.
func (s *State) DeleteEphemeralNode(id types.NodeID) (bool, error) {
	// Phase 1 — decide under persistMu alone. A registration whose SQL this
	// GC queued behind may publish the node's new lifetime (permanent, or
	// reconnected) before the lock arrives, so the check must see what that
	// registration published; and this wait must not block session
	// admission, so connectMu is not held here.
	node, err := s.ephemeralDeleteCandidate(id)
	if err != nil || !node.Valid() {
		return false, err
	}

	// Phase 2 — delete under session admission, excluding Connect until the
	// node is gone from memory too. connectMu is never taken under
	// persistMu: a session parked on its batched world write must not have
	// every persist stall behind this delete while it is waited out.
	s.connectMu.Lock()
	defer s.connectMu.Unlock()

	outcome, fresh, err := s.deleteEphemeralRow(node)
	if err != nil {
		return false, err
	}

	if outcome == deleteRefused {
		return false, nil
	}

	// Keep session admission excluded until the node is gone from memory
	// too. This completes a dead winner's world removal as well: the world
	// delete is idempotent, and the node would otherwise orphan in peers'
	// maps until restart.
	s.world.DeleteNode(id)

	if outcome == deleteAlreadyGone {
		return false, nil
	}

	s.finishNodeDeletion(fresh)

	return true, nil
}

// ephemeralDeleteCandidate re-checks the node's lifetime under persistMu and
// returns the node to delete, or an invalid view if it is gone, no longer
// ephemeral, or has a live session.
func (s *State) ephemeralDeleteCandidate(id types.NodeID) (types.NodeView, error) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	node, ok := s.GetNodeByID(id)
	if !ok || !node.IsEphemeral() || node.ActiveSessions() > 0 {
		return types.NodeView{}, nil
	}

	return node, nil
}

// deleteEphemeralRow re-checks the lifetime under persistMu — the node may
// have changed since the candidate was picked — and writes the durable
// delete, returning the view the re-check read for the teardown. The lock is
// scoped to the row write with a deferred unlock, so a panic in the driver
// or a callback cannot leak it for the life of the process. The outcome is
// meaningful only when the error is nil.
func (s *State) deleteEphemeralRow(candidate types.NodeView) (deleteOutcome, types.NodeView, error) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	node, ok := s.GetNodeByID(candidate.ID())
	if !ok || !node.IsEphemeral() || node.ActiveSessions() > 0 {
		return deleteRefused, types.NodeView{}, nil
	}

	err := s.db.DeleteNode(node.AsStruct())
	if err != nil {
		// Both spellings mean another delete already dropped the row.
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, hsdb.ErrNodeNotFound) {
			return deleteAlreadyGone, types.NodeView{}, nil
		}

		return deleteRefused, types.NodeView{}, err
	}

	return deleteDroppedRow, node, nil
}

func (s *State) finishNodeDeletion(node types.NodeView) {
	s.ipAlloc.FreeIPs(node.IPs())

	if fn := s.onNodeDeleted.Load(); fn != nil {
		(*fn)(node.ID())
	}
}

// OnNodeDeleted sets fn to run after each node deletion, with the deleted
// node's ID, including conditional ephemeral garbage collection.
func (s *State) OnNodeDeleted(fn func(types.NodeID)) {
	s.onNodeDeleted.Store(&fn)
}

// Connect acquires a control session and returns a session epoch
// identifying this poll session, or 0 when the node is unknown. Every
// Connect acquires one live session; the caller must release it with
// exactly one [State.Disconnect] call once the session ends (see poll.go).
// An expired key can keep polling control, but cannot make the node online.
func (s *State) Connect(id types.NodeID) uint64 {
	s.connectMu.RLock()
	defer s.connectMu.RUnlock()

	// Reconnecting clears Unhealthy: the node just proved basic
	// connectivity by completing the Noise handshake.
	var epoch uint64

	node, ok := s.world.UpdateNode(id, func(n *types.Node) {
		n.SessionEpoch++
		epoch = n.SessionEpoch
		n.ActiveSessions++
		n.IsOnline = new(n.ShouldBeOnline())
		n.Unhealthy = false
	})
	if !ok {
		return 0
	}

	log.Info().EmbedObject(node).Msg("node connected")

	return epoch
}

// Disconnect releases one poll session previously acquired by
// [State.Connect] and marks the node offline when that was its
// last live session. Sessions are counted rather than compared by
// epoch: overlapping sessions for one node — a rapid reconnect, or a
// cancelled map request whose handler ran late — release in any order
// without stranding the node. An epoch-equality gate here loses when a
// dead-on-arrival session's Connect steals the latest epoch and its
// cleanup skips the release: the surviving session's Disconnect was
// then rejected as stale and the node stayed online forever.
// The count check and the IsOnline write share one
// [world.UpdateNode] closure, making them atomic against
// concurrent connects. epoch identifies the session for logging only.
func (s *State) Disconnect(id types.NodeID, epoch uint64) error {
	var wentOffline bool

	node, ok := s.world.UpdateNode(id, func(n *types.Node) {
		if n.ActiveSessions > 0 {
			n.ActiveSessions--
		}

		if n.ActiveSessions > 0 {
			return
		}

		wentOffline = true

		now := time.Now()
		n.LastSeen = &now
		n.IsOnline = new(n.ShouldBeOnline())
		// Offline nodes are not HA candidates; drop any stale
		// Unhealthy bit so it does not surface in DebugRoutes.
		n.Unhealthy = false
	})

	if !ok {
		return fmt.Errorf("%w: %d", ErrNodeNotFound, id)
	}

	if !wentOffline {
		log.Debug().
			Uint64("disconnect_epoch", epoch).
			Int("active_sessions", node.ActiveSessions()).
			Msg("session released, other control sessions remain")

		return nil
	}

	log.Info().EmbedObject(node).Msg("node disconnected")

	// Persist LastSeen best-effort: memory already reflects offline.
	_, err := s.persistNode(node)
	if err != nil {
		// A node whose row a lifetime delete already dropped still clears
		// its session here; the delete finishes removing the node
		// microseconds later, so this is the expected race, not a fault.
		if errors.Is(err, ErrNodeNotInNodeStore) {
			log.Debug().Err(err).EmbedObject(node).Msg("node vanished before last seen persist")

			return nil
		}

		log.Error().Err(err).EmbedObject(node).Msg("failed to update last seen in database")
	}

	return nil
}

// GetNodeByID retrieves a node by ID.
// GetNodeByID retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByID(nodeID types.NodeID) (types.NodeView, bool) {
	return s.Snapshot().GetNode(nodeID)
}

// GetNodeByNodeKey retrieves a node by its Tailscale public key.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	return s.Snapshot().GetNodeByNodeKey(nodeKey)
}

// GetNodesByMachineKeyAllUsers returns every node sharing the machine key,
// keyed by owning UserID (tagged nodes under UserID(0)). See
// [Snapshot.GetNodesByMachineKeyAllUsers].
func (s *State) GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView {
	return s.Snapshot().GetNodesByMachineKeyAllUsers(machineKey)
}

// ResolveNode looks up a node by numeric ID, IPv4/IPv6 address, given
// name, or hostname. It tries ID first, then IP, then GivenName
// (unique per tailnet), then Hostname (client-reported, may collide).
// Within the name passes, the lowest NodeID wins so repeated calls
// are deterministic across snapshot iterations.
func (s *State) ResolveNode(query string) (types.NodeView, bool) {
	snap := s.Snapshot()

	// Try numeric ID first.
	id, idErr := types.ParseNodeID(query)
	if idErr == nil {
		return snap.GetNode(id)
	}

	// keepLowest returns whichever node has the lower ID, so repeated
	// calls resolve deterministically across snapshot iterations.
	keepLowest := func(cur, cand types.NodeView) types.NodeView {
		if !cur.Valid() || cand.ID() < cur.ID() {
			return cand
		}

		return cur
	}

	// Try IP address.
	addr, addrErr := netip.ParseAddr(query)
	if addrErr == nil {
		var match types.NodeView

		for _, n := range snap.ListNodes().All() {
			if !slices.Contains(n.IPs(), addr) {
				continue
			}

			match = keepLowest(match, n)
		}

		return match, match.Valid()
	}

	// Try GivenName then Hostname, each with a stable tie-break on
	// lowest NodeID.
	var givenMatch, hostMatch types.NodeView

	for _, n := range snap.ListNodes().All() {
		if n.GivenName() == query {
			givenMatch = keepLowest(givenMatch, n)
		} else if n.Hostname() == query {
			hostMatch = keepLowest(hostMatch, n)
		}
	}

	if givenMatch.Valid() {
		return givenMatch, true
	}

	return hostMatch, hostMatch.Valid()
}

// ListNodes retrieves specific nodes by ID, or all nodes if no IDs provided.
func (s *State) ListNodes(nodeIDs ...types.NodeID) views.Slice[types.NodeView] {
	allNodes := s.Snapshot().ListNodes()
	if len(nodeIDs) == 0 {
		return allNodes
	}

	nodeIDSet := make(map[types.NodeID]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		nodeIDSet[id] = struct{}{}
	}

	var filteredNodes []types.NodeView

	for _, node := range allNodes.All() {
		if _, exists := nodeIDSet[node.ID()]; exists {
			filteredNodes = append(filteredNodes, node)
		}
	}

	return views.SliceOf(filteredNodes)
}

// ListNodesByUser retrieves all nodes belonging to a specific user.
func (s *State) ListNodesByUser(userID types.UserID) views.Slice[types.NodeView] {
	return s.Snapshot().ListNodesByUser(userID)
}

// ListPeers retrieves nodes that can communicate with the specified node
// based on policy, optionally narrowed to peerIDs.
func (s *State) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) views.Slice[types.NodeView] {
	peers := s.Snapshot().ListPeers(nodeID)
	if len(peerIDs) == 0 {
		return peers
	}

	// Resolve through the recipient's adjacency so a node the policy hides
	// from this recipient is never returned. Adjacency is built from node
	// pairs, so it never contains the recipient itself.
	nodeIDSet := make(map[types.NodeID]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		nodeIDSet[id] = struct{}{}
	}

	var filteredNodes []types.NodeView

	for _, peer := range peers.All() {
		if _, exists := nodeIDSet[peer.ID()]; exists {
			filteredNodes = append(filteredNodes, peer)
		}
	}

	return views.SliceOf(filteredNodes)
}

// ListEphemeralNodes retrieves all ephemeral (temporary) nodes in the system.
func (s *State) ListEphemeralNodes() views.Slice[types.NodeView] {
	var ephemeralNodes []types.NodeView

	for _, node := range s.Snapshot().ListNodes().All() {
		// Check if node is ephemeral by checking its AuthKey
		if node.AuthKey().Valid() && node.AuthKey().Ephemeral() {
			ephemeralNodes = append(ephemeralNodes, node)
		}
	}

	return views.SliceOf(ephemeralNodes)
}

// LogoutNode applies a client logout only to its still-current registration.
// The initial checks run unlocked for the early returns; the expiry write
// re-reads the node under persistMu and re-decides (logoutExpiry), so an
// admin write landing between the two cannot be stamped over.
func (s *State) LogoutNode(node types.NodeView, expiry *time.Time) (types.NodeView, error) {
	defer s.lockRegistration(node.MachineKey())()

	current, ok := s.GetNodeByID(node.ID())
	if !ok {
		return types.NodeView{}, ErrNodeNotInNodeStore
	}

	if current.NodeKey() != node.NodeKey() || current.MachineKey() != node.MachineKey() {
		return types.NodeView{}, ErrNodeKeyChanged
	}

	if current.IsExpired() {
		return current, nil
	}

	if current.IsEphemeral() {
		// The delete spans row and memory; keep session admission excluded
		// across all of it, as the ephemeral GC does. connectMu is taken
		// here, not persistMu: DeleteNode takes persistMu itself. Both are
		// released by defers, so a panicking delete cannot wedge admission
		// or the rest of the control plane.
		s.connectMu.Lock()
		defer s.connectMu.Unlock()

		return types.NodeView{}, s.DeleteNode(current)
	}
	// Client logout cannot expire a tagged device; admin expiry remains supported.
	if current.IsTagged() {
		return current, nil
	}

	// beforeLogoutWrite, for tests, interposes an admin write between the
	// unlocked checks above and the locked re-decision below.
	if fn := s.beforeLogoutWrite; fn != nil {
		fn()
	}

	return s.logoutExpiry(current, expiry)
}

// logoutExpiry stamps the logout expiry in one locked section: the node is
// re-read under persistMu and the tagged/expired guards re-decided against
// what the lock sees, so an admin retag landing between LogoutNode's read
// and this write cannot leave a tagged node expired by a client logout —
// #3371 territory, where a stale past stamp used to lock a node out for good.
func (s *State) logoutExpiry(stale types.NodeView, expiry *time.Time) (types.NodeView, error) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	current, ok := s.GetNodeByID(stale.ID())
	if !ok {
		return types.NodeView{}, ErrNodeNotInNodeStore
	}

	if current.NodeKey() != stale.NodeKey() || current.MachineKey() != stale.MachineKey() {
		return types.NodeView{}, ErrNodeKeyChanged
	}

	if current.IsExpired() || current.IsTagged() {
		return current, nil
	}

	return s.setNodeExpiryLocked(current.ID(), expiry)
}

// SetNodeExpiry updates the expiration time for a node.
// If expiry is nil, the node's expiry is disabled (node will never expire).
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry *time.Time) (types.NodeView, error) {
	// A client-reported expiry must round-trip the wire: refuse one that
	// cannot be encoded rather than storing what clients cannot read.
	if expiry != nil {
		utc, err := types.ValidateExpiry(*expiry)
		if err != nil {
			return types.NodeView{}, err
		}

		expiry = &utc
	}

	// A re-auth stages and persists a whole row under persistMu: an expiry
	// must not land between staging and publication and be overwritten.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	return s.setNodeExpiryLocked(nodeID, expiry)
}

// setNodeExpiryLocked is [State.SetNodeExpiry] for a caller holding
// persistMu. Callers re-reading the node under the same lock may re-decide
// against what they see; this helper only writes.
func (s *State) setNodeExpiryLocked(nodeID types.NodeID, expiry *time.Time) (types.NodeView, error) {
	// Memory first: it is what clients are served. The database update must
	// make the exact same change; if it fails, memory keeps the new expiry.
	n, ok := s.world.UpdateNode(nodeID, func(node *types.Node) {
		node.Expiry = expiry
		// Control stays connected in NeedsLogin so an expiry extension can
		// recover the client, but an expired key is not online.
		node.IsOnline = new(node.ShouldBeOnline())
	})

	if !ok {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	// Persist expiry directly: persistNode omits it.
	err := s.db.NodeSetExpiry(nodeID, expiry)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
		}

		return types.NodeView{}, fmt.Errorf("setting node expiry in database: %w", err)
	}

	return n, nil
}

// SetNodeTags assigns tags to a node, making it a "tagged node".
// Once a node is tagged, it cannot be un-tagged (only tags can be changed).
// Setting tags clears UserID since tagged nodes are owned by their tags.
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (types.NodeView, error) {
	if len(tags) == 0 {
		return types.NodeView{}, types.ErrCannotRemoveAllTags
	}

	snap := s.Snapshot()

	// Get node for validation
	existingNode, exists := snap.GetNode(nodeID)
	if !exists {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotFound, nodeID)
	}

	// Validate tags: must have correct format and exist in policy
	validatedTags := make([]string, 0, len(tags))
	invalidTags := make([]string, 0)

	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") || !snap.Policy().TagExists(tag) {
			invalidTags = append(invalidTags, tag)

			continue
		}

		validatedTags = append(validatedTags, tag)
	}

	if len(invalidTags) > 0 {
		return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, invalidTags)
	}

	slices.Sort(validatedTags)
	validatedTags = slices.Compact(validatedTags)

	// Log the operation
	logTagOperation(existingNode, validatedTags)

	// Held across both writes, as by SetNodeExpiry: a re-auth must not
	// publish staged ownership over a later admin retag.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	n, ok := s.world.UpdateNode(nodeID, func(node *types.Node) {
		node.Tags = validatedTags
		// Tagged nodes are owned by their tags, not a user.
		node.UserID = nil
		node.User = nil
	})

	if !ok {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	return s.persistNodeLocked(n)
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (types.NodeView, error) {
	// TODO(kradalby): In principle we should call the AutoApprove logic here
	// because even if the CLI removes an auto-approved route, it will be added
	// back automatically.
	n, ok := s.world.UpdateNode(nodeID, func(node *types.Node) {
		node.ApprovedRoutes = routes
		// A node with no approved routes is no longer an HA
		// candidate; drop any stale Unhealthy bit (mirrors the
		// legacy routes.SetRoutes(empty) auto-clear).
		if len(node.AllApprovedRoutes()) == 0 {
			node.Unhealthy = false
		}
	})

	if !ok {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	return s.persistNode(n)
}

// RenameNode changes the display name of a node. The admin supplies
// the exact DNS label they want; malformed input is rejected (no
// auto-sanitisation) and collisions error out rather than silently
// bumping a user-facing label. See HOSTNAME.md for the CLI contract.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (types.NodeView, error) {
	// DNS is case-insensitive but uniqueness and the client's certificate
	// name match are not, so "Foo" and "foo" would share one name.
	newName = strings.ToLower(newName)

	// Validate the label AND that the resulting FQDN fits MaxHostnameLength:
	// a valid 63-char label can still overflow under a long base_domain, and
	// an unmappable name would break this node and its peers (issue #3346).
	err := types.ValidateGivenName(newName, s.Snapshot().DNS().BaseDomain())
	if err != nil {
		return types.NodeView{}, fmt.Errorf("%w: %w", ErrGivenNameInvalid, err)
	}

	view, err := s.world.SetGivenName(nodeID, newName)
	if err != nil {
		switch {
		case errors.Is(err, ErrGivenNameTaken):
			return types.NodeView{}, fmt.Errorf("%w: %s", ErrNodeNameNotUnique, newName)
		case errors.Is(err, ErrNodeNotFound):
			return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
		default:
			return types.NodeView{}, fmt.Errorf("renaming node: %w", err)
		}
	}

	return s.persistNode(view)
}

// BackfillNodeIPs assigns IP addresses to nodes that don't have them.
func (s *State) BackfillNodeIPs() ([]string, error) {
	// Hold persistMu until memory has the new addresses, or a concurrent
	// persist writes the old ones back from memory in between.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	changes, err := s.db.BackfillNodeIPs(s.ipAlloc)
	if err != nil {
		return nil, err
	}

	if len(changes) == 0 {
		return changes, nil
	}

	nodes, err := s.db.ListNodes()
	if err != nil {
		return changes, fmt.Errorf("refreshing nodes after IP backfill: %w", err)
	}

	snap := s.Snapshot()

	// Copy only the IPs: the database rows lack runtime-only state such as
	// sessions and online status.
	updates := make(map[types.NodeID]UpdateNodeFunc)

	for _, node := range nodes {
		existing, ok := snap.GetNode(node.ID)
		if !ok || slices.Equal(existing.IPs(), node.IPs()) {
			continue
		}

		updates[node.ID] = func(n *types.Node) {
			n.IPv4 = node.IPv4
			n.IPv6 = node.IPv6
		}
	}

	s.world.UpdateNodes(updates)

	return changes, nil
}

// ExpireExpiredNodes marks nodes whose key expired since lastCheck offline.
// It returns the time to use as the next lastCheck and whether any node
// expired.
func (s *State) ExpireExpiredNodes(lastCheck time.Time) (time.Time, bool) {
	// Why capture start time: We need to ensure we don't miss nodes that expire
	// while this function is running by using a consistent timestamp for the next check
	started := time.Now()

	nodeUpdates := make(map[types.NodeID]UpdateNodeFunc)

	// The closures run one at a time inside the writer.
	var found bool

	for _, node := range s.Snapshot().ListNodes().All() { //nolint:unqueryvet // Snapshot.ListNodes not a SQL query
		if !node.Valid() {
			continue
		}

		// Why check After(lastCheck): We only want to handle nodes that
		// expired since the last check to avoid duplicate work.
		if !node.IsExpired() || !node.Expiry().Get().After(lastCheck) {
			continue
		}

		nodeUpdates[node.ID()] = func(n *types.Node) {
			// The key may have been restored since the snapshot was read.
			if !n.IsExpired() || !n.Expiry.After(lastCheck) {
				return
			}

			found = true
			n.IsOnline = new(n.ShouldBeOnline())
		}
	}

	// Commit simultaneous expirations together so route election sees all
	// unavailable nodes in one snapshot. The commit also wakes map streams,
	// which is what renders the expiry: Expired is computed from the clock,
	// not stored.
	s.world.UpdateNodes(nodeUpdates)

	return started, found
}

// SSHPolicy returns the SSH access policy for a node.
func (s *State) SSHPolicy(node types.NodeView) (*tailcfg.SSHPolicy, error) {
	return s.Snapshot().Policy().SSHPolicy(s.cfg.ServerURL, node)
}

// SSHCheckParams resolves the SSH check period for src logging in to dst
// as localUser from the current policy.
func (s *State) SSHCheckParams(
	srcNodeID, dstNodeID types.NodeID,
	localUser string,
) (time.Duration, bool) {
	return s.Snapshot().Policy().SSHCheckParams(srcNodeID, dstNodeID, localUser)
}

// Filter returns the current network filter rules and matches.
func (s *State) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	return s.Snapshot().Policy().Filter()
}

// NodeCanHaveTag checks if a node is allowed to have a specific tag.
func (s *State) NodeCanHaveTag(node types.NodeView, tag string) bool {
	return s.Snapshot().Policy().NodeCanHaveTag(node, tag)
}

// policyTester is the part of the v2 policy manager [policy.PolicyManager]
// does not expose: running the document's own tests.
type policyTester interface {
	RunTests() error
	RunSSHTests() error
}

// SetPolicy replaces the policy document and reports whether it differs
// from the current one. A document that does not compile against the
// users and nodes it is published with, or whose own tests fail against
// them, is rejected and leaves the policy as it was. An empty document is
// ignored, and the live one is accepted unchanged even when its tests fail
// since: refusing it would keep out nothing, and would fail the reload
// that runs auto-approval.
func (s *State) SetPolicy(pol []byte) (bool, error) {
	if len(pol) == 0 {
		return false, nil
	}

	// An unchanged document is already live: recompiling it would only
	// wake every map stream, and its tests cannot keep out what is already
	// in. Boot only warns about them for the same reason.
	if bytes.Equal(pol, s.Snapshot().PolicySource()) {
		return false, nil
	}

	changed, err := s.publishPolicy(bytes.Clone(pol))
	if err != nil || !changed {
		return false, err
	}

	// Clear SSH check auth times so stale approvals don't persist if
	// checkPeriod rules were modified or removed.
	s.ClearSSHCheckAuth()

	return true, nil
}

// policyAttempts is how often [State.SetPolicy] tries to publish a
// document: every try but the last tests it outside the world's lock.
const policyAttempts = 3

var errPolicyInputsMoved = errors.New("policy users or nodes changed while its tests ran")

// publishPolicy publishes pol once it compiles and its tests pass against
// the users and nodes of the commit publishing it, so a refused document
// is never served, not even briefly. Tests run outside the world's lock:
// an sshTest compiles SSH for every node it names, seconds at scale, and
// every write would wait on it. The commit refuses a document whose users
// or nodes moved meanwhile, and it is tested again; on the last try the
// commit runs the tests itself, holding every write while they run. Only a
// user added, removed or changed in name, email or provider identity, or a
// node joining, leaving or changing its addresses, owner, tags or routes,
// during each earlier try leads there. The tests check a candidate compiled
// from scratch, the commit publishes the world's incremental compile of
// the same inputs; the policy audit is what holds the two equal.
func (s *State) publishPolicy(pol []byte) (bool, error) {
	for range policyAttempts - 1 {
		snap := s.Snapshot()
		users, nodes, inputs := snap.policyInputs()

		candidate, err := policy.NewPolicyManager(pol, users, nodes)
		if err != nil {
			return false, err
		}

		err = policyTestsFail(candidate)
		if err != nil {
			return false, err
		}

		changed, err := s.world.SetPolicy(pol, func(next *Snapshot) error {
			if _, _, moved := next.policyInputs(); moved != inputs {
				return errPolicyInputsMoved
			}

			return next.PolicyErr()
		})
		if !errors.Is(err, errPolicyInputsMoved) {
			return changed, err
		}
	}

	return s.world.SetPolicy(pol, func(next *Snapshot) error {
		return multierr.New(next.PolicyErr(), policyTestsFail(next.Policy()))
	})
}

// policyTestsFail returns why pm's tests or sshTests fail.
func policyTestsFail(pm policy.PolicyManager) error {
	if t, ok := pm.(policyTester); ok {
		return multierr.New(t.RunTests(), t.RunSSHTests())
	}

	return nil
}

// AutoApproveRoutes approves the node's announced routes the policy
// auto-approves, and stores the result.
func (s *State) AutoApproveRoutes(nv types.NodeView) error {
	approved, changed := policy.ApproveRoutesWithPolicy(s.Snapshot().Policy(), nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
	if !changed {
		return nil
	}

	log.Debug().
		EmbedObject(nv).
		Strs("routes.announced", util.PrefixesToString(nv.AnnouncedRoutes())).
		Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
		Strs("routes.approved.new", util.PrefixesToString(approved)).
		Msg("Single node auto-approval detected route changes")

	_, err := s.SetApprovedRoutes(nv.ID(), approved)
	if err != nil {
		log.Error().
			EmbedObject(nv).
			Err(err).
			Msg("Failed to persist auto-approved routes")

		return err
	}

	log.Info().EmbedObject(nv).Strs(zf.RoutesApproved, util.PrefixesToString(approved)).Msg("routes approved")

	return nil
}

// GetPolicy retrieves the current policy from the database.
func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy()
}

// SetPolicyInDB stores policy data in the database.
func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data)
}

// GetNodePrimaryRoutes returns the primary routes for a node.
func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.Snapshot().PrimaryRoutesForNode(nodeID)
}

// PrimaryRoutesString renders the current prefix→primary assignment
// for diagnostics.
func (s *State) PrimaryRoutesString() string {
	return s.Snapshot().PrimaryRoutesString()
}

// IsNodeHealthy reports the HA prober's view of id. Unknown nodes
// report healthy.
func (s *State) IsNodeHealthy(id types.NodeID) bool {
	return s.Snapshot().IsNodeHealthy(id)
}

// SetNodeHealth flips the runtime health bit for one node and reports
// whether the resulting primary-route assignment changed. true means
// healthy; false means unhealthy. An unhealthy mark is dropped when
// the node is no longer an HA candidate (offline or no approved
// routes) — between probe dispatch and result the node may have left
// candidacy, and the bit would just be stale. The check happens
// inside the writer so it serialises against the
// SetApprovedRoutes / Disconnect that removed candidacy. Single-node
// convenience wrapper around [State.BatchSetNodeHealth].
func (s *State) SetNodeHealth(id types.NodeID, healthy bool) bool {
	return s.BatchSetNodeHealth(map[types.NodeID]bool{id: healthy})
}

// BatchSetNodeHealth applies a set of health updates atomically: the
// election runs once after every flag has been flipped, so observers
// never see an intermediate snapshot. Returns true when the
// primary-route assignment differs from before the batch. Map value
// true = healthy; false = unhealthy (gated as in [State.SetNodeHealth]).
//
// Per-call publication would let a writer applying two flips
// back-to-back elect a node that the next snapshot demotes,
// momentarily pointing peers at the wrong primary; the batched form
// closes that window.
func (s *State) BatchSetNodeHealth(updates map[types.NodeID]bool) bool {
	if len(updates) == 0 {
		return false
	}

	snap := s.Snapshot()
	prevRoutes := snap.PrimaryRoutes()

	// Skip writes that would not change anything so an all-unchanged
	// probe cycle publishes no snapshot. healthSetter stays authoritative
	// for the candidacy and race checks under the writer.
	fns := make(map[types.NodeID]UpdateNodeFunc, len(updates))

	for id, healthy := range updates {
		if nv, ok := snap.GetNode(id); ok && nv.Unhealthy() == !healthy {
			haHealthUpdates.WithLabelValues("unchanged").Inc()

			continue
		}

		fns[id] = healthSetter(healthy)
	}

	if len(fns) == 0 {
		return false
	}

	s.world.UpdateNodes(fns)

	return !maps.Equal(prevRoutes, s.Snapshot().PrimaryRoutes())
}

// healthSetter returns an UpdateNodeFunc that flips n.Unhealthy to
// the inverse of healthy, with the same gate as [State.SetNodeHealth]:
// an unhealthy mark only sticks when the node is still online and
// still advertises approved routes, so a node that left HA candidacy
// between probe dispatch and result does not carry a stale bit.
// Bounded labels only: every requested health update lands in exactly one
// outcome, so the series can be summed to the probe request count.
var haHealthUpdates = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: prometheusNamespace,
	Name:      "ha_health_updates_total",
	Help:      "HA health updates by outcome: unchanged and skipped, applied, or rejected because the node left candidacy.",
}, []string{"result"})

func healthSetter(healthy bool) UpdateNodeFunc {
	return func(n *types.Node) {
		if !healthy {
			if !n.Online() || len(n.AllApprovedRoutes()) == 0 {
				haHealthUpdates.WithLabelValues("rejected").Inc()

				return
			}
		}

		haHealthUpdates.WithLabelValues("changed").Inc()

		n.Unhealthy = !healthy
	}
}

// ValidateAPIKey checks if an API key is valid and active.
func (s *State) ValidateAPIKey(keyStr string) (bool, error) {
	return s.db.ValidateAPIKey(keyStr)
}

// AuthenticateAPIKey validates an API key and returns it (with its owning
// user), so callers like the v2 API can act as the key's owner.
func (s *State) AuthenticateAPIKey(keyStr string) (*types.APIKey, error) {
	return s.db.AuthenticateAPIKey(keyStr)
}

// SetAPIKeyUser sets the owning user of an API key by its database ID.
func (s *State) SetAPIKeyUser(keyID uint64, userID types.UserID) error {
	return s.db.SetAPIKeyUser(keyID, userID)
}

// CreateAPIKey generates a new API key with optional expiration.
func (s *State) CreateAPIKey(expiration *time.Time) (string, *types.APIKey, error) {
	return s.db.CreateAPIKey(expiration)
}

// GetAPIKey retrieves an API key by its prefix.
// Accepts both display format (hskey-api-{12chars}-***) and database format ({12chars}).
func (s *State) GetAPIKey(displayPrefix string) (*types.APIKey, error) {
	// Parse the display prefix to extract the database prefix
	prefix, err := hsdb.ParseAPIKeyPrefix(displayPrefix)
	if err != nil {
		return nil, err
	}

	return s.db.GetAPIKey(prefix)
}

// GetAPIKeyByID retrieves an API key by its database ID.
func (s *State) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	return s.db.GetAPIKeyByID(id)
}

// ExpireAPIKey marks an API key as expired.
func (s *State) ExpireAPIKey(key *types.APIKey) error {
	return s.db.ExpireAPIKey(key)
}

// ListAPIKeys returns all API keys in the system.
func (s *State) ListAPIKeys() ([]types.APIKey, error) {
	return s.db.ListAPIKeys()
}

// DestroyAPIKey permanently removes an API key.
func (s *State) DestroyAPIKey(key types.APIKey) error {
	return s.db.DestroyAPIKey(key)
}

// CreatePreAuthKey generates a new pre-authentication key for a user.
// The userID parameter is now optional (can be nil) for system-created tagged keys.
func (s *State) CreatePreAuthKey(userID *types.UserID, reusable bool, ephemeral bool, expiration *time.Time, aclTags []string) (*types.PreAuthKeyNew, error) {
	return s.db.CreatePreAuthKey(userID, reusable, ephemeral, expiration, aclTags)
}

// Test helpers for the state layer

// CreateUserForTest creates a test user. This is a convenience wrapper around the database layer.
func (s *State) CreateUserForTest(name ...string) *types.User {
	return s.db.CreateUserForTest(name...)
}

// CreateNodeForTest creates a test node. This is a convenience wrapper around the database layer.
func (s *State) CreateNodeForTest(user *types.User, hostname ...string) *types.Node {
	return s.db.CreateNodeForTest(user, hostname...)
}

// PutNodeInStoreForTest writes a test node into memory so handlers backed by
// [Snapshot] lookups (e.g. [State.GetNodeByID]) can see it.
// [State.CreateNodeForTest] only saves to the database, which is fine for
// tests that exercise the DB layer directly but insufficient for handler
// tests that go through [State].
func (s *State) PutNodeInStoreForTest(node types.Node) types.NodeView {
	return s.world.PutNode(node)
}

// DeleteNodeFromStoreForTest removes a node from memory without touching the
// database. Used to force [State.UpdateNodeFromMapRequest] failures in
// poll-session tests while keeping the DB row intact for later restore.
func (s *State) DeleteNodeFromStoreForTest(id types.NodeID) {
	s.world.DeleteNode(id)
}

// UpdatePolicyManagerNodesForTest is a no-op kept for tests: the policy is
// recompiled whenever a node it reads changes.
func (s *State) UpdatePolicyManagerNodesForTest() error {
	return nil
}

// CreateRegisteredNodeForTest creates a test node with allocated IPs. This is a convenience wrapper around the database layer.
func (s *State) CreateRegisteredNodeForTest(user *types.User, hostname ...string) *types.Node {
	return s.db.CreateRegisteredNodeForTest(user, hostname...)
}

// CreateNodesForTest creates multiple test nodes. This is a convenience wrapper around the database layer.
func (s *State) CreateNodesForTest(user *types.User, count int, namePrefix ...string) []*types.Node {
	return s.db.CreateNodesForTest(user, count, namePrefix...)
}

// CreateUsersForTest creates multiple test users. This is a convenience wrapper around the database layer.
func (s *State) CreateUsersForTest(count int, namePrefix ...string) []*types.User {
	return s.db.CreateUsersForTest(count, namePrefix...)
}

// DB returns the underlying database for testing purposes.
func (s *State) DB() *hsdb.HSDatabase {
	return s.db
}

// GetPreAuthKey retrieves a pre-authentication key by its secret. The caller is
// responsible for checking whether the key is usable (expired or used).
func (s *State) GetPreAuthKey(keyStr string) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKey(keyStr)
}

// GetPreAuthKeyByID retrieves a pre-authentication key by its database id.
func (s *State) GetPreAuthKeyByID(id uint64) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKeyByID(id)
}

// RevokePreAuthKey soft-revokes a pre-authentication key: it is kept and stays
// retrievable (invalid) until the collector reaps it after the retention window.
func (s *State) RevokePreAuthKey(id uint64) error {
	return s.db.RevokePreAuthKey(id)
}

// DestroyRevokedPreAuthKeysBefore hard-deletes pre-auth keys revoked before
// cutoff, returning how many were removed.
func (s *State) DestroyRevokedPreAuthKeysBefore(cutoff time.Time) (int, error) {
	return s.db.DestroyRevokedPreAuthKeysBefore(cutoff)
}

// ListPreAuthKeys returns all pre-authentication keys for a user.
func (s *State) ListPreAuthKeys() ([]types.PreAuthKey, error) {
	return s.db.ListPreAuthKeys()
}

// SetPreAuthKeyDescription sets the free-text description on a pre-auth key.
func (s *State) SetPreAuthKeyDescription(id uint64, description string) error {
	return s.db.SetPreAuthKeyDescription(id, description)
}

// ExpirePreAuthKey marks a pre-authentication key as expired.
func (s *State) ExpirePreAuthKey(id uint64) error {
	return s.db.ExpirePreAuthKey(id)
}

// DeletePreAuthKey permanently deletes a pre-authentication key.
func (s *State) DeletePreAuthKey(id uint64) error {
	return s.db.DeletePreAuthKey(id)
}

// CreateOAuthClient creates a new OAuth client-credentials client, returning the
// plaintext secret (shown once) and the stored client.
func (s *State) CreateOAuthClient(scopes, tags []string, description string, creatorUserID *uint) (string, *types.OAuthClient, error) {
	return s.db.CreateOAuthClient(scopes, tags, description, creatorUserID)
}

// AuthenticateOAuthClient validates a client secret and returns the client.
func (s *State) AuthenticateOAuthClient(secret string) (*types.OAuthClient, error) {
	return s.db.AuthenticateOAuthClient(secret)
}

// GetOAuthClientByClientID returns an OAuth client by its public client id.
func (s *State) GetOAuthClientByClientID(clientID string) (*types.OAuthClient, error) {
	return s.db.GetOAuthClientByClientID(clientID)
}

// ListOAuthClients returns every OAuth client.
func (s *State) ListOAuthClients() ([]types.OAuthClient, error) {
	return s.db.ListOAuthClients()
}

// RevokeOAuthClient deletes a client and the access tokens it issued.
func (s *State) RevokeOAuthClient(clientID string) error {
	return s.db.RevokeOAuthClient(clientID)
}

// MintAccessToken stores a new scoped access token for an OAuth client.
func (s *State) MintAccessToken(clientID string, scopes, tags []string, expiration *time.Time) (string, *types.OAuthAccessToken, error) {
	return s.db.MintAccessToken(clientID, scopes, tags, expiration)
}

// AuthenticateAccessToken validates a bearer access token and returns it with
// its granted scopes and tags.
func (s *State) AuthenticateAccessToken(token string) (*types.OAuthAccessToken, error) {
	return s.db.AuthenticateAccessToken(token)
}

// TagOwnedByTags reports whether a credential holding ownerTags may apply tag,
// per the policy's tag-to-tag ownership. Used to authorise the tags an OAuth
// access token sets on the auth keys it mints.
func (s *State) TagOwnedByTags(tag string, ownerTags []string) bool {
	return s.Snapshot().Policy().TagOwnedByTags(tag, ownerTags)
}

// TagExists reports whether tag is defined in the policy's tagOwners. Used to
// reject OAuth clients and auth keys carrying tags that no policy authorises,
// matching SetNodeTags.
func (s *State) TagExists(tag string) bool {
	return s.Snapshot().Policy().TagExists(tag)
}

// DeleteExpiredAccessTokens hard-deletes OAuth access tokens that expired before
// cutoff, returning how many were removed.
func (s *State) DeleteExpiredAccessTokens(cutoff time.Time) (int64, error) {
	return s.db.DeleteExpiredAccessTokens(cutoff)
}

// GetAuthCacheEntry retrieves a pending auth request from the cache.
func (s *State) GetAuthCacheEntry(id types.AuthID) (*types.AuthRequest, bool) {
	return s.authCache.Get(id)
}

// DeleteAuthCacheEntry releases a consumed authentication transaction.
func (s *State) DeleteAuthCacheEntry(id types.AuthID) {
	s.authCache.Remove(id)
}

// SetAuthCacheEntry admits a pending authentication without displacing
// existing transactions. Regular (unauthenticated registration) entries
// fill only their allocation; dead entries are dropped first, so a full
// cache never evicts a live session to admit another.
func (s *State) SetAuthCacheEntry(id types.AuthID, entry *types.AuthRequest) error {
	s.authCacheMu.Lock()
	defer s.authCacheMu.Unlock()

	if s.authCacheClosed {
		return ErrAuthCacheClosed
	}

	if existing, ok := s.authCache.Peek(id); ok {
		if existing == entry {
			return nil
		}

		return ErrAuthCacheEntryExists
	}

	s.authCache.Remove(id)

	if entry.IsFinished() {
		return ErrAuthRequestFinished
	}

	for {
		oldest, _, ok := s.authCache.GetOldest()
		if !ok {
			break
		}

		if _, live := s.authCache.Peek(oldest); live {
			break
		}

		s.authCache.Remove(oldest)
	}

	if (!entry.IsSSHCheck() && s.authCacheRegularEntries.Load() >= int64(s.authCacheMaxEntries)) ||
		s.authCache.Len() >= s.authCacheMaxEntries+authCacheSSHReserve {
		return ErrAuthCacheFull
	}

	err := entry.PrepareForCache()
	if err != nil {
		return err
	}

	if !entry.IsSSHCheck() {
		s.authCacheRegularEntries.Add(1)
	}

	s.authCache.Add(id, entry)

	return nil
}

// DeleteAuthCacheEntryForTest drops a pending auth request from the cache,
// exposed for testing so a test can reproduce a session that was lost
// (expired, evicted, or dropped on a control-plane restart) without faking an
// auth_id.
func (s *State) DeleteAuthCacheEntryForTest(id types.AuthID) {
	s.authCache.Remove(id)
}

// SetLastSSHAuth records a successful SSH check authentication
// for the given (src, dst) node pair.
func (s *State) SetLastSSHAuth(src, dst types.NodeID) {
	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	s.sshCheckAuth[sshCheckPair{Src: src, Dst: dst}] = time.Now()
}

// GetLastSSHAuth returns when src last authenticated for SSH check
// to dst.
func (s *State) GetLastSSHAuth(src, dst types.NodeID) (time.Time, bool) {
	s.sshCheckMu.RLock()
	defer s.sshCheckMu.RUnlock()

	t, ok := s.sshCheckAuth[sshCheckPair{Src: src, Dst: dst}]

	return t, ok
}

// ClearSSHCheckAuth clears all recorded SSH check auth times.
// Called when the policy changes to ensure stale auth times don't grant access.
func (s *State) ClearSSHCheckAuth() {
	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	s.sshCheckAuth = make(map[sshCheckPair]time.Time)
}

// preserveNetInfo preserves NetInfo from an existing node for faster DERP connectivity.
// If no existing node is provided, it creates new netinfo from the provided hostinfo.
func preserveNetInfo(existingNode types.NodeView, nodeID types.NodeID, validHostinfo *tailcfg.Hostinfo) *tailcfg.NetInfo {
	var existingHostinfo *tailcfg.Hostinfo
	if existingNode.Valid() {
		existingHostinfo = existingNode.Hostinfo().AsStruct()
	}

	return netInfoFromMapRequest(nodeID, existingHostinfo, validHostinfo)
}

// newNodeParams contains parameters for creating a new node.
type newNodeParams struct {
	User           types.User
	MachineKey     key.MachinePublic
	NodeKey        key.NodePublic
	DiscoKey       key.DiscoPublic
	Hostname       string
	Hostinfo       *tailcfg.Hostinfo
	Endpoints      []netip.AddrPort
	Expiry         *time.Time
	RegisterMethod string

	// Optional: Pre-auth key specific fields
	PreAuthKey *types.PreAuthKey

	// Optional: Existing node for netinfo preservation
	ExistingNodeForNetinfo types.NodeView
}

// authNodeUpdateParams contains parameters for updating an existing node during auth.
type authNodeUpdateParams struct {
	// Node to update; must be valid and in memory.
	ExistingNode types.NodeView
	// Cached registration payload from the originating client request.
	RegData *types.RegistrationData
	// Pre-validated hostinfo; NetInfo preserved from ExistingNode.
	ValidHostinfo *tailcfg.Hostinfo
	// Hostname from hostinfo, or generated from keys if client omits it.
	Hostname string
	// Auth user; may differ from ExistingNode.User() on conversion.
	User *types.User
	// Overrides RegData.Expiry; ignored for tagged nodes.
	Expiry *time.Time
	// Only used when IsConvertFromTag=true.
	RegisterMethod string
	// Set true for tagged->user conversion. Affects RegisterMethod only;
	// expiry follows the resulting tagged status of the staged candidate.
	IsConvertFromTag bool
}

// applyAuthNodeUpdate applies common update logic for re-authenticating or converting
// an existing node. It authorises a private candidate, persists it, then
// publishes its registration fields without replacing concurrent map updates.
// applyReauthExpiryTransition sets a re-auth candidate's expiry from the
// tagged-status transition and the client's request: tagged nodes never
// expire, a stale past expiry from an old logout stamp (#3371) is cleared,
// and everything else takes the requested or cached expiry.
func applyReauthExpiryTransition(
	node *types.Node,
	wasTagged bool,
	requested, cached *time.Time,
) {
	isTagged := node.IsTagged()

	switch {
	case !wasTagged && isTagged:
		// Personal → Tagged: clear expiry (tagged nodes don't expire)
		node.Expiry = nil
	case !isTagged:
		// Tagged → Personal (including explicit conversion) and
		// Personal → Personal: set expiry from client request.
		node.Expiry = cmp.Or(requested, cached)
	case isTagged && node.IsExpired():
		// Tagged → Tagged, but carrying a stale PAST expiry from an older
		// headscale's logout stamp (#3371). Tagged nodes never expire, so
		// clear it; a deliberate future expiry has IsExpired() == false and
		// falls through to the no-op below.
		node.Expiry = nil
	}
	// Tagged → Tagged with no stale expiry: keep existing expiry - no action.
}

func (s *State) applyAuthNodeUpdate(params authNodeUpdateParams) (types.NodeView, error) {
	regData := params.RegData

	// Log the operation type
	if params.IsConvertFromTag {
		log.Info().
			EmbedObject(params.ExistingNode).
			Strs("old.tags", params.ExistingNode.Tags().AsSlice()).
			Msg("Converting tagged node to user-owned node")
	} else {
		log.Info().
			Object("existing", params.ExistingNode).
			Str("incoming.hostname", regData.Hostname).
			Str("incoming.machine_key", regData.MachineKey.ShortString()).
			Msg("Updating existing node registration via reauth")
	}

	// Process RequestTags during reauth (#2979).
	// Due to json:",omitempty", empty/nil from the cached Hostinfo
	// means "clear tags".
	var requestTags []string
	if regData.Hostinfo != nil {
		requestTags = regData.Hostinfo.RequestTags
	}

	oldTags := params.ExistingNode.Tags().AsSlice()

	// Tags are authorised when staging below, against the current policy.
	// A later policy change does not undo that authorisation, as with a new
	// registration. A tag-owned node carries no user and its IP is not in
	// any tag owner's set, so checking the node alone rejects every tag on
	// re-auth (#3374); the authenticating user is checked too.

	// Stage without editing the graph: a failed row write must never expose
	// a provisional identity to readers or wake map streams.
	var (
		prior, candidate *types.Node
		rejectedTags     []string
	)

	// Held through publication so a concurrent persistNode cannot overwrite
	// the durable registration with the old identity still in memory.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	// Claim the rotated key across the staged write: a fresh registration
	// claiming it must finish its insert first, so the check below sees it.
	defer s.lockNodeKey(regData.NodeKey)()

	s.beforeAuthWrite()

	// Re-auth rotates the NodeKey to the client-supplied value. Enforce the
	// same 1:1 NodeKey<->MachineKey binding createAndSaveNewNode applies at
	// registration and getAndValidateNode enforces at poll time: a NodeKey
	// already bound to a different machine must not be claimed here, or a
	// re-authenticating node could rotate its key to a victim's and poison
	// the NodeKey index (denying the victim service).
	// Check under persistMu and the keyed claim, after earlier claims of this
	// key — re-authentications and fresh inserts alike — have published.
	if existing, ok := s.Snapshot().GetNodeByNodeKey(regData.NodeKey); ok &&
		existing.MachineKey() != regData.MachineKey {
		return types.NodeView{}, ErrNodeKeyInUse
	}

	var hostinfoErr error

	s.world.update(func(nodes *nodeEdit) {
		var ok bool

		prior, ok = nodes.Get(params.ExistingNode.ID())
		if !ok {
			return
		}

		node := prior.Clone()
		node.NodeKey = regData.NodeKey
		// A pending registration carries no disco key; the live one stays
		// until the node reports a new one.
		if !regData.DiscoKey.IsZero() {
			node.DiscoKey = regData.DiscoKey
		}
		node.Hostname = params.Hostname

		// A re-auth keeps the node's stored operational metadata and takes
		// only the auth-relevant fields from the registration: the client
		// reports operational metadata via MapRequest, not register, and a
		// browser-facilitated relogin carries a hostinfo the node never
		// sent. The merged result must still pass the wire bounds.
		node.Hostinfo = cmp.Or(prior.Hostinfo.Clone(), &tailcfg.Hostinfo{})
		node.Hostinfo.Hostname = params.Hostname
		node.Hostinfo.RequestTags = slices.Clone(requestTags)

		hostinfoErr = types.ValidateHostinfo(node.Hostinfo)
		if hostinfoErr != nil {
			return
		}

		node.Hostinfo.NetInfo = preserveNetInfo(
			prior.View(),
			prior.ID,
			params.ValidHostinfo,
		)

		// Preserve the node's live endpoints when the register request carried
		// none. Web/OIDC relogins report endpoints via MapRequest, not register,
		// so RegData.Endpoints is empty; clearing the stored set would advertise
		// the re-keyed node with no way for peers to reach it. The first
		// MapRequest restores the live set.
		if len(regData.Endpoints) > 0 {
			node.Endpoints = regData.Endpoints
		}
		// Preserve online state during re-registration so a live node does
		// not appear offline before the client restarts its map stream.
		node.LastSeen = new(time.Now())

		// On conversion (tagged → user) we set the new register method.
		// On plain reauth we preserve the existing node.RegisterMethod;
		// the cached RegistrationData no longer carries it because the
		// producer never populated it.
		if params.IsConvertFromTag {
			node.RegisterMethod = params.RegisterMethod
		}

		// Track tagged status BEFORE processing tags
		wasTagged := node.IsTagged()

		// Process tags - may change node.Tags and node.UserID. A rejected
		// tag discards the candidate: nothing of this write commits.
		rejectedTags = s.processReauthTags(node, requestTags, params.User, oldTags)
		if len(rejectedTags) > 0 {
			return
		}

		// Handle expiry AFTER tag processing, based on transition
		// This ensures expiry is correctly set/cleared based on the NEW
		// tagged status.
		applyReauthExpiryTransition(node, wasTagged, params.Expiry, regData.Expiry)

		// Apply default node expiry for non-tagged nodes when the
		// resolved expiry is still nil or zero (e.g., CLI registration
		// where the client did not request a specific expiry).
		needsDefaultExpiry := !node.IsTagged() &&
			(node.Expiry == nil || node.Expiry.IsZero()) &&
			s.cfg.Node.Expiry > 0
		if needsDefaultExpiry {
			exp := time.Now().Add(s.cfg.Node.Expiry)
			node.Expiry = &exp
		}

		candidate = node
	})

	if prior == nil {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, params.ExistingNode.ID())
	}

	if hostinfoErr != nil {
		return types.NodeView{}, hostinfoErr
	}

	if len(rejectedTags) > 0 {
		return types.NodeView{}, fmt.Errorf(
			"%w %v are invalid or not permitted",
			ErrRequestedTagsInvalidOrNotPermitted,
			rejectedTags,
		)
	}

	// Persist to database.
	// Explicitly select all node columns so GORM includes nil/zero-value fields
	// (see nodeUpdateColumns comment).
	//
	// AuthKeyID is excluded from nodeUpdateColumns (#2862: never persist a
	// possibly-deleted key's stale reference on the shared update path). But
	// when a re-auth untags a node it clears AuthKeyID to nil (above), and that
	// must persist or the node reloads as tagged/ephemeral after a restart and
	// is garbage-collected. Writing NULL can never cause an FK error, so include
	// the column only in that clearing case; the other transitions keep the
	// #2862-safe column set untouched.
	updateColumns := nodeUpdateColumns
	if candidate.AuthKeyID == nil {
		updateColumns = append(slices.Clone(nodeUpdateColumns), "AuthKeyID")
	}

	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		result := tx.Select(updateColumns).Updates(candidate)
		if result.Error != nil {
			return nil, fmt.Errorf("saving node: %w", result.Error)
		}

		if result.RowsAffected == 0 {
			return nil, ErrNodeNotInNodeStore
		}

		return nil, nil //nolint:nilnil // side-effect only write
	})
	if err != nil {
		return types.NodeView{}, err
	}

	updatedNodeView, err := s.publishRegistration(prior, candidate)
	if err != nil {
		return types.NodeView{}, err
	}

	// Log completion
	if params.IsConvertFromTag {
		log.Trace().
			EmbedObject(updatedNodeView).
			Msg("Tagged node converted to user-owned")
	} else {
		log.Trace().
			EmbedObject(updatedNodeView).
			Msg("Node re-authorized")
	}

	return updatedNodeView, nil
}

// publishRegistration merges a durable registration into the latest node.
// The caller holds persistMu: expiry, ownership and row deletion cannot race,
// but map updates, sessions and user refreshes remain live during the SQL write.
func (s *State) publishRegistration(prior, candidate *types.Node) (types.NodeView, error) {
	node, ok := s.world.UpdateNode(prior.ID, func(n *types.Node) {
		n.NodeKey = candidate.NodeKey
		n.RegisterMethod = candidate.RegisterMethod
		n.Tags, n.UserID = candidate.Tags, candidate.UserID
		n.AuthKey, n.AuthKeyID = candidate.AuthKey, candidate.AuthKeyID
		n.Expiry = candidate.Expiry
		n.IsOnline = new(n.ShouldBeOnline())

		// An unchanged owner already includes concurrent user refreshes.
		if n.UserID == nil {
			n.User = nil
		} else if n.User == nil || n.User.ID != *n.UserID {
			n.User = candidate.User
			for _, u := range s.Snapshot().Users() {
				if u.ID == *n.UserID {
					n.User = &u

					break
				}
			}
		}

		if n.Hostinfo.Equal(prior.Hostinfo) {
			n.Hostname = candidate.Hostname
			n.Hostinfo = candidate.Hostinfo
		}

		if n.DiscoKey == prior.DiscoKey {
			n.DiscoKey = candidate.DiscoKey
		}

		if slices.Equal(n.Endpoints, prior.Endpoints) {
			n.Endpoints = candidate.Endpoints
		}

		if n.LastSeen == nil || n.LastSeen.Before(*candidate.LastSeen) {
			n.LastSeen = candidate.LastSeen
		}
	})
	if !ok {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, prior.ID)
	}

	return node, nil
}

// createAndSaveNewNode creates a new node, allocates IPs, saves to DB, and adds it to memory.
// It preserves netinfo from an existing node if one is provided (for faster DERP connectivity).
func (s *State) createAndSaveNewNode(params newNodeParams) (types.NodeView, error) {
	// A NodeKey claim is exclusive per key, held until the row is inserted
	// and published: a re-auth rotating onto this key (applyAuthNodeUpdate,
	// reregisterNodeWithPAK, which claim it under persistMu) must not have
	// its index poisoned by a duplicate. persistMu is deliberately absent —
	// it would serialise every join behind every other and defeat the
	// group-commit batching; a staged re-auth is invisible to the snapshot
	// below, which is exactly why the claim has to cover the whole write.
	defer s.lockNodeKey(params.NodeKey)()

	// Preserve NetInfo from existing node if available
	if params.Hostinfo != nil {
		params.Hostinfo.NetInfo = preserveNetInfo(
			params.ExistingNodeForNetinfo,
			types.NodeID(0),
			params.Hostinfo,
		)
	}

	// Enforce NodeKey uniqueness across machines. NodeKeys are public
	// (peers learn them from the netmap), so an authenticated party could
	// otherwise register a node carrying a victim's NodeKey, poisoning the
	// NodeKey index so the victim's MapRequest resolves to the
	// wrong node and is rejected by getAndValidateNode's MachineKey check
	// (a DoS). createAndSaveNewNode only runs for a machine that has no
	// existing node, so any current holder of this NodeKey is a different
	// machine; mirror the 1:1 binding getAndValidateNode enforces at poll
	// time and reject before allocating any resources.
	if existing, ok := s.Snapshot().GetNodeByNodeKey(params.NodeKey); ok &&
		existing.MachineKey() != params.MachineKey {
		return types.NodeView{}, ErrNodeKeyInUse
	}

	// Prepare the node for registration
	nodeToRegister := types.Node{
		Hostname:       params.Hostname,
		MachineKey:     params.MachineKey,
		NodeKey:        params.NodeKey,
		DiscoKey:       params.DiscoKey,
		Hostinfo:       params.Hostinfo,
		Endpoints:      params.Endpoints,
		LastSeen:       new(time.Now()),
		IsOnline:       new(false), // Explicitly offline until [State.Connect] is called
		RegisterMethod: params.RegisterMethod,
		Expiry:         params.Expiry,
	}

	// Assign ownership based on PreAuthKey
	if params.PreAuthKey != nil {
		if params.PreAuthKey.IsTagged() {
			// Tagged nodes are owned by their tags, not a user.
			// UserID is intentionally left nil.
			nodeToRegister.Tags = params.PreAuthKey.Tags

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil
		} else {
			// USER-OWNED NODE
			nodeToRegister.UserID = &params.PreAuthKey.User.ID
			nodeToRegister.User = params.PreAuthKey.User
			nodeToRegister.Tags = nil
		}

		nodeToRegister.AuthKey = params.PreAuthKey.AsCredential()
		nodeToRegister.AuthKeyID = &params.PreAuthKey.ID
	} else {
		// Non-PreAuthKey registration (OIDC, CLI) - always user-owned
		nodeToRegister.UserID = &params.User.ID
		nodeToRegister.User = &params.User
		nodeToRegister.Tags = nil
	}

	// Process RequestTags (from tailscale up --advertise-tags) ONLY for non-PreAuthKey registrations.
	// Validate early before IP allocation to avoid resource leaks on failure.
	if params.PreAuthKey == nil && params.Hostinfo != nil && len(params.Hostinfo.RequestTags) > 0 {
		// Validate all tags before applying - reject if any tag is not permitted
		rejectedTags := s.validateRequestTags(nodeToRegister.View(), params.Hostinfo.RequestTags)
		if len(rejectedTags) > 0 {
			return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, rejectedTags)
		}

		// All tags are approved - apply them
		approvedTags := params.Hostinfo.RequestTags
		if len(approvedTags) > 0 {
			// Sort a copy: approvedTags is the node's reported Hostinfo.
			nodeToRegister.Tags = slices.Compact(slices.Sorted(slices.Values(approvedTags)))

			// Node is now tagged, so clear user ownership.
			// Tagged nodes are owned by their tags, not a user.
			nodeToRegister.UserID = nil
			nodeToRegister.User = nil

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil

			log.Info().
				Str(zf.NodeName, nodeToRegister.Hostname).
				Strs(zf.NodeTags, nodeToRegister.Tags).
				Msg("approved advertise-tags during registration")
		}
	}

	// Apply default node expiry for non-tagged nodes when the client
	// did not request a specific expiry.
	// Tagged nodes are exempt — they never expire.
	needsDefaultExpiry := !nodeToRegister.IsTagged() &&
		(nodeToRegister.Expiry == nil || nodeToRegister.Expiry.IsZero()) &&
		s.cfg.Node.Expiry > 0
	if needsDefaultExpiry {
		exp := time.Now().Add(s.cfg.Node.Expiry)
		nodeToRegister.Expiry = &exp
	}

	// Validate before saving
	err := validateNodeOwnership(&nodeToRegister)
	if err != nil {
		return types.NodeView{}, err
	}

	// Allocate new IPs
	ipv4, ipv6, err := s.ipAlloc.Next()
	if err != nil {
		return types.NodeView{}, fmt.Errorf("allocating IPs: %w", err)
	}

	nodeToRegister.IPv4 = ipv4
	nodeToRegister.IPv6 = ipv6

	// Seed GivenName from the sanitised raw hostname. [world.PutNode]
	// bumps on collision and falls back to "node" if the sanitised
	// result is empty (pure non-ASCII / punctuation input).
	if nodeToRegister.GivenName == "" {
		nodeToRegister.GivenName = dnsname.SanitizeHostname(nodeToRegister.Hostname)
	}

	// New node - database first to get ID, then memory
	savedNode, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		// Omit the AuthKey association: only auth_key_id is persisted here, the
		// credential row is owned by the credential CRUD and must not be
		// upserted from this node's (possibly stale) in-memory copy (#2862).
		err := tx.Omit("AuthKey").Save(&nodeToRegister).Error
		if err != nil {
			return nil, fmt.Errorf("saving node: %w", err)
		}

		if params.PreAuthKey != nil && !params.PreAuthKey.Reusable {
			err := hsdb.UsePreAuthKey(tx, params.PreAuthKey)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}

			// UsePreAuthKey marked the key used; refresh the node's in-memory
			// AuthKey so it matches the database.
			nodeToRegister.AuthKey = params.PreAuthKey.AsCredential()
		}

		return &nodeToRegister, nil
	})
	if err != nil {
		return types.NodeView{}, err
	}

	// Add to memory after database creates the ID
	return s.world.PutNode(*savedNode), nil
}

// validateRequestTags validates that the requested tags are permitted for the node.
// This should be called BEFORE [world.UpdateNode] to ensure we don't modify memory
// if validation fails. Returns the list of rejected tags (empty if all valid).
func (s *State) validateRequestTags(node types.NodeView, requestTags []string) []string {
	// Empty tags = clear tags, always permitted
	if len(requestTags) == 0 {
		return nil
	}

	pm := s.Snapshot().Policy()

	var rejectedTags []string

	for _, tag := range requestTags {
		if !pm.NodeCanHaveTag(node, tag) {
			rejectedTags = append(rejectedTags, tag)
		}
	}

	return rejectedTags
}

// processReauthTags handles tag changes during node re-authentication.
// It processes RequestTags from the client and updates node tags accordingly.
// Returns rejected tags (if any) for post-validation error handling.
func (s *State) processReauthTags(
	node *types.Node,
	requestTags []string,
	user *types.User,
	oldTags []string,
) []string {
	wasAuthKeyTagged := node.AuthKey != nil && node.AuthKey.IsTagged()

	logEvent := log.Debug().
		Uint64(zf.NodeID, uint64(node.ID)).
		Str(zf.NodeName, node.Hostname).
		Strs(zf.RequestTags, requestTags).
		Strs(zf.CurrentTags, node.Tags).
		Bool(zf.IsTagged, node.IsTagged()).
		Bool(zf.WasAuthKeyTagged, wasAuthKeyTagged)
	logEvent.Msg("processing RequestTags during reauth")

	// Empty RequestTags means untag node (transition to user-owned)
	if len(requestTags) == 0 {
		if node.IsTagged() {
			log.Info().
				Uint64(zf.NodeID, uint64(node.ID)).
				Str(zf.NodeName, node.Hostname).
				Strs(zf.RemovedTags, node.Tags).
				Str(zf.UserName, user.Name).
				Bool(zf.WasAuthKeyTagged, wasAuthKeyTagged).
				Msg("Reauth: removing all tags, returning node ownership to user")

			node.Tags = []string{}
			node.UserID = &user.ID
			node.User = user

			// The node is no longer tagged, so it must not keep a reference to
			// the tagged auth key. Leaving AuthKey set means a node created by a
			// tagged+ephemeral key stays IsEphemeral() after converting to
			// user-owned and is garbage-collected on its next disconnect,
			// silently deleting the user's just-claimed device. Clearing the
			// reference is persisted via the AuthKeyID column added to this
			// path's write below.
			node.AuthKey = nil
			node.AuthKeyID = nil
		}

		return nil
	}

	// Non-empty RequestTags: validate and apply. Authorise each tag against the
	// node OR the authenticating user: a tag-owned node (#3374) carries no
	// user, so the node half alone rejects every tag.
	authUser := user.View()
	pm := s.Snapshot().Policy()

	var approvedTags, rejectedTags []string

	for _, tag := range requestTags {
		if pm.NodeCanHaveTag(node.View(), tag) ||
			(authUser.Valid() && pm.UserCanHaveTag(authUser, tag)) {
			approvedTags = append(approvedTags, tag)
		} else {
			rejectedTags = append(rejectedTags, tag)
		}
	}

	if len(rejectedTags) > 0 {
		log.Warn().
			Uint64(zf.NodeID, uint64(node.ID)).
			Str(zf.NodeName, node.Hostname).
			Strs(zf.RejectedTags, rejectedTags).
			Msg("Reauth: requested tags are not permitted")

		return rejectedTags
	}

	if len(approvedTags) > 0 {
		slices.Sort(approvedTags)
		approvedTags = slices.Compact(approvedTags)

		wasTagged := node.IsTagged()
		node.Tags = approvedTags

		// Tagged nodes are owned by their tags, not a user.
		node.UserID = nil
		node.User = nil

		if !wasTagged {
			log.Info().
				Uint64(zf.NodeID, uint64(node.ID)).
				Str(zf.NodeName, node.Hostname).
				Strs(zf.NewTags, approvedTags).
				Str(zf.OldUser, user.Name).
				Msg("Reauth: applying tags, transferring node to tagged-devices")
		} else {
			log.Info().
				Uint64(zf.NodeID, uint64(node.ID)).
				Str(zf.NodeName, node.Hostname).
				Strs(zf.OldTags, oldTags).
				Strs(zf.NewTags, approvedTags).
				Msg("Reauth: updating tags on already-tagged node")
		}
	}

	return nil
}

// HandleNodeFromAuthPath handles node registration through authentication flow (like OIDC).
func (s *State) HandleNodeFromAuthPath(
	authID types.AuthID,
	userID types.UserID,
	expiry *time.Time,
	registrationMethod string,
) (types.NodeView, error) {
	// An OIDC token's expiry arrives here without passing handleRegister;
	// refuse one that cannot be encoded before any branch stores it.
	if expiry != nil {
		utc, err := types.ValidateExpiry(*expiry)
		if err != nil {
			return types.NodeView{}, err
		}

		expiry = &utc
	}

	// Get the registration entry from cache
	regEntry, ok := s.GetAuthCacheEntry(authID)
	if !ok {
		return types.NodeView{}, hsdb.ErrNodeNotFoundRegistrationCache
	}

	// Get the user
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return types.NodeView{}, fmt.Errorf("finding user: %w", err)
	}

	regData := regEntry.RegistrationData()

	// Hostname is the raw hostname the registering node reported, as
	// [registrationDataFromRequest] cached it. Build the initial Hostinfo
	// from the cached client-supplied Hostinfo (or an empty stub if the
	// client did not send one).
	hostname := regData.Hostname

	hostinfo := &tailcfg.Hostinfo{}
	if regData.Hostinfo != nil {
		hostinfo = regData.Hostinfo.Clone()
	}

	hostinfo.Hostname = hostname

	// Lookup existing nodes
	machineKey := regData.MachineKey

	// Serialise registration for this machine so concurrent auth callbacks
	// resolve to a single node rather than racing the find-then-create section.
	defer s.lockRegistration(machineKey)()

	all := s.Snapshot().GetNodesByMachineKeyAllUsers(machineKey)

	// Named conditions - describe WHAT we found, not HOW we check it.
	existingNode, nodeExists := loginNode(all, types.UserID(user.ID))

	var existingNodeOtherUser types.NodeView

	existingNodeOwnedByOtherUser := false

	for uid, n := range all {
		if uid != 0 && uid != types.UserID(user.ID) && !n.IsTagged() {
			existingNodeOtherUser = n
			existingNodeOwnedByOtherUser = true
		}
	}

	// Create logger with common fields for all auth operations
	logger := log.With().
		Str(zf.RegistrationID, authID.String()).
		Str(zf.UserName, user.Name).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.Method, registrationMethod).
		Logger()

	// Common params for update operations
	updateParams := authNodeUpdateParams{
		RegData:        regData,
		ValidHostinfo:  hostinfo,
		Hostname:       hostname,
		User:           user,
		Expiry:         expiry,
		RegisterMethod: registrationMethod,
	}

	var finalNode types.NodeView

	if nodeExists && !existingNode.IsTagged() {
		updateParams.ExistingNode = existingNode

		finalNode, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, err
		}
	} else if nodeExists {
		updateParams.ExistingNode = existingNode
		updateParams.IsConvertFromTag = true

		finalNode, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, err
		}
	} else if existingNodeOwnedByOtherUser {
		oldUser := existingNodeOtherUser.User()

		oldUserName := ""
		if oldUser.Valid() {
			oldUserName = oldUser.Name()
		}

		logger.Info().
			Str(zf.ExistingNodeName, existingNodeOtherUser.Hostname()).
			Uint64(zf.ExistingNodeID, existingNodeOtherUser.ID().Uint64()).
			Str(zf.OldUser, oldUserName).
			Msg("Creating new node for different user (same machine key exists for another user)")

		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regData, hostname, hostinfo,
			expiry, registrationMethod, existingNodeOtherUser,
		)
		if err != nil {
			return types.NodeView{}, err
		}
	} else {
		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regData, hostname, hostinfo,
			expiry, registrationMethod, types.NodeView{},
		)
		if err != nil {
			return types.NodeView{}, err
		}
	}

	// Signal to waiting clients
	regEntry.FinishAuth(types.AuthVerdict{Node: finalNode})

	// Remove from registration cache
	s.authCache.Remove(authID)

	// The login may have created the user (OIDC), which the policy must see.
	err = s.refreshUsers()
	if err != nil {
		return finalNode, fmt.Errorf("updating policy manager users: %w", err)
	}

	return finalNode, nil
}

// createNewNodeFromAuth creates a new node during auth callback.
// This is used for both new registrations and when a machine already has a node
// for a different user.
func (s *State) createNewNodeFromAuth(
	logger zerolog.Logger,
	user *types.User,
	regData *types.RegistrationData,
	hostname string,
	validHostinfo *tailcfg.Hostinfo,
	expiry *time.Time,
	registrationMethod string,
	existingNodeForNetinfo types.NodeView,
) (types.NodeView, error) {
	logger.Debug().
		Interface("expiry", expiry).
		Msg("Registering new node from auth callback")

	return s.createAndSaveNewNode(newNodeParams{
		User:                   *user,
		MachineKey:             regData.MachineKey,
		NodeKey:                regData.NodeKey,
		DiscoKey:               regData.DiscoKey,
		Hostname:               hostname,
		Hostinfo:               validHostinfo,
		Endpoints:              regData.Endpoints,
		Expiry:                 cmp.Or(expiry, regData.Expiry),
		RegisterMethod:         registrationMethod,
		ExistingNodeForNetinfo: existingNodeForNetinfo,
	})
}

// HandleNodeFromPreAuthKey handles node registration using a pre-authentication key.
// findExistingNodeForPAK looks up an existing node by machine key,
// matching the PAK's ownership. A key with a user finds that user's node,
// else the machine's tagged node; a tags-only key checks UserID(0) since
// tagged nodes have no owning user.
func (s *State) findExistingNodeForPAK(
	machineKey key.MachinePublic,
	pak *types.PreAuthKey,
	nodeKey key.NodePublic,
) (types.NodeView, bool, error) {
	all := s.Snapshot().GetNodesByMachineKeyAllUsers(machineKey)

	if pak.User != nil {
		node, ok := all[types.UserID(pak.User.ID)]
		if !ok {
			// The machine's tagged node, when the key speaks for it. Any other
			// key under its own node key is the device restarting (#3312);
			// pakReregister lets that key only wake it.
			node, ok = all[0]
			ok = ok && node.IsTagged() && (pak.CanReauthenticate(node) || node.NodeKey() == nodeKey)
		}

		return node, ok, nil
	}

	// A tagged key re-registers the same machine regardless of how it is
	// currently owned. An existing tagged node is a plain re-registration. A
	// single user-owned node is converted to tagged in place (handled by the
	// caller). More than one user-owned node is ambiguous - we cannot know
	// which to convert - so reject rather than convert an arbitrary one and
	// orphan the rest.
	if pak.IsTagged() {
		if node, ok := all[0]; ok && node.IsTagged() {
			return node, true, nil
		}

		var userOwned types.NodeView

		count := 0

		for uid, node := range all {
			if uid != 0 && !node.IsTagged() {
				userOwned = node
				count++
			}
		}

		switch count {
		case 0:
			return types.NodeView{}, false, nil
		case 1:
			return userOwned, true, nil
		default:
			return types.NodeView{}, false, ErrAmbiguousNodeOwnership
		}
	}

	return types.NodeView{}, false, nil
}

// loginNode picks, from a machine's nodes, the one a login by userID
// re-authenticates: the user's own node, else the machine's tagged node when
// the user can claim it. A tagged node that joined by login records no former
// owner, so any login re-authenticates it, as before; the tags the login asks
// for decide whether it stays tagged. Otherwise another user's login on a
// tagged machine adds a device for that user beside it, as on Tailscale SaaS.
func loginNode(all map[types.UserID]types.NodeView, userID types.UserID) (types.NodeView, bool) {
	if node, ok := all[userID]; ok {
		return node, true
	}

	if node, ok := all[0]; ok && node.IsTagged() &&
		(node.ClaimableBy(userID) || node.RegisterMethod() != util.RegisterMethodAuthKey) {
		return node, true
	}

	return types.NodeView{}, false
}

// pakSkipsValidation reports whether re-registering n with pak may skip key
// validation at now. The machine key proves identity and a pre-auth key only
// authorises the initial join, so a plain restart (container "tailscale up
// --authkey=KEY") re-presents a spent key legitimately. Anything that
// authorises something new must present a valid key:
//   - a node key rotation;
//   - an expired node, including a tagged node expired by an admin;
//   - a tagged key converting a user-owned node to tagged;
//   - a different credential, which can change tags or ephemeral lifetime.
//
// A key that does not speak for a tagged node only wakes it and binds
// nothing, so it is held only to the node key and expiry.
//
// It is a pure function of the node so the writer can decide again
// on the node it actually replaces.
func pakSkipsValidation(n types.NodeView, pak *types.PreAuthKey, nodeKey key.NodePublic, now time.Time) bool {
	if !n.Valid() {
		return false
	}

	isNodeKeyRotation := n.NodeKey() != nodeKey
	isExpired := n.IsExpiredAt(now)

	if !pak.CanReauthenticate(n) {
		return n.IsTagged() && !isNodeKeyRotation && !isExpired
	}

	if !n.AuthKeyID().Valid() || n.AuthKeyID().Get() != pak.ID {
		return false
	}

	isOwnershipConversion := pak.ConvertsNodeToTagged(n)
	isRetag := pak.RetagsNode(n)
	ownershipMatches := n.IsTagged() ||
		(pak.User != nil && n.UserID().Valid() && n.UserID().Get() == pak.User.ID)

	return ownershipMatches && !isNodeKeyRotation && !isExpired &&
		!isOwnershipConversion && !isRetag
}

// pakReregister is the authorisation decision for re-registering n with pak
// at now: whether the key re-authenticates n, and nil when validation may be
// skipped, else the key's validity. A key that does not speak for n only
// wakes it under its own node key.
func pakReregister(n types.NodeView, pak *types.PreAuthKey, nodeKey key.NodePublic, now time.Time) (bool, error) {
	reauth := pak.CanReauthenticate(n)
	if pakSkipsValidation(n, pak, nodeKey, now) {
		return reauth, nil
	}

	err := pak.ValidAt(now)
	if err == nil && !reauth {
		err = types.PAKError("authkey cannot re-authenticate this node")
	}

	return reauth, err
}

//nolint:gocyclo // sequential validation/update/create paths with security-sensitive ordering
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (types.NodeView, error) {
	// Serialise registration for this machine so concurrent restarts resolve
	// to a single node rather than racing the find-then-create section.
	defer s.lockRegistration(machineKey)()

	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return types.NodeView{}, err
	}

	// A pre-auth key node's tags come from the key, never from RequestTags.
	// Advertising a subset of the key's tags is redundant, not an escalation,
	// and the tailscale client's OAuth authkey flow always does it; any other
	// tag is rejected. Checked before key validation or resource allocation so
	// new nodes and re-registrations are held to the same rule.
	if regReq.Hostinfo != nil {
		var extraTags []string

		for _, tag := range regReq.Hostinfo.RequestTags {
			if !slices.Contains(pak.Tags, tag) {
				extraTags = append(extraTags, tag)
			}
		}

		if len(extraTags) > 0 {
			return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, extraTags)
		}
	}

	existingNodeSameUser, existsSameUser, err := s.findExistingNodeForPAK(machineKey, pak, regReq.NodeKey)
	if err != nil {
		return types.NodeView{}, err
	}

	// This decision is only an early reject that keeps a key error ahead of
	// ErrNodeKeyInUse. An in-place re-registration decides again in the
	// writer, on the node it replaces; see reregisterNodeWithPAK.
	if existsSameUser && pakSkipsValidation(existingNodeSameUser, pak, regReq.NodeKey, time.Now()) {
		log.Debug().
			Caller().
			Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
			Str(zf.NodeName, existingNodeSameUser.Hostname()).
			Str(zf.MachineKey, machineKey.ShortString()).
			Str(zf.NodeKeyExisting, existingNodeSameUser.NodeKey().ShortString()).
			Str(zf.NodeKeyRequest, regReq.NodeKey.ShortString()).
			Uint64(zf.AuthKeyID, pak.ID).
			Bool(zf.AuthKeyUsed, pak.Used).
			Bool(zf.AuthKeyExpired, pak.Expiration != nil && pak.Expiration.Before(time.Now())).
			Bool(zf.AuthKeyReusable, pak.Reusable).
			Msg("Existing node re-registering with same NodeKey; lookup permits skipping key validation, writer re-decides")
	} else {
		err = pak.Validate()
		if err != nil {
			return types.NodeView{}, err
		}
	}

	// Preserve the raw hostname as reported by the client. Sanitisation
	// for the DNS label lives on node.GivenName, not on node.Hostname;
	// see HOSTNAME.md.
	var hostname string
	if regReq.Hostinfo != nil {
		hostname = regReq.Hostinfo.Hostname
	}

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regReq.Hostinfo.Clone(), &tailcfg.Hostinfo{})

	log.Debug().
		Caller().
		Str(zf.NodeName, hostname).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, regReq.NodeKey.ShortString()).
		Str(zf.UserName, pak.Username()).
		Msg("Registering node with pre-auth key")

	var finalNode types.NodeView

	// If this node exists for this user, update the node in place. For a
	// tags-only key (pak.User == nil) this is true when the machine already has
	// a tagged node (findExistingNodeForPAK matches it under UserID 0); for a
	// user-owned key it is true when the same user already has the node.
	if existsSameUser && existingNodeSameUser.Valid() {
		finalNode, err = s.reregisterNodeWithPAK(existingNodeSameUser, pak, regReq, machineKey, hostname, validHostinfo)
		if err != nil {
			return types.NodeView{}, err
		}
	} else {
		// Node does not exist for this user with this machine key.
		// For a user-owned key, check whether the machine key is already held
		// by a node belonging to a different user (tags-only keys skip this;
		// tagged nodes have no owning user). Any such node yields the same
		// outcome - create a new node for the new user, do not transfer - so a
		// single representative is enough.
		var differentUserNode types.NodeView

		belongsToDifferentUser := false

		if pak.User != nil {
			for uid, node := range s.Snapshot().GetNodesByMachineKeyAllUsers(machineKey) {
				if uid != 0 && !node.IsTagged() && uid != types.UserID(pak.User.ID) {
					differentUserNode = node
					belongsToDifferentUser = true
				}
			}
		}

		if belongsToDifferentUser {
			// Node exists but belongs to a different user.
			// Create a new node for the new user (do not transfer).
			oldUser := differentUserNode.User()

			oldUserName := ""
			if oldUser.Valid() {
				oldUserName = oldUser.Name()
			}

			log.Info().
				Caller().
				Str(zf.ExistingNodeName, differentUserNode.Hostname()).
				Uint64(zf.ExistingNodeID, differentUserNode.ID().Uint64()).
				Str(zf.MachineKey, machineKey.ShortString()).
				Str(zf.OldUser, oldUserName).
				Str(zf.NewUser, pak.Username()).
				Msg("Creating new node for different user (same machine key exists for another user)")
		}

		// This is a new node - create it
		// For user-owned keys: create for the user
		// For tags-only keys: create as tagged node (createAndSaveNewNode handles this via PreAuthKey)

		// Create and save new node
		// Note: For tags-only keys, User is empty but createAndSaveNewNode uses PreAuthKey for ownership
		var pakUser types.User
		if pak.User != nil {
			pakUser = *pak.User
		}

		// Only pass the client-requested expiry when it is actually set.
		// A pointer to a zero time.Time gets persisted as "0001-01-01 00:00:00"
		// rather than NULL, which breaks downstream consumers that distinguish
		// "no expiry" from "expires at year 1".
		var reqExpiry *time.Time
		if !regReq.Expiry.IsZero() {
			reqExpiry = &regReq.Expiry
		}

		var err error

		finalNode, err = s.createAndSaveNewNode(newNodeParams{
			User:                   pakUser,
			MachineKey:             machineKey,
			NodeKey:                regReq.NodeKey,
			DiscoKey:               key.DiscoPublic{}, // DiscoKey not available in RegisterRequest
			Hostname:               hostname,
			Hostinfo:               validHostinfo,
			Endpoints:              nil, // Endpoints not available in RegisterRequest
			Expiry:                 reqExpiry,
			RegisterMethod:         util.RegisterMethodAuthKey,
			PreAuthKey:             pak,
			ExistingNodeForNetinfo: differentUserNode,
		})
		if err != nil {
			return types.NodeView{}, fmt.Errorf("creating new node: %w", err)
		}
	}

	err = s.refreshUsers()
	if err != nil {
		return finalNode, fmt.Errorf("updating policy manager users: %w", err)
	}

	return finalNode, nil
}

// reregisterNodeWithPAK updates an existing node in place for a pre-auth key
// re-registration: authorise a private candidate, persist it and consume the
// key in one transaction, then publish the committed identity.
//
// The caller's lookup view goes stale before the writer runs: an
// admin or logout expiry, a node key reconcile, a retag or a deletion can land
// in between, and the key or the node can expire. So the writer decides
// whether the key must be valid on the node it replaces, at its own clock, and
// leaves the node untouched when it is not. existingNodeSameUser is used only
// for its ID and for logging.
func (s *State) reregisterNodeWithPAK(
	existingNodeSameUser types.NodeView,
	pak *types.PreAuthKey,
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	hostname string,
	validHostinfo *tailcfg.Hostinfo,
) (types.NodeView, error) {
	log.Trace().
		Caller().
		Str(zf.NodeName, existingNodeSameUser.Hostname()).
		Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, existingNodeSameUser.NodeKey().ShortString()).
		Str(zf.UserName, pak.Username()).
		Msg("Node re-registering with existing machine key and user, updating in place")

	// prior is the staging baseline for preserving concurrent map updates.
	var (
		prior, candidate *types.Node
		authErr          error
		reauth           bool
	)

	// Held through publication so a concurrent persistNode cannot overwrite
	// the durable registration with the old identity still in memory.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	// Claim the rotated key across the staged write: a fresh registration
	// claiming it must finish its insert first, so the check below sees it.
	defer s.lockNodeKey(regReq.NodeKey)()

	// Re-registration rotates the NodeKey to the client-supplied value.
	// Enforce the same 1:1 NodeKey<->MachineKey binding the auth path
	// (applyAuthNodeUpdate) and poll-time validation enforce: a NodeKey
	// already bound to a different machine must not be claimed here, or a
	// re-registering node could rotate its key to a victim's and poison the
	// NodeKey index, denying the victim service.
	// Check under persistMu and the keyed claim, after earlier claims of this
	// key — re-authentications and fresh inserts alike — have published.
	if existing, ok := s.Snapshot().GetNodeByNodeKey(regReq.NodeKey); ok &&
		existing.MachineKey() != machineKey {
		return types.NodeView{}, ErrNodeKeyInUse
	}

	s.world.update(func(nodes *nodeEdit) {
		var ok bool

		prior, ok = nodes.Get(existingNodeSameUser.ID())
		if !ok {
			return
		}

		node := prior.Clone()
		// One clock read, so the whole mutation is decided at one instant.
		now := time.Now()

		reauth, authErr = pakReregister(node.View(), pak, regReq.NodeKey, now)
		if authErr != nil {
			return
		}

		node.Hostname = hostname

		// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
		// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

		// Preserve NetInfo from existing node when re-registering
		node.Hostinfo = validHostinfo
		node.Hostinfo.NetInfo = preserveNetInfo(prior.View(), prior.ID, validHostinfo)

		// Preserve online state during re-registration so a live node does
		// not appear offline before the client restarts its map stream.
		node.LastSeen = new(now)

		if !reauth {
			candidate = node

			return
		}

		node.NodeKey = regReq.NodeKey

		node.RegisterMethod = util.RegisterMethodAuthKey

		// Tags from a PreAuthKey are applied on initial registration and
		// re-applied whenever a *different* key is presented on
		// re-registration: re-keying is Tailscale's documented way to change
		// an auth-key device's tags, replacing its existing ones. Presenting
		// the SAME key again (a container restart) preserves the node's
		// current tags and any admin override. A tagged key presented for a
		// user-owned node also converts it, dropping user ownership.
		// See https://tailscale.com/kb/1068/tags#apply-a-tag-to-a-device-with-the-cli.
		//
		// node.AuthKeyID still holds the prior key's ID here (it is reassigned
		// below), and SetNodeTags leaves AuthKeyID intact, so an admin retag
		// cannot masquerade as a new key.
		if pak.ConvertsNodeToTagged(node.View()) || pak.RetagsNode(node.View()) {
			wasUserOwned := !node.IsTagged()

			node.Tags = pak.Tags
			node.UserID = nil
			node.User = nil

			// Converting a user-owned node to tagged drops the user's key
			// expiry (tagged nodes never expire). But retagging an
			// already-tagged node must preserve a deliberate FUTURE expiry
			// set via `headscale nodes expire` - that is a node property, not
			// tied to the auth key - and only clear a stale PAST expiry. This
			// keeps the retag path symmetric with the same-key relogin path
			// below rather than silently overriding an admin decision.
			if wasUserOwned || node.IsExpiredAt(now) {
				node.Expiry = nil
			}
		} else if node.IsTagged() && !pak.IsTagged() && prior.NodeKey != regReq.NodeKey {
			// A user key that speaks for a tagged node, with a new node key,
			// takes it back as that user's device, as on Tailscale SaaS. A
			// relogin under the same node key keeps it tagged.
			node.Tags = nil
			node.UserID = &pak.User.ID
			node.User = pak.User
		}

		node.AuthKey = pak.AsCredential()
		node.AuthKeyID = &pak.ID
		// If this registration will consume a single-use key (the tx below
		// calls UsePreAuthKey under the same condition), reflect that in the
		// cached AuthKey so the in-memory copy matches the database.
		if !pak.Reusable && !pak.Used {
			node.AuthKey.Used = true
		}

		// Tagged nodes keep their existing expiry (disabled).
		// User-owned nodes update expiry from the client request,
		// falling back to the configured default if the client
		// did not request a specific expiry. If neither is set,
		// clear the expiry so the database holds NULL instead of
		// a pointer to zero time.
		// A spent-key restart resumes existing authorization, never extends it.
		if !node.IsTagged() && pak.ValidAt(now) == nil {
			if !regReq.Expiry.IsZero() {
				node.Expiry = &regReq.Expiry
			} else if s.cfg.Node.Expiry > 0 {
				exp := now.Add(s.cfg.Node.Expiry)
				node.Expiry = &exp
			} else {
				node.Expiry = nil
			}
		} else if node.IsTagged() && node.IsExpiredAt(now) {
			// Expired nodes reached here only after fresh authorization.
			node.Expiry = nil
		}

		candidate = node
	})

	// A nil prior means the writer never saw the node (deleted), so nothing
	// was decided and nothing may be persisted.
	if prior == nil {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, existingNodeSameUser.ID())
	}

	if authErr != nil {
		log.Debug().
			Caller().
			Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
			Str(zf.MachineKey, machineKey.ShortString()).
			Uint64(zf.AuthKeyID, pak.ID).
			Err(authErr).
			Msg("Re-registration needs a valid auth key when it applies, rejecting")

		return types.NodeView{}, authErr
	}

	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		// Explicitly select all node columns so GORM includes nil/zero-value fields
		// (see nodeUpdateColumns comment). AuthKeyID is excluded on MapRequest
		// so a deleted key's stale reference is not persisted, but
		// re-registration presents a key just loaded from the database, so
		// its ID must be persisted here — otherwise a restart reloads the old
		// key and any key-scoped property (e.g. Ephemeral) silently reverts.
		// A wake-up keeps the prior key, which may have been deleted (#2862).
		reregColumns := nodeUpdateColumns
		if reauth {
			reregColumns = append(slices.Clone(nodeUpdateColumns), "AuthKeyID")
		}

		result := tx.Select(reregColumns).Updates(candidate)
		if result.Error != nil {
			return nil, fmt.Errorf("saving node: %w", result.Error)
		}

		if result.RowsAffected == 0 {
			return nil, ErrNodeNotInNodeStore
		}

		// Only mark the key used on the *first* registration. On
		// re-registration the same key is already used and the
		// atomic compare-and-set in [hsdb.UsePreAuthKey] would otherwise
		// reject it as "authkey already used", locking out containers
		// that restart with the same one-shot key.
		if reauth && !pak.Reusable && !pak.Used {
			err := hsdb.UsePreAuthKey(tx, pak)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return nil, nil //nolint:nilnil // intentional: transaction success
	})
	if err != nil {
		return types.NodeView{}, fmt.Errorf("writing node to database: %w", err)
	}

	updatedNodeView, err := s.publishRegistration(prior, candidate)
	if err != nil {
		return types.NodeView{}, err
	}

	log.Trace().
		Caller().
		Str(zf.NodeName, updatedNodeView.Hostname()).
		Uint64(zf.NodeID, updatedNodeView.ID().Uint64()).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, updatedNodeView.NodeKey().ShortString()).
		Str(zf.UserName, pak.Username()).
		Msg("Node re-authorized")

	return updatedNodeView, nil
}

// UpdatePolicyManagerUsersForTest loads the database's users into memory,
// for tests that create users with CreateUserForTest().
func (s *State) UpdatePolicyManagerUsersForTest() error {
	return s.refreshUsers()
}

// PingDB checks if the database connection is healthy.
func (s *State) PingDB(ctx context.Context) error {
	return s.db.PingDB(ctx)
}

// autoApproveNodes re-runs route auto-approval on every node against the
// current policy and returns how many nodes it changed. It is _only_
// intended for use when the policy is replaced.
func (s *State) autoApproveNodes() (int, error) {
	snap := s.Snapshot()
	pm := snap.Policy()

	// Compute every node's approval first, then apply them all in one
	// commit. One SetApprovedRoutes per node would recompile the policy and
	// rebuild the peer map once per changed node.
	approvedByID := make(map[types.NodeID][]netip.Prefix)

	for _, nv := range snap.ListNodes().All() {
		approved, changed := policy.ApproveRoutesWithPolicy(pm, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
		if !changed {
			continue
		}

		log.Debug().
			Uint64(zf.NodeID, nv.ID().Uint64()).
			Str(zf.NodeName, nv.Hostname()).
			Strs(zf.RoutesApprovedOld, util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
			Strs(zf.RoutesApprovedNew, util.PrefixesToString(approved)).
			Msg("Routes auto-approved by policy")

		approvedByID[nv.ID()] = approved
	}

	if len(approvedByID) == 0 {
		return 0, nil
	}

	updates := make(map[types.NodeID]UpdateNodeFunc, len(approvedByID))
	for id, approved := range approvedByID {
		updates[id] = func(n *types.Node) {
			n.ApprovedRoutes = approved

			// A node with no approved routes is no longer an HA candidate;
			// drop any stale Unhealthy bit (mirrors SetApprovedRoutes).
			if len(n.AllApprovedRoutes()) == 0 {
				n.Unhealthy = false
			}
		}
	}

	s.world.UpdateNodes(updates)

	snap = s.Snapshot()
	for id := range approvedByID {
		fresh, ok := snap.GetNode(id)
		if !ok {
			continue
		}

		_, err := s.persistNode(fresh)
		if err != nil {
			// A node whose row a lifetime delete already dropped is on its
			// way out of the graph too; its approval has nowhere to persist,
			// and one vanished node must not hold the rest hostage.
			if errors.Is(err, ErrNodeNotInNodeStore) {
				continue
			}

			return len(approvedByID), err
		}
	}

	return len(approvedByID), nil
}

// isAutoDerivedGivenName reports whether given matches what
// dnsname.SanitizeHostname(hostname) would produce, optionally with a
// [uniqueGivenName] collision-bump "-N" suffix. It is used to detect whether a
// GivenName has been admin-renamed (in which case it must not be
// overwritten by client-side hostname changes).
func isAutoDerivedGivenName(given, hostname string) bool {
	base := dnsname.SanitizeHostname(hostname)
	if given == base {
		return true
	}

	suffix, ok := strings.CutPrefix(given, base+"-")
	if !ok {
		return false
	}

	_, err := strconv.Atoi(suffix)

	return err == nil
}

// UpdateNodeFromMapRequest is the sync point where Hostinfo changes,
// endpoint updates, and route advertisements from a [tailcfg.MapRequest]
// land in memory, and in the database when they are worth persisting.
//
// When a field is added to a MapRequest that is stored on the node, also add
// it to [types.Node.PeerChangeFromMapRequest], [types.Node.ApplyPeerChange],
// and (if the policy reads it) [types.NodeView.HasPolicyChange].
func (s *State) UpdateNodeFromMapRequest(id types.NodeID, req tailcfg.MapRequest) error {
	log.Trace().
		Caller().
		Uint64(zf.NodeID, id.Uint64()).
		EmbedObject(zlog.MapRequest(&req)).
		Msg("Processing MapRequest for node")

	var (
		delta              mapRequestDelta
		routeChange        bool
		autoApprovedRoutes []netip.Prefix
		updateErr          error
	)

	// Only for the debug line below; a concurrent writer can move it too.
	prevPrimaries := s.Snapshot().PrimariesRev()

	// We need to ensure we update the node as it is in memory at the time of
	// the request.
	snap := s.world.update(func(nodes *nodeEdit) {
		updateErr = nil

		stored, ok := nodes.Get(id)
		if !ok {
			updateErr = fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
			return
		}
		// Noise authentication precedes this write; reauthentication may have replaced its key.
		if stored.NodeKey != req.NodeKey {
			updateErr = ErrNodeKeyChanged
			return
		}

		currentNode := stored.Clone()
		routeChange, autoApprovedRoutes = false, nil
		// Capture the raw wire-level peer change; LastSeen is always
		// stamped.
		delta.peerChange = currentNode.PeerChangeFromMapRequest(req)

		// Normalize before comparing. A nil req.Hostinfo means the client
		// did not send one (e.g., endpoint-only/lite requests); we must NOT
		// clobber the stored Hostinfo with a shell containing only NetInfo.
		// When Hostinfo is present but NetInfo is omitted (Tailscale >= 1.66
		// sends NetInfo only when it changed), the stored NetInfo is carried
		// over. Every comparison below runs against this normalized value,
		// otherwise an omitted NetInfo reads as a Hostinfo change.
		var newHostinfo *tailcfg.Hostinfo

		if req.Hostinfo != nil {
			// Copy so the comparison never mutates the caller's request.
			hi := *req.Hostinfo
			hi.NetInfo = netInfoFromMapRequest(id, currentNode.Hostinfo, req.Hostinfo)
			newHostinfo = &hi
		}

		// DERP comparison is independent of the rest of Hostinfo: DERP zero
		// on the wire means "unchanged", so a clear-to-zero must be detected
		// here. A request without Hostinfo says nothing about DERP, so it
		// compares equal.
		storedDERP := hostinfoDERP(currentNode.Hostinfo)
		requestedDERP := storedDERP

		if newHostinfo != nil {
			requestedDERP = hostinfoDERP(newHostinfo)
		}

		delta.oldDERP = storedDERP
		delta.newDERP = requestedDERP
		delta.derpChanged = requestedDERP != storedDERP

		// Routes are policy and election inputs, so they are compared on
		// their own.
		delta.routesChanged = newHostinfo != nil &&
			routesChanged(currentNode.View(), newHostinfo)
		delta.hostinfoChanged = newHostinfo != nil &&
			!hostinfoEqual(currentNode.Hostinfo, newHostinfo)

		// A change carrying only an updated LastSeen is not worth a
		// full-row database UPDATE: LastSeen is best-effort and rides
		// along the next substantive write. DERP is called out because
		// peerChangePersistWorthy cannot see a clear-to-zero.
		delta.persistWorthy = peerChangePersistWorthy(delta.peerChange) ||
			delta.hostinfoChanged ||
			delta.derpChanged

		hostinfoToStore := delta.hostinfoChanged || delta.derpChanged

		needsRouteApproval := delta.hostinfoChanged &&
			(delta.routesChanged || (len(newHostinfo.RoutableIPs) > 0 && len(currentNode.ApprovedRoutes) == 0))
		if needsRouteApproval {
			announcedRoutes := newHostinfo.RoutableIPs

			// Apply policy-based auto-approval if routes are announced. The
			// latest snapshot is the one this write builds on: no other
			// writer can commit while this closure runs.
			if len(announcedRoutes) > 0 {
				autoApprovedRoutes, routeChange = policy.ApproveRoutesWithPolicy(
					s.Snapshot().Policy(),
					currentNode.View(),
					currentNode.ApprovedRoutes,
					announcedRoutes,
				)
			}
		}

		// Log when routes change but approval doesn't
		if delta.routesChanged && !routeChange {
			log.Debug().
				Caller().
				Uint64(zf.NodeID, id.Uint64()).
				Strs(zf.OldAnnouncedRoutes, util.PrefixesToString(currentNode.AnnouncedRoutes())).
				Strs(zf.NewAnnouncedRoutes, util.PrefixesToString(newHostinfo.RoutableIPs)).
				Strs(zf.ApprovedRoutes, util.PrefixesToString(currentNode.ApprovedRoutes)).
				Bool(zf.RouteChanged, routeChange).
				Msg("announced routes changed but approved routes did not")
		}

		currentNode.ApplyPeerChange(&delta.peerChange)

		if hostinfoToStore {
			// The snapshot outlives the request; deep-copy so its slices and NetInfo are never shared.
			currentNode.Hostinfo = newHostinfo.Clone()
		}

		// Only a real hostname change may re-derive GivenName.
		if newHostinfo != nil && newHostinfo.Hostname != "" &&
			newHostinfo.Hostname != currentNode.Hostname {
			// Preserve an admin-renamed GivenName: only auto-derive
			// when the current GivenName is still what
			// SanitizeHostname of the old Hostname would produce
			// (possibly with a "-N" collision bump).
			autoDerived := isAutoDerivedGivenName(currentNode.GivenName, currentNode.Hostname)

			currentNode.Hostname = newHostinfo.Hostname
			if autoDerived {
				currentNode.GivenName = dnsname.SanitizeHostname(newHostinfo.Hostname)
			}
		}

		if routeChange {
			log.Info().
				Uint64(zf.NodeID, id.Uint64()).
				Strs(zf.OldApprovedRoutes, util.PrefixesToString(currentNode.ApprovedRoutes)).
				Strs(zf.NewApprovedRoutes, util.PrefixesToString(autoApprovedRoutes)).
				Bool(zf.RouteChanged, routeChange).
				Msg("applying route approval results")

			// Approving in this write keeps one request at one commit and
			// one row update. Persisting is already due: route approval
			// only runs on a Hostinfo change.
			currentNode.ApprovedRoutes = autoApprovedRoutes
		}

		// AllApprovedRoutes is announced ∩ approved; a Hostinfo
		// update that shrinks the announced set can drop the node
		// out of HA candidacy without touching ApprovedRoutes.
		// Clear any stale Unhealthy bit in that case.
		if len(currentNode.AllApprovedRoutes()) == 0 {
			currentNode.Unhealthy = false
		}

		if currentNode.GivenName != stored.GivenName {
			currentNode.GivenName = uniqueGivenName(nodes, id, currentNode.GivenName)
		}

		nodes.Set(id, currentNode)
	})

	if updateErr != nil {
		return updateErr
	}

	updatedNode, ok := snap.GetNode(id)
	if !ok {
		return fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	// SubnetRoutes = announced ∩ approved, so a Hostinfo update can
	// move a primary without ever touching ApprovedRoutes.
	if s.Snapshot().PrimariesRev() != prevPrimaries {
		log.Debug().
			Caller().
			Uint64(zf.NodeID, id.Uint64()).
			Strs(zf.RoutesAnnounced, util.PrefixesToString(updatedNode.AnnouncedRoutes())).
			Strs(zf.ApprovedRoutes, util.PrefixesToString(updatedNode.ApprovedRoutes().AsSlice())).
			Strs(zf.AllApprovedRoutes, util.PrefixesToString(updatedNode.AllApprovedRoutes())).
			Msg("primary route assignment shifted after MapRequest")
	}

	// A no-op MapRequest (identical re-send / reconnect with matching state)
	// leaves the row untouched, so skip the full-row UPDATE.
	if delta.persistWorthy {
		_, err := s.persistNode(updatedNode)
		if err != nil {
			return fmt.Errorf("saving to database: %w", err)
		}
	}

	log.Trace().
		Uint64(zf.NodeID, id.Uint64()).
		Bool("routes.approved", routeChange).
		EmbedObject(delta).
		Msg("processed MapRequest")

	return nil
}

func routesChanged(oldNode types.NodeView, newHI *tailcfg.Hostinfo) bool {
	// Copies, as they are sorted below; the view reads without cloning
	// the whole node.
	var oldRoutes []netip.Prefix
	if oldNode.Valid() && oldNode.Hostinfo().Valid() {
		oldRoutes = oldNode.Hostinfo().RoutableIPs().AsSlice()
	}

	newRoutes := slices.Clone(newHI.RoutableIPs)

	slices.SortFunc(oldRoutes, netip.Prefix.Compare)
	slices.SortFunc(newRoutes, netip.Prefix.Compare)

	return !slices.Equal(oldRoutes, newRoutes)
}

// peerChangePersistWorthy reports whether a peer change carries anything that
// warrants a database write. It deliberately ignores LastSeen, which
// [Node.PeerChangeFromMapRequest] always stamps: a keepalive that only bumps
// LastSeen should not trigger a full-row UPDATE and policy rescan.
func peerChangePersistWorthy(peerChange tailcfg.PeerChange) bool {
	return peerChange.Key != nil ||
		peerChange.DiscoKey != nil ||
		peerChange.Online != nil ||
		peerChange.Endpoints != nil ||
		peerChange.DERPRegion != 0 ||
		peerChange.KeyExpiry != nil
}
