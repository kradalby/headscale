package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestCreatePreAuthKey(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "error_invalid_user_id",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				_, err := db.CreatePreAuthKey(new(types.UserID(12345)), true, false, nil, nil)
				assert.Error(t, err)
			},
		},
		{
			name: "success_create_and_list",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)

				key, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
				require.NoError(t, err)
				assert.NotEmpty(t, key.Key)

				// List keys for the user
				keys, err := db.ListPreAuthKeys()
				require.NoError(t, err)
				assert.Len(t, keys, 1)

				// Verify User association is populated
				assert.Equal(t, user.ID, keys[0].User.ID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			tt.test(t, db)
		})
	}
}

func TestPreAuthKeyACLTags(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "reject_malformed_tags",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test-tags-1"})
				require.NoError(t, err)

				_, err = db.CreatePreAuthKey(user.TypedID(), false, false, nil, []string{"badtag"})
				assert.Error(t, err)
			},
		},
		{
			name: "deduplicate_and_sort_tags",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test-tags-2"})
				require.NoError(t, err)

				expectedTags := []string{"tag:test1", "tag:test2"}
				tagsWithDuplicate := []string{"tag:test1", "tag:test2", "tag:test2"}

				_, err = db.CreatePreAuthKey(user.TypedID(), false, false, nil, tagsWithDuplicate)
				require.NoError(t, err)

				listedPaks, err := db.ListPreAuthKeys()
				require.NoError(t, err)
				require.Len(t, listedPaks, 1)

				gotTags := slices.Clone(listedPaks[0].Tags)
				slices.Sort(gotTags)
				assert.Equal(t, expectedTags, gotTags)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			tt.test(t, db)
		})
	}
}

func TestCannotDeleteAssignedPreAuthKey(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)
	user, err := db.CreateUser(types.User{Name: "test8"})
	require.NoError(t, err)

	key, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, []string{"tag:good"})
	require.NoError(t, err)

	node := types.Node{
		ID:             0,
		Hostname:       "testest",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      new(key.ID),
	}
	db.DB.Save(&node)

	err = db.DB.Where("kind = ? AND id = ?", types.CredentialPreAuthKey, key.ID).
		Delete(&types.Credential{}).Error
	require.ErrorContains(t, err, "constraint failed: FOREIGN KEY constraint failed")
}

func TestPreAuthKeyAuthentication(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test-user")

	tests := []struct {
		name            string
		setupKey        func() string // Returns key string to test
		wantFindErr     bool          // Error when finding the key
		findErrIs       error         // Specific error expected when finding, if any
		wantValidateErr bool          // Error when validating the key
		validateResult  func(*testing.T, *types.PreAuthKey)
	}{
		{
			// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
			name: "unknown_unprefixed_key_rejected",
			setupKey: func() string {
				// An unprefixed string is looked up as a migrated legacy
				// plaintext key; one that was never stored is unknown.
				return "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
			},
			wantFindErr:     true,
			findErrIs:       ErrPreAuthKeyNotFound,
			wantValidateErr: false,
		},
		{
			name: "new_key_sha256",
			setupKey: func() string {
				// Create new key via API
				keyStr, err := db.CreatePreAuthKey(
					user.TypedID(),
					true, false, nil, []string{"tag:test"},
				)
				require.NoError(t, err)

				return keyStr.Key
			},
			wantFindErr:     false,
			wantValidateErr: false,
			validateResult: func(t *testing.T, pak *types.PreAuthKey) {
				t.Helper()

				assert.Equal(t, user.ID, *pak.UserID)
				assert.Len(t, pak.Prefix, 12)
				assert.True(t, strings.HasPrefix(string(pak.Hash), hashPrefixSHA256))
			},
		},
		{
			name: "new_key_format_validation",
			setupKey: func() string {
				keyStr, err := db.CreatePreAuthKey(
					user.TypedID(),
					true, false, nil, nil,
				)
				require.NoError(t, err)

				// Verify format: hskey-auth-{12-char-prefix}-{64-char-hash}
				// Use fixed-length parsing since prefix/hash can contain dashes (base64 URL-safe)
				assert.True(t, strings.HasPrefix(keyStr.Key, "hskey-auth-"))

				// Extract prefix and hash using fixed-length parsing like the real code does
				_, prefixAndHash, found := strings.Cut(keyStr.Key, "hskey-auth-")
				assert.True(t, found)
				assert.GreaterOrEqual(t, len(prefixAndHash), 12+1+64) // prefix + '-' + hash minimum

				prefix := prefixAndHash[:12]
				assert.Len(t, prefix, 12)                     // Prefix is 12 chars
				assert.Equal(t, byte('-'), prefixAndHash[12]) // Separator
				hash := prefixAndHash[13:]
				assert.Len(t, hash, 64) // Hash is 64 chars

				return keyStr.Key
			},
			wantFindErr:     false,
			wantValidateErr: false,
		},
		{
			name: "wrong_secret",
			setupKey: func() string {
				// Create valid key
				key, err := db.CreatePreAuthKey(
					user.TypedID(),
					true, false, nil, nil,
				)
				require.NoError(t, err)

				keyStr := key.Key

				// Well-formed key with the right identifier but a wrong secret:
				// must read as an unknown key (401), not a server error.
				_, prefixAndHash, _ := strings.Cut(keyStr, "hskey-auth-")
				prefix := prefixAndHash[:12]

				return "hskey-auth-" + prefix + "-" + strings.Repeat("0", 64)
			},
			wantFindErr:     true,
			findErrIs:       errSecretMismatch,
			wantValidateErr: false,
		},
		{
			name: "empty_key",
			setupKey: func() string {
				return ""
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "key_too_short",
			setupKey: func() string {
				return "hskey-auth-short"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "missing_separator",
			setupKey: func() string {
				return "hskey-auth-ABCDEFGHIJKLabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "hash_too_short",
			setupKey: func() string {
				return "hskey-auth-ABCDEFGHIJKL-short"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "prefix_with_invalid_chars",
			setupKey: func() string {
				return "hskey-auth-ABC$EF@HIJKL-" + strings.Repeat("a", 64)
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "hash_with_invalid_chars",
			setupKey: func() string {
				return "hskey-auth-ABCDEFGHIJKL-" + "invalid$chars" + strings.Repeat("a", 54)
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "prefix_not_found_in_db",
			setupKey: func() string {
				// Create a validly formatted key but with a prefix that doesn't exist
				return "hskey-auth-NotInDB12345-" + strings.Repeat("a", 64)
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyStr := tt.setupKey()

			pak, err := db.GetPreAuthKey(keyStr)

			if tt.wantFindErr {
				require.Error(t, err)

				if tt.findErrIs != nil {
					require.ErrorIs(t, err, tt.findErrIs)
					require.ErrorIs(t, err, gorm.ErrRecordNotFound, "must map to 401")
				}

				return
			}

			require.NoError(t, err)
			require.NotNil(t, pak)

			// Check validation if needed
			if tt.wantValidateErr {
				err := pak.Validate()
				assert.Error(t, err)

				return
			}

			if tt.validateResult != nil {
				tt.validateResult(t, pak)
			}
		})
	}
}

// TestPreAuthKeysHaveUniqueIdentifiers verifies that freshly created pre-auth
// keys get distinct identifiers in the unified credentials table.
func TestPreAuthKeysHaveUniqueIdentifiers(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "test-unique"})
	require.NoError(t, err)

	key1, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	key2, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	pak1, err := db.GetPreAuthKey(key1.Key)
	require.NoError(t, err)

	pak2, err := db.GetPreAuthKey(key2.Key)
	require.NoError(t, err)

	assert.NotEmpty(t, pak1.Prefix)
	assert.NotEmpty(t, pak2.Prefix)
	assert.NotEqual(t, pak1.Prefix, pak2.Prefix, "new keys should have unique identifiers")
}

// TestUsePreAuthKeyAtomicCAS verifies that UsePreAuthKey is an atomic
// compare-and-set: a second call against an already-used key reports
// PAKError("authkey already used") rather than silently succeeding.
func TestUsePreAuthKeyAtomicCAS(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "atomic-cas"})
	require.NoError(t, err)

	pakNew, err := db.CreatePreAuthKey(user.TypedID(), false /* reusable */, false, nil, nil)
	require.NoError(t, err)

	pak, err := db.GetPreAuthKey(pakNew.Key)
	require.NoError(t, err)
	require.False(t, pak.Reusable, "test sanity: key must be single-use")

	// First Use should commit cleanly.
	err = db.Write(func(tx *gorm.DB) error {
		return UsePreAuthKey(tx, pak)
	})
	require.NoError(t, err, "first UsePreAuthKey should succeed")

	// Reload from disk to drop the in-memory Used=true the first call
	// set on the struct, simulating a second concurrent transaction
	// that loaded the same row before the first one committed.
	stale, err := db.GetPreAuthKey(pakNew.Key)
	require.NoError(t, err)

	stale.Used = false

	err = db.Write(func(tx *gorm.DB) error {
		return UsePreAuthKey(tx, stale)
	})
	require.Error(t, err, "second UsePreAuthKey on the same single-use key must fail")

	var pakErr types.PAKError
	require.ErrorAs(t, err, &pakErr,
		"second UsePreAuthKey error must be a PAKError, got: %v", err)
	assert.Equal(t, "authkey already used", pakErr.Error())
}

// TestGetPreAuthKeyUnknownMapsToRecordNotFound ensures an unknown (or deleted)
// pre-auth key resolves to a record-not-found error, which the registration
// handler maps to a 401 rather than a raw server error.
func TestGetPreAuthKeyUnknownMapsToRecordNotFound(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, err = db.GetPreAuthKey("nonexistent-key")
	require.Error(t, err)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound,
		"unknown pre-auth key must map to record-not-found (handled as 401)")
}

// TestPreAuthKeyLazyRehashesBcrypt seeds a new-format key whose secret is stored
// as a legacy bcrypt hash and asserts that authenticating it upgrades the stored
// hash to SHA-256, while continuing to authenticate.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
func TestPreAuthKeyLazyRehashesBcrypt(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("rehash-user")

	prefix := "abcdefghijkl"
	secret := strings.Repeat("b", 64)
	keyStr := "hskey-auth-" + prefix + "-" + secret

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)

	err = db.DB.Exec(
		`INSERT INTO credentials (kind, identifier, hash, user_id, reusable, ephemeral, used, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		types.CredentialPreAuthKey, prefix, hash, user.ID, true, false, false, time.Now(),
	).Error
	require.NoError(t, err)

	pak, err := db.GetPreAuthKey(keyStr)
	require.NoError(t, err)
	require.NotNil(t, pak)

	reloaded, err := db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(reloaded.Hash), hashPrefixSHA256),
		"a bcrypt-stored key must be rehashed to SHA-256 on first auth")

	// Still authenticates against the upgraded hash.
	_, err = db.GetPreAuthKey(keyStr)
	require.NoError(t, err)
}

// Frozen from 1096abfc8 before optimizing collection; keep both bodies independent.
func destroyPreAuthKeyOriginal(tx *gorm.DB, id uint64) error {
	return tx.Transaction(func(db *gorm.DB) error {
		// First, clear the foreign key reference on any nodes using this key
		err := db.Model(&types.Node{}).
			Where("auth_key_id = ?", id).
			Update("auth_key_id", nil).Error
		if err != nil {
			return fmt.Errorf("clearing auth_key_id on nodes: %w", err)
		}

		// Then delete the pre-auth key, on the same savepoint as the
		// node update so both roll back together.
		res := db.Unscoped().
			Delete(&types.Credential{}, "kind = ? AND id = ?", types.CredentialPreAuthKey, id)
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrPreAuthKeyNotFound
		}

		return nil
	})
}

func destroyRevokedPreAuthKeysBeforeOriginal(hsdb *HSDatabase, cutoff time.Time) (int, error) {
	var count int

	err := hsdb.Write(func(tx *gorm.DB) error {
		var ids []uint64

		err := tx.Model(&types.Credential{}).
			Where("kind = ? AND revoked IS NOT NULL AND revoked < ?", types.CredentialPreAuthKey, cutoff).
			Where("id NOT IN (SELECT auth_key_id FROM nodes WHERE auth_key_id IS NOT NULL)").
			Pluck("id", &ids).Error
		if err != nil {
			return err
		}

		for _, id := range ids {
			err := destroyPreAuthKeyOriginal(tx, id)
			if err != nil {
				return err
			}
		}

		count = len(ids)

		return nil
	})

	return count, err
}

var errCollectorInjected = errors.New("collector injected failure")

var revokedCollectors = []struct {
	name string
	run  func(*HSDatabase, time.Time) (int, error)
}{
	{"original", destroyRevokedPreAuthKeysBeforeOriginal},
	{"current", (*HSDatabase).DestroyRevokedPreAuthKeysBefore},
}

func newRevokedCollectorDB(tb testing.TB) *HSDatabase {
	tb.Helper()
	cfg := sqliteTestConfig(tb.TempDir() + "/collector.db")
	cfg.Database.Sqlite.WriteAheadLog = true
	db, err := NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, db.Close()) })

	return db
}

func seedRevokedCollector(tb testing.TB, db *HSDatabase, eligible int) time.Time {
	tb.Helper()

	cutoff := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	before, after := cutoff.Add(-time.Second), cutoff.Add(time.Second)
	db.DB = db.DB.Session(&gorm.Session{NowFunc: func() time.Time { return cutoff }})

	require.NoError(tb, db.Write(func(tx *gorm.DB) error {
		for _, table := range []string{"nodes", "credentials", "users"} {
			err := tx.Exec("DELETE FROM " + table).Error
			if err != nil {
				return err
			}
		}

		model := gorm.Model{ID: 1, CreatedAt: before, UpdatedAt: before}
		user := types.User{Model: model, Name: "collector-owner"}

		err := tx.Create(&user).Error
		if err != nil {
			return err
		}

		creds := make([]types.Credential, eligible+7)
		for i := range creds {
			creds[i] = types.Credential{
				ID: uint64(i + 1), Kind: types.CredentialPreAuthKey,
				Identifier: fmt.Sprintf("collector-%06d", i), Hash: hashSecret("fixture"),
				UserID: &user.ID, Description: fmt.Sprintf("key %d", i),
				CreatedAt: &before, Revoked: &before, Expiration: &after,
				Tags: []string{"tag:collector"}, Reusable: i%2 == 0,
				Ephemeral: true, Used: i%3 == 0,
			}
		}

		creds[eligible].Revoked = nil
		creds[eligible+1].Revoked = &cutoff
		creds[eligible+2].Revoked = &after
		creds[eligible+4].Kind = types.CredentialAPIKey
		creds[eligible+5].Kind = types.CredentialOAuthClient

		creds[eligible+6].Kind = types.CredentialOAuthToken

		err = tx.CreateInBatches(&creds, 100).Error
		if err != nil {
			return err
		}

		nodes := []types.Node{
			{ID: 1, Hostname: "referenced", Tags: []string{"tag:collector"}, AuthKeyID: &creds[eligible+3].ID, CreatedAt: before},
			{ID: 2, Hostname: "null-reference", UserID: &user.ID, CreatedAt: before},
		}

		return tx.Create(&nodes).Error
	}))

	return cutoff
}

type revokedCollectorRows struct {
	Credentials []types.Credential
	Nodes       types.Nodes
	Users       []types.User
}

func revokedCollectorSnapshot(tb testing.TB, db *HSDatabase) revokedCollectorRows {
	tb.Helper()

	var rows revokedCollectorRows
	require.NoError(tb, db.DB.Unscoped().Order("id").Find(&rows.Credentials).Error)
	require.NoError(tb, preloadNode(db.DB.Unscoped()).Order("id").Find(&rows.Nodes).Error)
	require.NoError(tb, db.DB.Unscoped().Order("id").Find(&rows.Users).Error)

	return rows
}

type revokedCollectorTrace struct {
	logger.Interface

	statements []string
}

func (l *revokedCollectorTrace) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	query, _ := fc()
	l.statements = append(l.statements, query)
}

func TestRevokedCollectorDifferential(t *testing.T) {
	for _, eligible := range []int{0, 1, 100, 1000} {
		t.Run(strconv.Itoa(eligible), func(t *testing.T) {
			var wantRows revokedCollectorRows

			var wantQueries []string

			for _, collector := range revokedCollectors {
				db := newRevokedCollectorDB(t)
				cutoff := seedRevokedCollector(t, db, eligible)
				trace := &revokedCollectorTrace{Interface: logger.Discard}
				db.DB = db.DB.Session(&gorm.Session{Logger: trace})
				count, err := collector.run(db, cutoff)
				require.NoError(t, err)
				require.Equal(t, eligible, count)

				db.DB = db.DB.Session(&gorm.Session{Logger: logger.Discard})
				rows := revokedCollectorSnapshot(t, db)
				require.True(t, rows.Nodes[0].IsEphemeral())

				queries := slices.DeleteFunc(slices.Clone(trace.statements), func(s string) bool {
					return strings.HasPrefix(s, "SAVEPOINT ")
				})
				wantStatements := 1 + 2*eligible

				if collector.name == "original" {
					wantRows, wantQueries = rows, queries
					wantStatements += eligible
				} else {
					require.Equal(t, wantRows, rows, "whole surviving rows and associations")
					require.Equal(t, wantQueries, queries, "same SQL in the same order, except savepoints")
				}

				require.Len(t, trace.statements, wantStatements, collector.name)
				t.Logf("%s: %d eligible, %d SQL statements", collector.name, eligible, len(trace.statements))
				count, err = collector.run(db, cutoff)
				require.NoError(t, err)
				require.Zero(t, count, "second collection is a no-op")
			}
		})
	}
}

func TestRevokedCollectorRollback(t *testing.T) {
	for _, failure := range []string{"select", "update", "delete", "missing", "foreign-key", "deferred-foreign-key"} {
		t.Run(failure, func(t *testing.T) {
			var wantError string

			var wantConnectionRows revokedCollectorRows

			for _, collector := range revokedCollectors {
				t.Run(collector.name, func(t *testing.T) {
					db := newRevokedCollectorDB(t)
					cutoff := seedRevokedCollector(t, db, 3)
					before := revokedCollectorSnapshot(t, db)
					injected := errCollectorInjected

					switch failure {
					case "select":
						require.NoError(t, db.DB.Callback().Query().Before("gorm:query").Register("collector_failure", func(tx *gorm.DB) {
							if _, ok := tx.Statement.Dest.(*[]uint64); ok {
								_ = tx.AddError(injected)
							}
						}))
					case "update":
						updates := 0

						require.NoError(t, db.DB.Callback().Update().Before("gorm:update").Register("collector_failure", func(tx *gorm.DB) {
							updates++
							if updates == 2 {
								_ = tx.AddError(injected)
							}
						}))
					case "delete", "missing":
						action := "RAISE(ABORT, 'collector injected failure')"
						if failure == "missing" {
							action = "RAISE(IGNORE)"
						}

						require.NoError(t, db.DB.Exec("CREATE TRIGGER collector_failure BEFORE DELETE ON credentials WHEN OLD.id = 2 BEGIN SELECT "+action+"; END").Error)
					case "foreign-key", "deferred-foreign-key":
						if failure == "deferred-foreign-key" {
							require.NoError(t, db.DB.Callback().Query().After("gorm:query").Register("collector_defer", func(tx *gorm.DB) {
								if _, ok := tx.Statement.Dest.(*[]uint64); ok {
									_ = tx.AddError(tx.Exec("PRAGMA defer_foreign_keys = ON").Error)
								}
							}))
						}

						require.NoError(t, db.DB.Exec("CREATE TRIGGER collector_failure AFTER DELETE ON credentials WHEN OLD.id = 2 BEGIN UPDATE nodes SET auth_key_id = OLD.id WHERE id = 2; END").Error)
					}

					count, err := collector.run(db, cutoff)
					require.Error(t, err)

					if failure == "deferred-foreign-key" {
						require.Equal(t, 3, count, "original reports selected count on commit failure")
					} else {
						require.Zero(t, count)
					}

					if failure == "missing" {
						require.ErrorIs(t, err, ErrPreAuthKeyNotFound)
					}

					if collector.name == "original" {
						wantError = err.Error()
					} else {
						require.Equal(t, wantError, err.Error())
					}

					rows := revokedCollectorSnapshot(t, db)

					if failure == "deferred-foreign-key" {
						// The original driver path leaves a failed COMMIT open on this connection.
						if collector.name == "original" {
							wantConnectionRows = rows
						} else {
							require.Equal(t, wantConnectionRows, rows)
						}

						other, openErr := gorm.Open(db.DB.Dialector, &gorm.Config{Logger: logger.Discard})
						require.NoError(t, openErr)
						sqlDB, openErr := other.DB()
						require.NoError(t, openErr)

						defer sqlDB.Close()

						require.Equal(t, before, revokedCollectorSnapshot(t, &HSDatabase{DB: other}), "failed commit must not persist deletions")
						require.NoError(t, db.DB.Exec("ROLLBACK").Error)
					} else {
						require.Equal(t, before, rows, "all earlier deletes must roll back")
					}
				})
			}
		})
	}
}

func TestRevokedCollectorSQLiteConcurrentReference(t *testing.T) {
	for _, collector := range revokedCollectors {
		t.Run(collector.name, func(t *testing.T) {
			db := newRevokedCollectorDB(t)
			cutoff := seedRevokedCollector(t, db, 1)
			selected, resume := make(chan struct{}), make(chan struct{})

			var once sync.Once
			defer once.Do(func() { close(resume) })

			require.NoError(t, db.DB.Callback().Query().After("gorm:query").Register("collector_pause", func(tx *gorm.DB) {
				if _, ok := tx.Statement.Dest.(*[]uint64); ok {
					close(selected)
					<-resume
				}
			}))

			done := make(chan error, 1)

			go func() {
				_, err := collector.run(db, cutoff)
				done <- err
			}()

			select {
			case <-selected:
			case <-time.After(10 * time.Second):
				t.Fatal("collector did not reach selection")
			}

			other, err := sql.Open("sqlite", "file:"+db.cfg.Database.Sqlite.Path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(0)")
			require.NoError(t, err)

			defer other.Close()

			_, err = other.ExecContext(t.Context(), "UPDATE nodes SET auth_key_id = 1 WHERE id = 2")
			require.ErrorContains(t, err, "database is locked", "BEGIN IMMEDIATE prevents a new reference after selection")
			once.Do(func() { close(resume) })
			require.NoError(t, <-done)
			_, err = other.ExecContext(t.Context(), "UPDATE nodes SET auth_key_id = 1 WHERE id = 2")
			require.ErrorContains(t, err, "FOREIGN KEY constraint failed")
			rows := revokedCollectorSnapshot(t, db)
			require.Len(t, rows.Credentials, 7)
			require.Nil(t, rows.Nodes[1].AuthKeyID)
			require.True(t, rows.Nodes[0].IsEphemeral())
		})
	}
}

func TestRevokedCollectorPostgresConcurrency(t *testing.T) {
	for _, interleave := range []string{"reference-before-update", "reference-before-delete", "concurrent-delete", "concurrent-delete-late"} {
		t.Run(interleave, func(t *testing.T) {
			var wantRows revokedCollectorRows

			var wantError string

			for _, collector := range revokedCollectors {
				t.Run(collector.name, func(t *testing.T) {
					db := newPostgresTestDB(t)
					t.Cleanup(func() { require.NoError(t, db.Close()) })
					cutoff := seedRevokedCollector(t, db, 3)
					paused, resume := make(chan struct{}), make(chan struct{})

					var release, pause sync.Once

					var selectedID uint64

					successfulDeletes := 0

					require.NoError(t, db.DB.Callback().Delete().After("gorm:delete").Register("collector_count_deletes", func(tx *gorm.DB) {
						if tx.Error == nil && tx.RowsAffected > 0 {
							successfulDeletes++
						}
					}))

					defer release.Do(func() { close(resume) })

					hook := func(_ *gorm.DB) {
						pause.Do(func() { close(paused); <-resume })
					}
					if interleave == "reference-before-delete" {
						require.NoError(t, db.DB.Callback().Update().After("gorm:update").Register("collector_pause", hook))
					}

					require.NoError(t, db.DB.Callback().Query().After("gorm:query").Register("collector_pause", func(tx *gorm.DB) {
						if ids, ok := tx.Statement.Dest.(*[]uint64); ok && len(*ids) > 0 {
							selectedID = (*ids)[0]
							if interleave == "concurrent-delete-late" {
								selectedID = (*ids)[len(*ids)-1]
							}

							if interleave != "reference-before-delete" {
								hook(tx)
							}
						}
					}))

					type result struct {
						count int
						err   error
					}

					done := make(chan result, 1)

					go func() {
						count, err := collector.run(db, cutoff)
						done <- result{count, err}
					}()

					select {
					case <-paused:
					case <-time.After(10 * time.Second):
						t.Fatal("collector did not reach pause")
					}

					other, err := db.DB.DB()
					require.NoError(t, err)

					statement := "UPDATE nodes SET auth_key_id = $1 WHERE id = 2"
					if interleave == "concurrent-delete" || interleave == "concurrent-delete-late" {
						statement = "DELETE FROM credentials WHERE id = $1"
					}

					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()

					_, err = other.ExecContext(ctx, statement, selectedID)
					require.NoError(t, err)
					release.Do(func() { close(resume) })

					got := <-done
					errText := ""

					if interleave == "reference-before-update" {
						require.NoError(t, got.err)
						require.Equal(t, 3, got.count)
					} else {
						require.Error(t, got.err)
						require.Zero(t, got.count)

						errText = got.err.Error()
						if interleave == "concurrent-delete" || interleave == "concurrent-delete-late" {
							require.ErrorIs(t, got.err, ErrPreAuthKeyNotFound)
						} else {
							require.ErrorContains(t, got.err, "violates foreign key constraint")
						}
					}

					if interleave == "concurrent-delete-late" {
						require.Equal(t, 2, successfulDeletes, "failure must follow two successful deletes")
					}

					rows := revokedCollectorSnapshot(t, db)
					if collector.name == "original" {
						wantRows, wantError = rows, errText
					} else {
						require.Equal(t, wantError, errText)
						require.Equal(t, wantRows, rows)
					}
				})
			}
		})
	}
}

// Use a fixed iteration count (e.g. -benchtime=3x); fixture restoration is untimed.
func BenchmarkRevokedCollector(b *testing.B) {
	for _, eligible := range []int{0, 1, 100, 1000} {
		for _, rollback := range []bool{false, true} {
			if rollback && eligible == 0 {
				continue
			}

			for _, collector := range revokedCollectors {
				b.Run(fmt.Sprintf("keys=%d/rollback=%t/%s", eligible, rollback, collector.name), func(b *testing.B) {
					db := newRevokedCollectorDB(b)
					reset := func() time.Time {
						require.NoError(b, db.DB.Exec("DROP TRIGGER IF EXISTS collector_failure").Error)

						cutoff := seedRevokedCollector(b, db, eligible)
						if rollback {
							require.NoError(b, db.DB.Exec(fmt.Sprintf("CREATE TRIGGER collector_failure BEFORE DELETE ON credentials WHEN OLD.id = %d BEGIN SELECT RAISE(ABORT, 'collector injected failure'); END", eligible)).Error)
						}

						return cutoff
					}
					check := func(count int, err error) {
						if rollback {
							require.ErrorContains(b, err, "collector injected failure")
							require.Zero(b, count)
						} else {
							require.NoError(b, err)
							require.Equal(b, eligible, count)
						}
					}
					cutoff := reset()
					trace := &revokedCollectorTrace{Interface: logger.Discard}
					db.DB = db.DB.Session(&gorm.Session{Logger: trace})
					count, err := collector.run(db, cutoff)
					check(count, err)

					db.DB = db.DB.Session(&gorm.Session{Logger: logger.Discard})

					b.ReportAllocs()
					b.ResetTimer()

					for range b.N {
						b.StopTimer()

						cutoff := reset()

						b.StartTimer()

						count, err := collector.run(db, cutoff)

						b.StopTimer()
						check(count, err)
					}

					b.ReportMetric(float64(len(trace.statements)), "statements/op")
				})
			}
		}
	}
}
