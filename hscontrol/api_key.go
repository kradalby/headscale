package hscontrol

import (
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	apiPrefixLength = 7
	apiKeyLength    = 32
)

var ErrAPIKeyFailedToParse = errors.New("failed to parse ApiKey")

// APIKey describes the datamodel for API keys used to remotely authenticate with
// headscale.
type APIKey struct {
	ID     uint64 `gorm:"primary_key"`
	Prefix string `gorm:"uniqueIndex"`
	Hash   []byte

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

// CreateAPIKey creates a new ApiKey in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
) (string, *APIKey, error) {
	prefix, err := util.GenerateRandomStringURLSafe(apiPrefixLength)
	if err != nil {
		return "", nil, err
	}

	toBeHashed, err := util.GenerateRandomStringURLSafe(apiKeyLength)
	if err != nil {
		return "", nil, err
	}

	// Key to return to user, this will only be visible _once_
	keyStr := prefix + "." + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	key := APIKey{
		Prefix:     prefix,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := hsdb.db.Save(&key).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of ApiKeys for a user.
func (hsdb *HSDatabase) ListAPIKeys() ([]APIKey, error) {
	keys := []APIKey{}
	if err := hsdb.db.Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a ApiKey for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*APIKey, error) {
	key := APIKey{}
	if result := hsdb.db.First(&key, "prefix = ?", prefix); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a ApiKey for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*APIKey, error) {
	key := APIKey{}
	if result := hsdb.db.Find(&APIKey{ID: id}).First(&key); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a ApiKey. Returns error if the ApiKey
// does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key APIKey) error {
	if result := hsdb.db.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a ApiKey as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *APIKey) error {
	if err := hsdb.db.Model(&key).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) ValidateAPIKey(keyStr string) (bool, error) {
	prefix, hash, found := strings.Cut(keyStr, ".")
	if !found {
		return false, ErrAPIKeyFailedToParse
	}

	key, err := hsdb.GetAPIKey(prefix)
	if err != nil {
		return false, fmt.Errorf("failed to validate api key: %w", err)
	}

	if key.Expiration.Before(time.Now()) {
		return false, nil
	}

	if err := bcrypt.CompareHashAndPassword(key.Hash, []byte(hash)); err != nil {
		return false, err
	}

	return true, nil
}

func (key *APIKey) toProto() *v1.ApiKey {
	protoKey := v1.ApiKey{
		Id:     key.ID,
		Prefix: key.Prefix,
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	if key.LastSeen != nil {
		protoKey.LastSeen = timestamppb.New(*key.LastSeen)
	}

	return &protoKey
}
