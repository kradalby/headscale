package commands

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

// Common flag groups that can be embedded in command-specific flags

// globalFlags contains flags available to all commands
type globalFlags struct {
	Config string `flag:"config,c,Config file path"`
	Output string `flag:"output,o,Output format (json, yaml, table)"`
	Force  bool   `flag:"force,Skip confirmation prompts"`
}

// identifierFlags for commands that need to identify resources by ID or name
type identifierFlags struct {
	ID   uint64 `flag:"id,i,Resource ID"`
	Name string `flag:"name,n,Resource name"`
}

// userFlags for commands that reference users
type userFlags struct {
	User string `flag:"user,u,User identifier (ID, username, email, or provider ID)"`
}

// expirationFlags for commands that set expiration
type expirationFlags struct {
	Expiration string `flag:"expiration,e,default=24h,Expiration duration (e.g. 1h, 24h, 7d)"`
}

// Helper function to create SetFlags with less boilerplate
func setFlags[T any](flags *T) func(*command.Env, *flag.FlagSet) {
	return command.Flags(flax.MustBind, flags)
}

// Validation helper functions

// requireString validates that a required string flag is provided
func requireString(value, name string) error {
	if value == "" {
		return fmt.Errorf("--%s flag is required", name)
	}
	return nil
}

// requireUint64 validates that a required uint64 flag is provided
func requireUint64(value uint64, name string) error {
	if value == 0 {
		return fmt.Errorf("--%s flag is required", name)
	}
	return nil
}

// requireEither validates that at least one of two string values is provided
func requireEither(value1, name1, value2, name2 string) error {
	if value1 == "" && value2 == "" {
		return fmt.Errorf("either --%s or --%s flag is required", name1, name2)
	}
	return nil
}

// validateIdentifier validates that either ID or name is provided
func validateIdentifier(flags identifierFlags) error {
	return requireEither(fmt.Sprintf("%d", flags.ID), "id", flags.Name, "name")
}

// User lookup function - resolves user identifier to user ID
// TODO: Implement actual user lookup logic when backend API is available
func resolveUserID(userIdentifier string) (uint64, error) {
	// Try parsing as uint64 first (direct ID)
	if id, err := strconv.ParseUint(userIdentifier, 10, 64); err == nil && id > 0 {
		return id, nil
	}

	// Check if it looks like an email
	if strings.Contains(userIdentifier, "@") {
		// TODO: Call API to lookup user by email
		return 0, fmt.Errorf("user lookup by email not yet implemented: %s", userIdentifier)
	}

	// Check if it's a provider identifier (contains specific patterns)
	if strings.Contains(userIdentifier, ":") || strings.HasPrefix(userIdentifier, "oauth_") {
		// TODO: Call API to lookup user by provider identifier
		return 0, fmt.Errorf("user lookup by provider ID not yet implemented: %s", userIdentifier)
	}

	// Otherwise treat as username
	// TODO: Call API to lookup user by username
	return 0, fmt.Errorf("user lookup by username not yet implemented: %s", userIdentifier)
}

// validateUserReference validates that user is provided and resolves it to ID
func validateUserReference(flags userFlags) (uint64, error) {
	if err := requireString(flags.User, "user"); err != nil {
		return 0, err
	}
	return resolveUserID(flags.User)
}

// parseDurationFlag parses duration with default fallback
func parseDurationFlag(s string, defaultDuration time.Duration) (time.Duration, error) {
	if s == "" {
		return defaultDuration, nil
	}
	return time.ParseDuration(s)
}
