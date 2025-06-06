package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/creachadair/command"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Common flag structures that can be embedded

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

// tagsFlags for commands that work with tags
type tagsFlags struct {
	Tags []string `flag:"tags,t,Comma-separated tags"`
}

// routesFlags for commands that work with routes
type routesFlags struct {
	Routes []string `flag:"routes,r,Comma-separated routes"`
}

// Helper function to simplify flag binding
func Flags(bind func(*flag.FlagSet, interface{}), flags interface{}) func(*command.Env, *flag.FlagSet) {
	return func(env *command.Env, fs *flag.FlagSet) {
		bind(fs, flags)
		env.Config = flags
	}
}

// UserIdentifier represents a parsed user identifier
type UserIdentifier struct {
	Type  string // "id", "username", "email", "provider"
	Value string
}

// ParseUserIdentifier parses a user identifier string and determines its type
func ParseUserIdentifier(input string) UserIdentifier {
	// Try to parse as numeric ID first
	if id, err := strconv.ParseUint(input, 10, 64); err == nil && id > 0 {
		return UserIdentifier{Type: "id", Value: input}
	}

	// Check if it looks like an email
	if strings.Contains(input, "@") && strings.Contains(input, ".") {
		return UserIdentifier{Type: "email", Value: input}
	}

	// Check if it looks like a provider identifier (contains a colon)
	if strings.Contains(input, ":") {
		return UserIdentifier{Type: "provider", Value: input}
	}

	// Default to username
	return UserIdentifier{Type: "username", Value: input}
}

// ResolveUserToID resolves a user identifier to a user ID
// This function will make a gRPC call to find the user by different identifier types
func ResolveUserToID(ctx context.Context, client v1.HeadscaleServiceClient, identifier string) (uint64, error) {
	if identifier == "" {
		return 0, fmt.Errorf("user identifier cannot be empty")
	}

	parsed := ParseUserIdentifier(identifier)

	switch parsed.Type {
	case "id":
		// Already an ID, just parse and return
		id, err := strconv.ParseUint(parsed.Value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid user ID: %w", err)
		}
		return id, nil

	case "username":
		// TODO: Implement gRPC call to find user by username
		// For now, return a placeholder error
		return 0, fmt.Errorf("user lookup by username not yet implemented - need gRPC API for GetUserByName")

	case "email":
		// TODO: Implement gRPC call to find user by email
		// For now, return a placeholder error
		return 0, fmt.Errorf("user lookup by email not yet implemented - need gRPC API for GetUserByEmail")

	case "provider":
		// TODO: Implement gRPC call to find user by provider identifier
		// For now, return a placeholder error
		return 0, fmt.Errorf("user lookup by provider ID not yet implemented - need gRPC API for GetUserByProviderIdentifier")

	default:
		return 0, fmt.Errorf("unknown user identifier type: %s", parsed.Type)
	}
}

// RequireString validates that a required string flag is provided
func RequireString(value, name string) error {
	if value == "" {
		return fmt.Errorf("--%s flag is required", name)
	}
	return nil
}

// RequireUint64 validates that a required uint64 flag is provided
func RequireUint64(value uint64, name string) error {
	if value == 0 {
		return fmt.Errorf("--%s flag is required", name)
	}
	return nil
}

// RequireEither validates that at least one of two string values is provided
func RequireEither(value1, name1, value2, name2 string) error {
	if value1 == "" && value2 == "" {
		return fmt.Errorf("either --%s or --%s flag is required", name1, name2)
	}
	return nil
}

// ValidateIdentifier validates that either ID or name is provided
func ValidateIdentifier(flags identifierFlags) error {
	return RequireEither(fmt.Sprintf("%d", flags.ID), "id", flags.Name, "name")
}

// ValidateIdentifierFromFields validates that either ID or name is provided from explicit fields
func ValidateIdentifierFromFields(id uint64, name string) error {
	if id == 0 && name == "" {
		return fmt.Errorf("either --id or --name flag is required")
	}
	return nil
}
