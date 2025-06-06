package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Global flags available to all commands
var globalArgs struct {
	Config string `flag:"config,c,Config file path"`
	Output string `flag:"output,o,Output format (json, yaml, table)"`
	Force  bool   `flag:"force,Skip confirmation prompts"`
}

// userIdentifier represents a parsed user identifier
type userIdentifier struct {
	Type  string // "id", "username", "email", "provider"
	Value string
}

// parseUserIdentifier parses a user identifier string and determines its type
func parseUserIdentifier(input string) userIdentifier {
	// Try to parse as numeric ID first
	if id, err := strconv.ParseUint(input, 10, 64); err == nil && id > 0 {
		return userIdentifier{Type: "id", Value: input}
	}

	// Check if it looks like an email
	if strings.Contains(input, "@") && strings.Contains(input, ".") {
		return userIdentifier{Type: "email", Value: input}
	}

	// Check if it looks like a provider identifier (contains a colon)
	if strings.Contains(input, ":") {
		return userIdentifier{Type: "provider", Value: input}
	}

	// Default to username
	return userIdentifier{Type: "username", Value: input}
}

// ResolveUserToID resolves a user identifier to a user ID
// This function will make a gRPC call to find the user by different identifier types
func ResolveUserToID(ctx context.Context, client v1.HeadscaleServiceClient, identifier string) (uint64, error) {
	if identifier == "" {
		return 0, fmt.Errorf("user identifier cannot be empty")
	}

	parsed := parseUserIdentifier(identifier)

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

// validateUserIdentifier validates that either ID or name is provided for user commands
func validateUserIdentifier(id uint64, name string) error {
	if id == 0 && name == "" {
		return fmt.Errorf("either --id or --name flag is required")
	}
	return nil
}

// validateNodeIdentifier validates that either ID or name/user combination is provided for node commands
func validateNodeIdentifier(id uint64, user string) error {
	if id == 0 && user == "" {
		return fmt.Errorf("either --id or --user flag is required")
	}
	return nil
}

// parseCommaSeparated parses a comma-separated string into a slice of strings
func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
