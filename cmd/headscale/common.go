package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/creachadair/command"
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

// nodeIdentifier represents a parsed node identifier
type nodeIdentifier struct {
	Type  string // "id", "name"
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

// parseNodeIdentifier parses a node identifier string and determines its type
func parseNodeIdentifier(input string) nodeIdentifier {
	// Try to parse as numeric ID first
	if id, err := strconv.ParseUint(input, 10, 64); err == nil && id > 0 {
		return nodeIdentifier{Type: "id", Value: input}
	}

	// Default to name (will search both hostname and givenname on server side)
	return nodeIdentifier{Type: "name", Value: input}
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

// withHeadscaleClient handles the common gRPC client setup and cleanup pattern
// It takes a function that accepts a context and client, and handles all the boilerplate
func withHeadscaleClient(fn func(context.Context, v1.HeadscaleServiceClient) error) error {
	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()
	return fn(ctx, client)
}

// resolveUserWithFallback resolves a user identifier to a user ID with backwards compatibility fallback
// It first tries to resolve via ResolveUserToID, then falls back to parsing as direct uint64
func resolveUserWithFallback(ctx context.Context, client v1.HeadscaleServiceClient, userIdentifier string) (uint64, error) {
	// Try to resolve user identifier to ID
	userID, err := ResolveUserToID(ctx, client, userIdentifier)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(userIdentifier, 10, 64); parseErr == nil {
			return parsedID, nil
		}
		return 0, fmt.Errorf("cannot resolve user identifier '%s': %w", userIdentifier, err)
	}
	return userID, nil
}

// ResolveNodeToID resolves a node identifier to a node ID
// This function will make a gRPC call to find the node by different identifier types
func ResolveNodeToID(ctx context.Context, client v1.HeadscaleServiceClient, identifier string) (uint64, error) {
	if identifier == "" {
		return 0, fmt.Errorf("node identifier cannot be empty")
	}

	parsed := parseNodeIdentifier(identifier)

	switch parsed.Type {
	case "id":
		// Already an ID, just parse and return
		id, err := strconv.ParseUint(parsed.Value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid node ID: %w", err)
		}
		return id, nil

	case "name":
		// Find node by name (searches both hostname and givenname)
		return findNodeByName(ctx, client, parsed.Value)

	default:
		return 0, fmt.Errorf("unknown node identifier type: %s", parsed.Type)
	}
}

// findNodeByName searches for a node by name (hostname or given name)
func findNodeByName(ctx context.Context, client v1.HeadscaleServiceClient, name string) (uint64, error) {
	// List all nodes to search through them
	listReq := &v1.ListNodesRequest{}
	listResp, err := client.ListNodes(ctx, listReq)
	if err != nil {
		return 0, fmt.Errorf("cannot list nodes: %w", err)
	}

	var matchingNodes []*v1.Node
	for _, node := range listResp.GetNodes() {
		// Check if name matches either hostname (name field) or given name
		if node.GetName() == name || node.GetGivenName() == name {
			matchingNodes = append(matchingNodes, node)
		}
	}

	if len(matchingNodes) == 0 {
		return 0, fmt.Errorf("node with name '%s' not found", name)
	}

	if len(matchingNodes) > 1 {
		return 0, fmt.Errorf("multiple nodes found with name '%s'", name)
	}

	return matchingNodes[0].GetId(), nil
}

// resolveNodeWithFallback resolves a node identifier to a node ID with backwards compatibility fallback
// It first tries to resolve via ResolveNodeToID, then falls back to parsing as direct uint64
func resolveNodeWithFallback(ctx context.Context, client v1.HeadscaleServiceClient, nodeIdentifier string) (uint64, error) {
	// Try to resolve node identifier to ID
	nodeID, err := ResolveNodeToID(ctx, client, nodeIdentifier)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(nodeIdentifier, 10, 64); parseErr == nil {
			return parsedID, nil
		}
		return 0, fmt.Errorf("cannot resolve node identifier '%s': %w", nodeIdentifier, err)
	}
	return nodeID, nil
}

// Command alias helper functions

// createCommandAlias creates a command alias with Unlisted: true
// It copies the original command structure and updates the name and help text
func createCommandAlias(original *command.C, aliasName, aliasHelp string) *command.C {
	alias := &command.C{
		Name:     aliasName,
		Usage:    original.Usage,
		Help:     aliasHelp,
		Run:      original.Run,
		SetFlags: original.SetFlags,
		Commands: original.Commands,
		Unlisted: true,
	}
	return alias
}

// createSubcommandAlias creates an alias for a subcommand within a command group
func createSubcommandAlias(originalRun func(*command.Env) error, aliasName, usage, aliasHelp string) *command.C {
	return &command.C{
		Name:     aliasName,
		Usage:    usage,
		Help:     aliasHelp,
		Run:      originalRun,
		Unlisted: true,
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

// validateNodeIdentifier validates that either ID or node identifier is provided for node commands
func validateNodeIdentifier(id uint64, node string) error {
	if id == 0 && node == "" {
		return fmt.Errorf("either --id or --node flag is required")
	}
	return nil
}

// requireNodeIdentifier validates that either ID or node identifier is provided
func requireNodeIdentifier(id uint64, node string) error {
	return validateNodeIdentifier(id, node)
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

// getUserIDFromIdentifier resolves a user identifier (ID or name) to a user ID
// This centralizes the common pattern of looking up users by ID or name
func getUserIDFromIdentifier(ctx context.Context, client v1.HeadscaleServiceClient, id uint64, name string) (uint64, error) {
	if id != 0 {
		return id, nil
	}

	if name == "" {
		return 0, fmt.Errorf("either ID or name must be provided")
	}

	// Find user by name
	listReq := &v1.ListUsersRequest{Name: name}
	listResp, err := client.ListUsers(ctx, listReq)
	if err != nil {
		return 0, fmt.Errorf("cannot find user: %w", err)
	}
	if len(listResp.GetUsers()) == 0 {
		return 0, fmt.Errorf("user with name '%s' not found", name)
	}

	return listResp.GetUsers()[0].GetId(), nil
}

// getNodeIDFromIdentifier resolves a node identifier (ID or node identifier) to a node ID
// This centralizes the common pattern of looking up nodes by ID or identifier
func getNodeIDFromIdentifier(ctx context.Context, client v1.HeadscaleServiceClient, id uint64, nodeIdentifier string) (uint64, error) {
	if id != 0 {
		return id, nil
	}

	if nodeIdentifier == "" {
		return 0, fmt.Errorf("either ID or node identifier must be provided")
	}

	// Resolve node identifier to ID with fallback
	return resolveNodeWithFallback(ctx, client, nodeIdentifier)
}

// confirmDeletion prompts for deletion confirmation unless force is specified
// Returns true if the operation should proceed, false if cancelled
func confirmDeletion(itemType, itemName string, force bool) (bool, error) {
	if force {
		return true, nil
	}

	// For now, just print a message and require --force
	// TODO: Add interactive confirmation prompt when survey library is available
	fmt.Printf("This will delete %s '%s'. Use --force to skip this confirmation.\n", itemType, itemName)
	return false, fmt.Errorf("deletion cancelled - use --force to proceed")
}

// parseDurationWithDefault parses a duration string with a default fallback
// This centralizes the common pattern of parsing expiration durations
func parseDurationWithDefault(durationStr string, defaultDuration time.Duration) (time.Time, error) {
	if durationStr == "" {
		return time.Now().Add(defaultDuration), nil
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid duration: %w", err)
	}

	return time.Now().Add(duration), nil
}
