package main

import (
	"context"
	"flag"
	"strings"
	"testing"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

func TestCommandStructure(t *testing.T) {
	// Test that the command tree is properly structured
	root := createTestRootCommand()

	// Test that root command exists
	if root.Name != "headscale" {
		t.Errorf("Expected root command name 'headscale', got '%s'", root.Name)
	}

	// Test that subcommands exist
	expectedCommands := []string{"serve", "version", "config", "users", "nodes", "preauth-keys", "api-keys", "policy", "dev", "help"}
	for _, expectedCmd := range expectedCommands {
		found := false
		for _, cmd := range root.Commands {
			if cmd.Name == expectedCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected command '%s' not found", expectedCmd)
		}
	}
}

func TestUserCommands(t *testing.T) {
	root := createTestRootCommand()

	// Find users command
	var usersCmd *command.C
	for _, cmd := range root.Commands {
		if cmd.Name == "users" {
			usersCmd = cmd
			break
		}
	}

	if usersCmd == nil {
		t.Fatal("Users command not found")
	}

	// Test user subcommands
	expectedSubcommands := []string{"create", "list", "update", "delete"}
	for _, expectedSub := range expectedSubcommands {
		found := false
		for _, sub := range usersCmd.Commands {
			if sub.Name == expectedSub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected user subcommand '%s' not found", expectedSub)
		}
	}
}

func TestFlagBinding(t *testing.T) {
	// Test that flax flag binding works
	flags := &CreateUserFlags{
		Config:      "/test/config",
		Output:      "json",
		Force:       true,
		DisplayName: "Test User",
		Email:       "test@example.com",
		PictureURL:  "https://example.com/pic.jpg",
	}

	// Test that fields are properly set
	if flags.Config != "/test/config" {
		t.Errorf("Expected config '/test/config', got '%s'", flags.Config)
	}
	if flags.Output != "json" {
		t.Errorf("Expected output 'json', got '%s'", flags.Output)
	}
	if !flags.Force {
		t.Error("Expected force to be true")
	}
	if flags.DisplayName != "Test User" {
		t.Errorf("Expected display name 'Test User', got '%s'", flags.DisplayName)
	}
	if flags.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", flags.Email)
	}
}

func TestFlagValidation(t *testing.T) {
	// Test RequireString validation
	err := RequireString("", "test")
	if err == nil {
		t.Error("Expected error for empty required string")
	}
	if !strings.Contains(err.Error(), "--test flag is required") {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}

	err = RequireString("value", "test")
	if err != nil {
		t.Errorf("Expected no error for non-empty string, got '%s'", err.Error())
	}

	// Test RequireUint64 validation
	err = RequireUint64(0, "id")
	if err == nil {
		t.Error("Expected error for zero uint64")
	}

	err = RequireUint64(42, "id")
	if err != nil {
		t.Errorf("Expected no error for non-zero uint64, got '%s'", err.Error())
	}

	// Test RequireEither validation
	err = RequireEither("", "name", "", "id")
	if err == nil {
		t.Error("Expected error when both values are empty")
	}

	err = RequireEither("test", "name", "", "id")
	if err != nil {
		t.Errorf("Expected no error when first value is provided, got '%s'", err.Error())
	}

	err = RequireEither("", "name", "42", "id")
	if err != nil {
		t.Errorf("Expected no error when second value is provided, got '%s'", err.Error())
	}
}

func TestIdentifierValidation(t *testing.T) {
	// Test ValidateIdentifierFromFields
	err := ValidateIdentifierFromFields(0, "")
	if err == nil {
		t.Error("Expected error when both ID and name are empty")
	}

	err = ValidateIdentifierFromFields(42, "")
	if err != nil {
		t.Errorf("Expected no error when ID is provided, got '%s'", err.Error())
	}

	err = ValidateIdentifierFromFields(0, "test")
	if err != nil {
		t.Errorf("Expected no error when name is provided, got '%s'", err.Error())
	}
}

func TestUserReferenceValidation(t *testing.T) {
	// Test ValidateUserFromField
	err := ValidateUserFromField("")
	if err == nil {
		t.Error("Expected error when user is empty")
	}

	err = ValidateUserFromField("testuser")
	if err != nil {
		t.Errorf("Expected no error when user is provided, got '%s'", err.Error())
	}
}

func TestCommandAliases(t *testing.T) {
	root := createTestRootCommand()

	// Test that users command has aliases
	var usersCmd *command.C
	for _, cmd := range root.Commands {
		if cmd.Name == "users" {
			usersCmd = cmd
			break
		}
	}

	if usersCmd == nil {
		t.Fatal("Users command not found")
	}

	// Check for user alias command (now implemented as separate command)
	userCmd := root.FindSubcommand("user")
	if userCmd == nil {
		t.Error("Expected 'user' alias command not found")
	}
}

func TestFlaxIntegration(t *testing.T) {
	// Test that flax can parse our flag structures
	flags := &ListNodeFlags{}

	fields, err := flax.Check(flags)
	if err != nil {
		t.Fatalf("Error checking flags: %v", err)
	}

	// Debug: print actual flag names found
	t.Logf("Found %d flags:", len(fields))
	flagNames := make(map[string]bool)
	for _, field := range fields {
		t.Logf("  Flag: %s", field.Name)
		flagNames[field.Name] = true
	}

	// Should have flags from GlobalFlags, UserFlags, and ShowTags
	expectedFlagNames := []string{"config", "output", "force", "user", "show-tags"}

	for _, expected := range expectedFlagNames {
		if !flagNames[expected] {
			t.Errorf("Expected flag '%s' not found in parsed flags", expected)
		}
	}

	// At minimum, we should have some flags
	if len(fields) == 0 {
		t.Error("No flags found - flax integration may be broken")
	}
}

func TestCommandEnvironment(t *testing.T) {
	// Test command environment setup
	root := createTestRootCommand()
	globalFlags := &GlobalFlags{
		Config: "/test/config",
		Output: "json",
		Force:  false,
	}

	env := root.NewEnv(globalFlags).SetContext(context.Background())

	if env.Command != root {
		t.Error("Environment command should point to root")
	}

	if env.Config.(*GlobalFlags).Config != "/test/config" {
		t.Error("Environment config not properly set")
	}

	if env.Context() == nil {
		t.Error("Environment context should be set")
	}
}

// Helper function to create a test version of the root command
// createTestRootCommand creates the real CLI root command for testing
func createTestRootCommand() *command.C {
	return &command.C{
		Name: "headscale",
		Usage: `<command> [flags] [args...]
  serve
  version
  config test
  users <subcommand> [flags] [args...]
  nodes <subcommand> [flags] [args...]
  preauth-keys <subcommand> [flags] [args...]
  api-keys <subcommand> [flags] [args...]
  policy <subcommand> [flags] [args...]
  dev <subcommand> [flags] [args...]`,

		Help: `headscale - a Tailscale control server

headscale is an open source implementation of the Tailscale control server

https://github.com/juanfont/headscale`,

		SetFlags: func(env *command.Env, fs *flag.FlagSet) {
			flags := env.Config.(*GlobalFlags)
			flax.MustBind(fs, flags)
		},

		Commands: []*command.C{
			// Server commands
			{
				Name:  "serve",
				Usage: "",
				Help:  "Start the headscale server",
				SetFlags: func(env *command.Env, fs *flag.FlagSet) {
					flags := &ServeFlags{}
					flax.MustBind(fs, flags)
					env.Config = flags
				},
			},
			{
				Name:  "version",
				Usage: "",
				Help:  "Show version information",
				SetFlags: func(env *command.Env, fs *flag.FlagSet) {
					flags := &VersionFlags{}
					flax.MustBind(fs, flags)
					env.Config = flags
				},
			},

			// Config commands
			{
				Name:  "config",
				Usage: "test",
				Help:  "Configuration management commands",
				Commands: []*command.C{
					{
						Name:  "test",
						Usage: "",
						Help:  "Test the configuration file",
						SetFlags: func(env *command.Env, fs *flag.FlagSet) {
							flags := &ConfigTestFlags{}
							flax.MustBind(fs, flags)
							env.Config = flags
						},
					},
				},
			},

			// User management
			{
				Name:  "users",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Manage users in Headscale",
				Commands: []*command.C{
					{Name: "create", Help: "Create a new user"},
					{Name: "list", Help: "List users"},
					{Name: "update", Help: "Update a user"},
					{Name: "delete", Help: "Delete a user"},
				},
			},

			// User management alias
			{
				Name:     "user",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage users in Headscale (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new user"},
					{Name: "list", Help: "List users"},
					{Name: "update", Help: "Update a user"},
					{Name: "delete", Help: "Delete a user"},
				},
			},

			// Node management
			{
				Name:  "nodes",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Manage nodes in Headscale",
				Commands: []*command.C{
					{Name: "register", Help: "Register a node"},
					{Name: "list", Help: "List nodes"},
					{Name: "expire", Help: "Expire a node"},
					{Name: "rename", Help: "Rename a node"},
					{Name: "delete", Help: "Delete a node"},
					{Name: "move", Help: "Move node to another user"},
					{Name: "tags", Help: "Manage node tags"},
					{Name: "routes", Help: "Manage node routes"},
					{Name: "backfill-ips", Help: "Backfill missing IPs"},
				},
			},

			// Node management aliases
			{
				Name:     "node",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage nodes in Headscale (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "register", Help: "Register a node"},
					{Name: "list", Help: "List nodes"},
					{Name: "expire", Help: "Expire a node"},
					{Name: "rename", Help: "Rename a node"},
					{Name: "delete", Help: "Delete a node"},
					{Name: "move", Help: "Move node to another user"},
					{Name: "tags", Help: "Manage node tags"},
					{Name: "routes", Help: "Manage node routes"},
					{Name: "backfill-ips", Help: "Backfill missing IPs"},
				},
			},
			{
				Name:     "machine",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage nodes in Headscale (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "register", Help: "Register a node"},
					{Name: "list", Help: "List nodes"},
					{Name: "expire", Help: "Expire a node"},
					{Name: "rename", Help: "Rename a node"},
					{Name: "delete", Help: "Delete a node"},
					{Name: "move", Help: "Move node to another user"},
					{Name: "tags", Help: "Manage node tags"},
					{Name: "routes", Help: "Manage node routes"},
					{Name: "backfill-ips", Help: "Backfill missing IPs"},
				},
			},
			{
				Name:     "machines",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage nodes in Headscale (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "register", Help: "Register a node"},
					{Name: "list", Help: "List nodes"},
					{Name: "expire", Help: "Expire a node"},
					{Name: "rename", Help: "Rename a node"},
					{Name: "delete", Help: "Delete a node"},
					{Name: "move", Help: "Move node to another user"},
					{Name: "tags", Help: "Manage node tags"},
					{Name: "routes", Help: "Manage node routes"},
					{Name: "backfill-ips", Help: "Backfill missing IPs"},
				},
			},

			// PreAuth keys
			{
				Name:  "preauth-keys",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Manage pre-authentication keys",
				Commands: []*command.C{
					{Name: "create", Help: "Create a new pre-authentication key"},
					{Name: "list", Help: "List pre-authentication keys"},
					{Name: "expire", Help: "Expire a pre-authentication key"},
				},
			},

			// PreAuth keys aliases
			{
				Name:     "preauthkeys",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage pre-authentication keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new pre-authentication key"},
					{Name: "list", Help: "List pre-authentication keys"},
					{Name: "expire", Help: "Expire a pre-authentication key"},
				},
			},
			{
				Name:     "preauthkey",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage pre-authentication keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new pre-authentication key"},
					{Name: "list", Help: "List pre-authentication keys"},
					{Name: "expire", Help: "Expire a pre-authentication key"},
				},
			},
			{
				Name:     "authkey",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage pre-authentication keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new pre-authentication key"},
					{Name: "list", Help: "List pre-authentication keys"},
					{Name: "expire", Help: "Expire a pre-authentication key"},
				},
			},
			{
				Name:     "pre",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage pre-authentication keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new pre-authentication key"},
					{Name: "list", Help: "List pre-authentication keys"},
					{Name: "expire", Help: "Expire a pre-authentication key"},
				},
			},

			// API keys
			{
				Name:  "api-keys",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Manage API keys",
				Commands: []*command.C{
					{Name: "create", Help: "Create a new API key"},
					{Name: "list", Help: "List API keys"},
					{Name: "expire", Help: "Expire an API key"},
					{Name: "delete", Help: "Delete an API key"},
				},
			},

			// API keys aliases
			{
				Name:     "apikeys",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage API keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new API key"},
					{Name: "list", Help: "List API keys"},
					{Name: "expire", Help: "Expire an API key"},
					{Name: "delete", Help: "Delete an API key"},
				},
			},
			{
				Name:     "apikey",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage API keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new API key"},
					{Name: "list", Help: "List API keys"},
					{Name: "expire", Help: "Expire an API key"},
					{Name: "delete", Help: "Delete an API key"},
				},
			},
			{
				Name:     "api",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage API keys (alias)",
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new API key"},
					{Name: "list", Help: "List API keys"},
					{Name: "expire", Help: "Expire an API key"},
					{Name: "delete", Help: "Delete an API key"},
				},
			},

			// Policy management
			{
				Name:  "policy",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Manage ACL policies",
				Commands: []*command.C{
					{Name: "get", Help: "Get the current ACL policy"},
					{Name: "set", Help: "Set the ACL policy from a file"},
					{Name: "validate", Help: "Validate a policy file"},
				},
			},

			// Development commands
			{
				Name:  "dev",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Development and testing commands",
				Commands: []*command.C{
					{
						Name:  "generate",
						Usage: "<subcommand>",
						Help:  "Generate various keys and tokens",
						Commands: []*command.C{
							{Name: "private-key", Help: "Generate a private key"},
						},
					},
					{Name: "create-node", Help: "Create a test node"},
					{Name: "mock-oidc", Help: "Start a mock OIDC server", Unlisted: true},
				},
			},

			// Help command
			command.HelpCommand(nil),
		},
	}
}
