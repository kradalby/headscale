package main

import (
	"context"
	"testing"
)

// TestIntegrationBasicFunctionality tests basic CLI functionality
func TestIntegrationBasicFunctionality(t *testing.T) {
	// Test that we can create a basic command structure
	root := createTestRootCommand()

	if root == nil {
		t.Fatal("Failed to create root command")
	}

	if root.Name != "headscale" {
		t.Errorf("Expected root command name 'headscale', got '%s'", root.Name)
	}
}

// TestIntegrationCommandStructure tests the command structure
func TestIntegrationCommandStructure(t *testing.T) {
	root := createTestRootCommand()

	// Test that main commands exist
	expectedCommands := []string{
		"serve", "version", "config", "users", "nodes",
		"preauth-keys", "api-keys", "policy", "dev", "help",
	}

	for _, cmdName := range expectedCommands {
		cmd := root.FindSubcommand(cmdName)
		if cmd == nil {
			t.Errorf("Expected command '%s' not found", cmdName)
		}
	}
}

// TestIntegrationUserCommands tests user management commands
func TestIntegrationUserCommands(t *testing.T) {
	root := createTestRootCommand()

	usersCmd := root.FindSubcommand("users")
	if usersCmd == nil {
		t.Fatal("Users command not found")
	}

	// Test user subcommands
	expectedSubcommands := []string{"create", "list", "update", "delete"}
	for _, subCmd := range expectedSubcommands {
		cmd := usersCmd.FindSubcommand(subCmd)
		if cmd == nil {
			t.Errorf("Expected users subcommand '%s' not found", subCmd)
		}
	}

	// Test that user alias command exists
	userCmd := root.FindSubcommand("user")
	if userCmd == nil {
		t.Error("Expected 'user' alias command not found")
	}
}

// TestIntegrationNodeCommands tests node management commands
func TestIntegrationNodeCommands(t *testing.T) {
	root := createTestRootCommand()

	nodesCmd := root.FindSubcommand("nodes")
	if nodesCmd == nil {
		t.Fatal("Nodes command not found")
	}

	// Test node subcommands
	expectedSubcommands := []string{
		"register", "list", "expire", "rename", "delete", "move",
		"tags", "routes", "backfill-ips",
	}
	for _, subCmd := range expectedSubcommands {
		cmd := nodesCmd.FindSubcommand(subCmd)
		if cmd == nil {
			t.Errorf("Expected nodes subcommand '%s' not found", subCmd)
		}
	}

	// Test that node alias commands exist
	aliasCommands := []string{"node", "machine", "machines"}
	for _, alias := range aliasCommands {
		cmd := root.FindSubcommand(alias)
		if cmd == nil {
			t.Errorf("Expected '%s' alias command not found", alias)
		}
	}
}

// TestIntegrationPreAuthKeyCommands tests pre-auth key commands
func TestIntegrationPreAuthKeyCommands(t *testing.T) {
	root := createTestRootCommand()

	preAuthCmd := root.FindSubcommand("preauth-keys")
	if preAuthCmd == nil {
		t.Fatal("PreAuth keys command not found")
	}

	// Test preauth subcommands
	expectedSubcommands := []string{"create", "list", "expire"}
	for _, subCmd := range expectedSubcommands {
		cmd := preAuthCmd.FindSubcommand(subCmd)
		if cmd == nil {
			t.Errorf("Expected preauth-keys subcommand '%s' not found", subCmd)
		}
	}

	// Test that preauth alias commands exist
	aliasCommands := []string{"preauthkeys", "preauthkey", "authkey", "pre"}
	for _, alias := range aliasCommands {
		cmd := root.FindSubcommand(alias)
		if cmd == nil {
			t.Errorf("Expected '%s' alias command not found", alias)
		}
	}
}

// TestIntegrationAPIKeyCommands tests API key commands
func TestIntegrationAPIKeyCommands(t *testing.T) {
	root := createTestRootCommand()

	apiKeysCmd := root.FindSubcommand("api-keys")
	if apiKeysCmd == nil {
		t.Fatal("API keys command not found")
	}

	// Test API key subcommands
	expectedSubcommands := []string{"create", "list", "expire", "delete"}
	for _, subCmd := range expectedSubcommands {
		cmd := apiKeysCmd.FindSubcommand(subCmd)
		if cmd == nil {
			t.Errorf("Expected api-keys subcommand '%s' not found", subCmd)
		}
	}

	// Test that API key alias commands exist
	aliasCommands := []string{"apikeys", "apikey", "api"}
	for _, alias := range aliasCommands {
		cmd := root.FindSubcommand(alias)
		if cmd == nil {
			t.Errorf("Expected '%s' alias command not found", alias)
		}
	}
}

// TestIntegrationPolicyCommands tests policy commands
func TestIntegrationPolicyCommands(t *testing.T) {
	root := createTestRootCommand()

	policyCmd := root.FindSubcommand("policy")
	if policyCmd == nil {
		t.Fatal("Policy command not found")
	}

	// Test policy subcommands
	expectedSubcommands := []string{"get", "set", "validate"}
	for _, subCmd := range expectedSubcommands {
		cmd := policyCmd.FindSubcommand(subCmd)
		if cmd == nil {
			t.Errorf("Expected policy subcommand '%s' not found", subCmd)
		}
	}
}

// TestIntegrationDevCommands tests development commands
func TestIntegrationDevCommands(t *testing.T) {
	root := createTestRootCommand()

	devCmd := root.FindSubcommand("dev")
	if devCmd == nil {
		t.Fatal("Dev command not found")
	}

	// Test dev subcommands
	generateCmd := devCmd.FindSubcommand("generate")
	if generateCmd == nil {
		t.Error("Expected dev generate command not found")
	}

	createNodeCmd := devCmd.FindSubcommand("create-node")
	if createNodeCmd == nil {
		t.Error("Expected dev create-node command not found")
	}

	mockOidcCmd := devCmd.FindSubcommand("mock-oidc")
	if mockOidcCmd == nil {
		t.Error("Expected dev mock-oidc command not found")
	}

	// Verify mock-oidc is unlisted
	if !mockOidcCmd.Unlisted {
		t.Error("mock-oidc command should be unlisted")
	}
}

// TestIntegrationFlagBinding tests that flag binding works correctly
func TestIntegrationFlagBinding(t *testing.T) {
	root := createTestRootCommand()

	// Create a test environment
	globalFlags := &GlobalFlags{}
	env := root.NewEnv(globalFlags).SetContext(context.Background())

	// Test that we can access flags
	if env.Config == nil {
		t.Error("Environment config should not be nil")
	}

	flags, ok := env.Config.(*GlobalFlags)
	if !ok {
		t.Error("Environment config should be GlobalFlags type")
	}

	// Test flag defaults
	if flags.Output != "" {
		t.Error("Default output flag should be empty")
	}

	if flags.Force != false {
		t.Error("Default force flag should be false")
	}
}

// TestIntegrationCommandExecution tests basic command execution
func TestIntegrationCommandExecution(t *testing.T) {
	root := createTestRootCommand()

	// Test version command execution (should not panic)
	versionCmd := root.FindSubcommand("version")
	if versionCmd == nil {
		t.Fatal("Version command not found")
	}

	// Verify the command has a SetFlags function (needed for runnable test)
	if versionCmd.SetFlags == nil {
		t.Error("Version command should have SetFlags function")
	}
}

// TestIntegrationHelpCommand tests help functionality
func TestIntegrationHelpCommand(t *testing.T) {
	root := createTestRootCommand()

	helpCmd := root.FindSubcommand("help")
	if helpCmd == nil {
		t.Fatal("Help command not found")
	}

	// Verify help command is runnable
	if !helpCmd.Runnable() {
		t.Error("Help command should be runnable")
	}
}

// TestIntegrationBackwardCompatibility tests that old command aliases work
func TestIntegrationBackwardCompatibility(t *testing.T) {
	root := createTestRootCommand()

	// Test old command aliases
	oldCommands := map[string]string{
		"user":        "users",
		"node":        "nodes",
		"machine":     "nodes",
		"machines":    "nodes",
		"preauthkeys": "preauth-keys",
		"preauthkey":  "preauth-keys",
		"authkey":     "preauth-keys",
		"pre":         "preauth-keys",
		"apikeys":     "api-keys",
		"apikey":      "api-keys",
		"api":         "api-keys",
	}

	for oldCmd, _ := range oldCommands {
		cmd := root.FindSubcommand(oldCmd)
		if cmd == nil {
			t.Errorf("Backward compatibility: '%s' alias command not found", oldCmd)
		}
	}
}
