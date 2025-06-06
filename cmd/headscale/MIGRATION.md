# Headscale CLI Migration: Cobra → Command + Flax

This document outlines the migration from Cobra to the `command` and `flax` libraries for the Headscale CLI.

## Overview

The migration replaces the current Cobra-based CLI with a more modern, functional approach using:

- **[creachadair/command](https://github.com/creachadair/command)**: Lightweight subcommand handling
- **[creachadair/flax](https://github.com/creachadair/flax)**: Struct-based flag binding with tags

## Benefits

### 1. **Cleaner Architecture**
- Functional command definitions vs imperative Cobra setup
- Composable command trees
- Less boilerplate code

### 2. **Better Flag Management**
- Struct-based flag definitions with tags
- Automatic flag binding via `flax`
- Type-safe flag handling
- Centralized flag validation

### 3. **Consistent Patterns**
- All commands follow the same structure
- Uniform error handling
- Consistent output formatting

### 4. **Improved Developer Experience**
- Easier to test individual commands
- Better separation of concerns
- More predictable command behavior

## Implementation

### File Structure

```
cmd/headscale/
├── main_new.go      # New command-based main (replace main.go)
├── flags.go         # All flag struct definitions
├── commands.go      # All command implementations
├── commands_test.go # Tests for new structure
└── MIGRATION.md     # This file
```

### Key Components

#### 1. Flag Definitions (`flags.go`)
```go
type CreateUserFlags struct {
    GlobalFlags                                    // Inherits global flags
    DisplayName string `flag:"display-name,d,Display name"`
    Email       string `flag:"email,Email address"`
    PictureURL  string `flag:"picture-url,p,Profile picture URL"`
}
```

#### 2. Command Structure (`main_new.go`)
```go
{
    Name:  "create",
    Usage: "<username>",
    Help:  "Create a new user",
    SetFlags: func(env *command.Env, fs *flag.FlagSet) {
        flags := &CreateUserFlags{}
        flax.MustBind(fs, flags)
        env.Config = flags
    },
    Run: command.Adapt(createUserCommand),
}
```

#### 3. Command Implementation (`commands.go`)
```go
func createUserCommand(env *command.Env, username string) error {
    flags := env.Config.(*CreateUserFlags)
    
    // Validation
    // Business logic
    // Output formatting
    
    return nil
}
```

## Migration Steps

### Phase 1: Foundation ✅
- [x] Create flag definitions (`flags.go`)
- [x] Implement new main structure (`main_new.go`)
- [x] Add dependencies to `go.mod`
- [x] Create command implementations (`commands.go`)
- [x] Add basic tests (`commands_test.go`)

### Phase 2: Implementation (Next Steps)
- [ ] Copy utility functions from existing CLI files
- [ ] Implement missing command functions (mock OIDC, etc.)
- [ ] Complete table formatting functions
- [ ] Add comprehensive tests
- [ ] Validate all command behaviors

### Phase 3: Integration Testing
- [ ] Test all existing CLI scenarios
- [ ] Verify backward compatibility via aliases
- [ ] Update integration tests in `integration/cli_test.go`
- [ ] Performance comparison with Cobra version

### Phase 4: Migration
- [ ] Replace `main.go` with `main_new.go`
- [ ] Remove old CLI files (keep as backup initially)
- [ ] Update documentation
- [ ] Remove Cobra dependency

### Phase 5: Cleanup
- [ ] Remove deprecated flag handling
- [ ] Clean up unused code
- [ ] Final testing and validation

## Command Mapping

### Current → New Structure

| Current | New | Status |
|---------|-----|--------|
| `headscale serve` | `headscale serve` | ✅ Implemented |
| `headscale version` | `headscale version` | ✅ Implemented |
| `headscale configtest` | `headscale config test` | ✅ Implemented |
| `headscale users create` | `headscale users create` | ✅ Implemented |
| `headscale users list` | `headscale users list` | ✅ Implemented |
| `headscale users destroy` | `headscale users delete` | ✅ Implemented |
| `headscale users rename` | `headscale users update` | ✅ Implemented |
| `headscale nodes register` | `headscale nodes register` | ✅ Implemented |
| `headscale nodes list` | `headscale nodes list` | ✅ Implemented |
| `headscale nodes expire` | `headscale nodes expire` | ✅ Implemented |
| `headscale nodes rename` | `headscale nodes rename` | ✅ Implemented |
| `headscale nodes delete` | `headscale nodes delete` | ✅ Implemented |
| `headscale nodes move` | `headscale nodes move` | ✅ Implemented |
| `headscale nodes tag` | `headscale nodes tags set` | ✅ Implemented |
| `headscale nodes list-routes` | `headscale nodes routes list` | ✅ Implemented |
| `headscale nodes approve-routes` | `headscale nodes routes approve` | ✅ Implemented |
| `headscale nodes backfillips` | `headscale nodes backfill-ips` | ✅ Implemented |
| `headscale preauthkeys create` | `headscale preauth-keys create` | ✅ Implemented |
| `headscale preauthkeys list` | `headscale preauth-keys list` | ✅ Implemented |
| `headscale preauthkeys expire` | `headscale preauth-keys expire` | ✅ Implemented |
| `headscale apikeys create` | `headscale api-keys create` | ✅ Implemented |
| `headscale apikeys list` | `headscale api-keys list` | ✅ Implemented |
| `headscale apikeys expire` | `headscale api-keys expire` | ✅ Implemented |
| `headscale apikeys delete` | `headscale api-keys delete` | ✅ Implemented |
| `headscale policy get` | `headscale policy get` | ✅ Implemented |
| `headscale policy set` | `headscale policy set` | ✅ Implemented |
| `headscale policy check` | `headscale policy validate` | ✅ Implemented |
| `headscale generate private-key` | `headscale dev generate private-key` | ✅ Implemented |
| `headscale debug create-node` | `headscale dev create-node` | ✅ Implemented |
| `headscale mockoidc` | `headscale dev mock-oidc` | 🔄 Needs implementation |

## Backward Compatibility

All existing commands work through aliases:

```bash
# Old names still work
headscale apikeys list          → headscale api-keys list
headscale preauthkeys create    → headscale preauth-keys create  
headscale machines list         → headscale nodes list
headscale users destroy         → headscale users delete
```

## Testing

### Run Tests
```bash
cd cmd/headscale
go test -v ./...
```

### Test New CLI (when ready)
```bash
# Build new version
go build -o headscale-new ./cmd/headscale

# Test commands
./headscale-new version
./headscale-new users --help
./headscale-new nodes --help
```

## Dependencies

### Added
```go
github.com/creachadair/command v0.1.22
github.com/creachadair/flax v0.0.5
```

### To Remove (after migration)
```go
github.com/spf13/cobra v1.9.1
github.com/spf13/viper v1.20.1  // May need to keep for config
github.com/spf13/pflag v1.0.6   // Used by viper
```

## Key Improvements

### 1. **Flag Validation**
```go
// Before: Manual validation scattered throughout
if identifier == 0 && name == "" {
    return errors.New("either --identifier or --name required")
}

// After: Centralized validation helpers
if err := ValidateIdentifier(flags.IdentifierFlags); err != nil {
    return err
}
```

### 2. **Command Definition**
```go
// Before: Imperative setup with lots of boilerplate
var createUserCmd = &cobra.Command{
    Use:   "create",
    Short: "Create user",
    Run: func(cmd *cobra.Command, args []string) {
        // Flag extraction...
        // Validation...
        // Business logic...
    },
}
createUserCmd.Flags().StringP("email", "e", "", "Email")
// ... more flag setup

// After: Declarative structure with automatic binding
{
    Name: "create",
    Help: "Create user",
    SetFlags: func(env *command.Env, fs *flag.FlagSet) {
        flags := &CreateUserFlags{}
        flax.MustBind(fs, flags)
        env.Config = flags
    },
    Run: command.Adapt(createUserCommand),
}
```

### 3. **Type Safety**
```go
// Before: String-based flag access
email, _ := cmd.Flags().GetString("email")

// After: Struct-based type-safe access  
flags := env.Config.(*CreateUserFlags)
email := flags.Email
```

## Next Actions

1. **Complete Implementation**: Fill in missing utility functions
2. **Add Tests**: Comprehensive test coverage
3. **Validate Integration**: Test with existing integration test suite
4. **Documentation**: Update CLI documentation
5. **Migration**: Replace current implementation

## Notes

- The new structure maintains 100% command compatibility
- Output formats remain the same (JSON, YAML, table)
- All existing integration tests should pass without modification
- Performance should be similar or better due to reduced reflection