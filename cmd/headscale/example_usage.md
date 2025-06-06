# Headscale CLI Migration Example

This document shows examples of how the new `command` + `flax` based CLI works compared to the old Cobra-based CLI.

## Key Changes

1. **Flag Definition**: Flags are now defined using struct tags with `flax`
2. **Command Structure**: Commands are defined as a tree structure with `command.C`
3. **Validation**: Built-in validation using helper functions
4. **Consistent Patterns**: All commands follow the same structure

## Example Usage

### Users

```bash
# Create a user
headscale users create myuser --email user@example.com --display-name "My User"

# List users  
headscale users list
headscale users list --name myuser
headscale users list --id 1

# Update a user
headscale users update --id 1 --new-name newuser --email newemail@example.com

# Delete a user
headscale users delete --id 1
headscale users delete --name myuser
```

### Nodes

```bash
# Register a node
headscale nodes register --user myuser --key nodekey123

# List nodes
headscale nodes list
headscale nodes list --user myuser --show-tags

# Expire a node
headscale nodes expire --id 1

# Rename a node
headscale nodes rename --id 1 mynewnode

# Delete a node
headscale nodes delete --id 1

# Move a node to another user
headscale nodes move --id 1 --user 2

# Manage node tags
headscale nodes tags set --id 1 --tags tag1,tag2,tag3

# Manage node routes
headscale nodes routes list
headscale nodes routes list --id 1
headscale nodes routes approve --id 1 --routes 10.0.0.0/8,192.168.0.0/24

# Backfill IPs
headscale nodes backfill-ips
```

### PreAuth Keys

```bash
# Create a preauth key
headscale preauth-keys create --user 1 --expiration 24h --reusable --tags tag1,tag2

# List preauth keys
headscale preauth-keys list --user 1

# Expire a preauth key
headscale preauth-keys expire --user 1 keystring
```

### API Keys

```bash
# Create an API key
headscale api-keys create --expiration 90d

# List API keys
headscale api-keys list

# Expire an API key
headscale api-keys expire --prefix abc123

# Delete an API key
headscale api-keys delete --prefix abc123
```

### Policy

```bash
# Get current policy
headscale policy get

# Set policy from file
headscale policy set --file policy.json

# Validate a policy file
headscale policy validate --file policy.json
```

### Development Commands

```bash
# Generate a private key
headscale dev generate private-key

# Create a test node
headscale dev create-node --name testnode --user myuser --key nodekey123

# Start mock OIDC (hidden from help)
headscale dev mock-oidc
```

### Server Commands

```bash
# Start the server
headscale serve

# Test configuration
headscale config test

# Show version
headscale version
```

## Flag Structure Examples

### Global Flags (available on all commands)
```go
type GlobalFlags struct {
    Config string `flag:"config,c,Config file path"`
    Output string `flag:"output,o,Output format (json, yaml, table)"`
    Force  bool   `flag:"force,Skip confirmation prompts"`
}
```

### Command-specific Flags
```go
type CreateUserFlags struct {
    GlobalFlags                                    // Inherits global flags
    DisplayName string `flag:"display-name,d,Display name"`
    Email       string `flag:"email,Email address"`
    PictureURL  string `flag:"picture-url,p,Profile picture URL"`
}
```

## Backward Compatibility

All old command names work as aliases:

```bash
# These all work the same:
headscale apikeys list        # old name
headscale api-keys list       # new name

headscale preauthkeys create  # old name  
headscale preauth-keys create # new name

headscale machines list       # old alias
headscale nodes list          # new name
```

## Output Formats

All commands support consistent output formatting:

```bash
# Human-readable table (default)
headscale users list

# JSON output
headscale users list --output json

# YAML output  
headscale users list --output yaml

# JSON-line output
headscale users list --output json-line
```

## Error Handling

The new CLI provides better error messages:

```bash
$ headscale users update
Error: either --id or --name flag is required

$ headscale nodes register --user myuser
Error: --key flag is required

$ headscale preauth-keys create  
Error: --user flag is required
```

## Migration Path

1. **Phase 1**: Add new CLI alongside existing Cobra CLI
2. **Phase 2**: Update documentation to use new commands
3. **Phase 3**: Deprecate old CLI (keep aliases)
4. **Phase 4**: Remove Cobra dependency (future release)

The migration maintains 100% backward compatibility through command aliases.