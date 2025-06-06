package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PreAuth key command flags
var preAuthArgs struct {
	User       string `flag:"user,u,User identifier (required)"`
	Key        string `flag:"key,k,PreAuth key"`
	Expiration string `flag:"expiration,e,default=24h,Expiration duration"`
	Reusable   bool   `flag:"reusable,Make the key reusable"`
	Ephemeral  bool   `flag:"ephemeral,Create key for ephemeral nodes"`
	Tags       string `flag:"tags,Comma-separated tags to assign"`
}

// PreAuth key command implementations

func listPreAuthKeysCommand(env *command.Env) error {
	if err := requireString(preAuthArgs.User, "user"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Try to resolve user identifier to user ID
	userID, err := ResolveUserToID(ctx, client, preAuthArgs.User)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(preAuthArgs.User, 10, 64); parseErr == nil {
			userID = parsedID
		} else {
			return fmt.Errorf("cannot resolve user identifier '%s': %w", preAuthArgs.User, err)
		}
	}

	request := &v1.ListPreAuthKeysRequest{
		User: userID,
	}

	response, err := client.ListPreAuthKeys(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot list pre auth keys: %w", err)
	}

	return outputResult(response.GetPreAuthKeys(), "PreAuth Keys", globalArgs.Output)
}

func createPreAuthKeyCommand(env *command.Env) error {
	if err := requireString(preAuthArgs.User, "user"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Resolve user identifier to user ID
	userID, err := ResolveUserToID(ctx, client, preAuthArgs.User)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(preAuthArgs.User, 10, 64); parseErr == nil {
			userID = parsedID
		} else {
			return fmt.Errorf("cannot resolve user identifier '%s': %w", preAuthArgs.User, err)
		}
	}

	// Parse expiration with default
	expiration := time.Now().Add(24 * time.Hour) // Default 24 hours
	if preAuthArgs.Expiration != "" {
		duration, err := time.ParseDuration(preAuthArgs.Expiration)
		if err != nil {
			return fmt.Errorf("invalid expiration duration: %w", err)
		}
		expiration = time.Now().Add(duration)
	}

	request := &v1.CreatePreAuthKeyRequest{
		User:       userID,
		Reusable:   preAuthArgs.Reusable,
		Ephemeral:  preAuthArgs.Ephemeral,
		AclTags:    parseCommaSeparated(preAuthArgs.Tags),
		Expiration: timestamppb.New(expiration),
	}

	response, err := client.CreatePreAuthKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot create pre auth key: %w", err)
	}

	return outputResult(response.GetPreAuthKey(), "PreAuth Key created", globalArgs.Output)
}

func expirePreAuthKeyCommand(env *command.Env) error {
	if err := requireString(preAuthArgs.User, "user"); err != nil {
		return err
	}
	if err := requireString(preAuthArgs.Key, "key"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Try to resolve user identifier to user ID
	userID, err := ResolveUserToID(ctx, client, preAuthArgs.User)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(preAuthArgs.User, 10, 64); parseErr == nil {
			userID = parsedID
		} else {
			return fmt.Errorf("cannot resolve user identifier '%s': %w", preAuthArgs.User, err)
		}
	}

	request := &v1.ExpirePreAuthKeyRequest{
		User: userID,
		Key:  preAuthArgs.Key,
	}

	response, err := client.ExpirePreAuthKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot expire pre auth key: %w", err)
	}

	return outputResult(response, "PreAuth Key expired", globalArgs.Output)
}

// PreAuth key command definitions

func preAuthKeyCommands() []*command.C {
	return []*command.C{
		{
			Name:     "preauth-keys",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage pre-authentication keys",
			SetFlags: command.Flags(flax.MustBind, &preAuthArgs),
			Commands: []*command.C{
				{
					Name:  "list",
					Usage: "--user <user>",
					Help:  "List pre-authentication keys for a user",
					Run:   listPreAuthKeysCommand,
				},
				{
					Name:     "ls",
					Usage:    "--user <user>",
					Help:     "List pre-authentication keys for a user (alias)",
					Run:      listPreAuthKeysCommand,
					Unlisted: true,
				},
				{
					Name:  "create",
					Usage: "--user <user> [flags]",
					Help:  "Create a new pre-authentication key",
					Run:   createPreAuthKeyCommand,
				},
				{
					Name:  "expire",
					Usage: "--user <user> --key <key>",
					Help:  "Expire a pre-authentication key",
					Run:   expirePreAuthKeyCommand,
				},
			},
		},
		// PreAuth key aliases
		{
			Name:     "preauthkeys",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage pre-authentication keys (alias)",
			SetFlags: command.Flags(flax.MustBind, &preAuthArgs),
			Commands: []*command.C{
				{
					Name:  "list",
					Usage: "--user <user>",
					Help:  "List pre-authentication keys for a user",
					Run:   listPreAuthKeysCommand,
				},
				{
					Name:  "create",
					Usage: "--user <user> [flags]",
					Help:  "Create a new pre-authentication key",
					Run:   createPreAuthKeyCommand,
				},
				{
					Name:  "expire",
					Usage: "--user <user> --key <key>",
					Help:  "Expire a pre-authentication key",
					Run:   expirePreAuthKeyCommand,
				},
			},
			Unlisted: true,
		},
		{
			Name:     "preauth",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage pre-authentication keys (alias)",
			SetFlags: command.Flags(flax.MustBind, &preAuthArgs),
			Commands: []*command.C{
				{
					Name:  "list",
					Usage: "--user <user>",
					Help:  "List pre-authentication keys for a user",
					Run:   listPreAuthKeysCommand,
				},
				{
					Name:  "create",
					Usage: "--user <user> [flags]",
					Help:  "Create a new pre-authentication key",
					Run:   createPreAuthKeyCommand,
				},
				{
					Name:  "expire",
					Usage: "--user <user> --key <key>",
					Help:  "Expire a pre-authentication key",
					Run:   expirePreAuthKeyCommand,
				},
			},
			Unlisted: true,
		},
	}
}
