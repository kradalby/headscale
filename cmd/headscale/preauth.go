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

// PreAuth key command flag structures

type listPreAuthKeyFlags struct {
	globalFlags
	userFlags
}

type createPreAuthKeyFlags struct {
	globalFlags
	userFlags
	expirationFlags
	Reusable  bool     `flag:"reusable,Make the key reusable"`
	Ephemeral bool     `flag:"ephemeral,Create key for ephemeral nodes"`
	Tags      []string `flag:"tags,Comma-separated tags to assign"`
}

type expirePreAuthKeyFlags struct {
	globalFlags
	userFlags
	Key string `flag:"key,k,PreAuth key to expire (required)"`
}

// PreAuth key command implementations

func listPreAuthKeysCommand(env *command.Env) error {
	flags := env.Config.(*listPreAuthKeyFlags)

	if err := RequireString(flags.User, "user"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Parse user as uint64 for the API
	userID, err := strconv.ParseUint(flags.User, 10, 64)
	if err != nil {
		return fmt.Errorf("user must be a numeric ID: %w", err)
	}

	request := &v1.ListPreAuthKeysRequest{
		User: userID,
	}

	response, err := client.ListPreAuthKeys(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot list pre auth keys: %w", err)
	}

	return outputResult(response.GetPreAuthKeys(), "PreAuth Keys", flags.Output)
}

func createPreAuthKeyCommand(env *command.Env) error {
	flags := env.Config.(*createPreAuthKeyFlags)

	if err := RequireString(flags.User, "user"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Resolve user identifier to user ID
	userID, err := ResolveUserToID(ctx, client, flags.User)
	if err != nil {
		// For now, try to parse as numeric ID directly as fallback
		if id, parseErr := strconv.ParseUint(flags.User, 10, 64); parseErr == nil {
			userID = id
		} else {
			return fmt.Errorf("cannot resolve user '%s': %w", flags.User, err)
		}
	}

	// Parse expiration
	duration, err := time.ParseDuration(flags.Expiration)
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}

	expiration := time.Now().UTC().Add(duration)

	request := &v1.CreatePreAuthKeyRequest{
		User:       userID,
		Reusable:   flags.Reusable,
		Ephemeral:  flags.Ephemeral,
		AclTags:    flags.Tags,
		Expiration: timestamppb.New(expiration),
	}

	response, err := client.CreatePreAuthKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot create pre auth key: %w", err)
	}

	return outputResult(response.GetPreAuthKey(), "PreAuth Key created", flags.Output)
}

func expirePreAuthKeyCommand(env *command.Env) error {
	flags := env.Config.(*expirePreAuthKeyFlags)

	if err := RequireString(flags.User, "user"); err != nil {
		return err
	}
	if err := RequireString(flags.Key, "key"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Parse user as uint64 for the API
	userID, err := strconv.ParseUint(flags.User, 10, 64)
	if err != nil {
		return fmt.Errorf("user must be a numeric ID: %w", err)
	}

	request := &v1.ExpirePreAuthKeyRequest{
		User: userID,
		Key:  flags.Key,
	}

	response, err := client.ExpirePreAuthKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot expire pre auth key: %w", err)
	}

	return outputResult(response, "PreAuth Key expired", flags.Output)
}

// PreAuth key command definitions

func preAuthKeyCommands() []*command.C {
	return []*command.C{
		{
			Name:  "preauth-keys",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Manage pre-authentication keys",
			Commands: []*command.C{
				{
					Name:     "list",
					Usage:    "--user <user>",
					Help:     "List pre-authentication keys for a user",
					SetFlags: Flags(flax.MustBind, &listPreAuthKeyFlags{}),
					Run:      listPreAuthKeysCommand,
				},
				{
					Name:     "ls",
					Usage:    "--user <user>",
					Help:     "List pre-authentication keys for a user (alias)",
					SetFlags: Flags(flax.MustBind, &listPreAuthKeyFlags{}),
					Run:      listPreAuthKeysCommand,
					Unlisted: true,
				},
				{
					Name:     "create",
					Usage:    "--user <user> [flags]",
					Help:     "Create a new pre-authentication key",
					SetFlags: Flags(flax.MustBind, &createPreAuthKeyFlags{}),
					Run:      createPreAuthKeyCommand,
				},
				{
					Name:     "expire",
					Usage:    "--user <user> --key <key>",
					Help:     "Expire a pre-authentication key",
					SetFlags: Flags(flax.MustBind, &expirePreAuthKeyFlags{}),
					Run:      expirePreAuthKeyCommand,
				},
			},
		},
		// PreAuth key aliases
		{
			Name:     "preauthkeys",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage pre-authentication keys (alias)",
			Commands: preAuthKeyCommands()[0].Commands,
			Unlisted: true,
		},
		{
			Name:     "preauth",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage pre-authentication keys (alias)",
			Commands: preAuthKeyCommands()[0].Commands,
			Unlisted: true,
		},
	}
}
