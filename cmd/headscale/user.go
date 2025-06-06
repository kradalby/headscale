package main

import (
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// User command flag structures

type createUserFlags struct {
	globalFlags
	DisplayName string `flag:"display-name,d,Display name"`
	Email       string `flag:"email,Email address"`
	PictureURL  string `flag:"picture-url,p,Profile picture URL"`
}

type listUserFlags struct {
	globalFlags
	identifierFlags
	Email string `flag:"email,e,Filter by email"`
}

type updateUserFlags struct {
	globalFlags
	identifierFlags
	NewName string `flag:"new-name,New username"`
}

type deleteUserFlags struct {
	globalFlags
	identifierFlags
}

// User command implementations

func createUserCommand(env *command.Env, username string) error {
	flags := env.Config.(*createUserFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.CreateUserRequest{Name: username}

	if flags.DisplayName != "" {
		request.DisplayName = flags.DisplayName
	}
	if flags.Email != "" {
		request.Email = flags.Email
	}
	if flags.PictureURL != "" {
		request.PictureUrl = flags.PictureURL
	}

	response, err := client.CreateUser(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot create user: %w", err)
	}

	return outputResult(response.GetUser(), "User created", flags.Output)
}

func listUsersCommand(env *command.Env) error {
	flags := env.Config.(*listUserFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ListUsersRequest{}

	// Apply filters if specified
	if flags.ID != 0 {
		request.Id = flags.ID
	}
	if flags.Name != "" {
		request.Name = flags.Name
	}
	if flags.Email != "" {
		request.Email = flags.Email
	}

	response, err := client.ListUsers(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot list users: %w", err)
	}

	if flags.Output != "" {
		return outputResult(response.GetUsers(), "Users", flags.Output)
	}

	return outputResult(response.GetUsers(), "Users", "table")
}

func updateUserCommand(env *command.Env) error {
	flags := env.Config.(*updateUserFlags)

	// Validate that either ID or name is provided
	if err := ValidateIdentifier(flags.identifierFlags); err != nil {
		return err
	}

	// Validate that new name is provided
	if err := RequireString(flags.NewName, "new-name"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// First, get the user to update
	var userID uint64
	if flags.ID != 0 {
		userID = flags.ID
	} else {
		// Find user by name
		listReq := &v1.ListUsersRequest{Name: flags.Name}
		listResp, err := client.ListUsers(ctx, listReq)
		if err != nil {
			return fmt.Errorf("cannot find user: %w", err)
		}
		if len(listResp.GetUsers()) == 0 {
			return fmt.Errorf("user with name '%s' not found", flags.Name)
		}
		userID = listResp.GetUsers()[0].GetId()
	}

	request := &v1.RenameUserRequest{
		OldId:   userID,
		NewName: flags.NewName,
	}

	response, err := client.RenameUser(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot rename user: %w", err)
	}

	return outputResult(response.GetUser(), "User renamed", flags.Output)
}

func deleteUserCommand(env *command.Env) error {
	flags := env.Config.(*deleteUserFlags)

	// Validate that either ID or name is provided
	if err := ValidateIdentifier(flags.identifierFlags); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// First, get the user to delete
	var userID uint64
	if flags.ID != 0 {
		userID = flags.ID
	} else {
		// Find user by name
		listReq := &v1.ListUsersRequest{Name: flags.Name}
		listResp, err := client.ListUsers(ctx, listReq)
		if err != nil {
			return fmt.Errorf("cannot find user: %w", err)
		}
		if len(listResp.GetUsers()) == 0 {
			return fmt.Errorf("user with name '%s' not found", flags.Name)
		}
		userID = listResp.GetUsers()[0].GetId()
	}

	// Confirm deletion unless --force is specified
	if !flags.Force {
		// TODO: Add confirmation prompt
		fmt.Printf("This will delete user ID %d. Use --force to skip this confirmation.\n", userID)
		return fmt.Errorf("deletion cancelled")
	}

	request := &v1.DeleteUserRequest{Id: userID}

	_, err = client.DeleteUser(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot delete user: %w", err)
	}

	fmt.Printf("User %d deleted successfully\n", userID)
	return nil
}

// User command definitions

func userCommands() []*command.C {
	return []*command.C{
		{
			Name:  "users",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Manage users in Headscale",
			Commands: []*command.C{
				{
					Name:     "create",
					Usage:    "<username>",
					Help:     "Create a new user",
					SetFlags: Flags(flax.MustBind, &createUserFlags{}),
					Run:      command.Adapt(createUserCommand),
				},
				{
					Name:     "list",
					Usage:    "[flags]",
					Help:     "List users",
					SetFlags: Flags(flax.MustBind, &listUserFlags{}),
					Run:      listUsersCommand,
				},
				{
					Name:     "ls",
					Usage:    "[flags]",
					Help:     "List users (alias)",
					SetFlags: Flags(flax.MustBind, &listUserFlags{}),
					Run:      listUsersCommand,
					Unlisted: true,
				},
				{
					Name:     "rename",
					Usage:    "--id <id> | --name <name> --new-name <new-name>",
					Help:     "Rename a user",
					SetFlags: Flags(flax.MustBind, &updateUserFlags{}),
					Run:      updateUserCommand,
				},
				{
					Name:     "delete",
					Usage:    "--id <id> | --name <name>",
					Help:     "Delete a user",
					SetFlags: Flags(flax.MustBind, &deleteUserFlags{}),
					Run:      deleteUserCommand,
				},
				{
					Name:     "destroy",
					Usage:    "--id <id> | --name <name>",
					Help:     "Delete a user (alias)",
					SetFlags: Flags(flax.MustBind, &deleteUserFlags{}),
					Run:      deleteUserCommand,
					Unlisted: true,
				},
			},
		},
		// User management aliases
		{
			Name:     "user",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage users in Headscale (alias)",
			Commands: userCommands()[0].Commands, // Reuse the same subcommands
			Unlisted: true,
		},
	}
}
