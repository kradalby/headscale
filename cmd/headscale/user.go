package main

import (
	"context"
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// User command flags
var userArgs struct {
	ID    uint64 `flag:"id,i,User ID"`
	Name  string `flag:"name,n,User name"`
	Email string `flag:"email,e,Email address"`
}

// User command implementations

func createUserCommand(env *command.Env, username string) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.CreateUserRequest{Name: username}

		if userArgs.Email != "" {
			request.Email = userArgs.Email
		}

		response, err := client.CreateUser(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot create user: %w", err)
		}

		return outputResult(response.GetUser(), "User created", globalArgs.Output)
	})
}

func listUsersCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ListUsersRequest{}

		// Apply filters if specified
		if userArgs.ID != 0 {
			request.Id = userArgs.ID
		}
		if userArgs.Name != "" {
			request.Name = userArgs.Name
		}
		if userArgs.Email != "" {
			request.Email = userArgs.Email
		}

		response, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot list users: %w", err)
		}

		return outputResult(response.GetUsers(), "Users", globalArgs.Output)
	})
}

func renameUserCommand(env *command.Env, newName string) error {
	// Validate that either ID or name is provided
	if err := validateUserIdentifier(userArgs.ID, userArgs.Name); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// First, get the user to update
		var userID uint64
		if userArgs.ID != 0 {
			userID = userArgs.ID
		} else {
			// Find user by name
			listReq := &v1.ListUsersRequest{Name: userArgs.Name}
			listResp, err := client.ListUsers(ctx, listReq)
			if err != nil {
				return fmt.Errorf("cannot find user: %w", err)
			}
			if len(listResp.GetUsers()) == 0 {
				return fmt.Errorf("user with name '%s' not found", userArgs.Name)
			}
			userID = listResp.GetUsers()[0].GetId()
		}

		request := &v1.RenameUserRequest{
			OldId:   userID,
			NewName: newName,
		}

		response, err := client.RenameUser(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot rename user: %w", err)
		}

		return outputResult(response.GetUser(), "User renamed", globalArgs.Output)
	})
}

func deleteUserCommand(env *command.Env) error {
	// Validate that either ID or name is provided
	if err := validateUserIdentifier(userArgs.ID, userArgs.Name); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// First, get the user to delete
		var userID uint64
		if userArgs.ID != 0 {
			userID = userArgs.ID
		} else {
			// Find user by name
			listReq := &v1.ListUsersRequest{Name: userArgs.Name}
			listResp, err := client.ListUsers(ctx, listReq)
			if err != nil {
				return fmt.Errorf("cannot find user: %w", err)
			}
			if len(listResp.GetUsers()) == 0 {
				return fmt.Errorf("user with name '%s' not found", userArgs.Name)
			}
			userID = listResp.GetUsers()[0].GetId()
		}

		// Confirm deletion unless --force is specified
		if !globalArgs.Force {
			// TODO: Add confirmation prompt
			fmt.Printf("This will delete user ID %d. Use --force to skip this confirmation.\n", userID)
			return fmt.Errorf("deletion cancelled")
		}

		request := &v1.DeleteUserRequest{Id: userID}

		_, err := client.DeleteUser(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot delete user: %w", err)
		}

		fmt.Printf("User %d deleted successfully\n", userID)
		return nil
	})
}

// User command definitions

func userCommands() []*command.C {
	userCommand := &command.C{
		Name:     "users",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Manage users in Headscale",
		SetFlags: command.Flags(flax.MustBind, &userArgs),
		Commands: []*command.C{
			{
				Name:  "create",
				Usage: "<username>",
				Help:  "Create a new user",
				Run:   command.Adapt(createUserCommand),
			},
			{
				Name:  "list",
				Usage: "[flags]",
				Help:  "List users",
				Run:   listUsersCommand,
			},
			createSubcommandAlias(listUsersCommand, "ls", "[flags]", "List users (alias)"),
			{
				Name:  "rename",
				Usage: "<new-name>",
				Help:  "Rename a user",
				Run:   command.Adapt(renameUserCommand),
			},
			{
				Name:  "delete",
				Usage: "--id <id> | --name <name>",
				Help:  "Delete a user",
				Run:   deleteUserCommand,
			},
			createSubcommandAlias(deleteUserCommand, "destroy", "--id <id> | --name <name>", "Delete a user (alias)"),
		},
	}

	return []*command.C{
		userCommand,
		// User management alias
		createCommandAlias(userCommand, "user", "Manage users in Headscale (alias)"),
	}
}
