package commands

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/creachadair/command"
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
	NewName     string `flag:"new-name,New username"`
	DisplayName string `flag:"display-name,d,New display name"`
	Email       string `flag:"email,New email address"`
	PictureURL  string `flag:"picture-url,p,New profile picture URL"`
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
	if flags.Email != "" {
		request.Email = flags.Email
	}
	if flags.DisplayName != "" {
		request.DisplayName = flags.DisplayName
	}
	if flags.PictureURL != "" {
		request.PictureUrl = flags.PictureURL
	}

	response, err := client.CreateUser(ctx, request)
	if err != nil {
		return err
	}

	return outputResult(response.User, "User created", flags.Output)
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
	if flags.Email != "" {
		request.Email = flags.Email
	}

	response, err := client.ListUsers(ctx, request)
	if err != nil {
		return err
	}

	if len(response.Users) == 0 {
		return outputResult([]string{}, "No users found", flags.Output)
	}

	return outputResult(response.Users, "", flags.Output)
}

func updateUserCommand(env *command.Env) error {
	flags := env.Config.(*updateUserFlags)

	if err := validateIdentifier(flags.identifierFlags); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// First get the user
	listReq := &v1.ListUsersRequest{}
	listResp, err := client.ListUsers(ctx, listReq)
	if err != nil {
		return err
	}

	var targetUser *v1.User
	for _, user := range listResp.Users {
		if flags.ID != 0 && user.Id == flags.ID {
			targetUser = user
			break
		}
		if flags.Name != "" && user.Name == flags.Name {
			targetUser = user
			break
		}
	}

	if targetUser == nil {
		return fmt.Errorf("user not found")
	}

	// Update user
	request := &v1.UpdateUserRequest{
		UserId: targetUser.Id,
	}

	if flags.NewName != "" {
		request.Name = flags.NewName
	}
	if flags.DisplayName != "" {
		request.DisplayName = flags.DisplayName
	}
	if flags.Email != "" {
		request.Email = flags.Email
	}
	if flags.PictureURL != "" {
		request.PictureUrl = flags.PictureURL
	}

	response, err := client.UpdateUser(ctx, request)
	if err != nil {
		return err
	}

	return outputResult(response.User, "User updated", flags.Output)
}

func deleteUserCommand(env *command.Env) error {
	flags := env.Config.(*deleteUserFlags)

	if err := validateIdentifier(flags.identifierFlags); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// First get the user
	listReq := &v1.ListUsersRequest{}
	listResp, err := client.ListUsers(ctx, listReq)
	if err != nil {
		return err
	}

	var targetUser *v1.User
	for _, user := range listResp.Users {
		if flags.ID != 0 && user.Id == flags.ID {
			targetUser = user
			break
		}
		if flags.Name != "" && user.Name == flags.Name {
			targetUser = user
			break
		}
	}

	if targetUser == nil {
		return fmt.Errorf("user not found")
	}

	// Confirm deletion if not forced
	if !flags.Force {
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("Are you sure you want to delete user '%s'?", targetUser.Name),
		}
		var confirm bool
		if err := survey.AskOne(prompt, &confirm); err != nil {
			return err
		}
		if !confirm {
			return fmt.Errorf("user deletion cancelled")
		}
	}

	request := &v1.DeleteUserRequest{UserId: targetUser.Id}
	_, err = client.DeleteUser(ctx, request)
	if err != nil {
		return err
	}

	return outputResult(map[string]string{
		"message": fmt.Sprintf("User '%s' deleted", targetUser.Name),
	}, "User deleted", flags.Output)
}

// UserCommands returns the user management command tree
func UserCommands() []*command.C {
	return []*command.C{
		// Main users command
		{
			Name:  "users",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Manage users in Headscale",
			Commands: []*command.C{
				{
					Name:     "create",
					Usage:    "<username>",
					Help:     "Create a new user",
					SetFlags: setFlags(&createUserFlags{}),
					Run:      command.Adapt(createUserCommand),
				},
				{
					Name:     "list",
					Usage:    "[flags]",
					Help:     "List users",
					SetFlags: setFlags(&listUserFlags{}),
					Run:      listUsersCommand,
				},
				{
					Name:     "ls",
					Usage:    "[flags]",
					Help:     "List users (alias)",
					SetFlags: setFlags(&listUserFlags{}),
					Run:      listUsersCommand,
					Unlisted: true,
				},
				{
					Name:     "update",
					Usage:    "--id <id> | --name <name> [flags]",
					Help:     "Update a user",
					SetFlags: setFlags(&updateUserFlags{}),
					Run:      updateUserCommand,
				},
				{
					Name:     "rename",
					Usage:    "--id <id> | --name <name> [flags]",
					Help:     "Update a user (alias)",
					SetFlags: setFlags(&updateUserFlags{}),
					Run:      updateUserCommand,
					Unlisted: true,
				},
				{
					Name:     "delete",
					Usage:    "--id <id> | --name <name>",
					Help:     "Delete a user",
					SetFlags: setFlags(&deleteUserFlags{}),
					Run:      deleteUserCommand,
				},
				{
					Name:     "destroy",
					Usage:    "--id <id> | --name <name>",
					Help:     "Delete a user (alias)",
					SetFlags: setFlags(&deleteUserFlags{}),
					Run:      deleteUserCommand,
					Unlisted: true,
				},
			},
		},

		// User alias command
		{
			Name:     "user",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage users in Headscale (alias)",
			Unlisted: true,
			Commands: []*command.C{
				{
					Name:     "create",
					Usage:    "<username>",
					Help:     "Create a new user",
					SetFlags: setFlags(&createUserFlags{}),
					Run:      command.Adapt(createUserCommand),
				},
				{
					Name:     "list",
					Usage:    "[flags]",
					Help:     "List users",
					SetFlags: setFlags(&listUserFlags{}),
					Run:      listUsersCommand,
				},
				{
					Name:     "ls",
					Usage:    "[flags]",
					Help:     "List users (alias)",
					SetFlags: setFlags(&listUserFlags{}),
					Run:      listUsersCommand,
					Unlisted: true,
				},
				{
					Name:     "update",
					Usage:    "--id <id> | --name <name> [flags]",
					Help:     "Update a user",
					SetFlags: setFlags(&updateUserFlags{}),
					Run:      updateUserCommand,
				},
				{
					Name:     "rename",
					Usage:    "--id <id> | --name <name> [flags]",
					Help:     "Update a user (alias)",
					SetFlags: setFlags(&updateUserFlags{}),
					Run:      updateUserCommand,
					Unlisted: true,
				},
				{
					Name:     "delete",
					Usage:    "--id <id> | --name <name>",
					Help:     "Delete a user",
					SetFlags: setFlags(&deleteUserFlags{}),
					Run:      deleteUserCommand,
				},
				{
					Name:     "destroy",
					Usage:    "--id <id> | --name <name>",
					Help:     "Delete a user (alias)",
					SetFlags: setFlags(&deleteUserFlags{}),
					Run:      deleteUserCommand,
					Unlisted: true,
				},
			},
		},
	}
}
