package main

import (
	"fmt"
	"github.com/canonical/lxd/shared/api"
	"github.com/spf13/cobra"
	"strings"

	cli "github.com/canonical/lxd/shared/cmd"
	"github.com/canonical/lxd/shared/i18n"
)

type cmdClusterManger struct {
	global *cmdGlobal
}

// Command is a method of the cmdAlias structure that returns a new cobra Command for managing command aliases.
// This includes commands for adding, listing, renaming, and removing aliases, along with their usage and descriptions.
func (c *cmdClusterManger) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("cluster-manager")
	cmd.Short = i18n.G("Manage cluster-manager connection")
	cmd.Long = cli.FormatSection(i18n.G("Description"), i18n.G(
		`Manage cluster-manager connections`))

	// Join
	clusterManagerJoinCmd := cmdClusterManagerJoin{global: c.global, alias: c}
	cmd.AddCommand(clusterManagerJoinCmd.command())

	// Show
	clusterManagerShowCmd := cmdClusterManagerShow{global: c.global, alias: c}
	cmd.AddCommand(clusterManagerShowCmd.command())

	// Delete
	clusterManagerDeleteCmd := cmdClusterManagerDelete{global: c.global, alias: c}
	cmd.AddCommand(clusterManagerDeleteCmd.command())

	// Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
	cmd.Args = cobra.NoArgs
	cmd.Run = func(cmd *cobra.Command, args []string) { _ = cmd.Usage() }
	return cmd
}

// Join.
type cmdClusterManagerJoin struct {
	global *cmdGlobal
	alias  *cmdClusterManger
}

// Command is a method of the cmdAliasAdd structure that returns a new cobra Command for adding new command aliases.
// It specifies the command usage, description, and examples, and links it to the RunE method for execution logic.
func (c *cmdClusterManagerJoin) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("join", i18n.G("[<remote>:]<token>"))
	cmd.Short = i18n.G("Join a cluster manager")
	cmd.Long = cli.FormatSection(i18n.G("Description"), i18n.G(
		`Join a cluster manager`))
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc cluster-manager join "ababab...abab"`))

	cmd.RunE = c.run

	return cmd
}

// Run is a method of the cmdAliasAdd structure. It implements the logic to add a new alias command.
// The function checks for valid arguments, verifies if the alias already exists, and if not, adds the new alias to the configuration.
func (c *cmdClusterManagerJoin) run(cmd *cobra.Command, args []string) error {
	conf := c.global.conf

	// Check token argument is present.
	exit, err := c.global.CheckArgs(cmd, args, 1, 1)
	if exit {
		return err
	}

	// Get the remote
	remote, token, err := conf.ParseRemote(args[0])
	if err != nil {
		return err
	}

	if token == "" {
		return fmt.Errorf(i18n.G("Missing token"))
	}

	d, err := conf.GetInstanceServer(remote)
	if err != nil {
		return err
	}

	payload := api.ClusterManagerPost{
		Token: token,
	}

	err = d.PostClusterManager(payload)
	if err != nil {
		return err
	}

	fmt.Printf(i18n.G("Joined cluster manager with token") + "\n")

	return nil
}

// Show.
type cmdClusterManagerShow struct {
	global *cmdGlobal
	alias  *cmdClusterManger
}

// Command is a method of the cmdAliasAdd structure that returns a new cobra Command for adding new command aliases.
// It specifies the command usage, description, and examples, and links it to the RunE method for execution logic.
func (c *cmdClusterManagerShow) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("show")
	cmd.Short = i18n.G("Show cluster manager configuration")
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc cluster-manager show`))

	cmd.RunE = c.run

	return cmd
}

// Run is a method of the cmdAliasAdd structure. It implements the logic to add a new alias command.
// The function checks for valid arguments, verifies if the alias already exists, and if not, adds the new alias to the configuration.
func (c *cmdClusterManagerShow) run(cmd *cobra.Command, args []string) error {
	conf := c.global.conf

	// Get the remote
	remote, _, err := conf.ParseRemote("")
	if err != nil {
		return err
	}

	d, err := conf.GetInstanceServer(remote)
	if err != nil {
		return err
	}

	result, err := d.GetClusterManager()
	if err != nil {
		return err
	}

	if result.ServerCertFingerprint == "" {
		fmt.Printf(i18n.G("cluster manager not configured") + "\n")
		return nil
	}

	fmt.Printf(i18n.G("cluster manager configuration:") + "\n" +
		i18n.G("  addresses") + ": " + strings.Join(result.ClusterManagerAddresses, ", ") + "\n" +
		i18n.G("  local") + ": " + result.LocalCertFingerprint + "\n" +
		i18n.G("  server") + ": " + result.ServerCertFingerprint + "\n")

	return nil
}

// Delete.
type cmdClusterManagerDelete struct {
	global *cmdGlobal
	alias  *cmdClusterManger
}

// Command is a method of the cmdAliasAdd structure that returns a new cobra Command for adding new command aliases.
// It specifies the command usage, description, and examples, and links it to the RunE method for execution logic.
func (c *cmdClusterManagerDelete) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("delete")
	cmd.Short = i18n.G("Delete cluster manager configuration")
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc cluster-manager delete`))

	cmd.RunE = c.run

	return cmd
}

// Run is a method of the cmdAliasAdd structure. It implements the logic to add a new alias command.
// The function checks for valid arguments, verifies if the alias already exists, and if not, adds the new alias to the configuration.
func (c *cmdClusterManagerDelete) run(cmd *cobra.Command, args []string) error {
	conf := c.global.conf

	// Check token argument is present.
	exit, err := c.global.CheckArgs(cmd, args, 0, 0)
	if exit {
		return err
	}

	// Get the remote
	remote, _, err := conf.ParseRemote("")
	if err != nil {
		return err
	}

	d, err := conf.GetInstanceServer(remote)
	if err != nil {
		return err
	}

	err = d.DeleteClusterManager()
	if err != nil {
		return err
	}

	fmt.Printf(i18n.G("cluster manager config cleared") + "\n")

	return nil
}
