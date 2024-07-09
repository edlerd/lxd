package main

import (
	"fmt"
	"github.com/canonical/lxd/shared/api"
	"github.com/spf13/cobra"
	"strings"

	cli "github.com/canonical/lxd/shared/cmd"
	"github.com/canonical/lxd/shared/i18n"
)

type cmdSiteManger struct {
	global *cmdGlobal
}

// Command is a method of the cmdAlias structure that returns a new cobra Command for managing command aliases.
// This includes commands for adding, listing, renaming, and removing aliases, along with their usage and descriptions.
func (c *cmdSiteManger) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("site-manager")
	cmd.Short = i18n.G("Manage site-manager connection")
	cmd.Long = cli.FormatSection(i18n.G("Description"), i18n.G(
		`Manage site-manager connections`))

	// Join
	siteManagerJoinCmd := cmdSiteManagerJoin{global: c.global, alias: c}
	cmd.AddCommand(siteManagerJoinCmd.command())

	// Show
	siteManagerShowCmd := cmdSiteManagerShow{global: c.global, alias: c}
	cmd.AddCommand(siteManagerShowCmd.command())

	// Delete
	siteManagerDeleteCmd := cmdSiteManagerDelete{global: c.global, alias: c}
	cmd.AddCommand(siteManagerDeleteCmd.command())

	// Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
	cmd.Args = cobra.NoArgs
	cmd.Run = func(cmd *cobra.Command, args []string) { _ = cmd.Usage() }
	return cmd
}

// Join.
type cmdSiteManagerJoin struct {
	global *cmdGlobal
	alias  *cmdSiteManger
}

// Command is a method of the cmdAliasAdd structure that returns a new cobra Command for adding new command aliases.
// It specifies the command usage, description, and examples, and links it to the RunE method for execution logic.
func (c *cmdSiteManagerJoin) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("join", i18n.G("[<remote>:]<token>"))
	cmd.Short = i18n.G("Join a site manager")
	cmd.Long = cli.FormatSection(i18n.G("Description"), i18n.G(
		`Join a site manager`))
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc site-manager join "ababab...abab"`))

	cmd.RunE = c.run

	return cmd
}

// Run is a method of the cmdAliasAdd structure. It implements the logic to add a new alias command.
// The function checks for valid arguments, verifies if the alias already exists, and if not, adds the new alias to the configuration.
func (c *cmdSiteManagerJoin) run(cmd *cobra.Command, args []string) error {
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

	payload := api.SiteManagerPost{
		Token: token,
	}

	err = d.PostSiteManager(payload)
	if err != nil {
		return err
	}

	fmt.Printf(i18n.G("Joined site manager with token") + "\n")

	return nil
}

// Show.
type cmdSiteManagerShow struct {
	global *cmdGlobal
	alias  *cmdSiteManger
}

// Command is a method of the cmdAliasAdd structure that returns a new cobra Command for adding new command aliases.
// It specifies the command usage, description, and examples, and links it to the RunE method for execution logic.
func (c *cmdSiteManagerShow) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("show")
	cmd.Short = i18n.G("Show site manager configuration")
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc site-manager show`))

	cmd.RunE = c.run

	return cmd
}

// Run is a method of the cmdAliasAdd structure. It implements the logic to add a new alias command.
// The function checks for valid arguments, verifies if the alias already exists, and if not, adds the new alias to the configuration.
func (c *cmdSiteManagerShow) run(cmd *cobra.Command, args []string) error {
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

	result, err := d.GetSiteManager()
	if err != nil {
		return err
	}

	if result.ServerCertFingerprint == "" {
		fmt.Printf(i18n.G("Site manager not configured") + "\n")
		return nil
	}

	fmt.Printf(i18n.G("Site manager configuration:") + "\n" +
		i18n.G("  addresses:") + ": " + strings.Join(result.SiteManagerAddresses, ", ") + "\n" +
		i18n.G("  local:") + ": " + result.LocalCertFingerprint + "\n" +
		i18n.G("  server:") + ": " + result.ServerCertFingerprint + "\n")

	return nil
}

// Delete.
type cmdSiteManagerDelete struct {
	global *cmdGlobal
	alias  *cmdSiteManger
}

// Command is a method of the cmdAliasAdd structure that returns a new cobra Command for adding new command aliases.
// It specifies the command usage, description, and examples, and links it to the RunE method for execution logic.
func (c *cmdSiteManagerDelete) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = usage("delete")
	cmd.Short = i18n.G("Delete site manager configuration")
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc site-manager delete`))

	cmd.RunE = c.run

	return cmd
}

// Run is a method of the cmdAliasAdd structure. It implements the logic to add a new alias command.
// The function checks for valid arguments, verifies if the alias already exists, and if not, adds the new alias to the configuration.
func (c *cmdSiteManagerDelete) run(cmd *cobra.Command, args []string) error {
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

	err = d.DeleteSiteManager()
	if err != nil {
		return err
	}

	fmt.Printf(i18n.G("Site manager config cleared") + "\n")

	return nil
}
