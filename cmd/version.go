package cmd

import "github.com/spf13/cobra"

// versionCmd represents the version command
func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "show version",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetPersistentFlagsFromFile(cmd)
		},
		Run:          gApp.VersionRun,
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newVersionUpgradeCmd(),
	)
	return cmd
}

func newVersionUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "upgrade",
		Aliases: []string{"up"},
		Short:   "upgrade gNSIc",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetPersistentFlagsFromFile(cmd)
		},
		RunE:         gApp.VersionUpgradeRun,
		SilenceUsage: true,
	}
	return cmd
}
