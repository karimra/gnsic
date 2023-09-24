package cmd

import "github.com/spf13/cobra"

// authzCmd represents the authz command
func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "run a gNSI Server",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetPersistentFlagsFromFile(cmd)
		},
		RunE:         gApp.RunEServer,
		SilenceUsage: true,
	}
	gApp.InitServerFlags(cmd)
	cmd.AddCommand()
	return cmd
}
