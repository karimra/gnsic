package cmd

import "github.com/spf13/cobra"

// authzCmd represents the authz command
func newAuthzCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authz",
		Short: "run Authz gNSI RPCs",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetPersistentFlagsFromFile(cmd)
		},
		SilenceUsage: true,
	}
	gApp.InitAuthzFlags(cmd)
	cmd.AddCommand(
		newAuthzRotateCmd(),
		newAuthzProbeCmd(),
		newAuthzGetCmd(),
	)
	return cmd
}

// newAuthzRotateCmd represents the authz rotate command
func newAuthzRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "run authz Rotate gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunEAuthzRotate,
		SilenceUsage: true,
	}
	gApp.InitAuthzRotateFlags(cmd)
	return cmd
}

// newAuthzProbeCmd represents the authz probe command
func newAuthzProbeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "run authz Probe gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunEAuthzProbe,
		SilenceUsage: true,
	}
	gApp.InitAuthzProbeFlags(cmd)
	return cmd
}

// newAuthzGetCmd represents the authz get command
func newAuthzGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "run authz Get gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunEAuthzGet,
		SilenceUsage: true,
	}
	gApp.InitAuthzGetFlags(cmd)
	return cmd
}
