package cmd

import "github.com/spf13/cobra"

// newCertzCmd represents the certz command
func newCertzCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certz",
		Short: "run Certz gNSI RPCs",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetPersistentFlagsFromFile(cmd)
		},
		SilenceUsage: true,
	}
	gApp.InitCertzFlags(cmd)
	cmd.AddCommand(
		newCertzCreateCaCmd(),
		newCertzInfoCmd(),
		newCertzRotateCmd(),
		newCertzAddProfileCmd(),
		newCertzDeleteProfileCmd(),
		newCertzGetProfileListCmd(),
		newCertzCanGenerateCSRCmd(),
	)
	return cmd
}

// newCertzInfoCmd represents the certz info command
func newCertzInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "displays certificate in a human readable form",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunECertzInfo,
		SilenceUsage: true,
	}
	gApp.InitCertzInfoFlags(cmd)
	return cmd
}

// newCertzCreateCaCmd represents the certz create-ca command
func newCertzCreateCaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-ca",
		Short: "creates a self signed CA",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunECertzCreateCa,
		SilenceUsage: true,
	}
	gApp.InitCertzCreateCaFlags(cmd)
	return cmd
}

// newCertzRotateCmd represents the certz rotate command
func newCertzRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "run certz Rotate gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		PreRunE:      gApp.PreRunECertzRotate,
		RunE:         gApp.RunECertzRotate,
		SilenceUsage: true,
	}
	gApp.InitCertzRotateFlags(cmd)
	return cmd
}

// newCertzAddProfileCmd represents the certz add-profile command
func newCertzAddProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add-profile",
		Aliases: []string{"add"},
		Short:   "run certz AddProfile gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunECertzAddProfile,
		SilenceUsage: true,
	}
	gApp.InitCertzAddProfileFlags(cmd)
	return cmd
}

// newCertzDeleteProfileCmd represents the certz delete-profile command
func newCertzDeleteProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete-profile",
		Aliases: []string{"delete", "rm", "del"},
		Short:   "run certz DeleteProfile gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunECertzDeleteProfile,
		SilenceUsage: true,
	}
	gApp.InitCertzDeleteProfileFlags(cmd)
	return cmd
}

// newCertzGetProfileListCmd represents the certz get-profile-list command
func newCertzGetProfileListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get-profile-list",
		Aliases: []string{"ls", "get"},
		Short:   "run certz GetProfileList gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunECertzGetProfile,
		SilenceUsage: true,
	}
	gApp.InitCertzGetProfileFlags(cmd)
	return cmd
}

// newCertzCanGenerateCSRCmd represents the certz can-gen-csr command
func newCertzCanGenerateCSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "can-gen-csr",
		Aliases: []string{"cgc"},
		Short:   "run certz CanGenerateCSR gNSI RPC",
		PreRun: func(cmd *cobra.Command, _ []string) {
			gApp.Config.SetLocalFlagsFromFile(cmd)
		},
		RunE:         gApp.RunECertzCanGenerateCSR,
		SilenceUsage: true,
	}
	gApp.InitCertzCanGenerateCSRFlags(cmd)
	return cmd
}
