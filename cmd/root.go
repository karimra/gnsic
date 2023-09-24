/*
Copyright © 2022 Karim Radhounia <medkarimrdi@gmail.com>
*/
package cmd

import (
	"context"
	"os"

	"github.com/karimra/gnsic/app"
	"github.com/spf13/cobra"
)

var gApp = app.New()

func newRootCmd(ctx context.Context) *cobra.Command {
	gApp.RootCmd = &cobra.Command{
		Use:               "gnsic",
		PersistentPreRunE: gApp.PreRun,
	}
	gApp.RootCmd.SetContext(ctx)
	gApp.InitGlobalFlags()
	gApp.RootCmd.AddCommand(
		newAuthzCmd(),
		newServerCmd(),
	)
	return gApp.RootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(ctx context.Context) {
	// setupCloseHandler(gApp.Cfn)
	if err := newRootCmd(ctx).Execute(); err != nil {
		os.Exit(1)
	}
}
