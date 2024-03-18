/*
Copyright © 2022 Karim Radhounia <medkarimrdi@gmail.com>
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/karimra/gnsic/app"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
		newCertzCmd(),
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

func init() {
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	err := gApp.Config.Load()
	if err == nil {
		return
	}
	if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
		fmt.Fprintf(os.Stderr, "failed loading config file: %v\n", err)
	}
}
