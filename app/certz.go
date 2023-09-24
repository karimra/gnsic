package app

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitCertzFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	//
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}
