package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/karimra/gnsic/cmd"
)

func main() {
	ctx, cancel := context.WithCancel(context.TODO())
	setupCloseHandler(cancel)
	cmd.Execute(ctx)

}

func setupCloseHandler(cancelFn context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-c
		fmt.Printf("\nreceived signal '%s'. terminating...\n", sig.String())
		cancelFn()
		os.Exit(0)
	}()
}
