package main

import (
	"pico/cmd"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "pico"}
	rootCmd.AddCommand(cmd.ClientCmd)
	rootCmd.AddCommand(cmd.ServerCmd)
	rootCmd.AddCommand(cmd.GenerateKeysCmd)
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
