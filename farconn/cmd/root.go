package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   path.Base(os.Args[0]),
	Short: "Farcaster agent connection helper",
	Run:   run,
}

func run(cmd *cobra.Command, args []string) {
	cmd.Usage()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
