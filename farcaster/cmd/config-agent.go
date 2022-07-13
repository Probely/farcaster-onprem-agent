package cmd

import (
	"fmt"
	"os"

	"github.com/probely/farcaster-onprem-agent/farcaster/actions"
	"github.com/spf13/cobra"
)

func init() {
	configAgentCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show request details")
	rootCmd.AddCommand(configAgentCmd)
}

var configAgentCmd = &cobra.Command{
	Use:   "config-agent",
	Short: "fetch configuration and setup the agent",
	Run:   configAgent,
}

func configAgent(cmd *cobra.Command, args []string) {
	token := os.Getenv("FARCASTER_AGENT_TOKEN")
	if len(token) == 0 {
		fmt.Fprint(os.Stderr, "Please set the FARCASTER_AGENT_TOKEN env variable")
		os.Exit(1)
	}

	data, err := actions.FetchConfig(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading agent config: %s\n", err)
		os.Exit(1)
	}

	actions.CreateConfig(data, token)
}
