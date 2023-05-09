package cmd

import (
	"fmt"
	"os"

	"github.com/probely/farcaster-onprem-agent/farcaster/services"
	"github.com/spf13/cobra"
)

func init() {
	configAgentCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show request details")
	rootCmd.AddCommand(configAgentCmd)
}

var configAgentCmd = &cobra.Command{
	Use:   "config-agent DESTINATION",
	Short: "fetch configuration and setup the agent",
	Run:   configAgent,
	Args:  cobra.ExactArgs(1),
}

func configAgent(cmd *cobra.Command, args []string) {
	dest := args[0]

	token := os.Getenv("FARCASTER_AGENT_TOKEN")
	if len(token) == 0 {
		fmt.Fprint(os.Stderr, "Please set the FARCASTER_AGENT_TOKEN env variable\n")
		os.Exit(1)
	}

	// Fetch config files using the Probely API
	var data []byte
	var err error
	for _, url := range services.APIURLs() {
		fmt.Fprintf(os.Stderr, "Fetching agent config from %s to %s...\n", url, dest)
		if data, err = services.FetchConfig(token, url); err == nil {
			break
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading agent config: %s\n", err)
		os.Exit(1)
	}

	// Decrypt secrets and build the configuration files
	var files map[string]*services.ConfigFile
	if files, err = services.BuildConfig(data, token); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating agent config files: %s\n", err)
		os.Exit(1)
	}

	// Write secrets to the filesystem
	if err = services.WriteConfig(files, dest); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing agent config files to %s: %s\n",
			dest, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Agent config files written to %s...\n", dest)
}
