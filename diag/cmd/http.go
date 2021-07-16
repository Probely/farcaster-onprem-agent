package cmd

import (
	"fmt"

	"github.com/probely/farcaster-onprem-agent/diag/check"
	"github.com/probely/farcaster-onprem-agent/diag/format"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkHTTPCmd)
}

var checkHTTPCmd = &cobra.Command{
	Use:   "check-http",
	Short: "checks if the given URL is reachable",
	Run:   checkHTTP,
}

// Check WireGuard tunnels and base network endpoints reachability
func checkHTTP(cmd *cobra.Command, args []string) {
	for _, url := range args {
		s := fmt.Sprintf("Checking if %s is reachable ... ", url)
		fmt.Printf(format.PadFmtStr, s)
		format.PrintErr(check.HTTPEndpoint(url))
	}
}
