package cmd

import (
	"fmt"

	"github.com/probely/farcaster-onprem-agent/diag/check"
	"github.com/probely/farcaster-onprem-agent/diag/format"
	"github.com/spf13/cobra"
)

var verbose bool

func init() {
	checkHTTPCmd.Flags().BoolVar(&verbose, "verbose", false, "Show request details")
	rootCmd.AddCommand(checkHTTPCmd)
}

var checkHTTPCmd = &cobra.Command{
	Use:   "check-http",
	Short: "checks if the given URL is reachable",
	Run:   checkHTTP,
	Args:  cobra.MinimumNArgs(1),
}

func checkHTTP(cmd *cobra.Command, args []string) {
	for _, url := range args {
		var err error
		var res *check.HTTPResult
		format.PrintPadf("Checking if %s is reachable ... ", url)
		res, err = check.HTTPEndpoint(url)
		format.PrintErr(err)
		if err != nil {
			continue
		}
		if verbose && res.Data != nil {
			fmt.Printf("\n%s\n", res.Data)
		}
	}
}
