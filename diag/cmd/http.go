package cmd

import (
	"fmt"

	"github.com/probely/farcaster-onprem-agent/diag/check"
	"github.com/probely/farcaster-onprem-agent/diag/format"
	"github.com/spf13/cobra"
)

var dumpResp bool

func init() {
	checkHTTPCmd.Flags().BoolVar(&dumpResp, "dump-response", false, "Dump the server response")
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
		format.PrintPadf("Checking if %s is reachable ... ", url)
		res, err := check.HTTPEndpoint(url)
		format.PrintErr(err)
		if dumpResp {
			fmt.Printf("\n%s\n", res.Data)
		}
	}
}
