package cmd

import (
	"fmt"
	"net/url"

	"github.com/probely/farcaster-onprem-agent/farcaster/format"
	"github.com/probely/farcaster-onprem-agent/farcaster/services"
	"github.com/spf13/cobra"
)

var verbose bool

func init() {
	checkHTTPCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show request details")
	rootCmd.AddCommand(checkHTTPCmd)
}

var checkHTTPCmd = &cobra.Command{
	Use:   "check-http <url>",
	Short: "checks if the given URL is reachable",
	Run:   checkHTTP,
	Args:  cobra.MinimumNArgs(1),
}

func resultToString(res *services.HTTPResult) string {
	if res == nil {
		return "[empty]"
	}
	return string(res.Data)
}

func ensureURLSchemeExists(u string) (string, error) {
	pu, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	if pu.Scheme == "" {
		u = "http://" + u
	}
	return u, nil
}

func checkHTTP(cmd *cobra.Command, args []string) {
	var err error
	var res *services.HTTPResult
	for _, u := range args {
		format.PrintPadf("Checking if %s is reachable ... ", u)
		if u, err = ensureURLSchemeExists(u); err != nil {
			format.PrintErr(err)
			return
		}
		res, err = services.CheckHTTPEndpoint(u)
		format.PrintErr(err)
		if err != nil {
			if verbose {
				fmt.Printf("\nServer response:\n%s\n", resultToString(res))
			} else {
				fmt.Println("  * Use --verbose for more details")
			}
			continue
		}
		if verbose {
			fmt.Printf("\n%s\n", resultToString(res))
		}
	}
}
