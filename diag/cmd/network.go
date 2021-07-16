package cmd

import (
	"fmt"
	"os"

	"github.com/probely/farcaster-onprem-agent/diag/check"
	"github.com/probely/farcaster-onprem-agent/diag/format"
	"github.com/spf13/cobra"
)

const (
	wireguardDeviceName = "wg-tunnel"
)

var (
	farcasterHTTPEndpoints = [...]string{"https://api.probely.com"}
	externalHTPEndpoints   = [...]string{"https://google.comx"}
)

func init() {
	rootCmd.AddCommand(checkNetCmd)
}

var checkNetCmd = &cobra.Command{
	Use:   "check-network",
	Short: "checks if the agent is connected to Probely and if it can reach the Internet",
	Run:   checkNetwork,
}

// Check WireGuard tunnels and base network endpoints reachability
func checkNetwork(cmd *cobra.Command, args []string) {
	var err error
	errCnt := 0

	fmt.Printf(format.PadFmtStr, "Checking if WireGuard tunnel is up")
	err = check.WireguardTunnel(wireguardDeviceName)
	if err != nil {
		errCnt++
	}
	format.PrintErr(err)
	if err != nil {
		fmt.Println(`  * WireGuard tunnel appears to be down.
    Plase ensure that the agent can connect to hub.farcaster.probely.com on UDP port 443`)
	}

	for _, url := range farcasterHTTPEndpoints {
		s := fmt.Sprintf("Checking if %s is reachable", url)
		fmt.Printf(format.PadFmtStr, s)
		err = check.HTTPEndpoint(url)
		if err != nil {
			errCnt++
		}
		format.PrintErr(err)
	}

	prevErrCnt := errCnt
	for _, url := range externalHTPEndpoints {
		s := fmt.Sprintf("Checking if %s is reachable", url)
		fmt.Printf(format.PadFmtStr, s)
		err = check.HTTPEndpoint(url)
		if err != nil {
			errCnt++
		}
		format.PrintWarn(err)
	}
	if errCnt > prevErrCnt {
		fmt.Println(`  * External websites appear to be blocked.
    If your try to scan an internal website which includes external resources,
    the assessment might fail as the agent will not be able to load those resources`)
	}

	os.Exit(errCnt)
}
