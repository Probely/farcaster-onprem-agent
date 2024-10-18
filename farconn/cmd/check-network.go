package cmd

import (
	"fmt"
	"os"

	"github.com/probely/farcaster-onprem-agent/farconn/format"
	"github.com/probely/farcaster-onprem-agent/farconn/services"
	"github.com/spf13/cobra"
)

const (
	wireguardDeviceName = "wg-tunnel"
)

var (
	farcasterHTTPEndpoints = [...]string{"https://api.probely.com"}
	externalHTPEndpoints   = [...]string{"https://google.com"}
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

	format.PrintPadf("Checking if WireGuard tunnel is up")
	err = services.CheckWireguardTunnel(wireguardDeviceName)
	if err != nil {
		errCnt++
	}
	format.PrintErr(err)
	if err != nil {
		fmt.Println(`  * WireGuard tunnel appears to be down.
    Please ensure that the agent can connect to hub.farcaster.probely.com on UDP port 443`)
	}

	for _, url := range farcasterHTTPEndpoints {
		format.PrintPadf("Checking if %s is reachable", url)
		_, err = services.CheckHTTPEndpoint(url)
		if err != nil {
			errCnt++
		}
		format.PrintErr(err)
	}

	prevErrCnt := errCnt
	for _, url := range externalHTPEndpoints {
		format.PrintPadf("Checking if %s is reachable", url)
		_, err = services.CheckHTTPEndpoint(url)
		if err != nil {
			errCnt++
		}
		format.PrintWarn(err)
	}
	if errCnt > prevErrCnt {
		fmt.Println(`  * External websites appear to be blocked.
    If scanning internal websites which include external resources, the scan may fail.
  * If an HTTP proxy is needed for external websites, please set the HTTP_PROXY
    variable on docker-compose.yml, and then restart the agent.`)
	}

	os.Exit(errCnt)
}
