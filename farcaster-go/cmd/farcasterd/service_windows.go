//go:build windows
// +build windows

package farcasterd

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"probely.com/farcaster/winsvc"
)

var (
	name string
)

func isWindowsService() bool {
	isSvc, _ := svc.IsWindowsService()
	return isSvc
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the Farcaster service",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

var startCmd = &cobra.Command{
	Use:  "stop",
	Long: "Start the Farcaster service",
	Run: func(cmd *cobra.Command, args []string) {
		logger := initLogger(debug, logPath)
		defer logger.Sync()
		err := winsvc.Stop(name)
		if err != nil {
			logger.Errorf("Failed to stop service: %v", err)
			os.Exit(1)
		}
	},
}

var stopCmd = &cobra.Command{
	Use:  "stop",
	Long: "Stop the Farcaster service",
	Run: func(cmd *cobra.Command, args []string) {
		logger := initLogger(debug, logPath)
		defer logger.Sync()
		err := winsvc.Stop(name)
		if err != nil {
			logger.Errorf("Failed to stop service: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	serviceCmd.PersistentFlags().StringVarP(&name, "name", "n", "farcasterd", "Service name")
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(serviceCmd)
}
