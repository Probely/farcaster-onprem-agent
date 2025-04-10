//go:build windows
// +build windows

package farcasterd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
	"probely.com/farcaster/config"
	"probely.com/farcaster/osutils"
	"probely.com/farcaster/settings"
	"probely.com/farcaster/winsvc"
)

func isWindowsService() bool {
	isSvc, _ := svc.IsWindowsService()
	return isSvc
}

func runWindowsService(name string, agent func() error, logger *zap.SugaredLogger) error {
	service := winsvc.NewService(name, agent, logger)
	return service.Run()
}

var logger *zap.SugaredLogger

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the " + settings.Name + " service",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip admin check for help command
		if cmd.Name() == "help" {
			return
		}

		// Check if the current process has elevated privileges
		isAdmin, err := winsvc.IsAdmin()
		if err != nil {
			logger.Errorf("Failed to check admin privileges: %v", err)
			os.Exit(1)
		}

		if !isAdmin {
			fmt.Println("This operation requires administrative privileges.")
			fmt.Println("Press Enter to show the UAC prompt and continue...")
			fmt.Scanln()

			err := winsvc.RunElevated()
			if err != nil {
				logger.Errorf("Failed to elevate: %v", err)
				os.Exit(1)
			}
			// Exit the non-elevated process
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the " + settings.Name + " service",
	Run: func(cmd *cobra.Command, args []string) {
		err := winsvc.Start(settings.ServiceName)
		if err != nil {
			logger.Errorf("Failed to start service: %v", err)
			os.Exit(1)
		}
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the " + settings.Name + " service",
	Run: func(cmd *cobra.Command, args []string) {
		err := winsvc.Stop(settings.ServiceName)
		if err != nil {
			logger.Errorf("Failed to stop service: %v", err)
			os.Exit(1)
		}
	},
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the " + settings.Name + " service",
	Run: func(cmd *cobra.Command, args []string) {
		err := parseConfig(&appCfg)
		if err != nil {
			logger.Errorf("Failed to parse configuration: %v", err)
			os.Exit(1)
		}

		cfg := config.NewFarcasterConfig(appCfg.token, appCfg.apiURLs, logger)
		mustResolve := false
		if err := cfg.Load(mustResolve); err != nil {
			logger.Errorf("Failed to load configuration: %v", err)
			os.Exit(1)
		}

		exePath, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to get executable path: %v", err)
			os.Exit(1)
		}
		exePath, err = filepath.Abs(exePath)
		if err != nil {
			logger.Errorf("Failed to get absolute path: %v", err)
			os.Exit(1)
		}

		// Create the service data directory if it doesn't exist.
		serviceDir := filepath.Join(os.Getenv("PROGRAMDATA"), "Probely", "Farcaster")
		if err := os.MkdirAll(serviceDir, 0700); err != nil {
			logger.Errorf("Failed to create service directory: %v", err)
			os.Exit(1)
		}
		// Set ACLs on the agent directory to restrict access to administrators and the service account.
		if err := osutils.LockDownPermissions(serviceDir); err != nil {
			logger.Errorf("Failed to set ACLs on service directory: %v", err)
			os.Exit(1)
		}

		// Save the token to the service data directory.
		tokenPath := filepath.Join(serviceDir, "token.dat")
		if err := os.WriteFile(tokenPath, []byte(appCfg.token), 0600); err != nil {
			logger.Errorf("Failed to save token: %v", err)
			os.Exit(1)
		}

		logpath := filepath.Join(serviceDir, "Logs", settings.Filename+".log")
		// Create the log directory if it doesn't exist.
		if err := os.MkdirAll(filepath.Dir(logpath), 0700); err != nil {
			logger.Errorf("Failed to create log directory: %v", err)
			os.Exit(1)
		}

		svcArgs := []string{exePath, "--token", tokenPath, "--log", logpath}
		if !slices.Equal(appCfg.apiURLs, defaultAPIURLs) && len(appCfg.apiURLs) > 0 {
			svcArgs = append(svcArgs, "--api-url", appCfg.apiURLs[0])
		}

		if err := winsvc.Install(settings.ServiceName, settings.Description, svcArgs); err != nil {
			logger.Errorf("Failed to install service: %v", err)
			os.Exit(1)
		}
		logger.Infof("Service installed successfully. Logs will be written to %s", logpath)
	},
}

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove the " + settings.Name + " service",
	Run: func(cmd *cobra.Command, args []string) {
		if err := winsvc.Remove(settings.ServiceName); err != nil {
			logger.Errorf("Failed to remove service: %v", err)
			os.Exit(1)
		}
		logger.Info("Service removed successfully")
	},
}

func init() {
	l, err := initLogger(appCfg.debug, appCfg.logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	logger = l
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	serviceCmd.AddCommand(installCmd)
	serviceCmd.AddCommand(removeCmd)
	rootCmd.AddCommand(serviceCmd)
}
