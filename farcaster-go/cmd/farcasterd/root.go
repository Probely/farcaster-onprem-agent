package farcasterd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"probely.com/farcaster/agent"
	"probely.com/farcaster/control"
	"probely.com/farcaster/settings"
	"probely.com/farcaster/system"
)

const (
	// The number of times the agent will try to connect to the agent hub.
	// It starts by connecting to UDP 443. If it fails, it tries 53 UDP.
	// The total number of connection attempts is 2 * maxConnTries.
	maxConnTries = 3

	// Environment variable name for the API (old name) and AGENT tokens.
	envOldTokenName = "FARCASTER_API_TOKEN"
	envTokenName    = "FARCASTER_AGENT_TOKEN"
)

var (
	token      string
	checkToken bool
	controlAPI string
	group      string
	showVers   bool
	logPath    string
	debug      bool
)

var rootCmd = &cobra.Command{
	Use:   filepath.Base(os.Args[0]),
	Short: "The Farcaster connects your network to Probely",
	Run: func(cmd *cobra.Command, args []string) {
		if showVers {
			fmt.Fprintf(os.Stderr, "%s version %s on %s %s\n",
				settings.Name, settings.Version, runtime.GOOS, runtime.GOARCH)
			os.Exit(0)
		}

		// If the control API is enabled, we don't need a token.
		if controlAPI == "" && token == "" {
			// Check if the token is set in the environment.
			envToken := os.Getenv(envTokenName)
			if envToken == "" {
				envToken = os.Getenv(envOldTokenName)
				if envToken != "" {
					fmt.Fprintf(os.Stderr, "warning: %s environment variable is deprecated, use %s instead\n",
						envOldTokenName, envTokenName)
				}
			}
			if envToken == "" && controlAPI == "" {
				errMsg := "error: --token argument or " + envTokenName + " environment variable is required"
				fmt.Fprintln(os.Stderr, errMsg)
				os.Exit(1)
			}
			token = strings.TrimSpace(envToken)
		}

		runAgent(token)
	},
}

func init() {
	var apiListener string
	if runtime.GOOS == "windows" {
		apiListener = "Windows named pipe"
	} else {
		apiListener = "Unix socket"
	}
	rootCmd.PersistentFlags().StringVarP(&token, "token", "t", "", "Authentication token. Can either be the path to the token file, or the token itself")
	rootCmd.PersistentFlags().BoolVarP(&checkToken, "check-token", "", false, "Check if the token is valid and exit")
	rootCmd.PersistentFlags().StringVarP(&controlAPI, "control", "", "", "Enable the control API on the "+apiListener)
	rootCmd.PersistentFlags().StringVarP(&group, "group", "", "", "Group to grant access to the control API")
	rootCmd.PersistentFlags().BoolVarP(&showVers, "version", "v", false, "Print the version and exit")
	rootCmd.PersistentFlags().StringVarP(&logPath, "log", "l", "", "Log file path. Log to stderr if not specified")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
}

// Execute runs the Farcaster agent.
func Execute() {
	// Send all output to stderr.
	rootCmd.SetOut(os.Stderr)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// This is the main function of the agent.
func runAgent(token string) {
	// New logger.
	logger := initLogger(debug, logPath)

	exit := func(code int) {
		_ = logger.Sync()
		os.Exit(code)
	}

	// Netstack's logger.
	// glog.SetLevel(glog.Debug)

	// If the --check-token flag is set, we just check if the token is valid.
	if checkToken {
		a := agent.New(token, logger)
		if err := a.CheckToken(); err != nil {
			logger.Errorf("Token validation failed: %v", err)
			exit(1)
		}
		logger.Info("Token successfully validated")
		exit(0)
	}

	// If running as a Windows service, we need a path to the named pipe.
	if isWindowsService() {
		if controlAPI == "" {
			logger.Error("error: --control argument is required when running as a service")
			exit(1)
		}
		s, err := control.NewServer(controlAPI, group, logger)
		if err != nil {
			logger.Errorf("Could not start control API: %v", err)
			exit(1)
		}
		err = s.Run()
		if err != nil {
			logger.Errorf("Server failed: %v", err)
			exit(1)
		}
		exit(0)
	}

	// Run in the foreground.
	a := agent.New(token, logger)

	// Wait for the agent to connect to the agent hub.
	err := a.WaitForConnection(maxConnTries)
	if err != nil {
		logger.Errorf("Failed to connect to agent hub: %v", err)
		exit(1)
	}

	logger.Info("Agent successfully started")

	// Watch memory usage.
	go watchMemoryUsage(logger)

	// Wait for termination signals.
	waitForTermination()

	// Cleanups.
	logger.Info("Shutting down...")
	_ = logger.Sync()
}

func waitForTermination() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	<-c

	signal.Reset()
	close(c)
}

func watchMemoryUsage(log *zap.SugaredLogger) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()

	for range t.C {
		log.Info(system.GetMemStats())
	}
}
