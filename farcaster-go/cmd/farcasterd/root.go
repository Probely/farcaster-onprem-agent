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
	maxConnTries = 3

	// Environment variable name for the API (old name) and AGENT tokens.
	envOldTokenName = "FARCASTER_API_TOKEN"
	envTokenName    = "FARCASTER_AGENT_TOKEN"
	envAPIURLName   = "FARCASTER_API_URL"
)

type agentConfig struct {
	token      string
	apiURLs    []string
	checkToken bool
	controlAPI string
	group      string
	showVers   bool
	logPath    string
	debug      bool
	apiURL     string
}

var (
	appCfg agentConfig

	defaultAPIURLs = []string{
		"https://api.eu.probely.com",
		"https://api.us.probely.com",
	}
)

func parseConfig(cfg *agentConfig) error {
	token := getToken(cfg.token)
	// If the control API is enabled, we don't need a token.
	if cfg.controlAPI == "" && token == "" {
		return fmt.Errorf("error: --token argument or %s environment variable is required", envTokenName)
	}
	cfg.token = strings.TrimSpace(token)
	cfg.apiURLs = append(cfg.apiURLs, getAPIURLs(cfg.apiURL)...)
	return nil
}

var rootCmd = &cobra.Command{
	Use:   filepath.Base(os.Args[0]),
	Short: settings.Name + " creates a VPN to Probely",
	Run: func(cmd *cobra.Command, args []string) {
		if appCfg.showVers {
			fmt.Fprintf(os.Stderr, "%s version %s on %s %s\n",
				settings.Name, settings.Version, runtime.GOOS, runtime.GOARCH)
			os.Exit(0)
		}
		if err := parseConfig(&appCfg); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		runAgent(appCfg)
	},
}

func init() {
	var apiListener string
	if runtime.GOOS == "windows" {
		apiListener = "Windows named pipe"
	} else {
		apiListener = "Unix socket"
	}
	rootCmd.PersistentFlags().StringVarP(&appCfg.token, "token", "t", "", "Authentication token. Can either be the path to the token file, or the token itself")
	rootCmd.PersistentFlags().StringVarP(&appCfg.apiURL, "api-url", "", "", "Override the default API URL")
	rootCmd.PersistentFlags().BoolVarP(&appCfg.checkToken, "check-token", "", false, "Check if the token is valid and exit")
	rootCmd.PersistentFlags().StringVarP(&appCfg.controlAPI, "control", "", "", "Enable the control API on the "+apiListener)
	rootCmd.PersistentFlags().StringVarP(&appCfg.group, "group", "", "", "Group to grant access to the control API")
	rootCmd.PersistentFlags().BoolVarP(&appCfg.showVers, "version", "v", false, "Print the version and exit")
	rootCmd.PersistentFlags().StringVarP(&appCfg.logPath, "log", "l", "", "Log file path. Log to stderr if not specified")
	rootCmd.PersistentFlags().BoolVarP(&appCfg.debug, "debug", "d", false, "Enable debug logging")
}

// Execute runs the agent.
func Execute() {
	// Send all output to stderr.
	rootCmd.SetOut(os.Stderr)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// Main agent function.
func runAgent(cfg agentConfig) {
	logger, e := initLogger(cfg.debug, cfg.logPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, "Error:", e)
		os.Exit(1)
	}

	exit := func(code int) {
		_ = logger.Sync()
		os.Exit(code)
	}

	// Netstack's logger.
	// glog.SetLevel(glog.Debug)

	// If the --check-token flag is set, we just check if the token is valid.
	if cfg.checkToken {
		a := agent.New(cfg.token, cfg.apiURLs, logger)
		if err := a.CheckToken(); err != nil {
			logger.Errorf("Token validation failed: %v", err)
			exit(1)
		}
		logger.Info("Token successfully validated")
		exit(0)
	}

	// The agent can run as a service. Clients use the "Control API" to manage it.
	if cfg.controlAPI != "" {
		s, err := control.NewServer(cfg.controlAPI, cfg.group, logger)
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

	// Function to start the agent.
	startAgent := func() error {
		a := agent.New(cfg.token, cfg.apiURLs, logger)
		if err := a.ConnectWait(maxConnTries); err != nil {
			return err
		}
		return nil
	}

	// Start the agent as a Windows service.
	if isWindowsService() {
		if err := runWindowsService(settings.Name, startAgent, logger); err != nil {
			logger.Errorf("Agent failed: %v", err)
			exit(1)
		}
		exit(0)
	}

	// Start the agent as a foreground process.
	if err := startAgent(); err != nil {
		logger.Errorf("Agent failed: %v", err)
		exit(1)
	}
	logger.Info("Agent successfully started")

	go watchMemoryUsage(logger)
	waitForTermination()

	logger.Info("Shutting down...")
	exit(0)
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

func getToken(token string) string {
	if token != "" {
		return token
	}
	envToken := os.Getenv(envTokenName)
	if envToken != "" {
		return envToken
	}
	return os.Getenv(envOldTokenName)
}

func getAPIURLs(apiURL string) []string {
	if apiURL != "" {
		return []string{apiURL}
	}
	envURL := os.Getenv(envAPIURLName)
	if envURL != "" {
		return []string{envURL}
	}
	return defaultAPIURLs
}
