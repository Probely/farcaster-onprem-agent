// Windows service wrapper.

//go:build windows
// +build windows

package winsvc

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	acceptedRequests = svc.AcceptStop | svc.AcceptShutdown
)

type Service struct {
	name string
	stop chan struct{}

	// Function to start the agent.
	agent func() error

	log *zap.SugaredLogger
}

type TokenElevation struct {
	TokenIsElevated uint32
}

func NewService(name string, agent func() error, logger *zap.SugaredLogger) *Service {
	return &Service{
		name:  name,
		agent: agent,
		log:   logger,
	}
}

func (s *Service) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running, Accepts: acceptedRequests}
	s.log.Info("Service started")

	errCh := make(chan error)
	go func() {
		errCh <- s.agent()
	}()

loop:
	for {
		select {
		case err := <-errCh:
			if err != nil {
				s.log.Errorf("Agent failed: %v", err)
				status <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			s.log.Info("Agent successfully started")
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				s.log.Warnf("Unexpected control request #%d", c)
			}
		}
	}

	status <- svc.Status{State: svc.StopPending}
	s.log.Info("Service stopped")

	return false, 0
}

func (s *Service) Run() error {
	return svc.Run(s.name, s)
}

// Install registers the service with Windows Service Manager
func Install(name, description string, svcArgs []string) error {
	if len(svcArgs) < 1 {
		return fmt.Errorf("executable path is required")
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", name)
	}

	config := mgr.Config{
		DisplayName: name,
		Description: description,
		StartType:   mgr.StartAutomatic,
	}

	s, err = m.CreateService(name, svcArgs[0], config, svcArgs[1:]...)
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	defer s.Close()

	return nil
}

// Remove deregisters the service from Windows Service Manager
func Remove(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", name)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	return nil
}

// Start starts the named service
func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not open service: %v", err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("could not start service: %v", err)
	}

	return nil
}

// Stop stops the named service
func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not open service: %v", err)
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("could not stop service: %v", err)
	}

	return nil
}

// IsAdmin checks if the current process has elevated privileges.
func IsAdmin() (bool, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, err
	}
	defer token.Close()

	var elevation TokenElevation
	var out uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)), &out)
	if err != nil {
		return false, err
	}
	return elevation.TokenIsElevated != 0, nil
}

// RunElevated relaunches the current executable with administrative privileges and returns its output
func RunElevated() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot get executable path: %v", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("cannot determine absolute path: %v", err)
	}

	// Helper function to escape Windows command line arguments
	escapeArg := func(arg string) string {
		// Escape ^ first since it's used as escape character
		arg = strings.ReplaceAll(arg, "^", "^^")
		// Escape other special characters
		arg = strings.ReplaceAll(arg, "&", "^&")
		arg = strings.ReplaceAll(arg, "<", "^<")
		arg = strings.ReplaceAll(arg, ">", "^>")
		arg = strings.ReplaceAll(arg, "|", "^|")
		arg = strings.ReplaceAll(arg, "%", "%%")
		// Wrap the entire argument in quotes and escape any existing quotes
		return `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
	}

	// Escape each argument individually
	escapedArgs := make([]string, len(os.Args[1:]))
	for i, arg := range os.Args[1:] {
		escapedArgs[i] = escapeArg(arg)
	}

	// Create a temporary batch file with a random name to avoid conflicts
	tmpDir := os.TempDir()
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("failed to generate random filename: %v", err)
	}
	batchFile := filepath.Join(tmpDir, fmt.Sprintf("farcaster_elevate_%x.bat", randBytes))

	// Construct the command with escaped arguments
	cmdLine := fmt.Sprintf(`@echo off
echo Running command with administrative privileges...
echo.
"%s" %s
echo.
if errorlevel 1 (
    echo Command failed. Press any key to exit...
    pause >nul
) else (
    echo Command completed successfully.
    echo This window will close automatically in 10 seconds...
    timeout /t 10 /nobreak >nul
)
del "%s"`, exePath, strings.Join(escapedArgs, " "), batchFile)

	// Write the batch file
	if err := os.WriteFile(batchFile, []byte(cmdLine), 0600); err != nil {
		return fmt.Errorf("failed to create batch file: %v", err)
	}

	// Launch the batch file with elevation
	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	batchPtr, err := windows.UTF16PtrFromString(batchFile)
	if err != nil {
		return err
	}

	// Launch the elevated process
	err = windows.ShellExecute(0, verbPtr, batchPtr, nil, nil, windows.SW_SHOW)
	if err != nil {
		os.Remove(batchFile)
		return fmt.Errorf("ShellExecute failed: %v", err)
	}

	return nil
}
