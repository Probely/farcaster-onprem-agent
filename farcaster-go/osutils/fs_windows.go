//go:build windows
// +build windows

package osutils

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// LockDownPermissions sets ACLs on Windows to restrict access to administrators
// and the service account.  This prevents unauthorized modification and reading of
// the target path by regular users.
func LockDownPermissions(path string) error {
	// SDDL string with inheritance flags:
	// D:P               => DACL is protected (do not inherit from parent)
	// (A;OICI;FA;;;SY) => Allow full access (FA) to SYSTEM (SY) with Object Inherit (OI) and Container Inherit (CI)
	// (A;OICI;FA;;;BA) => Allow full access to built-in Administrators (BA) likewise
	// This ensures only the system and administrators can access the files.
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("failed to convert SDDL to security descriptor: %v", err)
	}

	dacl, defaulted, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("failed to get DACL from security descriptor: %v", err)
	}
	if defaulted {
		return fmt.Errorf("got defaulted DACL from security descriptor")
	}
	if dacl == nil {
		return fmt.Errorf("got nil DACL from security descriptor")
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("SetNamedSecurityInfo failed: %v", err)
	}

	return nil
}

func RunElevated() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot get executable path: %v", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("cannot determine absolute path: %v", err)
	}

	// Escape special characters in the arguments to prevent command injection.
	escapeArg := func(arg string) string {
		arg = strings.ReplaceAll(arg, "^", "^^")
		arg = strings.ReplaceAll(arg, "&", "^&")
		arg = strings.ReplaceAll(arg, "<", "^<")
		arg = strings.ReplaceAll(arg, ">", "^>")
		arg = strings.ReplaceAll(arg, "|", "^|")
		arg = strings.ReplaceAll(arg, "%", "%%")
		return `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
	}
	escapedArgs := make([]string, len(os.Args[1:]))
	for i, arg := range os.Args[1:] {
		escapedArgs[i] = escapeArg(arg)
	}

	// Create temporary batch file.
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

	// Ensure the batch file is deleted, even if ShellExecute fails.
	defer os.Remove(batchFile)

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
		return fmt.Errorf("ShellExecute failed: %v", err)
	}

	return nil
}
