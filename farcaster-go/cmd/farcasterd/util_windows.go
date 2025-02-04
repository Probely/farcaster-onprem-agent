//go:build windows
// +build windows

package farcasterd

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// lockDownPermissions sets ACLs on Windows to restrict access to administrators
// and the service account.
func lockDownPermissions(path string) error {
	// SDDL string with inheritance flags:
	// D:P               => DACL is protected (do not inherit from parent)
	// (A;OICI;FA;;;SY) => Allow full access (FA) to SYSTEM (SY) with Object Inherit (OI) and Container Inherit (CI)
	// (A;OICI;FA;;;BA) => Allow full access to built-in Administrators (BA) likewise
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
