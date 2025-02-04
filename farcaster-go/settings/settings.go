package settings

import "runtime"

const (
	Filename    = "farcasterd"
	Name        = "Probely Farcaster"
	ServiceName = Name + " Agent"
	Description = Name + " creates a VPN to Probely to allow internal network scanning."
)

func LogPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\ProgramData\\Probely\\Farcaster\\farcasterd.log"
	}

	return "/var/lib/probely/farcaster/farcasterd.log"
}

func ControlAPIPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\ProtectedPrefix\LocalService\Probely\Farcaster\\control`
	}

	return "/var/lib/probely/farcaster/control.sock"
}
