package settings

import "runtime"

const (
	Name = "farcasterd"
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
