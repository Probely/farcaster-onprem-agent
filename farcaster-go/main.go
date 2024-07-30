package main

import (
	"probely.com/farcaster/cmd/farcasterd"
)

func main() {
	// Start the agent.
	// Check runAgent in cmd/farcasterd/root.go for the startup logic.
	farcasterd.Execute()
}
