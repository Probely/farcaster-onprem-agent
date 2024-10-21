package system

import (
	"fmt"
	"os"

	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
)

func GetMemStats() string {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return "Could not get memory stats: " + err.Error()
	}

	memInfo, err := p.MemoryInfo()
	if err != nil {
		return "Could not get memory stats: " + err.Error()
	}

	v, _ := mem.VirtualMemory()
	return fmt.Sprintf("Mem Stats - Process: %v MB, Total: %v MB, Available: %v MB",
		memInfo.RSS/1024/1024, v.Total/1024/1024, v.Available/1024/1024)
}
