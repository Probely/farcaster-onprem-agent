package wireguard

import (
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

type WireguardStats struct {
	// The number of seconds since the last handshake.
	LastHandshakeTimeSec int64
	// The number of bytes transmitted.
	TxBytes uint64
	// The number of bytes received.
	RxBytes uint64
}

// DeviceStats returns the statistics of the Wireguard device.
// Note it assumes that only one peer is configured.
func DeviceStats(dev *device.Device) (*WireguardStats, error) {
	data, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	stats := &WireguardStats{}
	// Split the string into lines.
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		// Split each line into key and value.
		kv := strings.Split(line, "=")
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "tx_bytes":
			value, err := strconv.ParseUint(kv[1], 10, 64)
			if err != nil {
				return nil, err
			}
			stats.TxBytes = value
		case "rx_bytes":
			value, err := strconv.ParseUint(kv[1], 10, 64)
			if err != nil {
				return nil, err
			}
			stats.RxBytes = value
		case "last_handshake_time_sec":
			value, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return nil, err
			}
			stats.LastHandshakeTimeSec = value
		}
	}
	return stats, nil
}
