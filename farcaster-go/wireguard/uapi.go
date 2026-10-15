package wireguard

import (
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

// Stats holds peer traffic counters and the last handshake time of a WireGuard
// device.
type Stats struct {
	// The Unix time of the last handshake in seconds, or zero before the first.
	LastHandshakeTimeSec int64
	TxBytes              uint64
	RxBytes              uint64
}

// DeviceStats returns the statistics of the WireGuard device.
// It assumes that only one peer is configured.
func DeviceStats(dev *device.Device) (*Stats, error) {
	data, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	stats := &Stats{}
	for line := range strings.SplitSeq(data, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "tx_bytes":
			value, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, err
			}
			stats.TxBytes = value
		case "rx_bytes":
			value, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, err
			}
			stats.RxBytes = value
		case "last_handshake_time_sec":
			value, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, err
			}
			stats.LastHandshakeTimeSec = value
		}
	}
	return stats, nil
}
