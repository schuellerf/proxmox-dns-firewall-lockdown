package netdetect

import (
	"net"
	"os"
	"strings"
)

// PreferredServiceIPv4 returns LOCKDOWN_SERVICE_IP if set; otherwise picks a heuristic primary IPv4.
func PreferredServiceIPv4() string {
	if v := strings.TrimSpace(os.Getenv("LOCKDOWN_SERVICE_IP")); v != "" {
		return v
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ip := ipnet.IP.To4()
			if ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
