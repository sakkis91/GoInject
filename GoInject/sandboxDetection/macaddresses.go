package sandboxDetection

import(
	"net"
	"strings"
)

func MACaddresses() bool{
	bad_macs := []string{
		"00:0C:29", // VMWare
		"00:1C:14", // VMWare
		"00:50:56", // VMWare
		"00:05:69", // VMWare
		"08:00:27", // VirtualBox
		"00:0F:4F", // Oracle VirtualBox
		"02:42:ac", // Docker
		"00:1C:42", // Parallels
		"00:15:5d", // Hyper-V
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		for _, mac := range bad_macs {
			if strings.Contains(strings.ToLower(iface.HardwareAddr.String()), strings.ToLower(mac)) {
				return true
			}
		}
	}
	return false
}