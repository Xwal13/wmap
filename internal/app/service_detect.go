package scan

import (
    "strings"
)

func DetectServiceVersion(portResult *PortResult) {
    banner := strings.ToLower(portResult.Banner)
    if strings.Contains(banner, "http") {
        if idx := strings.Index(banner, "server: "); idx != -1 {
            end := strings.Index(banner[idx:], "\n")
            if end != -1 {
                portResult.Service += " " + strings.TrimSpace(banner[idx+8:idx+end])
            }
        }
    } else if strings.Contains(banner, "ssh") {
        parts := strings.Fields(banner)
        if len(parts) > 0 {
            portResult.Service += " " + parts[0]
        }
    }
    // Add more protocol handlers as needed
}