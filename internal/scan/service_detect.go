package main

import (
    "fmt"
    "strings"
)

func detectServiceVersion(portResult *PortResult) {
    // For demonstration, simple banner logic for HTTP/FTP/SSH
    banner := strings.ToLower(portResult.Banner)
    if strings.Contains(banner, "http") {
        // Example: HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)
        if idx := strings.Index(banner, "server: "); idx != -1 {
            end := strings.Index(banner[idx:], "\n")
            if end != -1 {
                portResult.Service += " " + strings.TrimSpace(banner[idx+8:idx+end])
            }
        }
    } else if strings.Contains(banner, "ssh") {
        // SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
        parts := strings.Fields(banner)
        if len(parts) > 0 {
            portResult.Service += " " + parts[0]
        }
    }
    // Add more protocol handlers as needed
}