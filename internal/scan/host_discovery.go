package main

import (
    "net"
    "os/exec"
    "strings"
)

func discoverHosts(subnet string) []string {
    // Example using system ping (ICMP); adjust for OS as needed
    ips := []string{}
    for i := 1; i < 254; i++ {
        ip := strings.Replace(subnet, ".0/24", fmt.Sprintf(".%d", i), 1)
        out, err := exec.Command("ping", "-c", "1", "-W", "1", ip).Output()
        if err == nil && strings.Contains(string(out), "ttl=") {
            ips = append(ips, ip)
        }
    }
    return ips
}