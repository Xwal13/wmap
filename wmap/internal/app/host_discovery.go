package scan

import (
    "fmt"
    "os/exec"
    "strings"
)

func DiscoverHosts(subnet string) []string {
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