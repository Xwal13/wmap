package main

import (
    "fmt"
)

func printMarkdownOutput(results []HostResult) {
    fmt.Println("# Scan Report")
    for _, host := range results {
        fmt.Printf("## Host: %s\n", host.IP)
        for _, port := range host.Ports {
            fmt.Printf("- **Port %d/%s**: %s\n", port.Port, port.Protocol, port.Service)
            if port.Banner != "" {
                fmt.Printf("  - Banner: `%s`\n", port.Banner)
            }
            if len(port.CVEs) > 0 {
                for _, cve := range port.CVEs {
                    fmt.Printf("  - CVE: [%s](%s) %s\n", cve.ID, cve.URL, cve.Description)
                }
            }
        }
    }
}