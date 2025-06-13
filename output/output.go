package main

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "os"
    "strconv"
    "time"
)

func printNormalOutput(results []HostResult) {
    for _, host := range results {
        fmt.Printf("Nmap scan report for %s\n", host.IP)
        for _, port := range host.Ports {
            fmt.Printf("%d/%s\t%s\t%s\n", port.Port, port.Protocol, port.State, port.Service)
        }
    }
}

func printGrepableOutput(results []HostResult) {
    for _, host := range results {
        for _, port := range host.Ports {
            fmt.Printf("%s:%d (%s) open %s | %s\n", host.IP, port.Port, port.Service, port.Banner, formatCVEs(port.CVEs))
        }
    }
}

func printJSONOutput(results []HostResult) {
    data, _ := json.MarshalIndent(results, "", "  ")
    fmt.Println(string(data))
}

func printXMLOutput(results []HostResult) {
    fmt.Println("<nmaprun>")
    for _, host := range results {
        fmt.Printf("  <host>\n    <address addr=\"%s\"/>\n", host.IP)
        for _, port := range host.Ports {
            fmt.Printf("    <ports><port protocol=\"tcp\" portid=\"%d\">\n      <service name=\"%s\" banner=\"%s\" />\n", port.Port, port.Service, port.Banner)
            for _, cve := range port.CVEs {
                fmt.Printf("      <script id=\"%s\" output=\"%s\" />\n", cve.ID, cve.Description)
            }
            fmt.Println("    </port></ports>")
        }
        fmt.Println("  </host>")
    }
    fmt.Println("</nmaprun>")
}

func printCustomOutput(results []HostResult) {
    for _, host := range results {
        fmt.Printf("Host: %s\n", host.IP)
        for _, port := range host.Ports {
            fmt.Printf("  Port: %d (%s)\n    Banner: %s\n", port.Port, port.Service, port.Banner)
            for _, cve := range port.CVEs {
                fmt.Printf("    Vulnerability: %s | Score: %s | %s\n", cve.ID, cve.Severity, cve.URL)
            }
        }
    }
}

func printCSVOutput(results []HostResult) {
    timestamp := time.Now().Format(time.RFC3339)
    writer := csv.NewWriter(os.Stdout)
    defer writer.Flush()

    headers := []string{"ip", "port", "service", "banner", "cve", "severity", "cvss_score", "timestamp"}
    _ = writer.Write(headers)

    for _, host := range results {
        for _, port := range host.Ports {
            for _, cve := range port.CVEs {
                record := []string{
                    host.IP,
                    strconv.Itoa(port.Port),
                    port.Service,
                    port.Banner,
                    cve.ID,
                    cve.Severity,
                    fmt.Sprintf("%.1f", cve.Score),
                    timestamp,
                }
                _ = writer.Write(record)
            }

            if len(port.CVEs) == 0 {
                record := []string{
                    host.IP,
                    strconv.Itoa(port.Port),
                    port.Service,
                    port.Banner,
                    "",
                    "",
                    "",
                    timestamp,
                }
                _ = writer.Write(record)
            }
        }
    }
}

func formatCVEs(cves []CVE) string {
    var s string
    for _, cve := range cves {
        s += cve.ID + ","
    }
    if len(s) > 0 {
        s = s[:len(s)-1]
    }
    return s
}