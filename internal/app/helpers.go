package main

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"
    "time"
)

// Remove all previous vulnerability scanning logic (detectCVE, vulnDB, etc.)
// Add Nmap Service Probes/Script DB-based vulnerability mapping

func canUseShodan() bool {
    return shodanAPIKey != "" || usePublicDB
}

func matchPort(filter string, port int) bool {
    if filter == "all" || filter == "" {
        return true
    }

    ranges := strings.Split(filter, ",")
    for _, r := range ranges {
        if strings.Contains(r, "-") {
            parts := strings.Split(r, "-")
            start, _ := strconv.Atoi(parts[0])
            end, _ := strconv.Atoi(parts[1])
            if port >= start && port <= end {
                return true
            }
        } else {
            p, _ := strconv.Atoi(r)
            if p == port {
                return true
            }
        }
    }
    return false
}

func parsePortFilter(filter string) []int {
    if filter == "" {
        return nil
    }

    var ports []int
    ranges := strings.Split(filter, ",")
    for _, r := range ranges {
        if strings.Contains(r, "-") {
            startEnd := strings.Split(r, "-")
            start, _ := strconv.Atoi(startEnd[0])
            end, _ := strconv.Atoi(startEnd[1])
            for i := start; i <= end; i++ {
                ports = append(ports, i)
            }
        } else {
            p, _ := strconv.Atoi(r)
            ports = append(ports, p)
        }
    }
    return ports
}

func getDefaultPorts() []int {
    return []int{21, 22, 80, 443, 8080}
}

func grabBanner(conn net.Conn) string {
    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    return string(buf[:n])
}

func detectService(banner string, port int) string {
    if s, ok := serviceNames[port]; ok {
        return s
    }
    return "Unknown"
}

// New vulnerability detection using Nmap scripts (nmap-service-probes and nmap-vulners.nse style)
// This is a minimal, built-in mapping for key banners/services to known vulnerabilities
// For real-world use, integrate nmap-vulners.nse or parse the Nmap script DB

// Vulnerability DB (truncated, demo style)
var nmapVulnDB = map[string][]CVE{
    // Example: Apache httpd 2.4.18
    "apache/2.4.18": {
        {
            ID:          "CVE-2019-0211",
            Description: "Apache HTTPD privilege escalation",
            URL:         "https://nvd.nist.gov/vuln/detail/CVE-2019-0211",
            Severity:    "high",
            Score:       8.8,
        },
    },
    // Example: Microsoft IIS 6.0
    "microsoft-iis/6.0": {
        {
            ID:          "CVE-2017-7269",
            Description: "IIS 6.0 WebDAV RCE",
            URL:         "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
            Severity:    "critical",
            Score:       9.8,
        },
    },
    // Example: vsftpd 2.3.4
    "vsftpd/2.3.4": {
        {
            ID:          "CVE-2011-2523",
            Description: "vsftpd backdoor",
            URL:         "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
            Severity:    "critical",
            Score:       10.0,
        },
    },
    // Add more mappings as needed (from nmap-vulners)
}

// Match banner against nmapVulnDB keys (case-insensitive, contain version)
func nmapVulnScan(banner string) []CVE {
    bannerLower := strings.ToLower(banner)
    var vulns []CVE
    for sig, cves := range nmapVulnDB {
        if strings.Contains(bannerLower, sig) {
            vulns = append(vulns, cves...)
        }
    }
    return vulns
}

func readLinesFromFile(path string) []string {
    file, _ := os.Open(path)
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var lines []string
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    return lines
}