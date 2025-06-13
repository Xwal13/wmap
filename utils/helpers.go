package main

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "regexp"
    "strconv"
    "strings"
    "time"
)

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

func detectCVE(banner string) []CVE {
    matchCVE := regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
    cves := matchCVE.FindAllString(banner, -1)

    var vulns []CVE
    for _, cveID := range cves {
        vulns = append(vulns, CVE{
            ID: cveID,
        })
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