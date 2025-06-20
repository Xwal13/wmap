package scan

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/hueristiq/goshodan"
)

var (
    shodanAPIKey string
    usePublicDB  bool
)

func ShodanScan(ip, portFilter string) *HostResult {
    client := goshodan.NewClient(shodanAPIKey)

    results, err := client.Host(ip)
    if err != nil {
        if !usePublicDB {
            fmt.Printf("[-] Shodan error: %v\n", err)
            return nil
        }
        return ShodanPublicScan(ip, portFilter)
    }

    host := HostResult{IP: ip}

    for _, data := range results.Data {
        port := data.Port
        if portFilter != "" && !MatchPort(portFilter, port) {
            continue
        }

        service := serviceNames[port]
        if service == "" {
            service = data.Service
        }

        cves := DetectCVE(data.Data)
        host.Ports = append(host.Ports, PortResult{
            Port:     port,
            Protocol: data.Transport,
            Service:  service,
            Banner:   data.Data,
            State:    "open",
            CVEs:     cves,
        })

        for _, cve := range cves {
            host.Vulns = append(host.Vulns, CVEDetail{
                ID:         cve.ID,
                Description: cve.Description,
                Score:      cve.Score,
                Severity:   cve.Severity,
                URL:        cve.URL,
            })
        }
    }

    return &host
}

func ShodanPublicScan(ip, portFilter string) *HostResult {
    url := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)
    resp, err := http.Get(url)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    type Response struct {
        IP         string   `json:"ip_str"`
        Ports      []int    `json:"ports"`
        Hostnames  []string `json:"hostnames"`
        Data       []struct {
            Port    int    `json:"port"`
            Banner  string `json:"data"`
            Product string `json:"product"`
        } `json:"data"`

        Tags []string `json:"tags"`
    }

    var r Response
    json.Unmarshal(body, &r)

    host := HostResult{IP: ip}

    for _, d := range r.Data {
        port := d.Port
        if portFilter != "" && !MatchPort(portFilter, port) {
            continue
        }

        service := serviceNames[port]
        if service == "" {
            service = d.Product
        }

        cves := DetectCVE(d.Banner)
        host.Ports = append(host.Ports, PortResult{
            Port:     port,
            Protocol: "tcp",
            Service:  service,
            Banner:   d.Banner,
            State:    "open",
            CVEs:     cves,
        })

        for _, cve := range cves {
            host.Vulns = append(host.Vulns, CVEDetail{
                ID:         cve.ID,
                Description: cve.Description,
                Score:      cve.Score,
                Severity:   cve.Severity,
                URL:        cve.URL,
            })
        }
    }

    return &host
}