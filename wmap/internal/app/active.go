package scan

import (
    "fmt"
    "net"
    "sync"
    "time"
)

func ActiveScan(ip, portFilter string) *HostResult {
    host := HostResult{IP: ip}

    ports := ParsePortFilter(portFilter)
    if len(ports) == 0 {
        ports = GetDefaultPorts()
    }

    var wg sync.WaitGroup
    resultsChan := make(chan PortResult, len(ports))

    for _, port := range ports {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()

            conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 2*time.Second)
            if err != nil {
                return
            }
            defer conn.Close()

            banner := GrabBanner(conn)
            service := DetectService(banner, p)

            cves := DetectCVE(banner)
            portRes := PortResult{
                Port:     p,
                Protocol: "tcp",
                Service:  service,
                Banner:   banner,
                State:    "open",
                CVEs:     cves,
            }
            resultsChan <- portRes
        }(port)
    }

    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    for res := range resultsChan {
        host.Ports = append(host.Ports, res)
    }

    return &host
}