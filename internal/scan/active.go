package main

import (
    "fmt"
    "net"
    "sync"
    "time"
)

func activeScan(ip, portFilter string) *HostResult {
    host := HostResult{IP: ip}

    ports := parsePortFilter(portFilter)
    if len(ports) == 0 {
        ports = getDefaultPorts()
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

            banner := grabBanner(conn)
            service := detectService(banner, p)

            cves := detectCVE(banner)
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
