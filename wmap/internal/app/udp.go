package scan

import (
    "fmt"
    "net"
    "time"
)

func UdpScan(ip, portFilter string) *HostResult {
    host := HostResult{IP: ip}
    ports := ParsePortFilter(portFilter)
    if len(ports) == 0 {
        ports = []int{53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 33434}
    }

    for _, port := range ports {
        addr := fmt.Sprintf("%s:%d", ip, port)
        conn, err := net.DialTimeout("udp", addr, 2*time.Second)
        if err != nil {
            continue
        }
        defer conn.Close()

        conn.SetDeadline(time.Now().Add(2 * time.Second))
        _, err = conn.Write([]byte{0x00})
        if err != nil {
            continue
        }

        buf := make([]byte, 1024)
        n, err := conn.Read(buf)
        state := "open|filtered"
        banner := ""
        if err == nil && n > 0 {
            state = "open"
            banner = string(buf[:n])
        }
        host.Ports = append(host.Ports, PortResult{
            Port:     port,
            Protocol: "udp",
            Service:  serviceNames[port],
            Banner:   banner,
            State:    state,
        })
    }
    return &host
}