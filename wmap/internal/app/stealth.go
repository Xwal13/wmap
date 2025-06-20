package scan

import (
    "fmt"
    "net"
    "time"
    "math/rand"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func StealthScan(ip, portFilter string) *HostResult {
    host := HostResult{IP: ip}
    ports := ParsePortFilter(portFilter)
    if len(ports) == 0 {
        ports = GetDefaultPorts()
    }

    iface, err := net.InterfaceByName("eth0") // Adjust if not eth0
    if err != nil {
        fmt.Println("[-] Could not find interface for stealth scan:", err)
        return &host
    }

    handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
    if err != nil {
        fmt.Println("[-] Could not open interface for packet capture:", err)
        return &host
    }
    defer handle.Close()

    srcIP, _ := getLocalIP(iface)
    srcPort := uint16(rand.Intn(65535-1024) + 1024)

    for _, port := range ports {
        synPkt := craftSYNPacket(srcIP, ip, srcPort, uint16(port))
        if err := handle.WritePacketData(synPkt); err != nil {
            fmt.Println("[-] Error sending SYN packet:", err)
            continue
        }

        filter := fmt.Sprintf("tcp and src host %s and src port %d and dst port %d", ip, port, srcPort)
        handle.SetBPFFilter(filter)

        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        timeout := time.After(2 * time.Second)
        found := false
        for {
            select {
            case packet := <-packetSource.Packets():
                if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
                    tcp, _ := tcpLayer.(*layers.TCP)
                    if tcp.SYN && tcp.ACK {
                        host.Ports = append(host.Ports, PortResult{
                            Port:     port,
                            Protocol: "tcp",
                            State:    "open",
                            Service:  serviceNames[port],
                        })
                        found = true
                        break
                    } else if tcp.RST {
                        found = true
                        break
                    }
                }
            case <-timeout:
                break
            }
            if found {
                break
            }
        }
    }

    return &host
}

func getLocalIP(iface *net.Interface) (string, error) {
    addrs, err := iface.Addrs()
    if err != nil {
        return "", err
    }
    for _, addr := range addrs {
        if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
            return ipNet.IP.String(), nil
        }
    }
    return "", fmt.Errorf("no IPv4 address found for interface")
}

func craftSYNPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
    eth := &layers.Ethernet{}
    ip := &layers.IPv4{
        SrcIP:    net.ParseIP(srcIP),
        DstIP:    net.ParseIP(dstIP),
        Protocol: layers.IPProtocolTCP,
    }
    tcp := &layers.TCP{
        SrcPort: layers.TCPPort(srcPort),
        DstPort: layers.TCPPort(dstPort),
        SYN:     true,
        Seq:     rand.Uint32(),
        Window:  14600,
    }
    tcp.SetNetworkLayerForChecksum(ip)

    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
    gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
    return buf.Bytes()
}