package main

import (
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

func discoverHosts(cidr string) {
	fmt.Printf(ColorCyan+"[*] Starting host discovery on %s ..."+ColorReset+"\n", cidr)
	ips, err := hostsInCIDR(cidr)
	if err != nil {
		fmt.Println(ColorRed+"[-] Invalid CIDR:", cidr, ColorReset)
		return
	}
	var wg sync.WaitGroup
	var mutex sync.Mutex
	live := []string{}
	sem := make(chan struct{}, 100)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			if pingHost(ip, 500*time.Millisecond) {
				mutex.Lock()
				live = append(live, ip)
				fmt.Println(ColorGreen+"[+] Host up: "+ip+ColorReset)
				mutex.Unlock()
			}
			<-sem
		}(ip)
	}
	wg.Wait()
	fmt.Printf("\n%s[+] Discovery complete. %d hosts up in %s%s\n", ColorCyan, len(live), cidr, ColorReset)
	for _, ip := range live {
		fmt.Println(ip)
	}
}

func hostsInCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 is supported")
	}
	mask := ipnet.Mask
	network := ip.Mask(mask)
	start := binaryToUint32(network)
	ones, bits := mask.Size()
	numHosts := uint32(math.Pow(2, float64(bits-ones)))
	for i := uint32(1); i < numHosts-1; i++ {
		addr := uint32(start + i)
		ipAddr := uint32ToIP(addr)
		ips = append(ips, ipAddr.String())
	}
	return ips, nil
}
func binaryToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
func pingHost(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", ip+":80", timeout)
	if err == nil {
		conn.Close()
		return true
	}
	conn, err = net.DialTimeout("tcp", ip+":443", timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}