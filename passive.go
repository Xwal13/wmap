package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Structure for storing passive port results with more details
type PassivePortResult struct {
	Source    string
	Host      string
	Port      int
	Service   string
	Version   string
	// ExtraInfo string // REMOVED Extra column
}

func passiveScanAll(host string, saveReport bool, reportPath string) {
	fmt.Printf(ColorCyan+"[*] Passive intelligence for %s..."+ColorReset+"\n", host)

	ips := resolveHostToIPs(host)
	if len(ips) == 0 {
		fmt.Println(ColorRed + "[-] Could not resolve host to IPs." + ColorReset)
		return
	}

	var results []PassivePortResult

	// Shodan (per IP)
	for _, ip := range ips {
		entries := passiveScanShodanPorts(ip)
		results = append(results, entries...)
	}

	// Censys
	if censysAPIID != "" && censysAPISecret != "" {
		for _, ip := range ips {
			entries := passiveScanCensysPorts(ip)
			results = append(results, entries...)
		}
	} else {
		fmt.Println(ColorYellow + "[!] Skipping Censys: API ID/Secret not set." + ColorReset)
	}

	// BinaryEdge
	if binaryedgeAPIKey != "" {
		for _, ip := range ips {
			entries := passiveScanBinaryEdgePorts(ip)
			results = append(results, entries...)
		}
	} else {
		fmt.Println(ColorYellow + "[!] Skipping BinaryEdge: API key not set." + ColorReset)
	}

	// ZoomEye
	if zoomeyeAPIKey != "" {
		for _, ip := range ips {
			entries := passiveScanZoomEyePorts(ip)
			results = append(results, entries...)
		}
	} else {
		fmt.Println(ColorYellow + "[!] Skipping ZoomEye: API key not set." + ColorReset)
	}

	// HackerTarget open ports (domain-based, only run once)
	entries := passiveScanDNSPorts(host)
	results = append(results, entries...)

	printPassiveResultsTable(results)

	if saveReport {
		report := generateNmapStyleReportDetailed(host, results)
		if err := saveReportToFile(reportPath, report); err != nil {
			fmt.Println(ColorRed+"[!] Failed to save report:"+ColorReset, err)
		} else {
			fmt.Println(ColorGreen + "[*] Report saved to: " + reportPath + ColorReset)
		}
	}
}

func resolveHostToIPs(host string) []string {
	ips := []string{}
	ipRecords, err := net.LookupIP(host)
	if err != nil {
		return ips
	}
	for _, ip := range ipRecords {
		if ipv4 := ip.To4(); ipv4 != nil {
			ips = append(ips, ipv4.String())
		}
	}
	return ips
}

func passiveScanShodanPorts(ip string) []PassivePortResult {
	var results []PassivePortResult
	if shodanAPIKey != "" {
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, shodanAPIKey)
		resp, err := http.Get(url)
		if err != nil {
			return results
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return results
		}
		var shodanResp struct {
			Data []struct {
				Port    int    `json:"port"`
				Product string `json:"product"`
				Version string `json:"version"`
				Info    string `json:"info"`
			} `json:"data"`
		}
		err = json.Unmarshal(body, &shodanResp)
		if err == nil && len(shodanResp.Data) > 0 {
			for _, entry := range shodanResp.Data {
				results = append(results, PassivePortResult{
					Source:    "Shodan",
					Host:      ip,
					Port:      entry.Port,
					Service:   entry.Product,
					Version:   entry.Version,
					// ExtraInfo: entry.Info, // REMOVED
				})
			}
		} else {
			// fallback to just port list if no info
			var portsResp struct {
				Ports []int `json:"ports"`
			}
			if err := json.Unmarshal(body, &portsResp); err == nil && len(portsResp.Ports) > 0 {
				for _, port := range portsResp.Ports {
					results = append(results, PassivePortResult{
						Source:  "Shodan",
						Host:    ip,
						Port:    port,
						Service: "",
						Version: "",
						// ExtraInfo: "", // REMOVED
					})
				}
			}
		}
	} else {
		url := fmt.Sprintf("https://www.shodan.io/host/%s", ip)
		resp, err := http.Get(url)
		if err != nil {
			return results
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		ports := extractPortsFromShodanHTML(string(body))
		for _, p := range ports {
			if n, err := strconv.Atoi(p); err == nil {
				results = append(results, PassivePortResult{
					Source:  "Shodan",
					Host:    ip,
					Port:    n,
					Service: "",
					Version: "",
					// ExtraInfo: "", // REMOVED
				})
			}
		}
	}
	return results
}

func extractPortsFromShodanHTML(html string) []string {
	portsMap := make(map[string]struct{})
	re := regexp.MustCompile(`/port/(\d{1,5})`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) == 2 {
			portsMap[match[1]] = struct{}{}
		}
	}
	var ports []string
	for p := range portsMap {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	return ports
}

func passiveScanDNSPorts(host string) []PassivePortResult {
	url := fmt.Sprintf("https://api.hackertarget.com/nmap/?q=%s", host)
	resp, err := http.Get(url)
	var results []PassivePortResult
	if err != nil {
		return results
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				p := fields[0]
				service := ""
				version := ""
				if len(fields) > 2 {
					service = fields[2]
				}
				if len(fields) > 3 {
					version = strings.Join(fields[3:], " ")
				}
				if n, err := strconv.Atoi(strings.Split(p, "/")[0]); err == nil {
					results = append(results, PassivePortResult{
						Source:  "HackerTarget",
						Host:    host,
						Port:    n,
						Service: service,
						Version: version,
						// ExtraInfo: "", // REMOVED
					})
				}
			}
		}
	}
	if len(results) == 0 {
		results = append(results, PassivePortResult{
			Source:  "HackerTarget",
			Host:    host,
			Port:    0,
			Service: "",
			Version: "",
			// ExtraInfo: "", // REMOVED
		})
	}
	return results
}

func passiveScanCensysPorts(ip string) []PassivePortResult {
	client := &http.Client{}
	req, err := http.NewRequest("GET", censysAPIURL+ip, nil)
	var results []PassivePortResult
	if err != nil {
		return results
	}
	req.SetBasicAuth(censysAPIID, censysAPISecret)
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var censysResp struct {
		Result struct {
			Services []struct {
				Port    int    `json:"port"`
				Service string `json:"service_name"`
			} `json:"services"`
		} `json:"result"`
	}
	err = json.Unmarshal(body, &censysResp)
	if err == nil && len(censysResp.Result.Services) > 0 {
		for _, svc := range censysResp.Result.Services {
			results = append(results, PassivePortResult{
				Source:  "Censys",
				Host:    ip,
				Port:    svc.Port,
				Service: svc.Service,
				// Version: "",
				// ExtraInfo: "", // REMOVED
			})
		}
	}
	return results
}

func passiveScanBinaryEdgePorts(ip string) []PassivePortResult {
	url := binaryedgeAPIURL + ip
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Key", binaryedgeAPIKey)
	client := &http.Client{}
	resp, err := client.Do(req)
	var results []PassivePortResult
	if err != nil {
		return results
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var beResp struct {
		Events []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
		} `json:"events"`
	}
	err = json.Unmarshal(body, &beResp)
	if err == nil && len(beResp.Events) > 0 {
		for _, e := range beResp.Events {
			results = append(results, PassivePortResult{
				Source:  "BinaryEdge",
				Host:    ip,
				Port:    e.Port,
				Service: e.Service,
				// Version: "",
				// ExtraInfo: "", // REMOVED
			})
		}
	}
	return results
}

func passiveScanZoomEyePorts(ip string) []PassivePortResult {
	client := &http.Client{}
	search := fmt.Sprintf(`{"query":"host:\"%s\""}`, ip)
	req, err := http.NewRequest("POST", zoomeyeAPIURL, strings.NewReader(search))
	var results []PassivePortResult
	if err != nil {
		return results
	}
	req.Header.Set("API-KEY", zoomeyeAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var zeResp struct {
		Matches []struct {
			Port    int    `json:"port"`
			App     string `json:"app"`
			Service string `json:"service"`
		} `json:"matches"`
	}
	err = json.Unmarshal(body, &zeResp)
	if err == nil && len(zeResp.Matches) > 0 {
		for _, m := range zeResp.Matches {
			results = append(results, PassivePortResult{
				Source:  "ZoomEye",
				Host:    ip,
				Port:    m.Port,
				Service: m.Service,
				Version: m.App,
				// ExtraInfo: "", // REMOVED
			})
		}
	}
	return results
}

// Table output for passive results, REMOVED Extra column
func printPassiveResultsTable(results []PassivePortResult) {
	// Find max widths
	maxSource := len("Source")
	maxHost := len("Host")
	maxPort := len("Port")
	maxService := len("Service")
	maxVersion := len("Version")
	for _, r := range results {
		if len(r.Source) > maxSource {
			maxSource = len(r.Source)
		}
		if len(r.Host) > maxHost {
			maxHost = len(r.Host)
		}
		portStr := "-"
		if r.Port > 0 {
			portStr = fmt.Sprintf("%d", r.Port)
		}
		if len(portStr) > maxPort {
			maxPort = len(portStr)
		}
		if len(r.Service) > maxService {
			maxService = len(r.Service)
		}
		if len(r.Version) > maxVersion {
			maxVersion = len(r.Version)
		}
	}
	if maxSource < 9 {
		maxSource = 9
	}
	if maxHost < 15 {
		maxHost = 15
	}
	if maxPort < 4 {
		maxPort = 4
	}
	if maxService < 7 {
		maxService = 7
	}
	if maxVersion < 7 {
		maxVersion = 7
	}

	// Table top
	fmt.Print(ColorCyan + "╭")
	fmt.Print(strings.Repeat("═", maxSource+2) + "╦" +
		strings.Repeat("═", maxHost+2) + "╦" +
		strings.Repeat("═", maxPort+2) + "╦" +
		strings.Repeat("═", maxService+2) + "╦" +
		strings.Repeat("═", maxVersion+2) +
		"╮" + ColorReset + "\n")
	fmt.Printf(ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+
		ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+
		ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+
		ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+
		ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+
		ColorCyan+"║"+ColorReset+"\n",
		maxSource, "Source",
		maxHost, "Host",
		maxPort, "Port",
		maxService, "Service",
		maxVersion, "Version")
	fmt.Print(ColorCyan + "╠")
	fmt.Print(strings.Repeat("═", maxSource+2) + "╬" +
		strings.Repeat("═", maxHost+2) + "╬" +
		strings.Repeat("═", maxPort+2) + "╬" +
		strings.Repeat("═", maxService+2) + "╬" +
		strings.Repeat("═", maxVersion+2) +
		"╣" + ColorReset + "\n")

	// Table rows
	for _, r := range results {
		portStr := "-"
		if r.Port > 0 {
			portStr = fmt.Sprintf("%d", r.Port)
		}
		fmt.Printf(ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+"\n",
			maxSource, r.Source,
			maxHost, r.Host,
			maxPort, portStr,
			maxService, r.Service,
			maxVersion, r.Version)
	}
	// Table bottom
	fmt.Print(ColorCyan + "╰")
	fmt.Print(strings.Repeat("═", maxSource+2) + "╩" +
		strings.Repeat("═", maxHost+2) + "╩" +
		strings.Repeat("═", maxPort+2) + "╩" +
		strings.Repeat("═", maxService+2) + "╩" +
		strings.Repeat("═", maxVersion+2) +
		"╯" + ColorReset + "\n")
}

// ----------- Nmap-style report saving with details -----------

func generateNmapStyleReportDetailed(target string, results []PassivePortResult) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	report := []string{
		fmt.Sprintf("# Nmap-style Passive Scan Report"),
		fmt.Sprintf(""),
		fmt.Sprintf("Host: %s", target),
		fmt.Sprintf("Scan type: Passive (Shodan, Censys, BinaryEdge, ZoomEye, HackerTarget)"),
		fmt.Sprintf("Scan time: %s", now),
		fmt.Sprintf(""),
	}
	// Group by Host
	hostPorts := make(map[string][]PassivePortResult)
	for _, r := range results {
		hostPorts[r.Host] = append(hostPorts[r.Host], r)
	}
	for host, entries := range hostPorts {
		report = append(report, fmt.Sprintf("---------------------------------------------------------------"))
		report = append(report, fmt.Sprintf("Host: %-20s", host))
		// Print table header
		report = append(report, "PORT     SOURCE      SERVICE   VERSION    STATE")
		foundAny := false
		for _, entry := range entries {
			if entry.Port == 0 {
				continue
			}
			report = append(report, fmt.Sprintf("%-8d%-12s%-10s%-10sopen", entry.Port, entry.Source, entry.Service, entry.Version))
			foundAny = true
		}
		if !foundAny {
			report = append(report, "No open ports found by passive sources.")
		}
		report = append(report, "")
	}
	report = append(report, "Report generated by wmap3")
	return strings.Join(report, "\n")
}