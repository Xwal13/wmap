package main

import (
    "encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func updateDatabases() {
	fmt.Println(ColorCyan + "[*] Checking for Nmap service probes update..." + ColorReset)
	if err := downloadFile(nmapDBUrl, nmapDBFile); err != nil {
		fmt.Println(ColorRed + "[-] Failed to update Nmap service probes:" + ColorReset, err)
	} else {
		fmt.Println(ColorGreen + "[+] Nmap service probes database updated." + ColorReset)
	}
	fmt.Println(ColorCyan + "[*] Checking for Nmap Vulners update..." + ColorReset)
	if err := downloadFile(nmapVulnURL, nmapVulnFile); err != nil {
		fmt.Println(ColorRed + "[-] Failed to update Nmap Vulners:" + ColorReset, err)
	} else {
		fmt.Println(ColorGreen + "[+] Nmap Vulners database updated." + ColorReset)
	}
	fmt.Println(ColorCyan + "[*] Checking for Exploit-DB update..." + ColorReset)
	if err := downloadFile(exploitDBURL, exploitDBFile); err != nil {
		fmt.Println(ColorRed + "[-] Failed to update Exploit-DB:" + ColorReset, err)
	} else {
		fmt.Println(ColorGreen + "[+] Exploit-DB updated." + ColorReset)
	}
}

func loadNmapFingerprints() map[int]ServiceFingerprints {
	fp := make(map[int]ServiceFingerprints)
	common := map[int]ServiceFingerprints{
		21:   {"ftp", "unknown", ""},
		22:   {"ssh", "unknown", ""},
		23:   {"telnet", "unknown", ""},
		25:   {"smtp", "unknown", ""},
		53:   {"dns", "unknown", ""},
		80:   {"http", "unknown", ""},
		110:  {"pop3", "unknown", ""},
		135:  {"msrpc", "unknown", ""},
		139:  {"netbios-ssn", "unknown", ""},
		143:  {"imap", "unknown", ""},
		443:  {"https", "unknown", ""},
		445:  {"microsoft-ds", "unknown", ""},
		993:  {"imaps", "unknown", ""},
		995:  {"pop3s", "unknown", ""},
		3306: {"mysql", "unknown", ""},
		3389: {"ms-wbt-server", "unknown", ""},
		5900: {"vnc", "unknown", ""},
		8080: {"http-proxy", "unknown", ""},
		8443: {"https-alt", "unknown", ""},
		5432: {"postgresql", "unknown", ""},
		6379: {"redis", "unknown", ""},
	}
	for k, v := range common {
		fp[k] = v
	}
	return fp
}

func loadNmapVulnerabilities() map[string][]string {
	vulns := make(map[string][]string)
	file, err := os.Open(nmapVulnFile)
	if err != nil {
		fmt.Println(ColorRed + "[-] Could not load Nmap vulnerabilities:" + ColorReset, err)
		return vulns
	}
	defer file.Close()
	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 3 {
			continue
		}
		port := record[1]
		vuln := record[2]
		vulns[port] = append(vulns[port], vuln)
	}
	return vulns
}

func loadExploitDB() map[string][]ExploitEntry {
	exploits := make(map[string][]ExploitEntry)
	file, err := os.Open(exploitDBFile)
	if err != nil {
		fmt.Println(ColorRed + "[-] Could not load Exploit-DB database:" + ColorReset, err)
		return exploits
	}
	defer file.Close()
	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 7 {
			continue
		}
		id := record[0]
		title := record[2]
		platform := record[6]
		portField := ""
		if len(record) > 7 {
			portField = record[7]
		}
		link := "https://www.exploit-db.com/exploits/" + id
		entry := ExploitEntry{
			EDBID:    id,
			Desc:     title,
			Link:     link,
			Platform: platform,
		}
		if portField != "" {
			ports := strings.Split(portField, ",")
			for _, p := range ports {
				p = strings.TrimSpace(p)
				if p != "" {
					exploits[p] = append(exploits[p], entry)
				}
			}
		}
	}
	return exploits
}

func enrichCVEs(vulns []string) []CVEEntry {
	var res []CVEEntry
	for _, v := range vulns {
		if strings.HasPrefix(strings.ToUpper(v), "CVE-") {
			link := "https://nvd.nist.gov/vuln/detail/" + v
			res = append(res, CVEEntry{
				CVE:       v,
				Desc:      "",
				Link:      link,
				RefSource: "NVD",
			})
		} else if strings.HasPrefix(strings.ToLower(v), "edb-") {
			id := strings.TrimPrefix(v, "EDB-")
			link := "https://www.exploit-db.com/exploits/" + id
			res = append(res, CVEEntry{
				CVE:       v,
				Desc:      "Exploit-DB",
				Link:      link,
				RefSource: "Exploit-DB",
			})
		}
	}
	return res
}

func enrichExploitDB(exploitDB map[string][]ExploitEntry, port int) []ExploitEntry {
	key := strconv.Itoa(port)
	return exploitDB[key]
}

func advancedBannerGrab(host string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	var probe string
	switch port {
	case 80, 8080, 8000, 8888, 443, 8443:
		probe = "HEAD / HTTP/1.0\r\n\r\n"
	case 25, 587:
		probe = "EHLO wmap\r\n"
	case 110:
		probe = "USER test\r\n"
	case 143:
		probe = "a001 CAPABILITY\r\n"
	case 3389:
		probe = "\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"
	default:
	}
	if probe != "" {
		conn.Write([]byte(probe))
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return strings.TrimSpace(string(buf[:n]))
	}
	return ""
}

func scanUDPPort(host string, port int, timeout time.Duration) (bool, string) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	var probe []byte
	switch port {
	case 53:
		probe = []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01")
	case 123:
		probe = []byte("\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	default:
		probe = []byte("Hello\r\n")
	}
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write(probe)
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return false, ""
	}
	if n > 0 {
		return true, strings.TrimSpace(string(buf[:n]))
	}
	return false, ""
}

func fingerprintServiceAdvanced(port int, banner string, fingerprints map[int]ServiceFingerprints) (string, string) {
	bannerLow := strings.ToLower(banner)
	if strings.Contains(bannerLow, "http/1.0") || strings.Contains(bannerLow, "http/1.1") || strings.Contains(bannerLow, "server:") {
		return "http", extractHTTPVersion(banner)
	}
	if strings.Contains(bannerLow, "ssh-") {
		return "ssh", extractSSHVersion(banner)
	}
	if strings.Contains(bannerLow, "ftp") {
		return "ftp", extractVersion(bannerLow)
	}
	if strings.Contains(bannerLow, "smtp") || strings.Contains(bannerLow, "220 ") {
		return "smtp", extractSMTPVersion(banner)
	}
	if strings.Contains(bannerLow, "imap") {
		return "imap", extractVersion(bannerLow)
	}
	if strings.Contains(bannerLow, "+ok") && port == 110 {
		return "pop3", extractVersion(bannerLow)
	}
	if port == 3306 && len(banner) > 0 {
		return "mysql", extractMySQLVersion(banner)
	}
	if port == 3389 && len(banner) > 0 {
		return "rdp", "unknown"
	}
	if port == 6379 && (strings.Contains(bannerLow, "redis") || strings.Contains(bannerLow, "welcome")) {
		return "redis", extractVersion(bannerLow)
	}
	if fp, ok := fingerprints[port]; ok {
		return fp.Service, fp.Version
	}
	return "unknown", "unknown"
}

func extractHTTPVersion(banner string) string {
	lines := strings.Split(banner, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
		if strings.Contains(line, "HTTP/") {
			return strings.TrimSpace(line)
		}
	}
	return "unknown"
}
func extractSSHVersion(banner string) string {
	for _, tok := range strings.Fields(banner) {
		if strings.HasPrefix(tok, "SSH-") {
			return tok
		}
	}
	return "unknown"
}
func extractSMTPVersion(banner string) string {
	for _, line := range strings.Split(banner, "\n") {
		if strings.HasPrefix(line, "220") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return strings.Join(parts[1:], " ")
			}
		}
	}
	return "unknown"
}
func extractMySQLVersion(banner string) string {
	parts := strings.Split(banner, "\x00")
	if len(parts) > 0 {
		return strings.Trim(parts[0], "\x00")
	}
	return "unknown"
}
func extractVersion(banner string) string {
	for _, field := range strings.Fields(banner) {
		if strings.Count(field, ".") >= 1 && (field[0] >= '0' && field[0] <= '9') {
			return field
		}
	}
	return "unknown"
}

func detectOS(host string, timeout time.Duration) OSDResult {
	ports := []int{80, 443, 22, 3389, 445, 8080}
	for _, port := range ports {
		ip := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", ip, timeout)
		if err != nil {
			continue
		}
		defer conn.Close()
		b := advancedBannerGrab(host, port, timeout)
		bLow := strings.ToLower(b)
		if strings.Contains(bLow, "microsoft") || strings.Contains(bLow, "iis") {
			return OSDResult{"Windows", "Detected Microsoft/IIS in banner"}
		}
		if strings.Contains(bLow, "linux") || strings.Contains(bLow, "ubuntu") || strings.Contains(bLow, "debian") {
			return OSDResult{"Linux", "Detected Linux/Ubuntu/Debian in banner"}
		}
		if strings.Contains(bLow, "cisco") {
			return OSDResult{"Cisco", "Detected Cisco in banner"}
		}
		if strings.Contains(bLow, "freebsd") {
			return OSDResult{"FreeBSD", "Detected FreeBSD in banner"}
		}
		if strings.Contains(bLow, "darwin") || strings.Contains(bLow, "apple") {
			return OSDResult{"Mac OS", "Detected Apple/Darwin in banner"}
		}
		if port == 22 && strings.Contains(bLow, "ssh-") {
			if strings.Contains(bLow, "openssh") {
				return OSDResult{"Linux/Unix", "Detected OpenSSH"}
			}
		}
		if port == 3389 && b != "" {
			return OSDResult{"Windows", "RDP port open, likely Windows"}
		}
		if port == 445 && b != "" {
			return OSDResult{"Windows", "SMB port open, likely Windows"}
		}
		if port == 80 || port == 8080 || port == 443 {
			if b != "" && strings.Contains(bLow, "apache") {
				return OSDResult{"Linux/Unix", "Apache in HTTP header"}
			}
		}
	}
	return OSDResult{"Unknown", "Could not fingerprint OS"}
}

func scanPortAdvanced(host string, port int, timeout time.Duration, serviceDetect bool) (bool, string) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	var banner string
	if serviceDetect {
		banner = advancedBannerGrab(host, port, timeout)
	}
	return true, banner
}

func activeScan(host string, opts ScanOptions, fingerprints map[int]ServiceFingerprints, vulnDB map[string][]string, exploitDB map[string][]ExploitEntry, osDetect *OSDResult) []PortResult {
	fmt.Printf(ColorCyan + "[*] Starting active scan on %s [%s]...\n" + ColorReset, host, opts.Speed.String())
	var openPorts []PortResult
	var wg sync.WaitGroup
	var mutex sync.Mutex

	sem := make(chan struct{}, opts.Speed.Threads())
	for _, port := range opts.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			ok, banner := scanPortAdvanced(host, p, opts.Speed.Timeout(), opts.ServiceDetect)
			<-sem
			if ok {
				service, version := "unknown", "unknown"
				if opts.ServiceDetect {
					service, version = fingerprintServiceAdvanced(p, banner, fingerprints)
				} else if fp, ok := fingerprints[p]; ok {
					service, version = fp.Service, fp.Version
				}
				vulns := []string{}
				if opts.VulnDetect && vulnDB != nil {
					portStr := strconv.Itoa(p)
					if v, ok := vulnDB[portStr]; ok {
						vulns = v
					}
				}
				var cveLinks []CVEEntry
				var exploitLinks []ExploitEntry
				if opts.VulnDetect {
					cveLinks = enrichCVEs(vulns)
					if exploitDB != nil {
						exploitLinks = enrichExploitDB(exploitDB, p)
					}
				}
				mutex.Lock()
				openPorts = append(openPorts, PortResult{
					Port:        p,
					Service:     service,
					Version:     version,
					Banner:      banner,
					Vulns:       vulns,
					CVERefs:     cveLinks,
					ExploitRefs: exploitLinks,
					Proto:       "tcp",
				})
				mutex.Unlock()
			}
		}(port)
	}
	if opts.UDPScan {
		for _, port := range opts.UDPPorts {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				sem <- struct{}{}
				ok, banner := scanUDPPort(host, p, opts.Speed.Timeout())
				<-sem
				if ok {
					service, version := "unknown", "unknown"
					if opts.ServiceDetect {
						service, version = fingerprintServiceAdvanced(p, banner, fingerprints)
					} else if fp, ok := fingerprints[p]; ok {
						service, version = fp.Service, fp.Version
					}
					vulns := []string{}
					if opts.VulnDetect && vulnDB != nil {
						portStr := strconv.Itoa(p)
						if v, ok := vulnDB[portStr]; ok {
							vulns = v
						}
					}
					var cveLinks []CVEEntry
					var exploitLinks []ExploitEntry
					if opts.VulnDetect {
						cveLinks = enrichCVEs(vulns)
						if exploitDB != nil {
							exploitLinks = enrichExploitDB(exploitDB, p)
						}
					}
					mutex.Lock()
					openPorts = append(openPorts, PortResult{
						Port:        p,
						Service:     service,
						Version:     version,
						Banner:      banner,
						Vulns:       vulns,
						CVERefs:     cveLinks,
						ExploitRefs: exploitLinks,
						Proto:       "udp",
					})
					mutex.Unlock()
				}
			}(port)
		}
	}
	if osDetect != nil {
		*osDetect = detectOS(host, opts.Speed.Timeout())
	}
	wg.Wait()
	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].Proto == openPorts[j].Proto {
			return openPorts[i].Port < openPorts[j].Port
		}
		return openPorts[i].Proto < openPorts[j].Proto
	})
	return openPorts
}

func colorPort(port int) string {
	switch {
	case port == 22 || port == 443 || port == 3389:
		return ColorCyan
	case port == 80 || port == 8080 || port == 8443:
		return ColorGreen
	case port == 21 || port == 23 || port == 25:
		return ColorYellow
	case port == 445 || port == 139:
		return ColorBlue
	default:
		return ColorWhite
	}
}

func colorService(service string) string {
	switch service {
	case "http", "https":
		return ColorGreen
	case "ftp", "telnet":
		return ColorYellow
	case "ssh":
		return ColorCyan
	case "redis", "postgresql", "mysql":
		return ColorBlue
	case "smtp", "pop3", "imap":
		return ColorYellow
	case "unknown":
		return ColorWhite
	default:
		return ColorWhite
	}
}

func colorVuln() string {
	return ColorRed + ColorBold
}

func printActiveResults(res []PortResult, quiet bool, osDetect *OSDResult) {
	fmt.Println()
	if osDetect != nil && osDetect.OSGuess != "" {
		fmt.Printf("%s[OS DETECTION]%s %s  (%s)\n\n", ColorBold+ColorYellow, ColorReset, osDetect.OSGuess, osDetect.Details)
	}
	if len(res) == 0 {
		fmt.Println(ColorYellow + "No open ports found!" + ColorReset)
		return
	}

	if quiet {
		for _, r := range res {
			fmt.Printf("%d/%s\n", r.Port, r.Proto)
		}
		return
	}

	maxPort := len("Port")
	maxProto := len("Proto")
	maxService := len("Service")
	maxVersion := len("Version")
	maxBanner := len("Banner")
	for _, r := range res {
		pLen := len(fmt.Sprintf("%d", r.Port))
		prLen := len(r.Proto)
		sLen := len(r.Service)
		vLen := len(r.Version)
		bLen := len(r.Banner)
		if pLen > maxPort {
			maxPort = pLen
		}
		if prLen > maxProto {
			maxProto = prLen
		}
		if sLen > maxService {
			maxService = sLen
		}
		if vLen > maxVersion {
			maxVersion = vLen
		}
		if bLen > maxBanner {
			maxBanner = bLen
		}
	}
	if maxPort < 4 {
		maxPort = 4
	}
	if maxProto < 5 {
		maxProto = 5
	}
	if maxService < 12 {
		maxService = 12
	}
	if maxVersion < 7 {
		maxVersion = 7
	}
	if maxBanner < 6 {
		maxBanner = 6
	}
	if maxBanner > 40 {
		maxBanner = 40
	}

	fmt.Print(ColorCyan + "╭")
	fmt.Print(strings.Repeat("═", maxPort+2) + "╦" + strings.Repeat("═", maxProto+2) + "╦" + strings.Repeat("═", maxService+2) + "╦" +
		strings.Repeat("═", maxVersion+2) + "╦" + strings.Repeat("═", maxBanner+2) + "╮" + ColorReset + "\n")
	fmt.Printf(ColorCyan+"║"+ColorTableHead+" %*s "+ColorReset+ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+ColorCyan+"║"+ColorTableHead+" %-*s "+ColorReset+ColorCyan+"║"+ColorReset+"\n",
		maxPort, "Port",
		maxProto, "Proto",
		maxService, "Service",
		maxVersion, "Version",
		maxBanner, "Banner")
	fmt.Print(ColorCyan + "╠")
	fmt.Print(strings.Repeat("═", maxPort+2) + "╬" + strings.Repeat("═", maxProto+2) + "╬" + strings.Repeat("═", maxService+2) + "╬" +
		strings.Repeat("═", maxVersion+2) + "╬" + strings.Repeat("═", maxBanner+2) + "╣" + ColorReset + "\n")
	for _, r := range res {
		bannerValue := r.Banner
		if len(bannerValue) > maxBanner {
			bannerValue = bannerValue[:maxBanner]
		}
		fmt.Printf(ColorCyan+"║"+ColorReset+" %s%*d "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+" %s%-*s "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+" %-*s "+ColorCyan+"║"+ColorReset+"\n",
			colorPort(r.Port), maxPort, r.Port,
			maxProto, r.Proto,
			colorService(r.Service), maxService, r.Service,
			maxVersion, r.Version,
			maxBanner, bannerValue)
	}
	fmt.Print(ColorCyan + "╰")
	fmt.Print(strings.Repeat("═", maxPort+2) + "╩" + strings.Repeat("═", maxProto+2) + "╩" +
		strings.Repeat("═", maxService+2) + "╩" + strings.Repeat("═", maxVersion+2) + "╩" + strings.Repeat("═", maxBanner+2) + "╯" + ColorReset + "\n")

	for _, r := range res {
		if len(r.Vulns) > 0 {
			fmt.Printf("\n%s[!] Vulnerabilities for port %d/%s (%s):%s\n", colorVuln(), r.Port, r.Proto, r.Service, ColorReset)
			for _, vuln := range r.Vulns {
				fmt.Printf("    %s- %s%s\n", colorVuln(), vuln, ColorReset)
			}
		}
		if len(r.CVERefs) > 0 {
			fmt.Printf("%s[+] CVE References:%s\n", ColorBlue, ColorReset)
			for _, cve := range r.CVERefs {
				fmt.Printf("    %s: %s\n", cve.CVE, cve.Link)
			}
		}
		if len(r.ExploitRefs) > 0 {
			fmt.Printf("%s[+] Exploit-DB References:%s\n", ColorYellow, ColorReset)
			for _, ex := range r.ExploitRefs {
				fmt.Printf("    %s: %s (%s)\n", ex.EDBID, ex.Link, ex.Desc)
			}
		}
	}
}

func saveResults(results []PortResult, host, filename, format string, osDetect *OSDResult) error {
	if filename == "" {
		return nil
	}
	switch format {
	case "json":
		return saveResultsJSON(results, host, filename, osDetect)
	case "csv":
		return saveResultsCSV(results, filename)
	default:
		return saveResultsText(results, filename)
	}
}

func saveResultsJSON(results []PortResult, host, filename string, osDetect *OSDResult) error {
	summary := ScanSummary{
		Host:  host,
		Ports: results,
	}
	if osDetect != nil && osDetect.OSGuess != "" {
		summary.OS = osDetect.OSGuess + " (" + osDetect.Details + ")"
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func saveResultsCSV(results []PortResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()
	header := []string{"Port", "Proto", "Service", "Version", "Banner", "Vulnerabilities", "CVEs", "ExploitDB"}
	writer.Write(header)
	for _, r := range results {
		vulnStr := "-"
		if len(r.Vulns) > 0 {
			vulnStr = strings.Join(r.Vulns, "; ")
		}
		cves := []string{}
		for _, c := range r.CVERefs {
			cves = append(cves, c.CVE)
		}
		cveStr := strings.Join(cves, ";")
		exploits := []string{}
		for _, ex := range r.ExploitRefs {
			exploits = append(exploits, ex.EDBID)
		}
		expStr := strings.Join(exploits, ";")
		writer.Write([]string{
			fmt.Sprintf("%d", r.Port),
			r.Proto,
			r.Service,
			r.Version,
			r.Banner,
			vulnStr,
			cveStr,
			expStr,
		})
	}
	return nil
}

func saveResultsText(results []PortResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range results {
		line := fmt.Sprintf("Port: %d/%s, Service: %s, Version: %s, Banner: %s", r.Port, r.Proto, r.Service, r.Version, r.Banner)
		if len(r.Vulns) > 0 {
			line += fmt.Sprintf(", Vulns: %s", strings.Join(r.Vulns, "; "))
		}
		if len(r.CVERefs) > 0 {
			cves := []string{}
			for _, cve := range r.CVERefs {
				cves = append(cves, cve.CVE+"("+cve.Link+")")
			}
			line += ", CVEs: " + strings.Join(cves, "; ")
		}
		if len(r.ExploitRefs) > 0 {
			exps := []string{}
			for _, ex := range r.ExploitRefs {
				exps = append(exps, ex.EDBID+"("+ex.Link+")")
			}
			line += ", Exploit-DB: " + strings.Join(exps, "; ")
		}
		f.WriteString(line + "\n")
	}
	return nil
}