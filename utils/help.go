package main

import (
	"fmt"
	"os"
)

func showHelp() {
	fmt.Printf(`
---------------------------------------------------
wmap - Easy & Powerful Port Scanner
---------------------------------------------------

Scan networks, find open ports/services, detect OS and vulnerabilities.
Perfect for beginners and pros!

USAGE:
  wmap [OPTIONS] TARGET

TARGET can be:
  - An IP address (e.g. 192.168.1.10)
  - A domain name (e.g. example.com)
  - A subnet (e.g. 192.168.1.0/24)
  - A file with targets (see -iL option)

BASIC OPTIONS:
  -h, --help           Show this help menu
  -q                   Quiet mode (minimal output)

SCAN TYPES:
  -active              Standard TCP scan (default)
  -stealth             Stealth/SYN scan (less detectable, needs admin/root)
  -passive             Use Shodan data (API key optional)
  -udp                 Scan UDP ports (like DNS, SNMP, etc.)

TARGET SELECTION:
  -iL <file>           Load targets from a file (one per line)
  -p <ports>           Ports to scan (e.g. 22,80,443 or 1-1000)
  --ping-sweep         Find live hosts before scanning

OUTPUT FORMATS:
  -oN                  Normal output (default, easy to read)
  -oG                  Grepable output (for scripts)
  -oJ                  JSON output (for tools/APIs)
  -oX                  XML output
  -oC                  CSV output (for Excel, SIEM, etc.)
  --html               HTML report
  --md                 Markdown report
  --xlsx               Excel (spreadsheet) report
  --post <url>         Send results to a server via HTTP POST

ANALYSIS & DETECTION:
  --os-detect          Try to guess the operating system (banner-based)
  --cve-live           Fetch vulnerabilities from online sources
  --service-version    Try to detect exact service versions

PERFORMANCE OPTIONS:
  --concurrency <n>    Number of parallel scans (default: 10)
  --rate-limit <n>     Scans per second (default: unlimited)
  --randomize          Scan ports in random order

SHODAN/INTERNETDB:
  --public             Use public Shodan database (no API key needed)
  --api-key <key>      Use your Shodan API key (for passive scans)

EXAMPLES:
  wmap 192.168.1.1 -active -p 22,80,443
  wmap example.com -stealth --os-detect
  wmap 192.168.1.0/24 --ping-sweep -oC results.csv
  wmap -iL targets.txt -udp -oJ
  wmap scanme.nmap.org -passive --api-key YOUR_SHODAN_KEY

TIPS:
- Only scan systems you have permission to test!
- For more info, see the README or docs.
- Quiet mode (-q) is great for scripting.

Happy scanning!
`)
	os.Exit(0)
}