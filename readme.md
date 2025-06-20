```
Y88b    e    / 888-~88e-~88e   /~~~8e  888-~88e  
 Y88b  d8b  /  888  888  888       88b 888  888b 
  Y888/Y88b/   888  888  888  e88~-888 888  8888 
   Y8/  Y8/    888  888  888 C888  888 888  888P 
    Y    Y     888  888  888  "88_-888 888-_88"  
                                       888        
```

# wmap - Easy & Powerful Port Scanner

`wmap` is a modern, user-friendly network scanner and reconnaissance tool written in Go.  
It helps you discover live hosts, scan for open ports and services, identify running software and versions, check for vulnerabilities, and generate detailed reports—all with a focus on simplicity and flexibility.

---

## 🚀 Key Features

- **Multiple Scan Modes:** Active TCP, Stealth/SYN, UDP, and Passive (Shodan/InternetDB) scanning
- **Host Discovery:** Quickly find live hosts in a subnet before scanning
- **Service & Version Detection:** Get banners and try to identify software/version
- **OS & Device Fingerprinting:** Guess the operating system and device type
- **Vulnerability Lookup:** Map detected services to known CVEs
- **Flexible Output:** Choose from normal, grepable, JSON, XML, CSV, Markdown, HTML, Excel, or HTTP POST output
- **Performance Controls:** Parallelism, rate limiting, randomization
- **Beginner Friendly:** Clean help menu, safe defaults, and practical examples
- **Extensible Design:** Modular codebase for easy feature addition

---

## 🛠️ Installation

**Go 1.21+ is required.**

1. **Clone or Install Directly:**

   ```
   go install github.com/yourusername/wmap/cmd/wmap@latest
   ```

   This will place the `wmap` binary in your `$GOBIN` or `$GOPATH/bin`.

2. **Or Clone and Build:**

   ```bash
   git clone https://github.com/yourusername/wmap.git
   cd wmap/cmd/wmap
   go build -o wmap
   ./wmap --help
   ```

   Replace `yourusername` with your actual GitHub username.

---

## 📖 Usage Guide

Run `wmap --help` to see all options.

### Basic Usage

```bash
wmap [OPTIONS] TARGET
```
**TARGET** can be:
- An IP address (e.g. `192.168.1.10`)
- A domain name (e.g. `example.com`)
- A subnet (e.g. `192.168.1.0/24`)
- A file with targets (`-iL targets.txt`)

### Common Examples

```bash
# Scan a single host for common TCP ports
wmap 192.168.1.1 -active -p 22,80,443

# Stealth scan with OS detection
wmap example.com -stealth --os-detect

# Discover live hosts in a subnet, output as CSV
wmap 192.168.1.0/24 --ping-sweep -oC results.csv

# Scan a list of hosts for UDP services, output as JSON
wmap -iL targets.txt -udp -oJ

# Passive scan using Shodan (requires API key)
wmap scanme.nmap.org -passive --api-key YOUR_SHODAN_KEY
```

---

## ⚙️ Main Options Overview

- `-h, --help`              Show help menu
- `-q`                      Quiet mode (minimal output)
- `-active`                 Standard TCP scan (default)
- `-stealth`                Stealth/SYN scan (needs admin/root)
- `-passive`                Use Shodan data (API key optional)
- `-udp`                    Scan UDP ports
- `-iL <file>`              Load targets from a file
- `-p <ports>`              Ports to scan (e.g. 22,80,443 or 1-1000)
- `--ping-sweep`            Find live hosts before scanning
- `-oN/-oG/-oJ/-oX/-oC`     Normal, grepable, JSON, XML, CSV output
- `--html/--md/--xlsx`      HTML, Markdown, Excel output
- `--post <url>`            Send results to a server via HTTP POST
- `--os-detect`             Guess the operating system
- `--cve-live`              Fetch vulnerabilities online
- `--service-version`       Detect exact service versions
- `--concurrency <n>`       Parallel scans (default: 10)
- `--rate-limit <n>`        Scans per second (default: unlimited)
- `--randomize`             Randomize scan order

---

## 🙏 Legal Notice

**Scan only networks and systems you have explicit permission to test.**  
Unauthorized scanning is illegal and unethical.

---

## 📚 Learn More

- See the [help menu](./help.go) or run `wmap --help` for more info and examples.
- Read the code and contribute via [GitHub Issues](https://github.com/yourusername/wmap/issues)!

---

Happy scanning!