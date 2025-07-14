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


- **Active Scanning:** Fast TCP/UDP port scanning, service and version detection, OS detection, aggressive scan mode, output customization.
- **Passive Reconnaissance:** Collects public data about domains and IPs, passive DNS, GeoIP, whois, and more.
- **Vulnerability Detection:** Maps detected services to known vulnerabilities and exploits.

---

## Installation

### Using Go

You will need Go 1.21 or later installed.

```sh
go install github.com/Xwal13/wmap@latest
```


## Usage

```sh
wmap <command> [options] <target or -l <listfile>>
```

### Commands

- `active`      : Perform an active scan on the target(s)
- `passive`     : Perform a passive recon scan
- `discover`    : Discover live hosts in a network range (CIDR)
- `update-db`   : Update vulnerability and exploit databases
- `-h, --help`  : Show the help message

### Options (common)

- `-l`, `--list <file>`   : Supply a file containing targets (one per line)
- `-o <file>`             : Output results to a file
- `-oJ`                   : Output results in JSON format
- `-q`                    : Quiet mode (minimal output)
- `-v`                    : Increase verbosity

#### Active Scan Options

- `-sV`                   : Enable service/version detection
- `-O`                    : Enable OS detection
- `-p <ports>`            : Specify ports (comma-separated, e.g., 80,443,8080)
- `-sU`                   : Enable UDP scan
- `-T <0-5>`              : Set timing template (0 = paranoid, 5 = insane)
- `-A`                    : Aggressive scan (OS, version, scripts, traceroute)
- `--vuln`                : Enable vulnerability detection
- `--exploit`             : Enable exploit mapping
- `--no-ping`             : Skip host discovery
- `--min-rate <n>`        : Minimum packets per second
- `--max-rate <n>`        : Maximum packets per second

#### Passive Scan Options

- `-report`               : Save passive scan report (default: passive_report.txt)
- `-report-path <file>`   : Set custom report file path

### Examples

```sh
# Active scan a single host with service detection and OS detection
wmap active example.com -sV -O

# Active scan a list of targets from a file, scan specific ports, save output to file
wmap active -l targets.txt -p 80,443,8080 -o results.txt

# Passive scan a single domain and save report
wmap passive example.com -report

# Passive scan multiple targets from a list
wmap passive -l domains.txt -report

# Discover live hosts in a subnet
wmap discover 192.168.1.0/24

# Update vulnerability and exploit databases
wmap update-db
```
**Author:** [Xwal13](https://github.com/Xwal13)

wmap is under active development. Feedback, issues, and pull requests are welcome!

