package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	ToolVersion = "1.0.2"
	ToolAuthor  = "Xwal13"
)

func printUsage() {
	fmt.Println(banner)
	fmt.Printf("wmap version %s by %s\n\n", ToolVersion, ToolAuthor)
	fmt.Println(`Usage:
  wmap <command> [options] <target or -l <listfile>]

Commands:
  active      Perform an active scan
  passive     Perform a passive scan
  discover    Discover hosts in a network range
  update-db   Update vulnerability and exploit databases

Options for passive scan:
  -report               Save the passive scan report to a file (default: passive_report.txt)
  -report-path <file>   Set custom report file path

Options for active scan:
  -sV                   Enable service/version detection
  -O                    Enable OS detection
  -p <ports>            Specify TCP ports to scan (comma-separated, e.g., 80,443,8080)
  -sU                   Enable UDP scan
  -T <0-5>              Set timing template (0 = paranoid, 5 = insane)
  -A                    Enable aggressive scan (OS, version, script, traceroute)
  -o <file>             Output results to file (CSV per host, greppable)
  -oJ                   Output in JSON format
  -v                    Increase verbosity
  -q                    Quiet mode (minimal output)
  --vuln                Enable vulnerability detection
  --exploit             Enable exploit search
  --no-ping             Skip host discovery (treat all hosts as online)
  --min-rate <rate>     Set minimum packets per second
  --max-rate <rate>     Set maximum packets per second
  -l, --list <file>     Provide a file containing a list of targets (one per line)
  -h, --help            Show this help message

Examples:
  wmap passive example.com -report
  wmap passive -l targets.txt -report
  wmap active example.com -sV -O -p 80,443 -sU -o output.txt
  wmap active -l targets.txt -sV -O -p 80,443 -sU -o output.txt
`)
}

func parseTargets(args []string) ([]string, []string, bool) {
	var targets []string
	var filteredArgs []string
	listFile := ""
	skip := 0

	for i := 0; i < len(args); i++ {
		if skip > 0 {
			skip--
			continue
		}
		if args[i] == "-l" || args[i] == "--list" {
			if i+1 < len(args) {
				listFile = args[i+1]
				skip = 1
			} else {
				fmt.Println("[-] -l/--list requires a filename")
				return nil, nil, false
			}
		} else {
			filteredArgs = append(filteredArgs, args[i])
		}
	}

	if listFile != "" {
		file, err := os.Open(listFile)
		if err != nil {
			fmt.Println("[-] Could not open target list file:", err)
			return nil, nil, false
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("[-] Error reading target list file:", err)
			return nil, nil, false
		}
	} else if len(filteredArgs) > 0 && !strings.HasPrefix(filteredArgs[0], "-") {
		targets = append(targets, filteredArgs[0])
		filteredArgs = filteredArgs[1:]
	} else {
		fmt.Println("[-] No target provided")
		return nil, nil, false
	}

	return targets, filteredArgs, true
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	switch cmd {
	case "active":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		fmt.Println(banner)
		targets, args, ok := parseTargets(os.Args[2:])
		if !ok || len(targets) == 0 {
			printUsage()
			os.Exit(1)
		}
		updateDatabases()
		for _, host := range targets {
			hostArgs := append([]string{host}, args...)
			host, opts, ok := parseActiveArgs(hostArgs)
			if !ok {
				fmt.Printf("[-] Skipping %s due to argument error\n", host)
				continue
			}
			var vulnDB map[string][]string
			if opts.VulnDetect {
				vulnDB = loadNmapVulnerabilities()
			}
			var exploitDB map[string][]ExploitEntry
			if opts.VulnDetect {
				exploitDB = loadExploitDB()
			}
			fingerprints := loadNmapFingerprints()
			var osDetect OSDResult
			results := activeScan(host, opts, fingerprints, vulnDB, exploitDB, &osDetect)
			printActiveResults(results, opts.Quiet, &osDetect)
			if opts.OutputFile != "" {
				err := saveResults(results, host, opts.OutputFile, opts.OutputFormat, &osDetect)
				if err != nil {
					fmt.Println(ColorRed + "[-] Failed to save output to file:" + ColorReset, err)
				} else {
					fmt.Println(ColorGreen + "[+] Output written to " + opts.OutputFile + ColorReset)
				}
			}
		}
	case "passive":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		fmt.Println(banner)
		targets, args, ok := parseTargets(os.Args[2:])
		if !ok || len(targets) == 0 {
			printUsage()
			os.Exit(1)
		}
		saveReport := false
		reportPath := ""
		for i := 0; i < len(args); i++ {
			if args[i] == "-report" {
				saveReport = true
			} else if args[i] == "-report-path" && i+1 < len(args) {
				reportPath = args[i+1]
				i++
			}
		}
		if saveReport && reportPath == "" {
			reportPath = "passive_report.txt"
		}
		for _, host := range targets {
			passiveScanAll(host, saveReport, reportPath)
		}
	case "discover":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		fmt.Println(banner)
		targets, _, ok := parseTargets(os.Args[2:])
		if !ok || len(targets) == 0 {
			printUsage()
			os.Exit(1)
		}
		for _, cidr := range targets {
			discoverHosts(cidr)
		}
	case "update-db":
		fmt.Println(banner)
		updateDatabases()
	case "-h", "--help", "help":
		printUsage()
	default:
		printUsage()
	}
}