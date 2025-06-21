package main

import (
	"strconv"
	"strings"
)

func parsePorts(input string) []int {
	ports := []int{}
	ranges := strings.Split(input, ",")
	for _, r := range ranges {
		if strings.Contains(r, "-") {
			bounds := strings.Split(r, "-")
			if len(bounds) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				continue
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			p, err := strconv.Atoi(r)
			if err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func parseActiveArgs(args []string) (host string, opts ScanOptions, ok bool) {
	speed := T3
	ports := []int{}
	udpPorts := []int{}
	allPorts := false
	allUDPPorts := false
	udpScan := false
	serviceDetect := false
	vulnDetect := false
	outputFile := ""
	outputFormat := ""
	quiet := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "-T") && len(arg) == 3:
			switch arg[2] {
			case '1':
				speed = T1
			case '2':
				speed = T2
			case '3':
				speed = T3
			case '4':
				speed = T4
			case '5':
				speed = T5
			}
		case arg == "-p" && i+1 < len(args):
			ports = parsePorts(args[i+1])
			i++
		case arg == "-P" && i+1 < len(args):
			udpPorts = parsePorts(args[i+1])
			udpScan = true
			i++
		case arg == "-p-":
			allPorts = true
		case arg == "-P-":
			allUDPPorts = true
			udpScan = true
		case arg == "-sU":
			udpScan = true
		case arg == "-sV":
			serviceDetect = true
		case arg == "-vuln":
			vulnDetect = true
		case arg == "-o" && i+1 < len(args):
			outputFile = args[i+1]
			i++
		case arg == "-of" && i+1 < len(args):
			outputFormat = args[i+1]
			i++
		case arg == "-q" || arg == "--quiet":
			quiet = true
		default:
			if !strings.HasPrefix(arg, "-") && host == "" {
				host = arg
			}
		}
	}

	if host == "" {
		return "", ScanOptions{}, false
	}

	if allPorts {
		ports = make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			ports[i-1] = i
		}
	} else if len(ports) == 0 {
		ports = defaultPorts
	}

	if allUDPPorts {
		udpPorts = make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			udpPorts[i-1] = i
		}
	} else if udpScan && len(udpPorts) == 0 {
		udpPorts = defaultUDPPorts
	}

	if outputFormat == "" && outputFile != "" {
		if strings.HasSuffix(outputFile, ".json") {
			outputFormat = "json"
		} else if strings.HasSuffix(outputFile, ".csv") {
			outputFormat = "csv"
		} else {
			outputFormat = "text"
		}
	}

	opts = ScanOptions{
		Ports:         ports,
		AllPorts:      allPorts,
		ServiceDetect: serviceDetect,
		VulnDetect:    vulnDetect,
		OutputFile:    outputFile,
		OutputFormat:  outputFormat,
		Quiet:         quiet,
		Speed:         speed,
		UDPScan:       udpScan,
		UDPPorts:      udpPorts,
	}

	return host, opts, true
}