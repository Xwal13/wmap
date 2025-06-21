package main

import "time"

type ScanSpeed int

const (
	T1 ScanSpeed = iota + 1
	T2
	T3
	T4
	T5
)

func (s ScanSpeed) Timeout() time.Duration {
	switch s {
	case T1:
		return 5 * time.Second
	case T2:
		return 3 * time.Second
	case T3:
		return 1 * time.Second
	case T4:
		return 500 * time.Millisecond
	case T5:
		return 100 * time.Millisecond
	default:
		return 1 * time.Second
	}
}

func (s ScanSpeed) Threads() int {
	switch s {
	case T1:
		return 20
	case T2:
		return 50
	case T3:
		return 100
	case T4:
		return 250
	case T5:
		return 500
	default:
		return 100
	}
}

func (s ScanSpeed) String() string {
	switch s {
	case T1:
		return "T1 (Paranoid/Slowest)"
	case T2:
		return "T2 (Polite/Slow)"
	case T3:
		return "T3 (Normal/Default)"
	case T4:
		return "T4 (Aggressive/Fast)"
	case T5:
		return "T5 (Insane/Fastest)"
	default:
		return "T3 (Normal/Default)"
	}
}

type ScanOptions struct {
	Ports         []int
	AllPorts      bool
	ServiceDetect bool
	VulnDetect    bool
	OutputFile    string
	OutputFormat  string
	Quiet         bool
	Speed         ScanSpeed
	UDPScan       bool
	UDPPorts      []int
}

type ServiceFingerprints struct {
	Service string
	Version string
	Banner  string
}

type CVEEntry struct {
	CVE       string
	Desc      string
	Link      string
	RefSource string
}

type ExploitEntry struct {
	EDBID    string
	Desc     string
	Link     string
	Platform string
}

type PortResult struct {
	Port        int           `json:"port"`
	Service     string        `json:"service"`
	Version     string        `json:"version"`
	Banner      string        `json:"banner"`
	Vulns       []string      `json:"vulns,omitempty"`
	CVERefs     []CVEEntry    `json:"cve_refs,omitempty"`
	ExploitRefs []ExploitEntry `json:"exploit_refs,omitempty"`
	Proto       string        `json:"proto"`
}

type ScanSummary struct {
	Host   string       `json:"host"`
	OS     string       `json:"os,omitempty"`
	Ports  []PortResult `json:"ports"`
}

type OSDResult struct {
	OSGuess string
	Details string
}