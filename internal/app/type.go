package scan

type HostResult struct {
    IP       string        `json:"ip"`
    Ports    []PortResult  `json:"ports"`
    Vulns    []CVEDetail   `json:"vulnerabilities"`
}

type PortResult struct {
    Port     int    `json:"port"`
    Protocol string `json:"protocol"`
    Service  string `json:"service"`
    Banner   string `json:"banner"`
    State    string `json:"state"`
    CVEs     []CVE  `json:"cves"`
}

type CVE struct {
    ID         string  `json:"id"`
    Description string  `json:"description,omitempty"`
    Score      float64 `json:"score,omitempty"`
    Severity   string  `json:"severity,omitempty"`
    URL        string  `json:"url,omitempty"`
}

type CVEDetail struct {
    ID         string  `json:"id"`
    Description string  `json:"description"`
    Score      float64 `json:"score"`
    Severity   string  `json:"severity"`
    URL        string  `json:"url"`
}