package scan

import (
    "strings"
)

// Sets the OS field in HostResult based on banners
func DetectOS(result *HostResult) {
    osCounts := map[string]int{}
    bannerPatterns := map[string][]string{
        "Windows":   {"Microsoft", "IIS", "Win32", "Windows"},
        "Linux":     {"Linux", "Ubuntu", "Debian", "Fedora", "CentOS"},
        "FreeBSD":   {"FreeBSD"},
        "OpenBSD":   {"OpenBSD"},
        "macOS":     {"Darwin", "Mac OS"},
        "RouterOS":  {"MikroTik"},
        "Embedded":  {"BusyBox"},
        "Solaris":   {"Solaris"},
    }
    for _, port := range result.Ports {
        for os, patterns := range bannerPatterns {
            for _, pat := range patterns {
                if strings.Contains(strings.ToLower(port.Banner), strings.ToLower(pat)) {
                    osCounts[os]++
                }
            }
        }
    }
    detected := ""
    maxCount := 0
    for os, count := range osCounts {
        if count > maxCount {
            detected = os
            maxCount = count
        }
    }
    if detected != "" {
        result.Vulns = append(result.Vulns, CVEDetail{
            ID:         "OS-Guess",
            Description: "Guessed OS: " + detected,
        })
    }
}