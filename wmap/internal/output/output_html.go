package main

import (
    "fmt"
    "html"
)

func printHTMLOutput(results []HostResult) {
    fmt.Println("<html><body><h1>Scan Report</h1>")
    for _, host := range results {
        fmt.Printf("<h2>Host: %s</h2><ul>", html.EscapeString(host.IP))
        for _, port := range host.Ports {
            fmt.Printf("<li>Port %d/%s: %s", port.Port, port.Protocol, html.EscapeString(port.Service))
            if port.Banner != "" {
                fmt.Printf("<br>Banner: <pre>%s</pre>", html.EscapeString(port.Banner))
            }
            if len(port.CVEs) > 0 {
                for _, cve := range port.CVEs {
                    fmt.Printf("<br>CVE: <a href='%s'>%s</a> %s", html.EscapeString(cve.URL), html.EscapeString(cve.ID), html.EscapeString(cve.Description))
                }
            }
            fmt.Print("</li>")
        }
        fmt.Println("</ul>")
    }
    fmt.Println("</body></html>")
}