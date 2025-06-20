package main

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "strconv"
    "time"
)

func writeToFile(results []HostResult, file, format string) {
    filename := file + "." + format
    switch format {
    case "json":
        data, _ := json.MarshalIndent(results, "", "  ")
        ioutil.WriteFile(filename, data, 0644)
    case "xml":
        xml := "<nmaprun>"
        for _, host := range results {
            xml += fmt.Sprintf("<host><address addr=\"%s\"/>", host.IP)
            for _, port := range host.Ports {
                xml += fmt.Sprintf("<ports><port protocol=\"tcp\" portid=\"%d\"><service name=\"%s\" banner=\"%s\" /></port></ports>", port.Port, port.Service, port.Banner)
            }
            xml += "</host>"
        }
        xml += "</nmaprun>"
        ioutil.WriteFile(filename, []byte(xml), 0644)
    case "csv":
        fileObj, _ := os.Create(filename)
        defer fileObj.Close()

        writer := csv.NewWriter(fileObj)
        headers := []string{"ip", "port", "service", "banner", "cve", "severity", "cvss_score", "timestamp"}
        _ = writer.Write(headers)

        timestamp := time.Now().Format(time.RFC3339)

        for _, host := range results {
            for _, port := range host.Ports {
                for _, cve := range port.CVEs {
                    record := []string{
                        host.IP,
                        strconv.Itoa(port.Port),
                        port.Service,
                        port.Banner,
                        cve.ID,
                        cve.Severity,
                        fmt.Sprintf("%.1f", cve.Score),
                        timestamp,
                    }
                    _ = writer.Write(record)
                }

                if len(port.CVEs) == 0 {
                    record := []string{
                        host.IP,
                        strconv.Itoa(port.Port),
                        port.Service,
                        port.Banner,
                        "",
                        "",
                        "",
                        timestamp,
                    }
                    _ = writer.Write(record)
                }
            }
        }
        writer.Flush()
        fmt.Printf("[*] Results saved to %s\n", filename)
    default:
        var content string
        for _, host := range results {
            content += fmt.Sprintf("Host: %s\n", host.IP)
            for _, port := range host.Ports {
                content += fmt.Sprintf("Port: %d (%s) | Banner: %s\n", port.Port, port.Service, port.Banner)
            }
        }
        ioutil.WriteFile(filename, []byte(content), 0644)
        fmt.Printf("[*] Results saved to %s\n", filename)
    }
}
