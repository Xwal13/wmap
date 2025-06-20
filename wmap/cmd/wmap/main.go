package main

import (
    "fmt"
    "os"

    "wmap/internal/scan"
    "wmap/internal/output"
    "wmap/internal/banners"
)

func main() {
    if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
        banners.ShowBanner()
        banners.ShowHelp()
        return
    }

    banners.ShowBanner()

    scanMode := "active"
    outputFormat := "normal"
    outputFile := ""
    portFilter := ""
    osDetect := false
    inputFile := ""
    pingSweep := false
    postURL := ""
    useMarkdown := false
    useHTML := false
    useExcel := false

    for i := 1; i < len(os.Args); i++ {
        switch os.Args[i] {
        case "-stealth":
            scanMode = "stealth"
        case "-active":
            scanMode = "active"
        case "-passive":
            scanMode = "passive"
        case "-udp":
            scanMode = "udp"
        case "--os-detect":
            osDetect = true
        case "-oN":
            outputFormat = "normal"
        case "-oG":
            outputFormat = "grepable"
        case "-oJ":
            outputFormat = "json"
        case "-oX":
            outputFormat = "xml"
        case "-oC":
            outputFormat = "csv"
        case "--md":
            useMarkdown = true
        case "--html":
            useHTML = true
        case "--xlsx":
            useExcel = true
        case "-p":
            if i+1 < len(os.Args) {
                portFilter = os.Args[i+1]
                i++
            }
        case "-iL":
            if i+1 < len(os.Args) {
                inputFile = os.Args[i+1]
                i++
            }
        case "--ping-sweep":
            pingSweep = true
        case "--post":
            if i+1 < len(os.Args) {
                postURL = os.Args[i+1]
                i++
            }
        }
    }

    var hostList []string
    if inputFile != "" {
        hostList = scan.ReadLinesFromFile(inputFile)
    } else if len(os.Args) > 1 {
        lastArg := os.Args[len(os.Args)-1]
        if len(lastArg) > 0 && lastArg[0] != '-' {
            hostList = []string{lastArg}
        }
    }

    if pingSweep && len(hostList) == 1 && len(hostList[0]) > 0 && (len(hostList[0]) >= 7 && hostList[0][len(hostList[0])-3:] == "/24") {
        hostList = scan.DiscoverHosts(hostList[0])
    }

    if len(hostList) == 0 {
        fmt.Fprintln(os.Stderr, "[!] No targets specified.")
        os.Exit(1)
    }

    var allResults []scan.HostResult
    for _, host := range hostList {
        var result *scan.HostResult

        switch scanMode {
        case "stealth":
            result = scan.StealthScan(host, portFilter)
        case "passive":
            result = scan.ShodanScan(host, portFilter)
        case "udp":
            result = scan.UdpScan(host, portFilter)
        case "active":
            result = scan.ActiveScan(host, portFilter)
        default:
            result = scan.ActiveScan(host, portFilter)
        }

        if result != nil {
            if osDetect {
                scan.DetectOS(result)
            }
            allResults = append(allResults, *result)
        }
    }

    switch {
    case useMarkdown:
        output.PrintMarkdownOutput(allResults)
    case useHTML:
        output.PrintHTMLOutput(allResults)
    case useExcel:
        output.PrintExcelOutput(allResults)
    case outputFormat == "normal":
        output.PrintNormalOutput(allResults)
    case outputFormat == "grepable":
        output.PrintGrepableOutput(allResults)
    case outputFormat == "json":
        output.PrintJSONOutput(allResults)
    case outputFormat == "xml":
        output.PrintXMLOutput(allResults)
    case outputFormat == "csv":
        output.PrintCSVOutput(allResults)
    }

    if outputFile != "" {
        output.WriteToFile(allResults, outputFile, outputFormat)
    }

    if postURL != "" {
        output.PostResults(allResults, postURL)
    }
}