// ...existing code...
    for i := 1; i < len(os.Args); i++ {
        switch os.Args[i] {
        // ...existing cases...
        case "-stealth":
            scanMode = "stealth"
            modeSet = true
        case "--os-detect":
            osDetect = true
        // ...existing cases...
        }
    }
// ...existing code...

    for _, host := range hostList {
        var result *HostResult

        switch scanMode {
        case "stealth":
            result = stealthScan(host, portFilter)
        case "passive":
            result = shodanScan(host, portFilter)
        case "active":
            result = activeScan(host, portFilter)
        default:
            if canUseShodan() {
                result = shodanScan(host, portFilter)
            } else {
                result = activeScan(host, portFilter)
            }
        }

        if result != nil {
            if osDetect {
                detectOS(result)
            }
            allResults = append(allResults, *result)
        }
    }
// ...existing code...
