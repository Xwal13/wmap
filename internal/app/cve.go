package scan

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
)

func EnrichWithCVEs(portResult *PortResult) {
    if portResult.Service == "" {
        return
    }
    query := strings.ReplaceAll(portResult.Service, " ", "+")
    url := fmt.Sprintf("https://vulners.com/api/v3/burp/software/?software=%s", query)
    resp, err := http.Get(url)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    var result struct {
        Data map[string]interface{} `json:"data"`
    }
    if err := json.Unmarshal(body, &result); err != nil {
        return
    }
    // Parse result.Data and append to portResult.CVEs as needed
}