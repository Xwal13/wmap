package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

func postResults(results []HostResult, url string) error {
    data, _ := json.Marshal(results)
    _, err := http.Post(url, "application/json", bytes.NewBuffer(data))
    return err
}