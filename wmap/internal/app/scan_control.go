package scan

import (
    "math/rand"
    "sync"
    "time"
)

var (
    concurrency = 10
    rateLimit   = 0 // per second, 0 = unlimited
    randomize   = false
)

// Shuffle ports if randomize is true
func ShufflePorts(ports []int) []int {
    if !randomize {
        return ports
    }
    rand.Seed(time.Now().UnixNano())
    r := make([]int, len(ports))
    perm := rand.Perm(len(ports))
    for i, v := range perm {
        r[i] = ports[v]
    }
    return r
}

// Run scan tasks with concurrency and rate limiting
func RunWithConcurrency(tasks []func()) {
    wg := sync.WaitGroup{}
    sem := make(chan struct{}, concurrency)
    for _, task := range tasks {
        wg.Add(1)
        go func(t func()) {
            sem <- struct{}{}
            t()
            <-sem
            wg.Done()
            if rateLimit > 0 {
                time.Sleep(time.Second / time.Duration(rateLimit))
            }
        }(task)
    }
    wg.Wait()
}