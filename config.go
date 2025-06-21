package main

var (
	shodanAPIKey     = "" // SHODAN API KEY
	censysAPIID      = "" // Censys API ID
	censysAPISecret  = "" // Censys API Secret
	binaryedgeAPIKey = "" // BinaryEdge API KEY
	zoomeyeAPIKey    = "" // ZoomEye API KEY
)

var (
	defaultPorts = []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
		995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 53, 161, 389, 636,
		137, 138, 1433, 1521, 5432, 6379, 11211, 27017,
	}
	defaultUDPPorts = []int{
		53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 33434, 11211,
	}
)