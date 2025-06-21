package main

const (
	ColorReset      = "\033[0m"
	ColorRed        = "\033[31m"
	ColorGreen      = "\033[32m"
	ColorYellow     = "\033[33m"
	ColorBlue       = "\033[34m"
	ColorCyan       = "\033[36m"
	ColorWhite      = "\033[37m"
	ColorBold       = "\033[1m"
	ColorUnderline  = "\033[4m"
	ColorTableHead  = "\033[46;1m"
	ColorTableBlock = "\033[40;37m"
)

const banner = `
` + ColorCyan + ColorBold + `
Y88b    e    / 888-~88e-~88e   /~~~8e  888-~88e  
 Y88b  d8b  /  888  888  888       88b 888  888b 
  Y888/Y88b/   888  888  888  e88~-888 888  8888 
   Y8/  Y8/    888  888  888 C888  888 888  888P 
    Y    Y     888  888  888  "88_-888 888-_88"
` + ColorReset

const (
	nmapDBUrl    = "https://svn.nmap.org/nmap/nmap-service-probes"
	nmapDBFile   = "nmap-service-probes"
	nmapVulnURL  = "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/nmap-vulners.csv"
	nmapVulnFile = "nmap-vulners.csv"
	exploitDBURL  = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
	exploitDBFile = "exploitdb.csv"
	shodanAPIURL     = "https://api.shodan.io/shodan/host/"
	censysAPIURL     = "https://search.censys.io/api/v2/hosts/"
	binaryedgeAPIURL = "https://api.binaryedge.io/v2/query/ip/"
	zoomeyeAPIURL    = "https://api.zoomeye.org/host/search"
	passiveDNSAPIURL = "https://api.hackertarget.com/hostsearch/?q="
)