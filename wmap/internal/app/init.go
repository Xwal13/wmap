package scan

var (
    serviceNames = make(map[int]string)
    vulnDB       = make(map[string][]string)
)

func init() {
    serviceNames = map[int]string{
        7:    "Echo",
        20:   "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53:   "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP", 80: "HTTP",
        110:  "POP3", 119: "NNTP", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS Datagram",
        139:  "NetBIOS Session", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
        389:  "LDAP", 443: "HTTPS", 445: "SMB", 500: "ISAKMP", 514: "Syslog",
        520:  "RIP", 631: "CUPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS Proxy",
        1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    }

    vulnDB = map[string][]string{
        "Apache/2.4.18": {"CVE-2019-0211", "Root privilege escalation"},
        "Microsoft-IIS/6.0": {"CVE-2017-7269", "Remote code execution"},
        "vsftpd 2.3.4": {"CVE-2011-2523", "Backdoor in vsftpd"},
        "Samba 3.0.20": {"CVE-2007-2447", "Command execution"},
        "OpenSSH_7.2p2": {"CVE-2016-6210", "Authentication bypass"},
    }
}