package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	requestIP := stringIPtoBytes()
	requestIPArr := [4]byte{requestIP[0], requestIP[1], requestIP[2], requestIP[3]}

	socket := setupSocket()
	defer syscall.Close(socket)

	fmt.Printf("traceroute to %s\n", parseIP(requestIP))
	ttl := 1
	for {
		_, dns1, ip1, time1 := pingHost(socket, requestIPArr, ttl)
		_, dns2, ip2, time2 := pingHost(socket, requestIPArr, ttl)
		code, dns3, ip3, time3 := pingHost(socket, requestIPArr, ttl)
		dnsIpString := dnsIpFormat(dns1, dns2, dns3, ip1, ip2, ip3)
		fmt.Printf("%d  %s %v %v %v\n",
			ttl, dnsIpString, time1, time2, time3)
		if code == 0 {
			break
		}
		ttl += 1
		err := syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		check(err)
	}
}

func stringIPtoBytes() []byte {
	ip := net.ParseIP(os.Args[1])
	return ip[12:16]
}

func setupSocket() int {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	check(err)

	err = syscall.SetsockoptInt(socket, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	check(err)
	err = syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, syscall.IP_TTL, 1)
	check(err)

	err = syscall.Bind(socket, &syscall.SockaddrInet4{Port: 9000})
	check(err)

	return socket
}

func parseIP(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func pingHost(socket int, requestIPArr [4]byte, ttl int) (byte, string, string, time.Duration) {
	pingRequest := []byte{8, 0, 0xf7, 0xfd, 0, 1, 0, 1}
	rsp := make([]byte, 72)

	start := time.Now()
	err := syscall.Sendto(socket, pingRequest, 0, &syscall.SockaddrInet4{Addr: requestIPArr})
	check(err)

	_, _, err = syscall.Recvfrom(socket, rsp, 0)
	check(err)
	end := time.Now()

	elapsed := end.Sub(start)
	code := rsp[20]
	ip := parseIP(rsp[12:16])
	dns, err := net.LookupAddr(ip)
	if err != nil {
		dns = []string{ip}
	}

	return code, dns[0], ip, elapsed
}

func dnsIpFormat(dns1 string, dns2 string, dns3 string, ip1 string, ip2 string, ip3 string) string {
	var sb strings.Builder

	sb.WriteString(dns1 + " (" + ip1 + ") ")

	if ip2 != ip1 {
		sb.WriteString(dns2 + " (" + ip2 + ") ")
	}

	if ip3 != ip1 {
		sb.WriteString(dns3 + " (" + ip3 + ") ")
	}

	return sb.String()
}
func check(err error) {
	if err != nil {
		log.Fatalf("%s", err)
	}
}
