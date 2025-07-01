package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"network-mapper/arp"
	"network-mapper/tcpscan"
)

func main() {
	// ---------- CLI flags ----------
	cidrFlag := flag.String("cidr", "192.168.1.0/24", "target CIDR block")
	portsCSV := flag.String("ports", "22,80,443,445,3389", "comma-separated TCP ports")
	workers   := flag.Int("concurrency", 256, "max simultaneous sockets")
	timeout   := flag.Duration("timeout", 60*time.Second, "overall timeout")
	flag.Parse()

	// ---------- Input validation ----------
	_, ipNet, err := net.ParseCIDR(*cidrFlag)
	if err != nil {
		log.Fatalf("Bad CIDR %q: %v", *cidrFlag, err)
	}

	ports := tcpscan.ParsePorts(*portsCSV)
	if len(ports) == 0 {
		log.Fatalf("No valid ports after parsing %q", *portsCSV)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// ---------- Phase 1: ARP ----------
	fmt.Println("ARP sweep…")
	arpAlive, err := arp.Sweep(ctx, ipNet, *workers)
	if err != nil {
		// ARP might need root or could time out—keep going with TCP
		log.Printf("ARP sweep error: %v (continuing…)", err)
	}
	for _, h := range arpAlive {
		fmt.Printf("%s  (MAC: %s)  [ARP]\n", h.IP, h.MAC)
	}

	// ---------- Phase 2: TCP ----------
	fmt.Println("TCP sweep…")
	tcpAlive := tcpscan.Sweep(ctx, ipNet, arpAlive, ports, *workers)
	for ip := range tcpAlive {
		fmt.Printf("%s  [TCP]\n", ip)
	}
}
