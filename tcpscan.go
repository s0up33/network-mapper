package tcpscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"network-mapper/arp"
)

// Sweep probes every IP not already found by ARP on the supplied ports.
// Returns a set (map[string]struct{}) of live IPs.
func Sweep(
	ctx context.Context,
	ipNet *net.IPNet,
	arpHosts []arp.Host,
	ports []int,
	workers int,
) map[string]struct{} {

	// Build skip-set of ARP-discovered hosts
	skip := map[string]struct{}{}
	for _, h := range arpHosts {
		skip[h.IP.String()] = struct{}{}
	}

	out := make(chan string, 1024)
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		addr := ip.String()
		if _, done := skip[addr]; done {
			continue // already detected by ARP
		}
		// Defensive copy of ip backing array (not strictly required here)
		targetIP := append(net.IP(nil), ip...)

		for _, port := range ports {
			wg.Add(1)
			go func(p int, host string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					if probe(host, p) {
						out <- host
					}
					<-sem
				case <-ctx.Done():
					return
				}
			}(port, targetIP.String())
		}
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	live := map[string]struct{}{}
	for ip := range out {
		live[ip] = struct{}{}
	}
	return live
}

// probe attempts a TCP connect; ECONNREFUSED (RST) also counts as "alive".
func probe(host string, port int) bool {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		conn.Close()
		return true // Connected = host up
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
		return true // RST still proves host exists
	}
	return false
}

// ParsePorts converts a comma-separated list into []int.
func ParsePorts(csv string) []int {
	var out []int
	for _, s := range strings.Split(csv, ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && p > 0 && p < 65536 {
			out = append(out, p)
		}
	}
	return out
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
