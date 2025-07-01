package arp

import (
	"context"
	"net"
	"sync"

	"github.com/j-keck/arping"
)

// Host represents an ARP-detected device.
type Host struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// Sweep sends ARP “who-has” to every IP in ipNet.
// Returns slice of live hosts plus any fatal error.
func Sweep(ctx context.Context, ipNet *net.IPNet, workers int) ([]Host, error) {
	ips := hosts(ipNet)               // list excludes network/broadcast
	out := make(chan Host, len(ips))  // buffered

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for _, ip := range ips {
		ip := ip // shadow for goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				if mac, _, err := arping.Ping(ip); err == nil {
					out <- Host{IP: ip, MAC: mac}
				}
				<-sem
			case <-ctx.Done():
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	var alive []Host
	for h := range out {
		alive = append(alive, h)
	}

	// Only propagate context errors that actually occurred
	if err := ctx.Err(); err != nil && err != context.Canceled {
		return alive, err
	}
	return alive, nil
}

// hosts returns every usable IP (no network/broadcast) in ipNet.
func hosts(ipNet *net.IPNet) []net.IP {
	var list []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		list = append(list, dup)
	}
	if len(list) > 2 {
		return list[1 : len(list)-1]
	}
	return nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
