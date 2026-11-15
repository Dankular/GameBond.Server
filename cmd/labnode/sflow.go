//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Dankular/GameBond.Server/lab"
)

type interfaceCounters struct {
	index, speed, inOctets, inPackets, inDiscards, inErrors uint64
	outOctets, outPackets, outDiscards, outErrors           uint64
	up                                                      bool
}

func runSFlow() error {
	data, err := os.ReadFile("/etc/gamebond-lab/sflow.conf")
	if err != nil {
		return err
	}
	config, err := lab.DecodeSFlowConfig(string(data))
	if err != nil {
		return err
	}
	if config.PollingSeconds == 0 {
		config.PollingSeconds = 30
	}
	if config.PollingSeconds < 1 || config.PollingSeconds > 3600 {
		return errors.New("sFlow polling_seconds must be between 1 and 3600")
	}
	collector, err := net.ResolveUDPAddr("udp", config.Collector)
	if err != nil || collector.Port < 1 {
		return errors.New("sFlow collector must be a resolvable host:port")
	}
	nodeData, err := os.ReadFile("/etc/gamebond-lab/node.json")
	if err != nil {
		return err
	}
	var node nodeConfig
	if err := json.Unmarshal(nodeData, &node); err != nil {
		return err
	}
	if len(node.Interfaces) == 0 {
		return errors.New("sFlow requires at least one node interface")
	}
	agentIP, err := selectAgentIP(config.AgentIP, node.Interfaces[0])
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, collector)
	if err != nil {
		return fmt.Errorf("open sFlow collector connection: %w", err)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ticker := time.NewTicker(time.Duration(config.PollingSeconds) * time.Second)
	defer ticker.Stop()
	started := time.Now()
	var sequence uint32
	for {
		for index, iface := range node.Interfaces {
			counters, err := readInterfaceCounters(iface, uint64(index+1))
			if err != nil {
				fmt.Fprintf(os.Stderr, "sFlow: skip interface %s: %v\n", iface, err)
				continue
			}
			sequence++
			packet := encodeSFlowCounterDatagram(agentIP, sequence, uint32(time.Since(started)/time.Millisecond), counters)
			if _, err := conn.Write(packet); err != nil {
				fmt.Fprintf(os.Stderr, "sFlow: send to collector: %v\n", err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func selectAgentIP(configured, iface string) (net.IP, error) {
	if configured != "" {
		ip := net.ParseIP(configured).To4()
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("sFlow agent_ip must be a unicast IPv4 address")
		}
		return ip, nil
	}
	if iface == "." || iface == ".." || filepath.Base(iface) != iface {
		return nil, errors.New("sFlow interface name is invalid")
	}
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("find sFlow agent interface %s: %w", iface, err)
	}
	addresses, err := link.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.IsMulticast() {
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("sFlow agent interface %s has no IPv4 address; set agent_ip explicitly", iface)
}

func readInterfaceCounters(iface string, fallbackIndex uint64) (interfaceCounters, error) {
	if iface == "." || iface == ".." || filepath.Base(iface) != iface {
		return interfaceCounters{}, errors.New("invalid interface name")
	}
	base := filepath.Join("/sys/class/net", iface)
	read := func(name string) uint64 {
		data, err := os.ReadFile(filepath.Join(base, "statistics", name))
		if err != nil {
			return 0
		}
		value, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		return value
	}
	index := fallbackIndex
	if data, err := os.ReadFile(filepath.Join(base, "ifindex")); err == nil {
		if value, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); parseErr == nil && value > 0 {
			index = value
		}
	}
	var speed uint64
	if data, err := os.ReadFile(filepath.Join(base, "speed")); err == nil {
		if mbps, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); parseErr == nil {
			speed = mbps * 1_000_000
		}
	}
	oper, _ := os.ReadFile(filepath.Join(base, "operstate"))
	_, err := os.Stat(base)
	if err != nil {
		return interfaceCounters{}, err
	}
	return interfaceCounters{index: index, speed: speed, inOctets: read("rx_bytes"), inPackets: read("rx_packets"), inDiscards: read("rx_dropped"), inErrors: read("rx_errors"), outOctets: read("tx_bytes"), outPackets: read("tx_packets"), outDiscards: read("tx_dropped"), outErrors: read("tx_errors"), up: strings.TrimSpace(string(oper)) == "up"}, nil
}

func encodeSFlowCounterDatagram(agentIP net.IP, sequence, uptime uint32, c interfaceCounters) []byte {
	var record bytes.Buffer
	put32(&record, uint32(c.index)) // ifIndex
	put32(&record, 6)               // ifType: ethernetCsmacd
	put64(&record, c.speed)
	put32(&record, 0) // ifDirection: unknown
	status := uint32(0)
	if c.up {
		status = 3 // admin and operational status up
	}
	put32(&record, status)
	put64(&record, c.inOctets)
	put32(&record, uint32(c.inPackets))
	put32(&record, 0) // multicast
	put32(&record, 0) // broadcast
	put32(&record, uint32(c.inDiscards))
	put32(&record, uint32(c.inErrors))
	put32(&record, 0) // unknown protocols
	put64(&record, c.outOctets)
	put32(&record, uint32(c.outPackets))
	put32(&record, 0) // multicast
	put32(&record, 0) // broadcast
	put32(&record, uint32(c.outDiscards))
	put32(&record, uint32(c.outErrors))
	put32(&record, 0) // promiscuous mode

	var sample bytes.Buffer
	put32(&sample, sequence)
	put32(&sample, uint32(c.index)&0x00ffffff) // ifIndex data source
	put32(&sample, 1)
	put32(&sample, 1) // standard generic interface counters
	put32(&sample, uint32(record.Len()))
	sample.Write(record.Bytes())

	var packet bytes.Buffer
	put32(&packet, 5) // sFlow version 5
	put32(&packet, 1) // IPv4 agent address
	packet.Write(agentIP.To4())
	put32(&packet, 0) // sub-agent id
	put32(&packet, sequence)
	put32(&packet, uptime)
	put32(&packet, 1)
	put32(&packet, 2) // standard counter sample
	put32(&packet, uint32(sample.Len()))
	packet.Write(sample.Bytes())
	return packet.Bytes()
}

func put32(buffer *bytes.Buffer, value uint32) { _ = binary.Write(buffer, binary.BigEndian, value) }
func put64(buffer *bytes.Buffer, value uint64) { _ = binary.Write(buffer, binary.BigEndian, value) }
