//go:build linux

package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"container/list"
)

// FlowRecord is connection metadata from Linux conntrack; payload bytes are never read.
type FlowRecord struct {
	ID          string    `json:"id"`
	Namespace   string    `json:"namespace"`
	Protocol    string    `json:"protocol"`
	Source      string    `json:"source"`
	SourcePort  uint16    `json:"source_port,omitempty"`
	Destination string    `json:"destination"`
	DestPort    uint16    `json:"destination_port,omitempty"`
	ReplySource string    `json:"reply_source,omitempty"`
	ReplyDest   string    `json:"reply_destination,omitempty"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// FlowSnapshot is a bounded view of current conntrack entries.
type FlowSnapshot struct {
	Available bool         `json:"available"`
	LastScan  time.Time    `json:"last_scan,omitempty"`
	Active    int          `json:"active"`
	Evicted   uint64       `json:"evicted"`
	Error     string       `json:"error,omitempty"`
	Flows     []FlowRecord `json:"flows"`
}

type flowEntry struct {
	key    string
	record FlowRecord
}

// FlowCollector polls Linux conntrack metadata and retains a bounded, payload-free view.
type FlowCollector struct {
	mu        sync.RWMutex
	path      string
	capacity  int
	retention time.Duration
	entries   map[string]*list.Element
	order     *list.List
	available bool
	lastScan  time.Time
	evicted   uint64
	lastErr   string
}

// NewFlowCollector creates a collector for /proc/net/nf_conntrack or an injected fixture.
func NewFlowCollector(cfg Config, path string) (*FlowCollector, error) {
	if !cfg.Features.FlowReport || cfg.Telemetry.FlowMaxRecords < 1 || cfg.Telemetry.FlowRetentionHours < 1 {
		return nil, errors.New("flow reporting requires an enabled feature, record cap, and retention")
	}
	if path == "" {
		path = "/proc/net/nf_conntrack"
	}
	return &FlowCollector{path: path, capacity: cfg.Telemetry.FlowMaxRecords, retention: time.Duration(cfg.Telemetry.FlowRetentionHours) * time.Hour, entries: make(map[string]*list.Element), order: list.New()}, nil
}

// Start refreshes the conntrack snapshot until ctx is cancelled.
func (c *FlowCollector) Start(ctx context.Context) {
	c.Refresh()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Refresh()
		}
	}
}

// Refresh reads at most capacity conntrack lines and updates the bounded active-flow set.
func (c *FlowCollector) Refresh() {
	file, err := os.Open(c.path)
	if err != nil && c.path == "/proc/net/nf_conntrack" {
		file, err = os.Open("/proc/net/ip_conntrack")
	}
	if err != nil {
		c.mu.Lock()
		c.lastErr = err.Error()
		c.available = false
		c.lastScan = time.Now().UTC()
		c.mu.Unlock()
		return
	}
	defer file.Close()
	now := time.Now().UTC()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	seen := make(map[string]bool)
	lineCount := 0
	truncated := false
	for scanner.Scan() {
		lineCount++
		if lineCount > c.capacity*2 {
			truncated = true
			break
		}
		record, key, ok := parseConntrackLine(scanner.Text(), now)
		if !ok {
			continue
		}
		seen[key] = true
		c.observe(key, record)
	}
	readErr := scanner.Err()
	c.mu.Lock()
	c.lastScan = now
	c.available = readErr == nil && !truncated
	c.lastErr = ""
	if readErr != nil {
		c.lastErr = readErr.Error()
	} else if truncated {
		c.lastErr = "conntrack snapshot truncated at configured record limit"
	}
	cutoff := now.Add(-c.retention)
	for e := c.order.Front(); e != nil; {
		next := e.Next()
		entry := e.Value.(flowEntry)
		if entry.record.LastSeen.Before(cutoff) {
			delete(c.entries, entry.key)
			c.order.Remove(e)
		}
		e = next
	}
	if readErr == nil && !truncated {
		for key, element := range c.entries {
			if !seen[key] {
				c.order.Remove(element)
				delete(c.entries, key)
			}
		}
	}
	c.mu.Unlock()
}

func (c *FlowCollector) observe(key string, current FlowRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil {
		prior := e.Value.(flowEntry)
		current.FirstSeen = prior.record.FirstSeen
		e.Value = flowEntry{key: key, record: current}
		c.order.MoveToBack(e)
		return
	}
	if c.order.Len() >= c.capacity {
		oldest := c.order.Front()
		if oldest != nil {
			entry := oldest.Value.(flowEntry)
			delete(c.entries, entry.key)
			c.order.Remove(oldest)
			c.evicted++
		}
	}
	e := c.order.PushBack(flowEntry{key: key, record: current})
	c.entries[key] = e
}

// Snapshot returns a stable copy ordered by most recently observed flow.
func (c *FlowCollector) Snapshot() FlowSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := FlowSnapshot{Available: c.available, LastScan: c.lastScan, Active: c.order.Len(), Evicted: c.evicted, Error: c.lastErr, Flows: make([]FlowRecord, 0, c.order.Len())}
	for e := c.order.Back(); e != nil; e = e.Prev() {
		out.Flows = append(out.Flows, e.Value.(flowEntry).record)
	}
	return out
}

func parseConntrackLine(line string, now time.Time) (FlowRecord, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 8 || (fields[0] != "ipv4" && fields[0] != "ipv6") {
		return FlowRecord{}, "", false
	}
	protocol := strings.ToLower(fields[2])
	var srcs, dsts, sports, dports []string
	var packetCount, byteCount uint64
	for _, field := range fields[3:] {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch name {
		case "src":
			srcs = append(srcs, value)
		case "dst":
			dsts = append(dsts, value)
		case "sport":
			sports = append(sports, value)
		case "dport":
			dports = append(dports, value)
		case "packets":
			n, _ := strconv.ParseUint(value, 10, 64)
			packetCount += n
		case "bytes":
			n, _ := strconv.ParseUint(value, 10, 64)
			byteCount += n
		}
	}
	if len(srcs) == 0 || len(dsts) == 0 {
		return FlowRecord{}, "", false
	}
	src, dst := srcs[0], dsts[0]
	var replySrc, replyDst string
	if len(srcs) > 1 {
		replySrc = srcs[1]
	}
	if len(dsts) > 1 {
		replyDst = dsts[1]
	}
	var sport, dport uint16
	if len(sports) > 0 {
		n, _ := strconv.ParseUint(sports[0], 10, 16)
		sport = uint16(n)
	}
	if len(dports) > 0 {
		n, _ := strconv.ParseUint(dports[0], 10, 16)
		dport = uint16(n)
	}
	key := strings.Join([]string{protocol, src, strconv.Itoa(int(sport)), dst, strconv.Itoa(int(dport)), replySrc, replyDst}, "|")
	record := FlowRecord{ID: fmt.Sprintf("%x", hashKey(key)), Namespace: "host", Protocol: protocol, Source: src, SourcePort: sport, Destination: dst, DestPort: dport, ReplySource: replySrc, ReplyDest: replyDst, Packets: packetCount, Bytes: byteCount, FirstSeen: now, LastSeen: now}
	return record, key, true
}

func hashKey(value string) uint64 {
	const offset uint64 = 14695981039346656037
	const prime uint64 = 1099511628211
	h := offset
	for i := 0; i < len(value); i++ {
		h ^= uint64(value[i])
		h *= prime
	}
	return h
}
