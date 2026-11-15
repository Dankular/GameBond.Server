//go:build !linux

package inspection

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
)

const DefaultProxyPort = 9445

type URLPolicy func(device netip.Addr, host, path string) (ruleID, action string, matched bool)

type ProxyStatus struct {
	Ready         bool   `json:"ready"`
	Active        int    `json:"active_sessions"`
	Maximum       int    `json:"max_sessions"`
	Rejected      uint64 `json:"rejected"`
	Bypassed      uint64 `json:"bypassed"`
	Errors        uint64 `json:"errors"`
	PolicyMatches uint64 `json:"policy_matches"`
	PolicyDenied  uint64 `json:"policy_denied"`
}

// Proxy keeps the security manager API available on platforms where the
// transparent TLS inspection listener is not implemented.
type Proxy struct {
	CA      *CA
	Limiter *Limiter
	Port    int
	errors  atomic.Uint64
}

func (p *Proxy) SetPolicy(URLPolicy) {}

func (p *Proxy) SetExhaustionAction(string) {}

func (p *Proxy) Status() ProxyStatus {
	status := ProxyStatus{Errors: p.errors.Load()}
	if p.Limiter != nil {
		status.Active = p.Limiter.Active()
		status.Maximum = p.Limiter.Limit()
		status.Rejected = p.Limiter.Rejected()
	}
	return status
}

func (p *Proxy) RecordError() { p.errors.Add(1) }

func (p *Proxy) Run(context.Context) error {
	return errors.New("inspection: transparent proxy is only supported on Linux")
}
