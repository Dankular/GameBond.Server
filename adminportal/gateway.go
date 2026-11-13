package adminportal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxGatewayResponse = 1 << 20

// GatewayClient speaks only the bounded, allowlisted API over a local Unix socket.
type GatewayClient struct {
	socket string
	client *http.Client
}

func NewGatewayClient(socket string) (*GatewayClient, error) {
	if socket == "" || !strings.HasPrefix(socket, "/") || strings.Contains(socket, "..") || len(socket) > 100 {
		return nil, errors.New("gateway socket path must be an absolute local path shorter than 100 bytes")
	}
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	return &GatewayClient{socket: socket, client: &http.Client{Transport: transport, Timeout: 3 * time.Second}}, nil
}

func (c *GatewayClient) Request(ctx context.Context, method, endpoint string, config json.RawMessage) (json.RawMessage, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("gateway socket is not configured")
	}
	if !(method == http.MethodGet && endpoint == "/v1/status") &&
		!(method == http.MethodPost && endpoint == "/v1/config/validate") &&
		!(method == http.MethodPut && endpoint == "/v1/config") {
		return nil, errors.New("gateway endpoint is not allowed")
	}
	var body io.Reader
	if method != http.MethodGet {
		if len(config) == 0 || len(config) > maxBody || !json.Valid(config) || config[0] != '{' {
			return nil, errors.New("gateway config must be a bounded JSON object")
		}
		body = bytes.NewReader(config)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://gateway"+endpoint, body)
	if err != nil {
		return nil, err
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway daemon unavailable: %w", err)
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(io.LimitReader(resp.Body, maxGatewayResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read gateway response: %w", err)
	}
	if len(result) > maxGatewayResponse {
		return nil, errors.New("gateway response exceeds 1 MiB")
	}
	if !json.Valid(result) {
		return nil, errors.New("gateway returned invalid JSON")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(result, &problem)
		if problem.Error == "" {
			problem.Error = "gateway request failed"
		}
		return nil, fmt.Errorf("gateway returned %d: %s", resp.StatusCode, problem.Error)
	}
	return result, nil
}
