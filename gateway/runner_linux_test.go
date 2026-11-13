//go:build linux

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerRequiresAllowlistedTool(t *testing.T) {
	r := newExecRunner(map[string]string{"ip": "/bin/echo"}, time.Second)
	if _, err := r.Run(context.Background(), "sh", "-c", "true"); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist rejection, got %v", err)
	}
}

func TestExecRunnerReturnsBoundedOutput(t *testing.T) {
	r := newExecRunner(map[string]string{"ip": "/bin/echo"}, time.Second)
	arg := strings.Repeat("x", maxCommandOutput+1)
	if _, err := r.Run(context.Background(), "ip", arg); err == nil || !strings.Contains(err.Error(), "output limit") {
		t.Fatalf("expected output limit error, got %v", err)
	}
}

func TestExecRunnerHonorsDeadline(t *testing.T) {
	r := newExecRunner(map[string]string{"ip": "/bin/sleep"}, 10*time.Millisecond)
	start := time.Now()
	if _, err := r.Run(context.Background(), "ip", "1"); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("runner exceeded its configured deadline")
	}
}

func TestExecRunnerRejectsOversizedArgumentsBeforeExecution(t *testing.T) {
	r := newExecRunner(map[string]string{"ip": "/bin/echo"}, time.Second)
	arg := strings.Repeat("x", maxCommandArguments+1)
	if _, err := r.Run(context.Background(), "ip", arg); err == nil || !strings.Contains(err.Error(), "argument limit") {
		t.Fatalf("expected argument limit error, got %v", err)
	}
}

func TestExecRunnerPassesBoundedInputToAllowlistedTool(t *testing.T) {
	r := newExecRunner(map[string]string{"nft": "/bin/cat"}, time.Second)
	result, err := r.RunInput(context.Background(), "nft", []byte("ruleset\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "ruleset\n" {
		t.Fatalf("stdin echo = %q", result.Stdout)
	}
	if _, err := r.RunInput(context.Background(), "nft", []byte(strings.Repeat("x", maxCommandArguments+1))); err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("expected input size limit, got %v", err)
	}
}
