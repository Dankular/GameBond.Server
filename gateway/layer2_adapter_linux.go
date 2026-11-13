//go:build linux

package gateway

import (
	"context"
	"errors"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type layer2RunnerAdapter struct{ runner Runner }

func (a layer2RunnerAdapter) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	result, err := a.runner.Run(ctx, tool, args...)
	return result.Stdout, err
}

func (a layer2RunnerAdapter) RunInput(ctx context.Context, tool string, input []byte, args ...string) ([]byte, error) {
	runner, ok := a.runner.(InputRunner)
	if !ok {
		return nil, errors.New("gateway runner does not support provider input")
	}
	result, err := runner.RunInput(ctx, tool, input, args...)
	return result.Stdout, err
}

func (a layer2RunnerAdapter) Available(tool string) bool { return a.runner.Available(tool) }

var _ layer2.HostRunner = layer2RunnerAdapter{}
