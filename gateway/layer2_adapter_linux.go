//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type layer2RunnerAdapter struct{ runner Runner }

func (a layer2RunnerAdapter) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if links, ok := a.runner.(interface {
		SetLinkUp(context.Context, string, bool) error
		SetMaster(context.Context, string, string) error
		SetMTU(context.Context, string, int) error
	}); ok {
		if err := runRtnetlinkLinkCommand(ctx, links, tool, args); err == nil {
			return nil, nil
		} else if !errors.Is(err, errNotRtnetlinkLinkCommand) {
			return nil, err
		}
	}
	result, err := a.runner.Run(ctx, tool, args...)
	return result.Stdout, err
}

var errNotRtnetlinkLinkCommand = errors.New("not a rtnetlink link command")

func runRtnetlinkLinkCommand(ctx context.Context, links interface {
	SetLinkUp(context.Context, string, bool) error
	SetMaster(context.Context, string, string) error
	SetMTU(context.Context, string, int) error
}, tool string, args []string) error {
	if tool != "ip" || len(args) < 5 || args[0] != "link" || args[1] != "set" || args[2] != "dev" {
		return errNotRtnetlinkLinkCommand
	}
	name := args[3]
	switch {
	case len(args) == 5 && args[4] == "up":
		return links.SetLinkUp(ctx, name, true)
	case len(args) == 5 && args[4] == "down":
		return links.SetLinkUp(ctx, name, false)
	case len(args) == 5 && args[4] == "nomaster":
		return links.SetMaster(ctx, name, "")
	case len(args) == 6 && args[4] == "master":
		return links.SetMaster(ctx, name, args[5])
	case len(args) == 6 && args[4] == "mtu":
		mtu, err := strconv.Atoi(args[5])
		if err != nil {
			return fmt.Errorf("parse rtnetlink MTU: %w", err)
		}
		return links.SetMTU(ctx, name, mtu)
	default:
		return errNotRtnetlinkLinkCommand
	}
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
