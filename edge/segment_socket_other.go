//go:build !linux

package edge

import (
	"context"
	"errors"

	"github.com/Dankular/GameBond.Core/bond"
)

func NewRemoteSegmentFabric(string, string, string, []byte) (*SegmentFabric, error) {
	return nil, errors.New("segment socket: remote attachments are supported on Linux only")
}

func NewRemoteSegmentFabricContext(context.Context, string, string, string, []byte) (*SegmentFabric, error) {
	return nil, errors.New("segment socket: remote attachments are supported on Linux only")
}

func (f *SegmentFabric) attachRemote(_ bond.L2PortConfig, _ int) (*SegmentPort, error) {
	return nil, errors.New("segment socket: remote attachments are supported on Linux only")
}
