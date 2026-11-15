//go:build linux

package edge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"golang.org/x/sys/unix"
)

type kernelVXLANAttachments struct {
	cancel    context.CancelFunc
	items     []kernelVXLANAttachmentRuntime
	wg        sync.WaitGroup
	closeOnce sync.Once
}

type kernelVXLANAttachmentRuntime struct {
	id             string
	fd             int
	port           *SegmentPort
	ingressRejects atomic.Uint64
	tapWriteDrops  atomic.Uint64
}

func (a *kernelVXLANAttachments) Stats() []map[string]any {
	if a == nil {
		return nil
	}
	rows := make([]map[string]any, 0, len(a.items))
	for i := range a.items {
		rows = append(rows, map[string]any{"id": a.items[i].id, "ingress_switch_rejects": a.items[i].ingressRejects.Load(), "tap_write_drops": a.items[i].tapWriteDrops.Load()})
	}
	return rows
}

func (a *kernelVXLANAttachments) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		if a.cancel != nil {
			a.cancel()
		}
		for i := range a.items {
			a.items[i].port.Close()
			_ = unix.Close(a.items[i].fd)
		}
		a.wg.Wait()
	})
}

// startKernelVXLANAttachments connects broker-owned per-VNI TAP devices to the
// segment switch. The kernel bridge and VXLAN netdevice perform encapsulation.
func startKernelVXLANAttachments(ctx context.Context, c *L2Config, fabric *SegmentFabric) (*kernelVXLANAttachments, error) {
	if c == nil || len(c.KernelVXLANAttachments) == 0 {
		return &kernelVXLANAttachments{}, nil
	}
	if fabric == nil {
		return nil, errors.New("kernel VXLAN TAP attachments require a segment fabric")
	}
	if err := c.validateKernelVXLANAttachments(); err != nil {
		return nil, err
	}
	runtime := &kernelVXLANAttachments{items: make([]kernelVXLANAttachmentRuntime, 0, len(c.KernelVXLANAttachments))}
	cleanup := func() {
		for i := range runtime.items {
			runtime.items[i].port.Close()
			_ = unix.Close(runtime.items[i].fd)
		}
	}
	for _, attachment := range c.KernelVXLANAttachments {
		fd, err := openTap(attachment.TapName, c.FrameMTU-bond.EthHeaderLen)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("open kernel VXLAN TAP %q: %w", attachment.TapName, err)
		}
		port, err := fabric.AttachService(bond.L2PortConfig{Name: "kernel-vxlan-" + attachment.ID, VLAN: bond.L2VLANPolicy{AccessVLAN: attachment.VLAN}, MulticastRouter: true}, 0, false, false)
		if err != nil {
			_ = unix.Close(fd)
			cleanup()
			return nil, fmt.Errorf("attach kernel VXLAN TAP %q to segment: %w", attachment.TapName, err)
		}
		runtime.items = append(runtime.items, kernelVXLANAttachmentRuntime{id: attachment.ID, fd: fd, port: port})
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.cancel = cancel
	for i := range runtime.items {
		item := &runtime.items[i]
		runtime.wg.Add(2)
		go func() {
			defer runtime.wg.Done()
			buf := make([]byte, c.FrameMTU+bond.EthHeaderLen+4)
			poll := []unix.PollFd{{Fd: int32(item.fd), Events: unix.POLLIN}}
			for {
				select {
				case <-runCtx.Done():
					return
				default:
				}
				poll[0].Revents = 0
				if _, err := unix.Poll(poll, 100); err != nil {
					if err == unix.EINTR {
						continue
					}
					return
				}
				if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
					return
				}
				if poll[0].Revents&unix.POLLIN == 0 {
					continue
				}
				n, err := unix.Read(item.fd, buf)
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
					continue
				}
				if err != nil || n == 0 {
					return
				}
				if !forwardKernelVXLANIngress(item.port.Send, buf[:n], time.Now()) {
					item.ingressRejects.Add(1)
				}
			}
		}()
		go func() {
			defer runtime.wg.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				case delivery, ok := <-item.port.Receive():
					if !ok {
						return
					}
					if !writeKernelVXLANFrame(func(frame []byte) (int, error) { return unix.Write(item.fd, frame) }, delivery.Frame) {
						item.tapWriteDrops.Add(1)
					}
				}
			}
		}()
	}
	return runtime, nil
}

func forwardKernelVXLANIngress(send func([]byte, time.Time) bond.L2Verdict, frame []byte, now time.Time) bool {
	return send(frame, now).Drop == bond.L2Forward
}

func writeKernelVXLANFrame(write func([]byte) (int, error), frame []byte) bool {
	n, err := write(frame)
	return err == nil && n == len(frame)
}
