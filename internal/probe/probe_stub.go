//go:build !linux

package probe

import (
	"context"
	"fmt"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type Live struct{}

func NewLive() (*Live, error) {
	return nil, fmt.Errorf("live eBPF collection is supported only on Linux")
}

func (live *Live) Run(context.Context, chan<- model.Event) error {
	return fmt.Errorf("live eBPF collection is supported only on Linux")
}

func (live *Live) Close() error {
	return nil
}
