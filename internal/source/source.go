package source

import (
	"context"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type Source interface {
	Run(context.Context, chan<- model.Event) error
	Close() error
}
