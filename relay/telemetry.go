package relay

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"context"
	"sync"
)

type Int64Gauge struct {
	gauge   metric.Int64Gauge
	options []metric.RecordOption
	mutex   sync.Mutex
}

var (
	tracer = otel.Tracer("github.com/datachainlab/lcp-go/relay")
	meter  = otel.Meter("github.com/datachainlab/lcp-go/relay")
)

const (
	namespaceRoot = "relayer.lcp_go"
)

func NewInt64Gauge(name string, desc string, options ...metric.RecordOption) (*Int64Gauge, error) {
	fullname := fmt.Sprintf("%s.%s", namespaceRoot, name)

	gauge, err := meter.Int64Gauge(
		fullname,
		metric.WithUnit("1"),
		metric.WithDescription(desc),
	)
	if err != nil {
		return nil, err
	}
	return &Int64Gauge{
		gauge:   gauge,
		options: options,
		mutex:   sync.Mutex{},
	}, nil
}

func (g *Int64Gauge) Set(ctx context.Context, value int64) {
	if g == nil {
		return
	}

	g.mutex.Lock()
	defer g.mutex.Unlock()

	if g.gauge != nil {
		g.gauge.Record(ctx, value, g.options...)
	}
}
