package relay

import "go.opentelemetry.io/otel"

var (
	tracer = otel.Tracer("github.com/datachainlab/lcp-go/relay")
)
