package shfu_logger

import (
	"context"
	"log/slog"

	"github.com/hyperledger-labs/yui-relayer/log"
)

const SHFULoggerKey = "SHFULogger"

// NOTE that go 1.24 has slog.DiscardHandler, but for compatibility with go 1.23, we define our own discardHandler here.
type discardHandler struct{}

var _ slog.Handler = (*discardHandler)(nil)

func (h *discardHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return false
}

func (h *discardHandler) Handle(ctx context.Context, record slog.Record) error {
	return nil
}

func (h *discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *discardHandler) WithGroup(name string) slog.Handler {
	return h
}

// GetSHFULogger returns a logger for SHFU operations, always returns a logger (using DiscardHandler as fallback)
func GetSHFULogger(ctx context.Context) *log.RelayLogger {
	if logger := GetSHFULoggerOrNil(ctx); logger != nil {
		return logger
	}

	if logger := log.GetLogger(); logger != nil {
		return logger.WithModule("shfu")
	}

	// Fallback to a null logger if GetLogger returns nil
	discardLogger := slog.New(&discardHandler{})
	return &log.RelayLogger{
		Logger: discardLogger,
	}
}

// GetSHFULoggerOrNil returns a logger for SHFU operations from context, or nil if not found
func GetSHFULoggerOrNil(ctx context.Context) *log.RelayLogger {
	if v := ctx.Value(SHFULoggerKey); v != nil {
		return v.(*log.RelayLogger)
	}
	return nil
}

func SetSHFULogger(ctx context.Context, logger *log.RelayLogger) context.Context {
	return context.WithValue(ctx, SHFULoggerKey, logger)
}
