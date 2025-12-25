package log

import (
	"context"
	"log/slog"

	"github.com/hyperledger-labs/yui-relayer/log"
)

const LoggerKey = "ELCUpdaterLogger"

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

// GetLogger returns a logger for ELCUpdater operations, always returns a logger (using DiscardHandler as fallback)
func GetLogger(ctx context.Context) *log.RelayLogger {
	if logger := GetLoggerOrNil(ctx); logger != nil {
		return logger
	}

	if logger := log.GetLogger(); logger != nil {
		return logger.WithModule("elc-updater")
	}

	// Fallback to a null logger if GetLogger returns nil
	discardLogger := slog.New(&discardHandler{})
	return &log.RelayLogger{
		Logger: discardLogger,
	}
}

// GetLoggerOrNil returns a logger for ELC updater operations from context, or nil if not found
func GetLoggerOrNil(ctx context.Context) *log.RelayLogger {
	if v := ctx.Value(LoggerKey); v != nil {
		return v.(*log.RelayLogger)
	}
	return nil
}

func SetLogger(ctx context.Context, logger *log.RelayLogger) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}
