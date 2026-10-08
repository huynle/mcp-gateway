package observability

import (
	"fmt"
	"io"
	"log/slog"
)

// NewLogger builds the process logger. level is one of debug, info, warn,
// error; format is json or text. Both are validated by the config package,
// so unknown values are programmer errors.
func NewLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("log format %q: must be json or text", format)
	}
	return slog.New(h), nil
}
