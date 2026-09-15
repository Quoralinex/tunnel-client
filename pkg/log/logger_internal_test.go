package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

func TestLevelControllerPreservesBaseDefaultHandlerFiltering(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
	controller, err := NewLevelController(&runtimeconfig.LoggingConfig{Level: slog.LevelDebug})
	if err != nil {
		t.Fatalf("NewLevelController returned error: %v", err)
	}

	logger := slog.New(newDefaultHandler(base, controller)).With(slog.String("test", "base-filtering"))
	logger.Warn("warn-should-still-be-filtered")
	if strings.Contains(buf.String(), "warn-should-still-be-filtered") {
		t.Fatalf("did not expect warn line to bypass base handler filtering, got: %s", buf.String())
	}

	logger.Error("error-should-pass")
	if !strings.Contains(buf.String(), "error-should-pass") {
		t.Fatalf("expected error line to pass base handler filtering, got: %s", buf.String())
	}
}
