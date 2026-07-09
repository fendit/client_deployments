package main

import (
	"bufio"
	stdlog "log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// version is injected at build time: go build -ldflags "-X main.version=2.1.0"
var version = "dev"

var (
	logger    zerolog.Logger
	logRoller *lumberjack.Logger
	logOnce   sync.Once
)

// initLogger configures the global structured logger. Must be called in main()
// before any goroutine starts. Idempotent.
//
// Output:
//   - JSON → rotating file (5 MB × 3 backups, compressed)
//   - Human-readable → stderr for interactive / RMM sessions
func initLogger() {
	logOnce.Do(func() {
		dir := logDir()
		_ = os.MkdirAll(dir, 0700)

		logRoller = &lumberjack.Logger{
			Filename:   filepath.Join(dir, "agent.log"),
			MaxSize:    5,
			MaxBackups: 3,
			Compress:   true,
		}

		multi := zerolog.MultiLevelWriter(
			logRoller,
			zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
		)
		zerolog.TimeFieldFormat = time.RFC3339
		zerolog.SetGlobalLevel(zerolog.InfoLevel)

		logger = zerolog.New(multi).With().
			Timestamp().
			Str("version", version).
			Str("goos", runtime.GOOS).
			Logger()

		// Bridge stdlib log → zerolog so all log.Printf/Println/Fatalf calls
		// in other files are captured in the structured log file without changing them.
		stdlog.SetFlags(0)
		stdlog.SetOutput(logger)
	})
}

// handlePanic must be called via defer in main(). It catches any unhandled
// panic, flushes the full stack trace to the log, attempts a last-gasp crash
// report to the SOC backend, and terminates with exit code 2.
func handlePanic() {
	r := recover()
	if r == nil {
		return
	}
	stack := debug.Stack()
	logger.Error().
		Interface("panic", r).
		Str("stack_trace", string(stack)).
		Msg("unhandled panic — fendit-agent terminating")

	if daemonCfg != nil {
		sendCrashReport(daemonCfg, stack)
	}

	if logRoller != nil {
		logRoller.Close()
	}
	os.Exit(2)
}

// logFilePath returns the path of the active log file.
func logFilePath() string {
	if logRoller != nil {
		return logRoller.Filename
	}
	return filepath.Join(logDir(), "agent.log")
}

// readTailLines returns the last n lines of the log file using an in-memory
// ring buffer — O(n) memory regardless of file size.
func readTailLines(n int) []string {
	f, err := os.Open(logFilePath())
	if err != nil {
		return nil
	}
	defer f.Close()

	ring := make([]string, 0, n+1)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ring = append(ring, scanner.Text())
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	return ring
}
