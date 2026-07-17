package main

// socket_client.go — Persistent Direct Socket to Fendit Guardian.
//
// The Go agent maintains a long-lived WebSocket connection to Guardian.
// Guardian pushes commands (quarantine, restore, kill_process, …) instantly
// over this channel and receives synchronous execution feedback within the
// same connection — no 5-second DB poll cycle involved.
//
// On disconnect the goroutine reconnects with exponential back-off (max 2 min).
// The existing HTTP poll path (runActionPoller) remains active as a fallback
// for commands that arrive while the socket is temporarily down.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wsInitialBackoff = 2 * time.Second
	wsMaxBackoff     = 2 * time.Minute
	wsPingInterval   = 30 * time.Second
	wsWriteTimeout   = 10 * time.Second
)

// DirectCommand is sent from Guardian to the agent via WebSocket.
// Args map 1:1 with the Intent.Args used by the existing ExecutionEngine.
type DirectCommand struct {
	CmdID  string                 `json:"cmd_id"`
	Action string                 `json:"action"`
	Args   map[string]interface{} `json:"args"`
}

// DirectResult is the agent's synchronous reply sent back to Guardian.
type DirectResult struct {
	CmdID        string `json:"cmd_id"`
	Success      bool   `json:"success"`
	Output       string `json:"output,omitempty"`
	Error        string `json:"error,omitempty"`
	QuarantineID string `json:"quarantine_id,omitempty"`
	OriginalPath string `json:"original_path,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
}

// runDirectSocket is launched as a goroutine from startDaemon.
// It connects to Guardian's WebSocket endpoint, executes incoming commands
// via the existing Intent/ExecutionEngine, and returns results immediately.
func runDirectSocket(ctx context.Context, cfg *Config) {
	backoff := wsInitialBackoff
	for {
		if err := dialAndServe(ctx, cfg); err != nil {
			logger.Warn().Err(err).Dur("backoff", backoff).Msg("[socket] reconnecting...")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			if backoff < wsMaxBackoff {
				backoff *= 2
			}
		}
	}
}

func directSocketURL(cfg *Config) string {
	// Convert https:// → wss://, http:// → ws:// for the WebSocket dial.
	base := strings.Replace(cfg.APIBase, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)
	return base + pathDirectSocket + "?token=" + url.QueryEscape(cfg.ReflexToken)
}

func dialAndServe(ctx context.Context, cfg *Config) error {
	wsURL := directSocketURL(cfg)
	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, wsURL, http.Header{
		"User-Agent": []string{"Fendit-Agent/2.0"},
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Reset back-off on a successful connection.
	logger.Info().Msg("[socket] Direct Socket connected to Guardian")

	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPingInterval * 2))
	})

	cmdCh := make(chan DirectCommand, 8)
	errCh := make(chan error, 1)

	// Read pump — blocks on ReadMessage and forwards commands to cmdCh.
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				errCh <- fmt.Errorf("read: %w", err)
				return
			}
			var cmd DirectCommand
			if jsonErr := json.Unmarshal(msg, &cmd); jsonErr != nil {
				logger.Warn().Err(jsonErr).Msg("[socket] ignoring malformed command")
				continue
			}
			cmdCh <- cmd
		}
	}()

	pingTicker := time.NewTicker(wsPingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shutdown"))
			return nil

		case err := <-errCh:
			return err

		case <-pingTicker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return fmt.Errorf("ping: %w", err)
			}

		case cmd := <-cmdCh:
			result := executeDirectCommand(cmd)
			resp, _ := json.Marshal(result)
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
	}
}

// executeDirectCommand routes a WebSocket command through the existing
// Intent / ExecutionEngine — zero code duplication with the HTTP poll path.
func executeDirectCommand(cmd DirectCommand) DirectResult {
	intent := &Intent{
		ID:     cmd.CmdID,
		Action: cmd.Action,
		Args:   cmd.Args,
	}

	ar := intent.Execute()

	return DirectResult{
		CmdID:        cmd.CmdID,
		Success:      ar.Success,
		Output:       ar.Output,
		Error:        ar.Error,
		QuarantineID: ar.QuarantineID,
		OriginalPath: ar.OriginalPath,
		SHA256:       ar.SHA256,
	}
}
