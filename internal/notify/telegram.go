package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/almerandika/reconciler/internal/config"
)

type Notifier struct {
	cfg    config.Telegram
	client *http.Client
}

func New(cfg config.Telegram) *Notifier {
	return &Notifier{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

// Enabled reports whether a bot token and chat are configured.
func (n *Notifier) Enabled() bool { return n.cfg.BotToken != "" && n.cfg.ChatID != "" }

// Send posts a message. Notification failure is never fatal: the reconcile
// already happened, and a dead bot token must not turn a successful deploy into
// a failed run.
func (n *Notifier) Send(ctx context.Context, text string) error {
	if !n.Enabled() || text == "" {
		return nil
	}
	// Telegram caps messages at 4096 characters.
	if len(text) > 3900 {
		text = text[:3900] + "\n… (truncated)"
	}

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage",
		url.PathEscape(n.cfg.BotToken))
	body, err := json.Marshal(map[string]any{
		"chat_id":                  n.cfg.ChatID,
		"text":                     text,
		"disable_web_page_preview": true,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram returned %d: %s", resp.StatusCode, snippet)
	}
	return nil
}
