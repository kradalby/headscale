package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

var (
	errWebhookURL        = errors.New("url must be an http or https URL")
	errWebhookRecordType = errors.New("webhook provider only handles TXT records")
	errWebhookStatus     = errors.New("webhook returned an error")
)

const webhookTimeout = 30 * time.Second

// WebhookProvider publishes records through an HTTP endpoint using
// lego's httpreq protocol, so DNS providers headscale does not compile in
// can be reached through an existing httpreq server or a small sidecar:
//
//	POST <url>/present {"fqdn": "_acme-challenge.node.example.com.", "value": "..."}
//	POST <url>/cleanup {"fqdn": "_acme-challenge.node.example.com.", "value": "..."}
//
// Any 2xx response is success.
type WebhookProvider struct {
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type webhookMessage struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

func (w *WebhookProvider) validate() error {
	u, err := url.Parse(w.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: %q", errWebhookURL, w.URL)
	}

	return nil
}

// AppendRecords returns the input records unchanged: the endpoint has no
// record identity to report, and certmagic matches the returned record
// against the value it asked for.
func (w *WebhookProvider) AppendRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	for i, rec := range recs {
		err := w.post(ctx, "present", zone, rec)
		if err != nil {
			return recs[:i], err
		}
	}

	return recs, nil
}

func (w *WebhookProvider) DeleteRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	for i, rec := range recs {
		err := w.post(ctx, "cleanup", zone, rec)
		if err != nil {
			return recs[:i], err
		}
	}

	return recs, nil
}

func (w *WebhookProvider) post(
	ctx context.Context,
	action, zone string,
	rec libdns.Record,
) error {
	rr := rec.RR()
	if rr.Type != "TXT" {
		return fmt.Errorf("%w, got %s", errWebhookRecordType, rr.Type)
	}

	body, err := json.Marshal(webhookMessage{
		FQDN:  libdns.AbsoluteName(rr.Name, zone),
		Value: rr.Data,
	})
	if err != nil {
		return fmt.Errorf("encoding webhook body: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimSuffix(w.URL, "/")+"/"+action,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if w.Username != "" {
		req.SetBasicAuth(w.Username, w.Password)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling webhook %s: %w", action, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return fmt.Errorf("%w: %s %s: %s", errWebhookStatus, action, resp.Status, bytes.TrimSpace(msg))
	}

	return nil
}
