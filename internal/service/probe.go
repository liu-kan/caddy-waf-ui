package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// ProbeRuleID is reserved for revision-specific origin verification.
const ProbeRuleID = 9001200

func verifyOrigin(g waf.Generated) (journal.Stage, error) {
	stage := journal.Stage{Name: "request", Result: "skipped", Detail: "No origin probe URL configured; only Admin API read-back verified"}
	raw := config.ProbeURLs()
	if raw == "" {
		return stage, nil
	}
	var urls map[string]string
	if json.Unmarshal([]byte(raw), &urls) != nil {
		return stage, errors.New("invalid CADDY_UI_PROBE_URLS JSON")
	}
	target := urls[g.Signature.Site]
	if target == "" {
		return stage, nil
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return stage, errors.New("invalid configured origin probe URL")
	}
	offset := int64(0)
	if fi, err := os.Stat(config.AuditLogPath()); err == nil {
		offset = fi.Size()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return stage, err
	}
	req.Host = g.Signature.Site
	req.Header.Set("X-Caddy-WAF-Probe", g.Revision)
	req.Header.Set("User-Agent", "caddy-waf-ui-origin-probe/1")
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: g.Signature.Site}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return stage, fmt.Errorf("origin request failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return stage, fmt.Errorf("origin probe returned HTTP %d", resp.StatusCode)
	}
	if g.Signature.Mode == "Off" {
		stage.Result = "success"
		stage.Detail = "Origin reachable; Off mode and revision verified by Admin API (no WAF audit expected)"
		return stage, nil
	}
	if g.Signature.Mode == "On" && resp.StatusCode != 418 {
		return stage, fmt.Errorf("on-mode probe expected HTTP 418, received %d", resp.StatusCode)
	}
	for {
		if auditHasProbe(config.AuditLogPath(), offset, g.Signature) {
			stage.Result = "success"
			stage.Detail = "Revision and engine mode confirmed in origin audit record"
			return stage, nil
		}
		select {
		case <-ctx.Done():
			return stage, errors.New("origin probe was not confirmed in the audit log")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func auditHasProbe(path string, offset int64, sig waf.Signature) bool {
	f, err := os.Open(path) //nolint:gosec // G304: operator-configured audit path; never derived from request data.
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.Size() < offset {
		offset = 0
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var rec struct {
			Transaction struct {
				Producer struct {
					Rulesets   []string `json:"rulesets"`
					RuleEngine string   `json:"rule_engine"`
				} `json:"producer"`
			} `json:"transaction"`
			Messages []struct {
				Actionset string `json:"actionset"`
				Data      struct {
					ID int `json:"id"`
				} `json:"data"`
			} `json:"messages"`
		}
		if dec.Decode(&rec) != nil {
			return false
		}
		sets := []string{}
		hit := false
		for _, m := range rec.Messages {
			sets = append(sets, m.Actionset)
			if m.Data.ID == ProbeRuleID {
				hit = true
			}
		}
		actual, ok := waf.FindSignature(rec.Transaction.Producer.Rulesets, sets...)
		if hit && ok && actual.Revision == sig.Revision && actual.Site == sig.Site && strings.EqualFold(rec.Transaction.Producer.RuleEngine, sig.Mode) {
			return true
		}
	}
}

func saveLastGood(site string, g waf.Generated, stages []journal.Stage) error {
	dir := filepath.Join(config.DataDir(), "releases", domain.DomainSlug(site))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := files.AtomicWrite(filepath.Join(dir, "last_good.conf"), g.Content); err != nil {
		return err
	}
	metadata := struct {
		Revision string          `json:"revision"`
		SHA256   string          `json:"sha256"`
		Checked  time.Time       `json:"checked"`
		Stages   []journal.Stage `json:"stages"`
	}{g.Revision, checksum(g.Content), time.Now().UTC(), stages}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return files.AtomicWrite(filepath.Join(dir, "last_good.json"), raw)
}
