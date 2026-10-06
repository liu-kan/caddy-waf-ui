package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/textdiff"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

var ErrStaleDraft = errors.New("the draft changed or expired; preview again before applying")

type Draft struct {
	ID         string          `json:"id"`
	Site       string          `json:"site"`
	Kind       string          `json:"kind"`
	Created    time.Time       `json:"created"`
	Base       string          `json:"base"`
	SHA256     string          `json:"sha256"`
	Generated  waf.Generated   `json:"generated"`
	Policy     *waf.Policy     `json:"policy,omitempty"`
	Exclusions []waf.Exclusion `json:"exclusions,omitempty"`
}

func draftPath(site string) string {
	return filepath.Join(config.DataDir(), "drafts", domain.DomainSlug(site)+".json")
}
func checksum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func baselineHash(site string) (string, error) {
	h := sha256.New()
	for _, path := range []string{files.WAFConfigPath(config.ManagedDir(), site), files.ExclusionsConfigPath(config.ManagedDir(), site), files.IPRulesConfigPath(config.ManagedDir(), site), config.CaddyfilePath(), config.BeforeFile(), config.AfterFile()} {
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: validated site paths and operator-owned baseline includes.
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(path), path, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func saveDraft(site, kind string, o wafOverride) (Preview, error) {
	changeMu.Lock()
	defer changeMu.Unlock()
	base, err := baselineHash(site)
	if err != nil {
		return Preview{}, err
	}
	g, err := renderSiteWAF(site, o)
	if err != nil {
		return Preview{}, err
	}
	current, _, err := readPreviousState(files.WAFConfigPath(config.ManagedDir(), site))
	if err != nil {
		return Preview{}, err
	}
	d := Draft{ID: g.Revision, Site: site, Kind: kind, Created: time.Now().UTC(), Base: base, SHA256: checksum(g.Content), Generated: g, Policy: o.policy}
	if o.exclusions != nil {
		d.Exclusions = *o.exclusions
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return Preview{}, err
	}
	if err := os.MkdirAll(filepath.Dir(draftPath(site)), 0o750); err != nil {
		return Preview{}, err
	}
	if err := files.AtomicWrite(draftPath(site), raw); err != nil {
		return Preview{}, err
	}
	p, err := previewDiff(current, g.Content)
	p.DraftID = d.ID
	p.SHA256 = d.SHA256
	return p, err
}
func previewDiff(before, after []byte) (Preview, error) {
	return Preview{Content: string(after), Diff: textdiff.Unified(string(before), string(after), 2, diffIgnore)}, nil
}
func CreatePolicyDraft(site string, p waf.Policy) (Preview, error) {
	if err := ValidateDomain(site); err != nil {
		return Preview{}, err
	}
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return Preview{}, err
	}
	return saveDraft(site, "policy", wafOverride{policy: &p})
}
func CreateExclusionsDraft(site string, list []waf.Exclusion) (Preview, error) {
	if err := ValidateDomain(site); err != nil {
		return Preview{}, err
	}
	if err := waf.ValidateExclusions(list); err != nil {
		return Preview{}, err
	}
	return saveDraft(site, "exclusions", wafOverride{exclusions: &list})
}
func loadDraft(site, id, kind string) (Draft, error) {
	if err := ValidateDomain(site); err != nil {
		return Draft{}, err
	}
	raw, err := os.ReadFile(draftPath(site))
	if err != nil {
		return Draft{}, ErrStaleDraft
	}
	var d Draft
	if json.Unmarshal(raw, &d) != nil || d.ID != id || d.Site != site || d.Kind != kind || time.Since(d.Created) > 30*time.Minute || checksum(d.Generated.Content) != d.SHA256 {
		return Draft{}, ErrStaleDraft
	}
	return d, nil
}
func ApplyPolicyDraft(a Actor, site string, p waf.Policy, id string) error {
	d, err := loadDraft(site, id, "policy")
	if err != nil {
		return err
	}
	p = p.Normalize()
	want, _ := json.Marshal(p)
	got, _ := json.Marshal(d.Policy)
	if string(want) != string(got) {
		return ErrStaleDraft
	}
	return applyDraft(a, d)
}
func ApplyExclusionsDraft(a Actor, site string, list []waf.Exclusion, id string) error {
	d, err := loadDraft(site, id, "exclusions")
	if err != nil {
		return err
	}
	want, _ := json.Marshal(list)
	got, _ := json.Marshal(d.Exclusions)
	if string(want) != string(got) {
		return ErrStaleDraft
	}
	return applyDraft(a, d)
}
func applyDraft(a Actor, d Draft) error {
	opts := chainOpts{fileType: files.FileTypeWAF, confPath: files.WAFConfigPath(config.ManagedDir(), d.Site), action: d.Kind, summary: "applied reviewed " + d.Kind + " draft", successEvent: d.Kind + "_updated", failEvent: d.Kind + "_failed", reloadFailEvent: "draft_reload_failed", base: d.Base}
	if d.Kind == "exclusions" {
		opts.fileType = files.FileTypeExclusions
		opts.confPath = files.ExclusionsConfigPath(config.ManagedDir(), d.Site)
		opts.mutate = func() error {
			content, err := waf.GenerateExclusions(&domain.Site{Domain: d.Site}, d.Exclusions)
			if err != nil {
				return err
			}
			return files.AtomicWrite(opts.confPath, content)
		}
	}
	opts.regenerate = func() (waf.Generated, error) {
		if err := files.AtomicWrite(files.WAFConfigPath(config.ManagedDir(), d.Site), d.Generated.Content); err != nil {
			return waf.Generated{}, err
		}
		return d.Generated, nil
	}
	return runChain(d.Site, a, opts)
}
