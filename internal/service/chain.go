package service

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/developmi/caddy-waf-ui/internal/caddy"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/metrics"
	"github.com/developmi/caddy-waf-ui/internal/textdiff"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// ErrInvalidMode signals an unsupported WAF mode: REST handlers translate it
// to 400 Bad Request.
var ErrInvalidMode = errors.New("invalid WAF mode: only On, Off or DetectionOnly are supported")

// ErrInvalidPolicy wraps policy validation failures (400 Bad Request).
var ErrInvalidPolicy = errors.New("invalid WAF policy")

// A reload reads all overlays. Serialize complete write/reload/restore
// transactions, including updates to different domains.
var changeMu sync.Mutex

// Actor identifies who requested a change and why. It is recorded in the
// change journal; it never grants authority.
type Actor struct {
	RemoteIP string
	User     string
	Reason   string
}

func baselineOptions() waf.Options {
	return waf.Options{
		VerifyProbe: config.ProbeURLs() != "", CRSMode: config.CRSMode(), CorazaConfig: config.CorazaConfig(),
		CRSSetup: config.CRSSetup(), CRSRules: config.CRSRules(),
		BeforeFile: config.BeforeFile(), AfterFile: config.AfterFile(),
		ResponseBodyAccess: config.ResponseBodyAccess(), AuditParts: config.AuditLogParts(),
	}
}

// SiteState is the managed WAF configuration of a site as stored on disk.
type SiteState struct {
	Mode       domain.WAFMode
	Policy     waf.Policy
	Exclusions []waf.Exclusion
	Revision   string
	HasWAF     bool
}

// readExclusionList parses the canonical exclusions file (missing = empty).
func readExclusionList(domainName string) ([]waf.Exclusion, error) {
	content, err := os.ReadFile(files.ExclusionsConfigPath(config.ManagedDir(), domainName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return waf.ParseExclusions(content)
}

// ReadSiteState returns the mode, policy and exclusions of a site. A site
// without a WAF overlay reports the DetectionOnly/default policy baseline
// that a first generation would use.
func ReadSiteState(domainName string) (SiteState, error) {
	if err := ValidateDomain(domainName); err != nil {
		return SiteState{}, err
	}
	state := SiteState{Mode: domain.ModeDetectionOnly, Policy: waf.DefaultPolicy()}
	content, existed, err := readPreviousState(files.WAFConfigPath(config.ManagedDir(), domainName))
	if err != nil {
		return SiteState{}, err
	}
	if existed {
		state.HasWAF = true
		mode, policy, err := waf.ParseManaged(content)
		if err != nil {
			return SiteState{}, err
		}
		switch domain.WAFMode(mode) {
		case domain.ModeOn, domain.ModeOff, domain.ModeDetectionOnly:
			state.Mode = domain.WAFMode(mode)
		}
		state.Policy = policy
		state.Revision = waf.Revision(content)
	}
	state.Exclusions, err = readExclusionList(domainName)
	if err != nil {
		return SiteState{}, fmt.Errorf("read exclusions: %w", err)
	}
	return state, nil
}

// wafOverride replaces parts of the stored state when rendering.
type wafOverride struct {
	mode       *domain.WAFMode
	policy     *waf.Policy
	exclusions *[]waf.Exclusion
}

// renderSiteWAF renders the WAF overlay of a site from its stored state and
// the current baseline, applying overrides. It does not write.
func renderSiteWAF(domainName string, o wafOverride) (waf.Generated, error) {
	state, err := ReadSiteState(domainName)
	if err != nil {
		return waf.Generated{}, err
	}
	if o.mode != nil {
		state.Mode = *o.mode
	}
	if o.policy != nil {
		state.Policy = *o.policy
	}
	if o.exclusions != nil {
		state.Exclusions = *o.exclusions
	}
	return waf.Generate(domainName, waf.Config{Mode: state.Mode, Policy: state.Policy, Exclusions: state.Exclusions},
		config.AuditLogPath(), baselineOptions())
}

// stageError carries the stage of a regeneration failure so the chain can
// report "generate" versus "write" consistently with the other entries.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

// writeSiteWAF renders and atomically writes the WAF overlay.
func writeSiteWAF(domainName string, o wafOverride) (waf.Generated, error) {
	g, err := renderSiteWAF(domainName, o)
	if err != nil {
		return waf.Generated{}, &stageError{stage: "generate", err: fmt.Errorf("error generating configuration: %w", err)}
	}
	if err := files.AtomicWrite(files.WAFConfigPath(config.ManagedDir(), domainName), g.Content); err != nil {
		return waf.Generated{}, &stageError{stage: "write", err: fmt.Errorf("error writing configuration: %w", err)}
	}
	return g, nil
}

// readPreviousState captures the current bytes of the overlay (if it exists)
// so they can be restored if the Caddy reload fails (decision D6).
func readPreviousState(confPath string) ([]byte, bool, error) {
	content, err := os.ReadFile(confPath)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

// restoreState reverts the overlay to its previous state (D6): it restores
// the original bytes if the file existed, or removes it if it did not.
func restoreState(confPath string, previous []byte, existed bool) error {
	if !existed {
		if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return files.AtomicWrite(confPath, previous)
}

// chainOpts groups the particularities of each public entry of the shared
// chain validate → backup → mutate → regenerate → reload → verify →
// restore → audit (finding J5-2): the error/restore/audit flow lives once in
// runChain; each entry contributes its event names, audit fields and steps.
type chainOpts struct {
	// fileType is the primary overlay/snapshot type: files.FileTypeWAF,
	// files.FileTypeExclusions or files.FileTypeIPRules.
	fileType string
	// confPath is the path of the primary managed file.
	confPath string
	// failEvent is the audit event of the failures prior to the reload
	// (e.g. "waf_mode_failed").
	failEvent string
	// reloadFailEvent is the audit event of the reload failure
	// (e.g. "waf_mode_changed_but_reload_failed").
	reloadFailEvent string
	// successEvent is the audit event of the success (e.g. "waf_mode_changed").
	successEvent string
	// from/failTo/to are the "from"/"to" fields of the audit log.
	from, failTo, to string
	// mutate writes the primary file. It is nil when the primary file is
	// the WAF overlay itself (mode and policy changes). It must audit its
	// own failure and wrap the error with the message of its stage.
	mutate func() error
	// regenerate rebuilds the site's WAF overlay after mutate (nil for IP
	// rules). Caddy must then report its revision in the live config.
	regenerate func() (waf.Generated, error)
	// action and summary describe the change in the journal.
	action, summary string
	base            string
}

// diffIgnore hides lines that change on every generation.
func diffIgnore(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "# domain:") || strings.HasPrefix(trimmed, "# waf-config-revision:") ||
		strings.HasPrefix(trimmed, "SecComponentSignature ")
}

// runChain runs the shared chain. The error messages that the tests assert
// ("error reading previous state", "error creating backup", "error
// reloading Caddy", "error restoring overlay") are generated HERE.
func runChain(domainName string, actor Actor, opts chainOpts) error {
	changeMu.Lock()
	defer changeMu.Unlock()
	if opts.base != "" {
		base, err := baselineHash(domainName)
		if err != nil {
			return err
		}
		if base != opts.base {
			return ErrStaleDraft
		}
	}
	remoteIP := actor.RemoteIP
	stages := []journal.Stage{{Name: "validate", Result: "success"}}
	configSHA := ""
	record := func(result, rev, diff string, err error) {
		entry := journal.Entry{Site: domainName, Action: opts.action, Summary: opts.summary, Reason: actor.Reason,
			Actor: actor.User, RemoteIP: actor.RemoteIP, Revision: rev, Result: result, Diff: diff, Stages: stages, SHA256: configSHA}
		if err != nil {
			entry.Error = err.Error()
		}
		if jerr := journal.Append(entry); jerr != nil {
			slog.Warn("could not append to the change journal", "error", jerr)
		}
	}
	fail := func(err error) error {
		metrics.Reloads.Inc(journal.ResultFailed)
		record(journal.ResultFailed, "", "", err)
		return err
	}

	previous, existed, err := readPreviousState(opts.confPath)
	if err != nil {
		logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "read error: "+err.Error())
		return fail(fmt.Errorf("error reading previous state: %w", err))
	}
	if err := files.Backup(domainName, opts.fileType); err != nil {
		logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "backup error: "+err.Error())
		return fail(fmt.Errorf("error creating backup: %w", err))
	}

	wafPath := files.WAFConfigPath(config.ManagedDir(), domainName)
	secondaryWAF := opts.regenerate != nil && opts.confPath != wafPath
	var previousWAF []byte
	var wafExisted bool
	if secondaryWAF {
		previousWAF, wafExisted, err = readPreviousState(wafPath)
		if err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "read error: "+err.Error())
			return fail(fmt.Errorf("error reading previous WAF state: %w", err))
		}
		if wafExisted {
			if err := files.Backup(domainName, files.FileTypeWAF); err != nil {
				logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "backup error: "+err.Error())
				return fail(fmt.Errorf("error creating WAF backup: %w", err))
			}
		}
	} else if opts.regenerate != nil {
		previousWAF, wafExisted = previous, existed
	}
	restore := func() error {
		primaryErr := restoreState(opts.confPath, previous, existed)
		var wafErr error
		if secondaryWAF {
			wafErr = restoreState(wafPath, previousWAF, wafExisted)
		}
		return errors.Join(primaryErr, wafErr)
	}

	if opts.mutate != nil {
		if err := opts.mutate(); err != nil {
			return fail(errors.Join(err, restore()))
		}
	}
	var gen waf.Generated
	var expect []string
	diff := ""
	if opts.regenerate != nil {
		gen, err = opts.regenerate()
		if err != nil {
			stage := "generate"
			var se *stageError
			if errors.As(err, &se) {
				stage = se.stage
			}
			restoreErr := restore()
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, stage+" error: "+err.Error())
			return fail(errors.Join(err, restoreErr))
		}
		expect = []string{gen.Revision}
		configSHA = checksum(gen.Content)
		diff = textdiff.Unified(string(previousWAF), string(gen.Content), 2, diffIgnore)
	} else if current, _, rerr := readPreviousState(opts.confPath); rerr == nil {
		diff = textdiff.Unified(string(previous), string(current), 2, diffIgnore)
	}

	if err := caddy.ReloadExpect(expect); err != nil {
		stages = append(stages, journal.Stage{Name: "load", Result: "failed"})
		if caddy.WasApplied(err) {
			stages[len(stages)-1].Result = "success"
			stages = append(stages, journal.Stage{Name: "readback", Result: "failed"})
		}
		restoreErr := restore()
		reloadStatus := fmt.Sprintf("failed: %v", err)
		if restoreErr != nil {
			reloadStatus = fmt.Sprintf("failed: %v (restore error: %v)", err, restoreErr)
		}
		logs.LogAction(opts.reloadFailEvent, domainName, opts.from, opts.to, remoteIP, reloadStatus)
		if restoreErr != nil {
			return fail(fmt.Errorf("error reloading Caddy: %v; error restoring overlay: %w", err, restoreErr))
		}
		// A successful /load followed by failed read-back already changed
		// Caddy. Restore live state as well as files before returning failure.
		if caddy.WasApplied(err) {
			if recoveryErr := caddy.Reload(); recoveryErr != nil {
				return fail(fmt.Errorf("error reloading Caddy: %v; error reloading restored configuration: %w", err, recoveryErr))
			}
		}
		return fail(fmt.Errorf("error reloading Caddy: %w", err))
	}

	stages = append(stages, journal.Stage{Name: "load", Result: "success"}, journal.Stage{Name: "readback", Result: "success"})
	if gen.Revision != "" {
		probe, probeErr := verifyOrigin(gen)
		if probeErr != nil {
			probe.Result = "failed"
			probe.Detail = probeErr.Error()
			stages = append(stages, probe)
			restoreErr := restore()
			if restoreErr == nil {
				restoreErr = caddy.Reload()
			}
			recovery := journal.Stage{Name: "compensate", Result: "success"}
			if restoreErr != nil {
				recovery.Result = "failed"
				recovery.Detail = restoreErr.Error()
			}
			stages = append(stages, recovery)
			return fail(errors.Join(fmt.Errorf("origin verification failed: %w", probeErr), restoreErr))
		}
		stages = append(stages, probe)
		if err := saveLastGood(domainName, gen, stages); err != nil {
			slog.Warn("could not save last_good metadata", "error", err)
		}
	}
	logs.LogAction(opts.successEvent, domainName, opts.from, opts.to, remoteIP, "success")
	metrics.Reloads.Inc(journal.ResultSuccess)
	record(journal.ResultSuccess, gen.Revision, diff, nil)
	return nil
}

// currentMode returns the stored mode for audit "from" fields.
func currentMode(domainName string) string {
	state, err := ReadSiteState(domainName)
	if err != nil || !state.HasWAF {
		return "unknown"
	}
	return string(state.Mode)
}

// UpdateWAFMode keeps the original API (attribution by remote address).
func UpdateWAFMode(domainName string, mode domain.WAFMode, remoteIP string) error {
	return ApplyMode(Actor{RemoteIP: remoteIP}, domainName, mode)
}

// ApplyMode changes the WAF engine mode, keeping the policy and exclusions.
func ApplyMode(actor Actor, domainName string, mode domain.WAFMode) error {
	// Strict domain validation BEFORE any use in paths, templates or backups
	// (finding J2): it blocks Caddyfile directive injection via the
	// "# domain:" header and backup path traversal.
	if err := ValidateDomain(domainName); err != nil {
		return err
	}
	if mode != domain.ModeOn && mode != domain.ModeOff && mode != domain.ModeDetectionOnly {
		return ErrInvalidMode
	}
	from := currentMode(domainName)
	opts := chainOpts{
		fileType:        files.FileTypeWAF,
		confPath:        files.WAFConfigPath(config.ManagedDir(), domainName),
		failEvent:       "waf_mode_failed",
		reloadFailEvent: "waf_mode_changed_but_reload_failed",
		successEvent:    "waf_mode_changed",
		from:            from,
		failTo:          string(mode),
		to:              string(mode),
		action:          "mode",
		summary:         fmt.Sprintf("WAF mode %s → %s", from, mode),
	}
	opts.regenerate = func() (waf.Generated, error) {
		return writeSiteWAF(domainName, wafOverride{mode: &mode})
	}
	return runChain(domainName, actor, opts)
}

// ApplyPolicy changes the CRS policy of a site, keeping mode and exclusions.
func ApplyPolicy(actor Actor, domainName string, policy waf.Policy) error {
	if err := ValidateDomain(domainName); err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	policy = policy.Normalize()
	opts := chainOpts{
		fileType:        files.FileTypeWAF,
		confPath:        files.WAFConfigPath(config.ManagedDir(), domainName),
		failEvent:       "waf_policy_failed",
		reloadFailEvent: "waf_policy_changed_but_reload_failed",
		successEvent:    "waf_policy_changed",
		to:              PolicySummary(policy),
		action:          "policy",
		summary:         "WAF policy: " + PolicySummary(policy),
	}
	opts.regenerate = func() (waf.Generated, error) {
		return writeSiteWAF(domainName, wafOverride{policy: &policy})
	}
	return runChain(domainName, actor, opts)
}

// PolicySummary renders a compact description of a policy.
func PolicySummary(p waf.Policy) string {
	p = p.Normalize()
	s := fmt.Sprintf("PL %d (detect %d), thresholds %d/%d", p.BlockingPL, p.DetectionPL, p.InboundThreshold, p.OutboundThreshold)
	if p.Tuning {
		s += ", tuning"
	}
	if p.EarlyBlocking {
		s += ", early blocking"
	}
	if len(p.DisabledGroups) > 0 {
		s += ", disabled " + strings.Join(p.DisabledGroups, ",")
	}
	return s
}

// UpdateExclusions keeps the original API (attribution by remote address).
func UpdateExclusions(domainName string, exclusions []waf.Exclusion, remoteIP string) error {
	return ApplyExclusions(Actor{RemoteIP: remoteIP}, domainName, exclusions)
}

// ApplyExclusions replaces the canonical exclusion list of the domain and
// recompiles it into the WAF overlay.
func ApplyExclusions(actor Actor, domainName string, exclusions []waf.Exclusion) error {
	if err := ValidateDomain(domainName); err != nil {
		return err
	}
	if err := waf.ValidateExclusions(exclusions); err != nil {
		return err
	}
	site := &domain.Site{Domain: domainName}
	opts := chainOpts{
		fileType:        files.FileTypeExclusions,
		confPath:        files.ExclusionsConfigPath(config.ManagedDir(), domainName),
		failEvent:       "exclusions_failed",
		reloadFailEvent: "exclusions_changed_but_reload_failed",
		successEvent:    "exclusions_updated",
		to:              fmt.Sprintf("%d rules", len(exclusions)),
		action:          "exclusions",
		summary:         fmt.Sprintf("%d exclusion(s)", len(exclusions)),
	}
	opts.mutate = func() error {
		snippet, err := waf.GenerateExclusions(site, exclusions)
		if err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, actor.RemoteIP, "generate error: "+err.Error())
			return fmt.Errorf("error generating configuration: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, actor.RemoteIP, "write error: "+err.Error())
			return fmt.Errorf("error writing configuration: %w", err)
		}
		return nil
	}
	opts.regenerate = func() (waf.Generated, error) {
		return writeSiteWAF(domainName, wafOverride{})
	}
	return runChain(domainName, actor, opts)
}

// UpdateIPRules keeps the original API (attribution by remote address).
func UpdateIPRules(domainName string, rules iprules.IPRules, remoteIP string) error {
	return ApplyIPRules(Actor{RemoteIP: remoteIP}, domainName, rules)
}

// ApplyIPRules replaces the allow/deny lists of the domain. The IP entries
// are validated and normalized BEFORE the backup.
func ApplyIPRules(actor Actor, domainName string, rules iprules.IPRules) error {
	if err := ValidateDomain(domainName); err != nil {
		return err
	}
	if err := iprules.ValidateIPRules(rules); err != nil {
		return err
	}
	site := &domain.Site{Domain: domainName}
	summary := fmt.Sprintf("allow:%d deny:%d", len(rules.Allowlist), len(rules.Denylist))
	opts := chainOpts{
		fileType:        files.FileTypeIPRules,
		confPath:        files.IPRulesConfigPath(config.ManagedDir(), domainName),
		failEvent:       "iprules_failed",
		reloadFailEvent: "iprules_changed_but_reload_failed",
		successEvent:    "iprules_updated",
		to:              summary,
		action:          "iprules",
		summary:         "IP rules " + summary,
	}
	opts.mutate = func() error {
		snippet, err := iprules.GenerateSnippet(site, rules)
		if err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, actor.RemoteIP, "generate error: "+err.Error())
			return fmt.Errorf("error generating configuration: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, actor.RemoteIP, "write error: "+err.Error())
			return fmt.Errorf("error writing configuration: %w", err)
		}
		return nil
	}
	return runChain(domainName, actor, opts)
}

// Rollback keeps the original API (attribution by remote address).
func Rollback(domainName, backupID, remoteIP string) error {
	return ApplyRollback(Actor{RemoteIP: remoteIP}, domainName, backupID)
}

// ApplyRollback restores a configuration snapshot (full name
// {ISO8601}.{type}.conf). A WAF snapshot restores its mode and policy; an
// exclusions snapshot restores the list. In both cases the WAF overlay is
// regenerated with the current baseline, so a rollback never resurrects an
// outdated include layout.
func ApplyRollback(actor Actor, domainName, backupID string) error {
	if err := ValidateDomain(domainName); err != nil {
		return err
	}
	// Validate the snapshot name and derive type + conf path BEFORE
	// mutating any state (fail-fast; the strict pattern blocks path
	// traversal).
	fileType, err := files.BackupType(backupID)
	if err != nil {
		logs.LogAction("rollback_failed", domainName, backupID, "", actor.RemoteIP, err.Error())
		return err
	}
	confPath, err := files.OverlayPath(config.ManagedDir(), fileType, domainName)
	if err != nil {
		logs.LogAction("rollback_failed", domainName, backupID, "", actor.RemoteIP, err.Error())
		return err
	}
	opts := chainOpts{
		fileType:        fileType,
		confPath:        confPath,
		failEvent:       "rollback_failed",
		reloadFailEvent: "rollback_changed_but_reload_failed",
		successEvent:    "rollback_restored",
		from:            backupID,
		to:              fileType,
		action:          "rollback",
		summary:         "restored " + backupID,
	}
	opts.mutate = func() error {
		if err := files.RestoreBackup(domainName, backupID); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, actor.RemoteIP, "restore error: "+err.Error())
			return fmt.Errorf("error restoring snapshot: %w", err)
		}
		return nil
	}
	if fileType == files.FileTypeWAF || fileType == files.FileTypeExclusions {
		opts.regenerate = func() (waf.Generated, error) {
			return writeSiteWAF(domainName, wafOverride{})
		}
	}
	return runChain(domainName, actor, opts)
}

// Preview renders the WAF overlay that a change would produce and returns
// the diff against the current overlay. Nothing is written.
type Preview struct {
	Diff    string
	Content string
	DraftID string
	SHA256  string
}

// PreviewPolicy previews a policy change.
func PreviewPolicy(domainName string, policy waf.Policy) (Preview, error) {
	if err := ValidateDomain(domainName); err != nil {
		return Preview{}, err
	}
	if err := policy.Validate(); err != nil {
		return Preview{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	return preview(domainName, wafOverride{policy: &policy})
}

// PreviewExclusions previews an exclusion list change.
func PreviewExclusions(domainName string, exclusions []waf.Exclusion) (Preview, error) {
	if err := ValidateDomain(domainName); err != nil {
		return Preview{}, err
	}
	if err := waf.ValidateExclusions(exclusions); err != nil {
		return Preview{}, err
	}
	return preview(domainName, wafOverride{exclusions: &exclusions})
}

func preview(domainName string, o wafOverride) (Preview, error) {
	current, _, err := readPreviousState(files.WAFConfigPath(config.ManagedDir(), domainName))
	if err != nil {
		return Preview{}, err
	}
	g, err := renderSiteWAF(domainName, o)
	if err != nil {
		return Preview{}, err
	}
	return Preview{Diff: textdiff.Unified(string(current), string(g.Content), 2, diffIgnore), Content: string(g.Content)}, nil
}
