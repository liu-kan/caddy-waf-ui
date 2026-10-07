package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// ErrIPGroupInUse rejects deleting a group that site policies use.
var ErrIPGroupInUse = errors.New("the IP group is used by site policies")

// ErrIPGroupsUnavailable means the registry is not configured.
var ErrIPGroupsUnavailable = errors.New("IP groups are not available")

var ipGroups atomic.Pointer[ipgroups.Registry]

// SetIPGroups installs the IP group registry used to render group rules.
func SetIPGroups(r *ipgroups.Registry) { ipGroups.Store(r) }

// IPGroups returns the registry, or nil when it is not configured.
func IPGroups() *ipgroups.Registry { return ipGroups.Load() }

// groupList resolves the groups of a rule to the list file Caddy reads,
// writing a merged list of several groups when needed.
func groupList(groups []string) (string, error) {
	r := IPGroups()
	if r == nil {
		return "", ErrIPGroupsUnavailable
	}
	return r.EnsureList(groups)
}

func groupDigest() string {
	if r := IPGroups(); r != nil {
		return r.Digest()
	}
	return ""
}

// IPGroupUsage returns the sites whose stored policy uses the group.
func IPGroupUsage(name string) ([]string, error) {
	sites, err := domain.NewScanner(config.ManagedDir()).Scan()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, site := range sites {
		state, err := ReadSiteState(site.Domain)
		if err != nil {
			return nil, err
		}
		for _, rule := range state.Policy.IPGroups {
			if slices.Contains(rule.Groups, name) {
				out = append(out, site.Domain)
				break
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// IPGroupPublication returns, per group, the sites whose policy uses it
// and the sites whose overlay does not load the group's active list yet
// (publishing it failed, or the list changed while Caddy was unavailable).
func IPGroupPublication() (usage, stale map[string][]string, err error) {
	usage, stale = map[string][]string{}, map[string][]string{}
	sites, err := domain.NewScanner(config.ManagedDir()).Scan()
	if err != nil {
		return usage, stale, err
	}
	r := IPGroups()
	for _, site := range sites {
		state, err := ReadSiteState(site.Domain)
		if err != nil {
			return usage, stale, err
		}
		content, _, err := readPreviousState(files.WAFConfigPath(config.ManagedDir(), site.Domain))
		if err != nil {
			return usage, stale, err
		}
		used, behind := map[string]bool{}, map[string]bool{}
		for _, rule := range state.Policy.IPGroups {
			var path string
			if r != nil {
				path, _ = r.ListPath(rule.Groups)
			}
			current := path != "" && strings.Contains(string(content), path)
			for _, name := range rule.Groups {
				used[name] = true
				behind[name] = behind[name] || !current
			}
		}
		for name := range used {
			usage[name] = append(usage[name], site.Domain)
			if behind[name] {
				stale[name] = append(stale[name], site.Domain)
			}
		}
	}
	return usage, stale, nil
}

// PutIPGroup creates or updates a group and publishes a changed list to the
// sites that use it.
func PutIPGroup(ctx context.Context, actor Actor, def ipgroups.Definition) (ipgroups.Group, error) {
	r := IPGroups()
	if r == nil {
		return ipgroups.Group{}, ErrIPGroupsUnavailable
	}
	before, _ := r.Get(def.Name)
	g, err := r.Put(ctx, def)
	if err != nil {
		return ipgroups.Group{}, err
	}
	recordGroup(actor, "saved IP group "+g.Name+" ("+describeSource(g.Definition)+")", g.Error)
	if activeChanged(before.Active, g.Active) {
		if err := ReapplyIPGroup(actor, g.Name); err != nil {
			return g, err
		}
	}
	return g, nil
}

// RefreshIPGroup imports a group now and publishes a changed list.
func RefreshIPGroup(ctx context.Context, actor Actor, name string, force bool) (bool, error) {
	r := IPGroups()
	if r == nil {
		return false, ErrIPGroupsUnavailable
	}
	changed, err := r.Refresh(ctx, name, force)
	if err != nil {
		return false, err
	}
	if g, _ := r.Get(name); g.Hold != "" {
		recordGroup(actor, "held update of IP group "+name+": "+g.Hold, "")
	}
	if !changed {
		return false, nil
	}
	return true, ReapplyIPGroup(actor, name)
}

// ApproveIPGroup activates a held update and publishes it.
func ApproveIPGroup(actor Actor, name string) error {
	r := IPGroups()
	if r == nil {
		return ErrIPGroupsUnavailable
	}
	if _, err := r.Approve(name); err != nil {
		return err
	}
	recordGroup(actor, "approved held update of IP group "+name, "")
	return ReapplyIPGroup(actor, name)
}

// DiscardIPGroup drops a held update.
func DiscardIPGroup(actor Actor, name string) error {
	r := IPGroups()
	if r == nil {
		return ErrIPGroupsUnavailable
	}
	if err := r.Discard(name); err != nil {
		return err
	}
	recordGroup(actor, "discarded held update of IP group "+name, "")
	return nil
}

// DeleteIPGroup removes a group that no site policy uses.
func DeleteIPGroup(actor Actor, name string) error {
	r := IPGroups()
	if r == nil {
		return ErrIPGroupsUnavailable
	}
	sites, err := IPGroupUsage(name)
	if err != nil {
		return err
	}
	if len(sites) > 0 {
		return fmt.Errorf("%w: %s", ErrIPGroupInUse, strings.Join(sites, ", "))
	}
	if err := r.Delete(name); err != nil {
		return err
	}
	recordGroup(actor, "deleted IP group "+name, "")
	return nil
}

// ReapplyIPGroup regenerates and publishes the WAF overlay of every site
// whose policy uses the group, so Caddy loads the group's active list.
func ReapplyIPGroup(actor Actor, name string) error {
	sites, err := IPGroupUsage(name)
	if err != nil {
		return err
	}
	summary := "IP group " + name + " updated"
	if r := IPGroups(); r == nil {
		return ErrIPGroupsUnavailable
	} else if g, ok := r.Get(name); ok && g.Active != nil {
		summary = fmt.Sprintf("IP group %s updated (%d prefixes, sha256 %s)", name, g.Active.Prefixes, g.Active.SHA256[:12])
	}
	var errs []error
	for _, site := range sites {
		opts := chainOpts{
			fileType:        files.FileTypeWAF,
			confPath:        files.WAFConfigPath(config.ManagedDir(), site),
			failEvent:       "ipgroup_publish_failed",
			reloadFailEvent: "ipgroup_changed_but_reload_failed",
			successEvent:    "ipgroup_published",
			to:              name,
			action:          "ipgroup",
			summary:         summary,
		}
		opts.regenerate = func() (waf.Generated, error) {
			return writeSiteWAF(site, wafOverride{})
		}
		if err := runChain(site, actor, opts); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", site, err))
		}
	}
	return errors.Join(errs...)
}

// listReference finds the IP group list files referenced by an overlay.
var listReference = regexp.MustCompile(`ipgroups/([A-Za-z0-9._-]+\.txt)`)

// GCIPGroupLists removes list files that no overlay references, that are
// neither active nor pending, and are older than a day.
func GCIPGroupLists() error {
	r := IPGroups()
	if r == nil {
		return nil
	}
	referenced := map[string]bool{}
	entries, err := os.ReadDir(config.ManagedDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "waf-") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(config.ManagedDir(), e.Name()))
		if err != nil {
			return err
		}
		for _, m := range listReference.FindAllStringSubmatch(string(content), -1) {
			referenced[m[1]] = true
		}
	}
	return r.GC(referenced, 24*time.Hour)
}

// RunIPGroups imports due groups every interval, publishes changed lists
// and removes unused list files, until ctx ends.
func RunIPGroups(ctx context.Context, every time.Duration) {
	r := IPGroups()
	if r == nil {
		return
	}
	actor := Actor{User: "ipgroup-refresh", Reason: "scheduled IP group import"}
	gc := time.NewTicker(time.Hour)
	defer gc.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-gc.C:
				if err := GCIPGroupLists(); err != nil {
					slog.Warn("IP group list cleanup failed", "error", err)
				}
			}
		}
	}()
	r.Run(ctx, every, func(name string) {
		if err := ReapplyIPGroup(actor, name); err != nil {
			slog.Warn("publishing an updated IP group failed", "group", name, "error", err)
		}
	})
}

func activeChanged(before, after *ipgroups.Version) bool {
	if after == nil {
		return false
	}
	return before == nil || before.SHA256 != after.SHA256
}

func describeSource(d ipgroups.Definition) string {
	if d.Source == ipgroups.SourceURL {
		return d.URL + ", every " + d.Refresh
	}
	return "file " + d.File
}

// recordGroup journals a registry change. It is not tied to one site.
func recordGroup(actor Actor, summary, failure string) {
	entry := journal.Entry{Action: "ipgroup", Summary: summary, Reason: actor.Reason, Actor: actor.User,
		RemoteIP: actor.RemoteIP, Result: journal.ResultSuccess}
	if failure != "" {
		entry.Result, entry.Error = journal.ResultFailed, failure
	}
	if err := journal.Append(entry); err != nil {
		slog.Warn("could not append to the change journal", "error", err)
	}
}
