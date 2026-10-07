package ui

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// setupIPGroups installs a registry over the UI test directories and returns
// the source directory of file groups.
func setupIPGroups(t *testing.T) string {
	t.Helper()
	sources := t.TempDir()
	t.Setenv("CADDY_UI_IPGROUP_DIR", sources)
	reg, err := ipgroups.Open(ipgroups.Options{
		StateDir: filepath.Join(os.Getenv("CADDY_UI_DATA_DIR"), "ipgroups"),
		ListDir:  filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "ipgroups"),
		CaddyDir: "/etc/caddy/ui-managed/ipgroups", SourceDir: sources,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.SetIPGroups(reg)
	t.Cleanup(func() { service.SetIPGroups(nil) })
	return sources
}

func writeGroupSource(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestIPGroupsPageManagesGroups(t *testing.T) {
	setupUIEnv(t)
	sources := setupIPGroups(t)
	writeGroupSource(t, sources, "office.txt", "192.0.2.0/24\n2001:db8::/48\n")
	mux := NewPagesMux()
	rec := formPost(t, mux, "/ipgroups", url.Values{"name": {"office"}, "source": {"file"}, "file": {"office.txt"},
		"note": {"HQ"}, "reason": {"add office"}, "tab": {"ipgroups"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	page := getPage(t, "/?tab=ipgroups")
	for _, want := range []string{"office", "office.txt", "2 prefixes", "HQ"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	if page := getPage(t, "/?tab=ipgroups&ip=192.0.2.7"); !strings.Contains(page, "192.0.2.7 belongs to") || !strings.Contains(page, ">office<") {
		t.Fatal("the lookup must name the groups that contain the address")
	}
	rec = formPost(t, mux, "/ipgroups", url.Values{"name": {"Bad Name"}, "source": {"file"}, "file": {"office.txt"}, "tab": {"ipgroups"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "invalid group name") {
		t.Fatalf("invalid definitions re-render the form with the error: %d", rec.Code)
	}

	seedManagedSite(t)
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"office"}, Action: waf.GroupEngine, Engine: "DetectionOnly"}}
	if err := service.ApplyPolicy(service.Actor{}, "example.com", p); err != nil {
		t.Fatal(err)
	}
	if page := getPage(t, "/?tab=ipgroups"); !strings.Contains(page, "example.com") {
		t.Fatal("the page must list the sites that use a group")
	}
	rec = formPost(t, mux, "/ipgroups/office/delete", url.Values{"reason": {"cleanup"}, "tab": {"ipgroups"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "used by site policies") {
		t.Fatalf("deleting a group in use must be refused with the reason: %d", rec.Code)
	}
	if rec := formPost(t, mux, "/ipgroups/office/refresh", url.Values{"reason": {"now"}, "tab": {"ipgroups"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyFormEditsIPGroupRules(t *testing.T) {
	setupUIEnv(t)
	sources := setupIPGroups(t)
	writeGroupSource(t, sources, "cn.txt", "203.0.113.0/24\n")
	if _, err := service.PutIPGroup(t.Context(), service.Actor{}, ipgroups.Definition{Name: "cn", Source: ipgroups.SourceFile, File: "cn.txt"}); err != nil {
		t.Fatal(err)
	}
	seedManagedSite(t)
	mux := NewPagesMux()
	form := url.Values{"blocking_pl": {"1"}, "detection_pl": {"1"}, "inbound_threshold": {"5"}, "outbound_threshold": {"4"},
		"ipg_count": {"2"}, "ipg_group_0": {"cn"}, "ipg_match_0": {"outside"}, "ipg_action_0": {"trial"},
		"ipg_group_1": {""}, "action": {"preview"}, "reason": {"trial outside cn"}}
	rec := formPost(t, mux, "/sites/example.com/policy", form)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "!@ipMatchFromFile") {
		t.Fatalf("preview must show the group rule in the diff: %d", rec.Code)
	}
	draft := regexpFind(t, body, `name="draft_id" value="([^"]+)"`)
	form.Set("draft_id", draft)
	form.Set("action", "apply")
	if rec := formPost(t, mux, "/sites/example.com/policy", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	state, err := service.ReadSiteState("example.com")
	if err != nil || len(state.Policy.IPGroups) != 1 || !state.Policy.IPGroups[0].Negate || state.Policy.IPGroups[0].Action != waf.GroupTrial {
		t.Fatalf("stored rules: %+v %v", state.Policy.IPGroups, err)
	}
	page := getPage(t, "/?tab=policy&domain=example.com")
	if !strings.Contains(page, `name="ipg_group_0"`) || !strings.Contains(page, `<option value="cn" selected`) {
		t.Fatal("the policy page must show the stored group rules")
	}
	// Removing the row removes the rule.
	form.Set("ipg_remove_0", "on")
	form.Set("action", "preview")
	form.Del("draft_id")
	rec = formPost(t, mux, "/sites/example.com/policy", form)
	if rec.Code != http.StatusOK || !regexp.MustCompile(`-\s+SecRule REMOTE_ADDR`).MatchString(rec.Body.String()) {
		t.Fatalf("removing a rule shows it leaving the overlay: %d", rec.Code)
	}
}

func TestPolicyFormBansClientsOutsideSeveralGroups(t *testing.T) {
	setupUIEnv(t)
	sources := setupIPGroups(t)
	writeGroupSource(t, sources, "cn.txt", "203.0.113.0/25\n")
	writeGroupSource(t, sources, "jp.txt", "203.0.113.128/25\n")
	for _, name := range []string{"cn", "jp"} {
		if _, err := service.PutIPGroup(t.Context(), service.Actor{}, ipgroups.Definition{Name: name, Source: ipgroups.SourceFile, File: name + ".txt"}); err != nil {
			t.Fatal(err)
		}
	}
	seedManagedSite(t)
	mux := NewPagesMux()
	form := url.Values{"blocking_pl": {"1"}, "detection_pl": {"1"}, "inbound_threshold": {"5"}, "outbound_threshold": {"4"},
		"ipg_count": {"1"}, "ipg_group_0": {"jp", "cn"}, "ipg_match_0": {"outside"}, "ipg_action_0": {"ban"},
		"action": {"preview"}, "reason": {"allow cn and jp only"}}
	rec := formPost(t, mux, "/sites/example.com/policy", form)
	body := html.UnescapeString(rec.Body.String())
	union := regexp.MustCompile(`!@ipMatchFromFile /etc/caddy/ui-managed/ipgroups/(_union\.[0-9a-f]{12}\.txt)`).FindStringSubmatch(body)
	// The site runs DetectionOnly: the ban records what it would deny.
	if rec.Code != http.StatusOK || union == nil || !strings.Contains(body, "auditlog,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.blocking_outbound_anomaly_score=0,setvar:tx.detection_inbound_anomaly_score=0,setvar:tx.detection_outbound_anomaly_score=0,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: outside cn+jp banned'") {
		t.Fatalf("preview must match the merged list of both groups: %d", rec.Code)
	}
	// The merged list holds both groups and was written for Caddy.
	merged, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "ipgroups", union[1]))
	if err != nil || !strings.Contains(string(merged), "\n203.0.113.0/24\n") {
		t.Fatalf("merged list: %q %v", merged, err)
	}
	form.Set("draft_id", regexpFind(t, body, `name="draft_id" value="([^"]+)"`))
	form.Set("action", "apply")
	if rec := formPost(t, mux, "/sites/example.com/policy", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	state, err := service.ReadSiteState("example.com")
	if err != nil || len(state.Policy.IPGroups) != 1 || strings.Join(state.Policy.IPGroups[0].Groups, ",") != "cn,jp" || state.Policy.IPGroups[0].Action != waf.GroupBan {
		t.Fatalf("stored rules: %+v %v", state.Policy.IPGroups, err)
	}
	page := getPage(t, "/?tab=policy&domain=example.com")
	if !strings.Contains(page, `<option value="cn" selected`) || !strings.Contains(page, `<option value="jp" selected`) {
		t.Fatal("the policy page must select both groups of the stored rule")
	}
	usage, stale, err := service.IPGroupPublication()
	if err != nil || len(usage["cn"]) != 1 || len(usage["jp"]) != 1 || len(stale) != 0 {
		t.Fatalf("both groups are used and published: %v %v %v", usage, stale, err)
	}
}

func TestEventDetailShowsClientGroups(t *testing.T) {
	setupUIEnv(t)
	sources := setupIPGroups(t)
	byPath := setupWAFRuntime(t)
	e := byPath["/.git/config|blocked"]
	writeGroupSource(t, sources, "seen.txt", e.ClientIP+"\n")
	if _, err := service.PutIPGroup(t.Context(), service.Actor{}, ipgroups.Definition{Name: "seen", Source: ipgroups.SourceFile, File: "seen.txt"}); err != nil {
		t.Fatal(err)
	}
	page := getPage(t, "/?tab=event&tx="+e.TxID)
	if !strings.Contains(page, "Client IP groups") || !strings.Contains(page, "seen") {
		t.Fatal("the event must show the IP groups of its client")
	}
}

func TestIPGroupAPI(t *testing.T) {
	api := setupUIEnv(t)
	sources := setupIPGroups(t)
	writeGroupSource(t, sources, "office.txt", "192.0.2.0/24\n")
	rec := apiCall(t, api, http.MethodPut, "/api/ipgroups/office", `{"source":"file","file":"office.txt","note":"HQ","reason":"api"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"prefixes":1`) {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodPut, "/api/ipgroups/office", `{"source":"url","url":"http://insecure.example/list"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid definitions are 400: %d", rec.Code)
	}
	rec = apiCall(t, api, http.MethodGet, "/api/ipgroups", "")
	var list struct {
		Groups []struct {
			Name  string   `json:"name"`
			Sites []string `json:"sites"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Groups) != 1 || list.Groups[0].Name != "office" {
		t.Fatalf("list: %s %v", rec.Body.String(), err)
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/ipgroups/lookup?ip=192.0.2.200", ""); !strings.Contains(rec.Body.String(), `"office"`) {
		t.Fatalf("lookup: %s", rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/ipgroups/lookup?ip=nope", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid lookup address: %d", rec.Code)
	}
	if rec := apiCall(t, api, http.MethodPost, "/api/ipgroups/office/refresh?force=true", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	if err := service.ApplyMode(service.Actor{}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"office"}, Action: waf.GroupBlock}}
	if err := service.ApplyPolicy(service.Actor{}, "example.com", p); err != nil {
		t.Fatal(err)
	}
	if rec := apiCall(t, api, http.MethodDelete, "/api/ipgroups/office", ""); rec.Code != http.StatusConflict {
		t.Fatalf("a group in use cannot be deleted: %d", rec.Code)
	}
	if rec := apiCall(t, api, http.MethodDelete, "/api/ipgroups/missing", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown group: %d", rec.Code)
	}
}

func regexpFind(t *testing.T, s, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) != 2 {
		t.Fatalf("no match for %s", pattern)
	}
	return m[1]
}
