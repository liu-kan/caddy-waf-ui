package events

import (
	"encoding/json"
	"github.com/developmi/caddy-waf-ui/internal/crs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privacyAudit(t *testing.T) []byte {
	t.Helper()
	raw := []byte(`{"transaction":{"id":"privacy-tx","unix_timestamp":1,"request":{"method":"GET","uri":"/search?q=ordinary&token=QUERY_SECRET","headers":{"Host":["example.com"],"User-Agent":["test-client"],"Authorization":["Bearer HEADER_SECRET"]}},"producer":{"rule_engine":"On","rulesets":["OWASP_CRS/4.25.0"]}},"messages":[{"data":{"id":942100,"msg":"SQL Injection Attack Detected","data":"Matched Data: select found within ARGS:q: ordinary select from users","severity":2}}]}`)
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec["transaction"].(map[string]any)["unix_timestamp"] = time.Now().UnixNano()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestNormalizerUsesSelectedRedactionBeforeStorage(t *testing.T) {
	raw := privacyAudit(t)
	for _, level := range []Level{LevelStrict, LevelStandard, LevelFull} {
		t.Run(level.String(), func(t *testing.T) {
			p := Redaction{Level: level}
			e, err := (&Normalizer{Dict: crs.Default(), Redaction: &p}).Normalize(raw)
			if err != nil {
				t.Fatal(err)
			}
			if e.Redaction != level.String() {
				t.Fatal("missing applied policy", e.Redaction)
			}
			b, _ := json.Marshal(e)
			s := string(b)
			if level == LevelStrict && (e.Query != "" || e.Headers != nil || e.Hits[0].Value != redacted) {
				t.Fatal("strict retained values")
			}
			if level == LevelStandard && (e.Hits[0].Value == redacted || !strings.Contains(e.Query, "ordinary") || strings.Contains(s, "QUERY_SECRET") || strings.Contains(s, "HEADER_SECRET")) {
				t.Fatal("standard not applied", s)
			}
			if level == LevelFull && (!strings.Contains(s, "QUERY_SECRET") || !strings.Contains(s, "HEADER_SECRET")) {
				t.Fatal("explicit full did not retain context")
			}
		})
	}
}
func TestIndependentCloudQueueAndRetryAfterExportFailure(t *testing.T) {
	root := t.TempDir()
	local, _ := OpenStore(filepath.Join(root, "local", "events"), 24*time.Hour, 1)
	cloud, _ := OpenStore(filepath.Join(root, "cloud", "events"), 24*time.Hour, 1)
	p := Redaction{Level: LevelFull}
	policy := Redaction{Level: LevelStrict}
	logPath := filepath.Join(root, "audit.log")
	raw := privacyAudit(t)
	if err := os.WriteFile(logPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	in := &Ingester{Path: logPath, StatePath: filepath.Join(root, "state.json"), Store: local, CloudStore: cloud, CloudRedaction: policy, Norm: &Normalizer{Dict: crs.Default(), Redaction: &p}}
	cloud.MaxDiskBytes = 1
	if err := in.Poll(); err == nil {
		t.Fatal("export budget error hidden")
	}
	if in.Status().Offset != 0 {
		t.Fatal("cursor advanced past unexported record")
	}
	cloud.MaxDiskBytes = 1 << 20
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if local.Stats().Stored != 1 || cloud.Stats().Stored != 1 {
		t.Fatal("retry duplicated or lost event")
	}
	file := filepath.Join(cloud.Dir(), "events-"+time.Now().UTC().Format("2006-01-02")+".jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") || !strings.Contains(string(b), `"redaction":"strict"`) {
		t.Fatal("local full reached strict export", string(b))
	}
	localEvent, _ := local.Get("privacy-tx")
	if localEvent.Headers["authorization"] != "Bearer HEADER_SECRET" {
		t.Fatal("cloud policy destroyed local context")
	}
}
func TestCompositeRedactionDoesNotLeakMatchedCredentialFragment(t *testing.T) {
	e := &Event{Hits: []Hit{
		{Var: "REQUEST_URI", Data: "QUERY_SECRET", Value: "/search?token=QUERY_SECRET&q=ordinary"},
		{Var: "REQUEST_BODY", Data: "BODY_SECRET", Value: `{"pass\u0077ord":{"value":"BODY_SECRET"},"q":"ordinary"}`},
		{Var: "REQUEST_HEADERS:Referer", Data: "HEADER_SECRET", Value: "https://user:HEADER_SECRET@example.com/?token=QUERY_SECRET"},
	}}
	b, _ := json.Marshal((Redaction{Level: LevelStandard}).Apply(e))
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("composite/escaped credential leaked", string(b))
	}
}
func TestExportMigrationDoesNotResendImportedEvents(t *testing.T) {
	root := t.TempDir()
	local, _ := OpenStore(filepath.Join(root, "local", "events"), 24*time.Hour, 1)
	cloud, _ := OpenStore(filepath.Join(root, "cloud", "events"), 24*time.Hour, 1)
	for _, source := range []string{SourceLocal, SourceLoki} {
		_, _ = local.Append(&Event{Kind: "event", V: 1, TxID: "from-" + source, TS: time.Now().UTC(), Redaction: "full", Query: "token=SECRET"}, source)
	}
	if err := local.ExportRetained(cloud, Redaction{Level: LevelStrict}); err != nil {
		t.Fatal(err)
	}
	if err := local.ExportRetained(cloud, Redaction{Level: LevelStrict}); err != nil {
		t.Fatal(err)
	}
	if cloud.Stats().Stored != 1 {
		t.Fatal("import loop or duplicate migration")
	}
}

func TestSettingsRejectInvalidLevelsAndClampCloudDetail(t *testing.T) {
	t.Setenv("CADDY_UI_REDACTION_LOCAL", "standard")
	t.Setenv("CADDY_UI_REDACTION_CLOUD", "full")
	t.Setenv("CADDY_UI_REDACTION_HIDE", "password,custom_field")
	t.Setenv("CADDY_UI_REDACTION_KEEP", "pass_rate x-correlation-id")
	cfg, err := ReadRedactionSettings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cloud.Level != LevelStandard || len(cfg.Local.Hide) != 2 || len(cfg.Cloud.Keep) != 2 {
		t.Fatal("configuration not wired", cfg)
	}
	t.Setenv("CADDY_UI_REDACTION_CLOUD", "standrad")
	if _, err := ReadRedactionSettings(); err == nil {
		t.Fatal("invalid privacy setting accepted")
	}
}

func TestStandardHandlesAcronymNamesAndDuplicateJSONMembers(t *testing.T) {
	e := &Event{Headers: map[string]string{"X-APISecret": "HEADER_SECRET"}, Hits: []Hit{
		{Var: "ARGS:JWTToken", Data: "MATCH_SECRET", Value: "VALUE_SECRET"},
		{Var: "REQUEST_BODY", Data: "BODY_SECRET", Value: `{"q":{"password":"BODY_SECRET"},"q":{"ordinary":"visible"}}`},
	}}
	b, _ := json.Marshal((Redaction{Level: LevelStandard}).Apply(e))
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("acronym or duplicate JSON secret leaked", string(b))
	}
}

func TestStandardHidesUnkeyedAggregateVariables(t *testing.T) {
	e := &Event{Hits: []Hit{{Var: "REQUEST_HEADERS", Data: "HEADER_SECRET", Value: "Authorization: HEADER_SECRET"}, {Var: "ARGS", Data: "ARGS_SECRET", Value: "token=ARGS_SECRET"}}}
	b, _ := json.Marshal((Redaction{Level: LevelStandard}).Apply(e))
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("unkeyed aggregate values were classified as safe", string(b))
	}
}

// 2026-10-06 09:00: verify attack URIs with invalid percent-encodings (%zz, %u0027)
// retain diagnostic path info while credentials in query remain redacted.
func TestRawURIFallbackOnMalformedURIs(t *testing.T) {
	policy := Redaction{Level: LevelStandard}
	malformed := "/login?path=%zz%u0027&password=MY_SECRET#token=SECRET"
	got := policy.URI(malformed)
	if strings.Contains(got, "MY_SECRET") || strings.Contains(got, "SECRET") {
		t.Fatalf("credential leaked from malformed URI: %s", got)
	}
	if !strings.Contains(got, "%zz%u0027") {
		t.Fatalf("attack payload path wiped out completely: %s", got)
	}
}

// 2026-10-06 09:00: verify unmodified JSON payloads retain unescaped HTML characters (<script>)
// instead of converting to unicode escapes (\u003cscript\u003e).
func TestJSONXSSPayloadNotEscapedWhenUnmodified(t *testing.T) {
	policy := Redaction{Level: LevelStandard}
	e := &Event{Hits: []Hit{{Var: "REQUEST_BODY", Data: "<script>", Value: `{"search":"<script>alert(1)</script>"}`}}}
	res := policy.Apply(e)
	if strings.Contains(res.Hits[0].Value, `\u003c`) {
		t.Fatalf("XSS payload was HTML-escaped: %s", res.Hits[0].Value)
	}
	if !strings.Contains(res.Hits[0].Value, "<script>") {
		t.Fatalf("payload content altered: %s", res.Hits[0].Value)
	}
}
