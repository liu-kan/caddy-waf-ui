package crs

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// UI-generated rule id ranges (see internal/waf). They are described by the
// dictionary so events never show an unexplained id.
const (
	UIRuleMin      = 9000000
	UIRuleMax      = 9009999
	UIExclusionMin = 9000001
	UIExclusionMax = 9000999
	UIPolicyMin    = 9001000
	UIPolicyMax    = 9001099
	UITuningRuleID = 9001100
)

// Dictionary is an id-indexed rule catalog for one ruleset version.
type Dictionary struct {
	Source     string `json:"source"`
	Docs       string `json:"docs,omitempty"`
	CRSVersion string `json:"crs_version"`
	License    string `json:"license"`
	Rules      []Rule `json:"rules"`

	byID map[int]*Rule
}

// generatedDictionary is produced by cmd/crsdict from the CRS files embedded
// in the backend's coraza-coreruleset module (see Makefile target crs-dict).
//
//go:embed data/crs-dictionary.json.gz
var generatedDictionary []byte

var (
	defaultOnce sync.Once
	defaultDict *Dictionary
	defaultErr  error
)

// Default returns the embedded dictionary. It panics only if the embedded
// asset is corrupt, which tests catch at build time.
func Default() *Dictionary {
	defaultOnce.Do(func() {
		defaultDict, defaultErr = Decode(bytes.NewReader(generatedDictionary))
	})
	if defaultErr != nil {
		panic(fmt.Sprintf("embedded CRS dictionary: %v", defaultErr))
	}
	return defaultDict
}

// Decode reads a gzip-compressed (or plain) JSON dictionary.
func Decode(r io.Reader) (*Dictionary, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		data, err = io.ReadAll(zr)
		if err != nil {
			return nil, err
		}
	}
	var d Dictionary
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	d.index()
	return &d, nil
}

// Encode writes the dictionary as gzip-compressed JSON.
func (d *Dictionary) Encode(w io.Writer) error {
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return err
	}
	return zw.Close()
}

func (d *Dictionary) index() {
	d.byID = make(map[int]*Rule, len(d.Rules))
	for i := range d.Rules {
		d.byID[d.Rules[i].ID] = &d.Rules[i]
	}
}

// Lookup returns the rule with the given id. UI-generated ids resolve to a
// synthetic description even though they are not part of the ruleset files.
func (d *Dictionary) Lookup(id int) (Rule, bool) {
	if d != nil && d.byID != nil {
		if r, ok := d.byID[id]; ok {
			return *r, true
		}
	}
	if r, ok := uiRule(id); ok {
		return r, true
	}
	return Rule{}, false
}

// Len returns the number of rules.
func (d *Dictionary) Len() int { return len(d.Rules) }

// Search returns rules whose id, message, tags or category contain query
// (case-insensitive), sorted by id; an empty query returns every rule.
func (d *Dictionary) Search(query string, kinds ...string) []Rule {
	if ids := ParseIDs(query); len(ids) > 0 && !d.partialID(query, ids) {
		var out []Rule
		for _, id := range ids {
			if r, ok := d.Lookup(id); ok {
				out = append(out, r)
			} else {
				out = append(out, Rule{ID: id, Kind: "unknown", Msg: "Unknown rule: inspect the event ruleset version or custom rules"})
			}
		}
		return out
	}
	query = strings.ToLower(strings.TrimSpace(query))
	allowed := map[string]bool{}
	for _, k := range kinds {
		allowed[k] = true
	}
	var out []Rule
	for _, r := range d.Rules {
		if len(allowed) > 0 && !allowed[r.Kind] {
			continue
		}
		if query != "" && !r.matches(query) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// partialID reports a single typed number that is not a known rule id
// ("9321"): it is searched as a substring instead of being reported unknown.
func (d *Dictionary) partialID(query string, ids []int) bool {
	if len(ids) != 1 || strings.ContainsAny(query, ",\"") {
		return false
	}
	_, known := d.Lookup(ids[0])
	return !known
}

func (r Rule) matches(query string) bool {
	if strings.Contains(fmt.Sprint(r.ID), query) ||
		strings.Contains(strings.ToLower(r.Msg), query) ||
		strings.Contains(strings.ToLower(r.Category), query) {
		return true
	}
	for _, tag := range r.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

// Merge overlays the rules of other on d (other wins) and returns a new
// dictionary. Used when operator-mounted rule files are available.
func (d *Dictionary) Merge(other *Dictionary) *Dictionary {
	out := &Dictionary{Source: d.Source, Docs: d.Docs, CRSVersion: d.CRSVersion, License: d.License}
	seen := map[int]bool{}
	if other != nil {
		out.Source = other.Source
		if other.CRSVersion != "" {
			out.CRSVersion = other.CRSVersion
		}
		for _, r := range other.Rules {
			if r.Comment == "" {
				if prev, ok := d.byID[r.ID]; ok {
					r.Comment, r.Link = prev.Comment, prev.Link
				}
			}
			out.Rules = append(out.Rules, r)
			seen[r.ID] = true
		}
	}
	for _, r := range d.Rules {
		if !seen[r.ID] {
			out.Rules = append(out.Rules, r)
		}
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].ID < out.Rules[j].ID })
	out.index()
	return out
}

var crsVersionPattern = regexp.MustCompile(`OWASP_CRS/(\d+\.\d+\.\d+)`)

// Build parses every *.conf* file below root (coraza-coreruleset "rules"
// layout or a CRS release tree) into a dictionary. When linkBase is set,
// each rule links to linkBase + file path + "#L" + line.
func Build(fsys fs.FS, source, linkBase string) (*Dictionary, error) {
	var names []string
	err := fs.WalkDir(fsys, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		base := path.Base(p)
		if strings.HasSuffix(base, ".conf") || strings.Contains(base, ".conf-") || strings.HasSuffix(base, ".conf.example") {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	d := &Dictionary{Source: source, License: "OWASP CRS and Coraza rule text: Apache-2.0"}
	seen := map[int]string{}
	versions := map[string]int{}
	for _, name := range names {
		f, err := fsys.Open(name)
		if err != nil {
			return nil, err
		}
		rules, perr := Parse(f, name)
		_ = f.Close()
		if perr != nil {
			return nil, perr
		}
		for _, r := range rules {
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("duplicate rule id %d in %s and %s", r.ID, prev, name)
			}
			seen[r.ID] = name
			if linkBase != "" {
				r.Link = fmt.Sprintf("%s%s#L%d", linkBase, name, r.Line)
			}
			if m := crsVersionPattern.FindStringSubmatch(r.Ver); m != nil {
				versions[m[1]]++
			}
			d.Rules = append(d.Rules, r)
		}
	}
	for version, count := range versions {
		if count > versions[d.CRSVersion] || (count == versions[d.CRSVersion] && version > d.CRSVersion) {
			d.CRSVersion = version
		}
	}
	if d.CRSVersion == "" {
		d.CRSVersion = versionFromFiles(fsys, names)
	}
	sort.Slice(d.Rules, func(i, j int) bool { return d.Rules[i].ID < d.Rules[j].ID })
	d.index()
	return d, nil
}

// ApplyDocs copies rule comments and source links from a documented tree of
// the same ruleset version (upstream CRS keeps the comments that packaged
// copies strip). Rules absent from docs keep their own values.
func (d *Dictionary) ApplyDocs(docs *Dictionary, label string) {
	if docs == nil {
		return
	}
	d.Docs = label
	for i := range d.Rules {
		doc, ok := docs.byID[d.Rules[i].ID]
		if !ok {
			continue
		}
		if doc.Comment != "" {
			d.Rules[i].Comment = doc.Comment
		}
		if doc.Link != "" {
			d.Rules[i].Link = doc.Link
		}
	}
	d.index()
}

// versionFromFiles finds "OWASP_CRS/x.y.z" in the ver: actions of the files.
func versionFromFiles(fsys fs.FS, names []string) string {
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			continue
		}
		if m := crsVersionPattern.FindSubmatch(data); m != nil {
			return string(m[1])
		}
	}
	return ""
}

// LoadDir builds a dictionary from an operator-mounted ruleset directory.
func LoadDir(dir string) (*Dictionary, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	return Build(os.DirFS(dir), "file://"+filepath.ToSlash(dir), "")
}

// LoadFile parses operator-mounted custom rules for local explanations.
func LoadFile(name string) (*Dictionary, error) {
	f, err := os.Open(name) //nolint:gosec // G304: operator-selected custom rule file.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rules, err := Parse(io.LimitReader(f, 4<<20), filepath.Base(name))
	if err != nil {
		return nil, err
	}
	d := &Dictionary{Source: "file://" + name, Rules: rules}
	d.index()
	return d, nil
}

// uiRule describes the rules generated by this UI.
func uiRule(id int) (Rule, bool) {
	switch {
	case id >= UIExclusionMin && id <= UIExclusionMax:
		return Rule{ID: id, Kind: KindUI, Phase: 1, Action: "pass", Category: "ui-exclusion",
			Msg: "UI exclusion: removes a rule or one of its targets for matching requests"}, true
	case id >= UIPolicyMin && id <= UIPolicyMax:
		return Rule{ID: id, Kind: KindUI, Phase: 1, Action: "pass", Category: "ui-policy",
			Msg: "UI policy: sets CRS paranoia level, anomaly thresholds or request limits"}, true
	case id == UITuningRuleID:
		return Rule{ID: id, Kind: KindUI, Phase: 5, Action: "pass", Category: "ui-tuning",
			Msg: "UI tuning mode: records transactions with a non-zero anomaly score"}, true
	case id >= UIRuleMin && id <= UIRuleMax:
		return Rule{ID: id, Kind: KindUI, Category: "ui", Msg: "Rule generated by caddy-waf-ui"}, true
	}
	return Rule{}, false
}

// IsExcludable reports whether excluding the rule is a meaningful tuning
// action. Decision rules only compare the total score with the threshold;
// excluding them disables blocking altogether. CRS initialization checks
// (901xxx) guard the ruleset configuration itself.
func (r Rule) IsExcludable() bool {
	return r.Kind == KindDetection || (r.Kind == KindBlocking && r.Category != "initialization")
}

// ParseIDs accepts CSV, whitespace-separated ids and a copied rule_ids_csv
// JSON field; unrelated free-text searches remain unchanged.
func ParseIDs(text string) []int {
	text = strings.TrimSpace(text)
	if strings.Contains(text, "rule_ids_csv") {
		if !strings.HasPrefix(text, "{") {
			text = "{" + text + "}"
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &fields) != nil {
			return nil
		}
		if json.Unmarshal(fields["rule_ids_csv"], &text) != nil {
			return nil
		}
	}
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })
	if len(fields) == 0 || len(fields) > 100 {
		return nil
	}
	var ids []int
	seen := map[int]bool{}
	for _, f := range fields {
		id, err := strconv.Atoi(f)
		if err != nil || id <= 0 || id > 999999999 {
			return nil
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}
