package events

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Level is how much request detail a stored event keeps.
type Level int

// Redaction levels, from the least to the most detail. The zero value is
// strict, so a policy that was never configured fails closed.
const (
	// LevelStrict keeps rule ids, variable names, the path and the query
	// parameter names; matched values are hidden.
	LevelStrict Level = iota
	// LevelStandard also keeps matched values, query values and diagnostic
	// request headers. Credential-like names stay hidden.
	LevelStandard
	// LevelFull keeps everything except the names of the hide list.
	LevelFull
)

var levelNames = [...]string{"strict", "standard", "full"}

func (l Level) String() string {
	if l < LevelStrict || l > LevelFull {
		return levelNames[LevelStrict]
	}
	return levelNames[l]
}

// ParseLevel parses strict, standard or full. Anything else is an error and
// yields strict.
func ParseLevel(s string) (Level, error) {
	for i, name := range levelNames {
		if strings.EqualFold(strings.TrimSpace(s), name) {
			return Level(i), nil
		}
	}
	return LevelStrict, fmt.Errorf("invalid redaction level %q: use strict, standard or full", s)
}

// Stricter returns the level that keeps less detail.
func Stricter(a, b Level) Level {
	if a < b {
		return a
	}
	return b
}

// Redaction is the redaction policy of stored events: a level plus the
// operator's name lists. Names are parameter, header or cookie names and
// match case-insensitively.
type Redaction struct {
	Level Level
	// Hide names are hidden at every level, full included. A hide entry
	// matches the whole name, its last dotted segment or one of its words.
	Hide []string
	// Keep names are never treated as credentials by the built-in rules
	// (false positives such as a business field named "pass_rate"). A keep
	// entry matches the whole name or its last dotted segment. Keep also
	// adds request headers to the standard allowlist.
	Keep []string
}

// WithLevel returns the policy with another level and the same name lists.
func (r Redaction) WithLevel(l Level) Redaction {
	r.Level = l
	return r
}

const maxQueryLen = 1024

// credentialWords mark a name as a credential when one of its words, or
// two adjacent words joined (api+key), is in the set. Whole words avoid
// the false positives of substring matching ("max_tokens", "author").
var credentialWords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true, "passphrase": true,
	"secret": true, "token": true, "apikey": true, "accesskey": true, "auth": true,
	"authorization": true, "session": true, "sessionid": true, "sid": true,
	"phpsessid": true, "jsessionid": true, "csrf": true, "xsrf": true, "otp": true,
	"totp": true, "mfa": true, "credential": true, "credentials": true, "private": true,
	"privatekey": true, "signature": true, "sig": true, "jwt": true, "bearer": true,
	"cookie": true, "cvv": true, "cvc": true, "cardnumber": true,
}

// diagnosticHeaders are kept at the standard level: they identify the
// client and the request format without carrying credentials.
var diagnosticHeaders = map[string]bool{
	"user-agent": true, "content-type": true, "content-length": true, "content-encoding": true,
	"accept": true, "accept-language": true, "accept-encoding": true, "origin": true,
	"referer": true, "x-forwarded-for": true, "x-forwarded-proto": true, "x-forwarded-host": true,
	"x-real-ip": true, "cf-connecting-ip": true, "cf-ipcountry": true, "cf-ray": true,
	"x-request-id": true, "sec-fetch-site": true, "sec-fetch-mode": true, "sec-fetch-dest": true,
	"upgrade": true, "via": true,
}

// words splits a name at separators, lower-to-upper case changes and
// letter/digit boundaries, and lowercases the parts:
// "X-Api-Key" → x api key, "maxTokens" → max tokens.
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case i > 0 && (unicode.IsUpper(r) && unicode.IsLower(prev) || unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) || unicode.IsDigit(r) != unicode.IsDigit(prev) && len(cur) > 0):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return out
}

// isCredential reports whether the built-in rules treat a name as a
// credential.
func isCredential(name string) bool {
	w := words(name)
	for i, word := range w {
		if credentialWords[word] || i > 0 && credentialWords[w[i-1]+word] {
			return true
		}
	}
	return false
}

func lastSegment(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// hides reports whether the operator's hide list covers a name.
func (r Redaction) hides(name string) bool {
	if len(r.Hide) == 0 || name == "" {
		return false
	}
	w := words(name)
	for _, h := range r.Hide {
		if strings.EqualFold(h, name) || strings.EqualFold(h, lastSegment(name)) {
			return true
		}
		for _, word := range w {
			if strings.EqualFold(h, word) {
				return true
			}
		}
	}
	return false
}

// keeps reports whether the operator's keep list exempts a name.
func (r Redaction) keeps(name string) bool {
	for _, k := range r.Keep {
		if strings.EqualFold(k, name) || strings.EqualFold(k, lastSegment(name)) {
			return true
		}
	}
	return false
}

// sensitive reports whether the value of a named parameter or header must
// be hidden at the policy's level.
func (r Redaction) sensitive(name string) bool {
	if r.hides(name) {
		return true
	}
	if r.Level >= LevelFull || r.keeps(name) {
		return false
	}
	return isCredential(name)
}

// sensitiveCookie: cookie values are session material, so every cookie is
// hidden below full unless the keep list names it.
func (r Redaction) sensitiveCookie(name string) bool {
	if r.hides(name) {
		return true
	}
	return r.Level < LevelFull && !r.keeps(name)
}

var (
	// namesCollections hold names, never values.
	namesCollections = map[string]bool{"ARGS_NAMES": true, "ARGS_GET_NAMES": true, "ARGS_POST_NAMES": true,
		"REQUEST_HEADERS_NAMES": true, "REQUEST_COOKIES_NAMES": true, "FILES_NAMES": true}
	// keyedCollections address one named parameter or header.
	keyedCollections = map[string]bool{"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "REQUEST_HEADERS": true, "FILES": true}
	// compositeCollections contain several name/value pairs at once.
	compositeCollections = map[string]bool{"REQUEST_URI": true, "REQUEST_URI_RAW": true, "QUERY_STRING": true,
		"REQUEST_LINE": true, "REQUEST_BODY": true, "XML": true}

	// formPair is a key=value pair of a query string or form body; jsonPair
	// a "key": value member of a JSON document.
	formPair = regexp.MustCompile(`([A-Za-z0-9_.~%\[\]-]+)=([^&\s"]*)`)
	jsonPair = regexp.MustCompile(`"([^"\\]{1,128})"(\s*:\s*)("(?:[^"\\]|\\.)*"?|[^,}\]\s]+)`)
)

// pairs hides the values of sensitive names inside a composite value (a
// URI, query string, form or JSON body).
func (r Redaction) pairs(s string) string {
	if s == "" || s == redacted {
		return s
	}
	// Parse complete JSON before regex fallback: escaped names, arrays and
	// sensitive object-valued members cannot be safely handled by a regex.
	if json.Valid([]byte(s)) && (strings.HasPrefix(strings.TrimSpace(s), "{") || strings.HasPrefix(strings.TrimSpace(s), "[")) {
		var value any
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		if dec.Decode(&value) == nil {
			// 2026-10-06 08:50: an unchanged document is returned verbatim, and a
			// changed one is encoded without HTML escaping, so XSS payloads such
			// as <script> stay readable instead of becoming \u003cscript\u003e.
			if !r.jsonValue(value, "", 0) {
				return s
			}
			var out strings.Builder
			enc := json.NewEncoder(&out)
			enc.SetEscapeHTML(false)
			if enc.Encode(value) == nil {
				return strings.TrimSuffix(out.String(), "\n")
			}
			return redacted
		}
	}
	s = jsonPair.ReplaceAllStringFunc(s, func(m string) string {
		sub := jsonPair.FindStringSubmatch(m)
		if r.sensitive(sub[1]) {
			return `"` + sub[1] + `"` + sub[2] + `"` + redacted + `"`
		}
		return m
	})
	return formPair.ReplaceAllStringFunc(s, func(m string) string {
		key, _, _ := strings.Cut(m, "=")
		name := key
		if u, err := url.QueryUnescape(key); err == nil {
			name = u
		}
		if r.sensitive(name) {
			return key + "=" + redacted
		}
		return m
	})
}

func (r Redaction) jsonValue(value any, prefix string, depth int) bool {
	changed := false
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			if r.sensitive(name) || depth >= 32 {
				v[key] = redacted
				changed = true
				continue
			}
			if r.jsonValue(item, name, depth+1) {
				changed = true
			}
		}
	case []any:
		for i, item := range v {
			if depth >= 32 {
				v[i] = redacted
				changed = true
				continue
			}
			if r.jsonValue(item, prefix, depth+1) {
				changed = true
			}
		}
	}
	return changed
}

func (r Redaction) uri(s string) string {
	if s == "" || s == redacted {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return r.rawURI(s)
	}
	if u.Opaque != "" && r.Level < LevelFull {
		return redacted
	}
	u.RawQuery = r.query(u.RawQuery)
	if u.User != nil {
		name := u.User.Username()
		password, hasPassword := u.User.Password()
		if r.sensitive("username") {
			name = redacted
		}
		if r.sensitive("password") {
			password = redacted
		}
		if hasPassword {
			u.User = url.UserPassword(name, password)
		} else {
			u.User = url.User(name)
		}
	}
	if strings.Contains(u.Fragment, "=") {
		u.Fragment = r.query(u.Fragment)
		u.RawFragment = ""
	}
	return u.String()
}

// rawURI handles URIs that url.Parse rejects. 2026-10-06 08:50: invalid
// escapes (%zz, %u0027) and control bytes are typical of attack payloads,
// so hiding the whole URI at standard removed the evidence needed to judge
// a match. Query and fragment pairs still follow the policy, and userinfo
// is hidden whenever the URL form would hide its password.
func (r Redaction) rawURI(s string) string {
	rest, fragment, hasFragment := strings.Cut(s, "#")
	path, query, hasQuery := strings.Cut(rest, "?")
	if scheme, after, ok := strings.Cut(path, "://"); ok && scheme != "" {
		authority, tail, hasTail := strings.Cut(after, "/")
		if at := strings.LastIndexByte(authority, '@'); at >= 0 && r.sensitive("password") {
			path = scheme + "://" + redacted + authority[at:]
			if hasTail {
				path += "/" + tail
			}
		}
	}
	out := path
	if hasQuery {
		out += "?" + r.query(query)
	}
	if hasFragment {
		if strings.Contains(fragment, "=") {
			fragment = r.query(fragment)
		}
		out += "#" + fragment
	}
	return out
}

// hit applies the policy to the matched data and value of one hit.
func (r Redaction) hit(h *Hit) {
	hide := func() {
		if h.Data != "" {
			h.Data = redacted
		}
		if h.Value != "" {
			h.Value = redacted
		}
	}
	if r.Level == LevelStrict {
		hide()
		return
	}
	collection, key, _ := strings.Cut(h.Var, ":")
	switch {
	case h.Var == "":
		// Logdata without a "found within" variable cannot be classified.
		if r.Level < LevelFull {
			hide()
			return
		}
		h.Data, h.Value = r.pairs(h.Data), r.pairs(h.Value)
	case namesCollections[collection]:
	case collection == "REQUEST_FILENAME" || collection == "REQUEST_BASENAME" || collection == "REQUEST_METHOD" || collection == "REQUEST_PROTOCOL" || collection == "SERVER_NAME" || collection == "REMOTE_ADDR":
	case collection == "REQUEST_COOKIES":
		if r.sensitiveCookie(key) {
			hide()
		}
	case keyedCollections[collection]:
		if key == "" && r.Level < LevelFull {
			hide()
			return
		}
		if r.sensitive(key) {
			hide()
			return
		}
		if collection == "REQUEST_HEADERS" && (strings.EqualFold(key, "referer") || strings.EqualFold(key, "origin")) {
			before := h.Value
			h.Value = r.uri(h.Value)
			if before != h.Value {
				h.Data = redacted
			}
		}
	case compositeCollections[collection]:
		before := h.Value
		switch collection {
		case "REQUEST_URI", "REQUEST_URI_RAW":
			h.Value = r.uri(h.Value)
		case "QUERY_STRING":
			h.Value = r.query(h.Value)
		case "REQUEST_LINE":
			fields := strings.SplitN(h.Value, " ", 3)
			if len(fields) == 3 {
				fields[1] = r.uri(fields[1])
				h.Value = strings.Join(fields, " ")
			} else if r.Level < LevelFull {
				h.Value = redacted
			}
		case "XML":
			if r.Level < LevelFull || len(r.Hide) > 0 {
				h.Value = redacted
			}
		default:
			if r.Level < LevelFull && !json.Valid([]byte(h.Value)) && !strings.Contains(h.Value, "=") {
				h.Value = redacted
			} else {
				h.Value = r.pairs(h.Value)
			}
		}
		if h.Value != before {
			h.Data = redacted
		} else {
			h.Data = r.pairs(h.Data)
		}
	default:
		if r.Level < LevelFull {
			hide()
		}
	}
}

// URI applies the same policy to the legacy local audit viewer.
func (r Redaction) URI(s string) string {
	if r.Level == LevelStrict {
		path, _ := splitURI(s)
		return path
	}
	return truncate(r.uri(s), maxPathLen+maxQueryLen)
}

// query applies the policy to a raw query string.
func (r Redaction) query(raw string) string {
	if r.Level == LevelStrict || raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		key, _, hasValue := strings.Cut(p, "=")
		name := key
		if u, err := url.QueryUnescape(key); err == nil {
			name = u
		}
		if hasValue && r.sensitive(name) {
			parts[i] = key + "=" + redacted
		}
	}
	return truncate(strings.Join(parts, "&"), maxQueryLen)
}

// headers applies the policy to request headers (lowercase names). Hidden
// credentials stay listed with a redacted value: their presence matters.
func (r Redaction) headers(in map[string]string) map[string]string {
	if r.Level == LevelStrict || len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for name, value := range in {
		name = strings.ToLower(name)
		switch {
		case r.sensitive(name):
			out[name] = redacted
		case r.Level >= LevelFull || diagnosticHeaders[name] || r.keeps(name):
			if name == "referer" || name == "origin" {
				value = r.uri(value)
			}
			out[name] = truncate(value, maxHeaderValue)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Apply returns a copy of e with the policy applied. Redaction only
// removes detail: applying a stricter policy to an already redacted event
// gives the same result as applying it to the original, and a less strict
// policy cannot restore or relabel hidden data.
func (r Redaction) Apply(e *Event) *Event {
	c := *e
	c.Hits = append([]Hit(nil), e.Hits...)
	c.QueryKeys = append([]string(nil), e.QueryKeys...)
	if e.Headers != nil {
		c.Headers = make(map[string]string, len(e.Headers))
		for k, v := range e.Headers {
			c.Headers[k] = v
		}
	}
	r.apply(&c)
	return &c
}

// apply redacts e in place.
func (r Redaction) apply(e *Event) {
	if r.Level < LevelStrict || r.Level > LevelFull {
		r.Level = LevelStrict
	}
	if e.Redaction != "" {
		if stored, err := ParseLevel(e.Redaction); err == nil {
			r.Level = Stricter(r.Level, stored)
		} else {
			r.Level = LevelStrict
		}
	}
	for i := range e.Hits {
		r.hit(&e.Hits[i])
		e.Hits[i].Var = truncate(e.Hits[i].Var, 256)
		e.Hits[i].Data = truncate(e.Hits[i].Data, maxDataLen)
		e.Hits[i].Value = truncate(e.Hits[i].Value, maxValueLen)
	}
	e.Query = r.query(e.Query)
	e.Headers = r.headers(e.Headers)
	e.Redaction = r.Level.String()
}

// maxHeaders bounds the request headers carried by one event.
const (
	maxHeaders     = 40
	maxHeaderValue = 256
)

// requestHeaders flattens the audit record's request headers (part B).
func requestHeaders(in map[string][]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maxHeaders {
		names = names[:maxHeaders]
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		out[strings.ToLower(name)] = strings.Join(in[name], ", ")
	}
	return out
}
