package ipgroups

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// List formats.
const (
	FormatSRS  = "srs"  // sing-box binary rule-set
	FormatJSON = "json" // sing-box source rule-set
	FormatText = "text" // one IP or CIDR per line, # comments
)

// Parsed is a list read from a source.
type Parsed struct {
	Set     *Set
	Format  string
	Version int // rule-set version (sing-box formats)
	Rules   int // top-level rules (sing-box formats)
	Skipped int // top-level rules without IP conditions (domains, ports...)
}

var (
	// MaxPrefixes bounds a group: Coraza compares the client address with
	// every prefix of a list, so very large lists cost time on each request.
	MaxPrefixes = 100000
	// maxDecompressed bounds the decompressed size of a binary rule-set.
	maxDecompressed int64 = 64 << 20

	errTooLarge = errors.New("decompressed rule-set too large")
)

var srsMagic = []byte("SRS")

// Parse detects the format of data and returns its IP set. sing-box rules
// can be used when they hold only ip_cidr/source_ip_cidr conditions (or are
// "or" logical rules of such rules). Rules without any IP condition (domain,
// port, process...) are skipped; rules that combine IP CIDRs with other
// conditions, inverted IP rules and "and" logical rules over IP rules cannot
// be expressed as an IP group and are rejected.
func Parse(data []byte) (Parsed, error) {
	var (
		p   Parsed
		b   Builder
		err error
	)
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(data, srsMagic):
		p.Format = FormatSRS
		err = parseSRS(data, &p, &b)
	case bytes.HasPrefix(trimmed, []byte("{")):
		p.Format = FormatJSON
		err = parseJSON(trimmed, &p, &b)
	default:
		p.Format = FormatText
		err = parseText(data, &b)
	}
	if err != nil {
		return Parsed{}, err
	}
	p.Set = b.Set()
	if p.Set.Empty() {
		return Parsed{}, errors.New("the list has no IP prefixes")
	}
	if n := len(p.Set.Prefixes()); n > MaxPrefixes {
		return Parsed{}, fmt.Errorf("the list has %d prefixes, more than the limit of %d", n, MaxPrefixes)
	}
	return p, nil
}

// parseText reads one IP or CIDR per line; "#" starts a comment.
func parseText(data []byte, b *Builder) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text, _, _ := strings.Cut(sc.Text(), "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if err := addCIDR(b, text); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	return sc.Err()
}

func addCIDR(b *Builder, s string) error {
	if p, err := netip.ParsePrefix(s); err == nil {
		b.AddPrefix(p)
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR %q", truncate(s, 64))
	}
	b.AddPrefix(netip.PrefixFrom(a, a.BitLen()))
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ruleIP reports whether a rule holds IP conditions, or why it cannot be
// used as an IP group. Usable rules add their ranges to the builder.
type ruleIP struct {
	hasIP bool
	err   error
}

// --- sing-box source (JSON) ---

type jsonRuleSet struct {
	Version int               `json:"version"`
	Rules   []json.RawMessage `json:"rules"`
}

// ipFields are the client-address conditions of a headless rule.
var ipFields = map[string]bool{"ip_cidr": true, "source_ip_cidr": true}

func parseJSON(data []byte, p *Parsed, b *Builder) error {
	var rs jsonRuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("invalid sing-box rule-set JSON: %w", err)
	}
	if rs.Version < 1 {
		return errors.New("invalid sing-box rule-set JSON: missing version")
	}
	p.Version, p.Rules = rs.Version, len(rs.Rules)
	for i, raw := range rs.Rules {
		r := jsonRule(raw, b, 0)
		if r.err != nil {
			return fmt.Errorf("rule %d: %w", i, r.err)
		}
		if !r.hasIP {
			p.Skipped++
		}
	}
	return nil
}

func jsonRule(raw json.RawMessage, b *Builder, depth int) ruleIP {
	if depth > 32 {
		return ruleIP{err: errors.New("logical rules nested too deep")}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ruleIP{err: err}
	}
	var kind string
	if t, ok := fields["type"]; ok {
		if err := json.Unmarshal(t, &kind); err != nil {
			return ruleIP{err: err}
		}
	}
	invert := false
	if v, ok := fields["invert"]; ok {
		if err := json.Unmarshal(v, &invert); err != nil {
			return ruleIP{err: err}
		}
	}
	if kind == "logical" {
		var mode string
		var rules []json.RawMessage
		if err := json.Unmarshal(fields["mode"], &mode); err != nil {
			return ruleIP{err: errors.New("logical rule without mode")}
		}
		if err := json.Unmarshal(fields["rules"], &rules); err != nil {
			return ruleIP{err: errors.New("logical rule without rules")}
		}
		// Sub-rules of an "and" or inverted rule must not contribute.
		scratch := &Builder{}
		target := b
		if mode != "or" || invert {
			target = scratch
		}
		hasIP := false
		for _, sub := range rules {
			r := jsonRule(sub, target, depth+1)
			if r.err != nil {
				return r
			}
			hasIP = hasIP || r.hasIP
		}
		if hasIP && (mode != "or" || invert) {
			return ruleIP{err: fmt.Errorf("%s logical rules over IP CIDRs cannot be used as an IP group", describeLogical(mode, invert))}
		}
		return ruleIP{hasIP: hasIP}
	}
	if kind != "" && kind != "default" {
		return ruleIP{err: fmt.Errorf("unknown rule type %q", kind)}
	}
	hasIP, other := false, false
	var cidrs []string
	for name, value := range fields {
		switch {
		case ipFields[name]:
			var list []string
			if err := json.Unmarshal(value, &list); err != nil {
				var one string
				if err := json.Unmarshal(value, &one); err != nil {
					return ruleIP{err: fmt.Errorf("%s: %w", name, err)}
				}
				list = []string{one}
			}
			hasIP = hasIP || len(list) > 0
			cidrs = append(cidrs, list...)
		case name == "type" || name == "invert":
		default:
			other = true
		}
	}
	if !hasIP {
		return ruleIP{}
	}
	if err := checkPlain(other, invert); err != nil {
		return ruleIP{err: err}
	}
	for _, c := range cidrs {
		if err := addCIDR(b, strings.TrimSpace(c)); err != nil {
			return ruleIP{err: err}
		}
	}
	return ruleIP{hasIP: true}
}

func describeLogical(mode string, invert bool) string {
	if invert {
		return "inverted " + mode
	}
	return `"` + mode + `"`
}

func checkPlain(other, invert bool) error {
	switch {
	case other:
		return errors.New("a rule combining IP CIDRs with other conditions cannot be used as an IP group")
	case invert:
		return errors.New("an inverted IP rule cannot be used as an IP group")
	}
	return nil
}

// --- sing-box binary (.srs) ---

// Item types of the binary format (sing-box common/srs).
const (
	itemQueryType = iota
	itemNetwork
	itemDomain
	itemDomainKeyword
	itemDomainRegex
	itemSourceIPCIDR
	itemIPCIDR
	itemSourcePort
	itemSourcePortRange
	itemPort
	itemPortRange
	itemProcessName
	itemProcessPath
	itemPackageName
	itemWIFISSID
	itemWIFIBSSID
	itemAdGuardDomain
	itemProcessPathRegex
	itemNetworkType
	itemNetworkIsExpensive
	itemNetworkIsConstrained
	itemNetworkInterfaceAddress
	itemDefaultInterfaceAddress
	itemPackageNameRegex
	itemFinal = 0xFF
)

// limitedReader fails, instead of truncating, past its limit.
type limitedReader struct {
	r    *bufio.Reader
	left int64
}

func (l *limitedReader) ReadByte() (byte, error) {
	if l.left <= 0 {
		return 0, errTooLarge
	}
	c, err := l.r.ReadByte()
	if err == nil {
		l.left--
	}
	return c, err
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

func parseSRS(data []byte, p *Parsed, b *Builder) error {
	if len(data) < 4 {
		return errors.New("truncated rule-set header")
	}
	p.Version = int(data[3])
	if p.Version < 1 {
		return fmt.Errorf("invalid rule-set version %d", p.Version)
	}
	zr, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		return fmt.Errorf("invalid rule-set compression: %w", err)
	}
	defer func() { _ = zr.Close() }()
	r := &limitedReader{r: bufio.NewReader(zr), left: maxDecompressed}
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return srsError(err)
	}
	for i := uint64(0); i < count; i++ {
		res := srsRule(r, b, 0)
		if res.err != nil {
			return fmt.Errorf("rule %d: %w", i, srsError(res.err))
		}
		p.Rules++
		if !res.hasIP {
			p.Skipped++
		}
	}
	// The writer emits nothing after the rules; trailing data means a
	// different or damaged format.
	if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after the last rule")
		}
		return srsError(err)
	}
	return nil
}

func srsError(err error) error {
	switch {
	case errors.Is(err, errTooLarge):
		return errTooLarge
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("truncated rule-set")
	}
	return err
}

func srsRule(r *limitedReader, b *Builder, depth int) ruleIP {
	if depth > 32 {
		return ruleIP{err: errors.New("logical rules nested too deep")}
	}
	kind, err := r.ReadByte()
	if err != nil {
		return ruleIP{err: err}
	}
	switch kind {
	case 0:
		return srsDefaultRule(r, b)
	case 1:
		mode, err := r.ReadByte()
		if err != nil {
			return ruleIP{err: err}
		}
		if mode > 1 {
			return ruleIP{err: fmt.Errorf("unknown logical mode %d", mode)}
		}
		count, err := binary.ReadUvarint(r)
		if err != nil {
			return ruleIP{err: err}
		}
		scratch := &Builder{}
		results := make([]ruleIP, 0, min(count, 1024))
		for i := uint64(0); i < count; i++ {
			// Ranges go to a scratch builder until the mode and invert
			// flag, written after the sub-rules, are known.
			res := srsRule(r, scratch, depth+1)
			if res.err != nil {
				return res
			}
			results = append(results, res)
		}
		invert, err := r.ReadByte()
		if err != nil {
			return ruleIP{err: err}
		}
		hasIP := false
		for _, res := range results {
			hasIP = hasIP || res.hasIP
		}
		modeName := map[byte]string{0: "and", 1: "or"}[mode]
		if hasIP && (mode != 1 || invert != 0) {
			return ruleIP{err: fmt.Errorf("%s logical rules over IP CIDRs cannot be used as an IP group", describeLogical(modeName, invert != 0))}
		}
		b.v4 = append(b.v4, scratch.v4...)
		b.v6 = append(b.v6, scratch.v6...)
		return ruleIP{hasIP: hasIP}
	}
	return ruleIP{err: fmt.Errorf("unknown rule type %d", kind)}
}

func srsDefaultRule(r *limitedReader, b *Builder) ruleIP {
	var scratch Builder
	hasIP, other := false, false
	for {
		item, err := r.ReadByte()
		if err != nil {
			return ruleIP{err: err}
		}
		switch item {
		case itemSourceIPCIDR, itemIPCIDR:
			hasIP = true
			err = readIPSet(r, &scratch)
		case itemQueryType, itemSourcePort, itemPort:
			other = true
			err = skipFixed(r, 2)
		case itemNetworkType:
			other = true
			err = skipFixed(r, 1)
		case itemNetwork, itemDomainKeyword, itemDomainRegex, itemSourcePortRange, itemPortRange,
			itemProcessName, itemProcessPath, itemPackageName, itemWIFISSID, itemWIFIBSSID,
			itemProcessPathRegex, itemPackageNameRegex:
			other = true
			err = skipStrings(r)
		case itemDomain, itemAdGuardDomain:
			other = true
			err = skipSuccinctSet(r)
		case itemNetworkIsExpensive, itemNetworkIsConstrained:
			other = true
		case itemNetworkInterfaceAddress:
			other = true
			err = skipInterfaceAddresses(r)
		case itemDefaultInterfaceAddress:
			other = true
			err = skipPrefixes(r)
		case itemFinal:
			invert, err := r.ReadByte()
			if err != nil {
				return ruleIP{err: err}
			}
			if !hasIP {
				return ruleIP{}
			}
			if err := checkPlain(other, invert != 0); err != nil {
				return ruleIP{err: err}
			}
			b.v4 = append(b.v4, scratch.v4...)
			b.v6 = append(b.v6, scratch.v6...)
			return ruleIP{hasIP: true}
		default:
			return ruleIP{err: fmt.Errorf("unknown rule item type %d", item)}
		}
		if err != nil {
			return ruleIP{err: err}
		}
	}
}

// readIPSet reads a netipx IPSet: version 1, a big-endian uint64 count and
// count (from, to) address pairs, each a uvarint length (4 or 16) and bytes.
func readIPSet(r *limitedReader, b *Builder) error {
	version, err := r.ReadByte()
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported IP set version %d", version)
	}
	var raw [8]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return err
	}
	count := binary.BigEndian.Uint64(raw[:])
	for i := uint64(0); i < count; i++ {
		from, err := readAddr(r)
		if err != nil {
			return err
		}
		to, err := readAddr(r)
		if err != nil {
			return err
		}
		if err := b.AddRange(from, to); err != nil {
			return err
		}
	}
	return nil
}

func readAddr(r *limitedReader) (netip.Addr, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return netip.Addr{}, err
	}
	if n != 4 && n != 16 {
		return netip.Addr{}, fmt.Errorf("invalid address length %d", n)
	}
	var buf [16]byte
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return netip.Addr{}, err
	}
	addr, _ := netip.AddrFromSlice(buf[:n])
	return addr, nil
}

// skipN discards n bytes without allocating n.
func skipN(r *limitedReader, n uint64) error {
	if n > uint64(r.left) { //nolint:gosec // G115: left is never negative (limitedReader stops at 0).
		return errTooLarge
	}
	_, err := io.CopyN(io.Discard, r, int64(n)) //nolint:gosec // G115: n <= left, an int64.
	return err
}

// skipFixed skips a uvarint count of fixed-size values.
func skipFixed(r *limitedReader, size uint64) error {
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	if count > uint64(r.left)/size { //nolint:gosec // G115: left is never negative.
		return errTooLarge
	}
	return skipN(r, count*size)
}

// skipStrings skips a uvarint count of uvarint-length strings.
func skipStrings(r *limitedReader) error {
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		n, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		if err := skipN(r, n); err != nil {
			return err
		}
	}
	return nil
}

// skipSuccinctSet skips a domain matcher: a reserved byte, two uint64
// slices (leaves, label bitmap) and a byte slice (labels).
func skipSuccinctSet(r *limitedReader) error {
	if _, err := r.ReadByte(); err != nil {
		return err
	}
	for _, size := range []uint64{8, 8, 1} {
		if err := skipFixed(r, size); err != nil {
			return err
		}
	}
	return nil
}

// skipPrefixes skips a uvarint count of (length, address, bits) prefixes.
func skipPrefixes(r *limitedReader) error {
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		if _, err := readAddr(r); err != nil {
			return err
		}
		if _, err := r.ReadByte(); err != nil {
			return err
		}
	}
	return nil
}

// skipInterfaceAddresses skips a map of interface type to prefixes.
func skipInterfaceAddresses(r *limitedReader) error {
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		if _, err := r.ReadByte(); err != nil {
			return err
		}
		if err := skipPrefixes(r); err != nil {
			return err
		}
	}
	return nil
}
