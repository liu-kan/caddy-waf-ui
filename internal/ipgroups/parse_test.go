package ipgroups

import (
	"bytes"
	"compress/zlib"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func expected(t *testing.T, name string) []string {
	t.Helper()
	return strings.Fields(string(readFixture(t, name+".expected")))
}

// The .srs fixtures were compiled by sing-box itself; the expectations are
// what sing-box's own decoder reads from them (see testdata/README.md).
func TestParseSingBoxBinaryRuleSets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		rules   int
		skipped int
	}{
		{"ip-v1", 1, 1, 0}, {"ip", 3, 2, 0}, {"mixed", 5, 9, 7}, {"random", 3, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(readFixture(t, tc.name+".srs"))
			if err != nil {
				t.Fatal(err)
			}
			if p.Format != FormatSRS || p.Version != tc.version || p.Rules != tc.rules || p.Skipped != tc.skipped {
				t.Fatalf("metadata: %+v", p)
			}
			if got := prefixStrings(p.Set); !reflect.DeepEqual(got, expected(t, tc.name)) {
				t.Fatalf("prefixes differ from sing-box:\n got %v\nwant %v", got, expected(t, tc.name))
			}
		})
	}
}

func TestParseSingBoxSourceRuleSets(t *testing.T) {
	for _, name := range []string{"ip-v1", "ip", "mixed", "random"} {
		p, err := Parse(readFixture(t, name+".json"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Format != FormatJSON {
			t.Fatalf("%s: format %q", name, p.Format)
		}
		if got := prefixStrings(p.Set); !reflect.DeepEqual(got, expected(t, name)) {
			t.Fatalf("%s: got %v", name, got)
		}
	}
}

func TestParseRejectsRulesThatAreNotPlainIPGroups(t *testing.T) {
	for name, want := range map[string]string{
		"mixed-condition": "other conditions",
		"inverted":        "inverted",
		"logical-and":     "logical",
	} {
		for _, ext := range []string{".srs", ".json"} {
			_, err := Parse(readFixture(t, name+ext))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s%s: %v", name, ext, err)
			}
		}
	}
}

func TestParsePlainText(t *testing.T) {
	p, err := Parse([]byte("# office\n192.0.2.0/24\n\n198.51.100.7   # gateway\r\n2001:db8::/32\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "198.51.100.7/32", "2001:db8::/32"}
	if got := prefixStrings(p.Set); p.Format != FormatText || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s %v", p.Format, got)
	}
	if _, err := Parse([]byte("192.0.2.0/24\nnot-an-ip\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("invalid lines must name their line: %v", err)
	}
}

func TestParseRejectsMalformedBinaries(t *testing.T) {
	good := readFixture(t, "ip.srs")
	for name, data := range map[string][]byte{
		"truncated":  good[:len(good)-6],
		"bad zlib":   append([]byte("SRS\x03"), bytes.Repeat([]byte{0xff}, 16)...),
		"no rules":   srsPayload(t, 3, []byte{0x00}),
		"bad item":   srsPayload(t, 3, []byte{0x01, 0x00, 0x7f}),
		"bad family": srsPayload(t, 3, []byte{0x01, 0x00, 0x06, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 5, 1, 2, 3, 4, 5}),
		"trailing":   append(append([]byte(nil), good[:4]...), compress(t, append(rawPayload(t, good), 0x00))...),
	} {
		if _, err := Parse(data); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestParseBoundsDecompressedSize(t *testing.T) {
	defer func(old int64) { maxDecompressed = old }(maxDecompressed)
	maxDecompressed = 64
	// A single huge string item that decompresses beyond the limit.
	body := append([]byte{0x01, 0x00, 0x03, 0x01, 0x80, 0x02}, bytes.Repeat([]byte("a"), 256)...)
	if _, err := Parse(srsPayload(t, 3, body)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("decompression bomb: %v", err)
	}
}

func TestParseBoundsPrefixCount(t *testing.T) {
	defer func(old int) { MaxPrefixes = old }(MaxPrefixes)
	MaxPrefixes = 100
	if _, err := Parse(readFixture(t, "random.srs")); err == nil || !strings.Contains(err.Error(), "prefixes") {
		t.Fatalf("prefix limit: %v", err)
	}
}

func compress(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// srsPayload builds a binary rule-set from an uncompressed body.
func srsPayload(t *testing.T, version byte, body []byte) []byte {
	t.Helper()
	return append([]byte{'S', 'R', 'S', version}, compress(t, body)...)
}

func rawPayload(t *testing.T, srs []byte) []byte {
	t.Helper()
	r, err := zlib.NewReader(bytes.NewReader(srs[4:]))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
