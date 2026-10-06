package ipgroups

import (
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
)

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func prefixStrings(s *Set) []string {
	var out []string
	for _, p := range s.Prefixes() {
		out = append(out, p.String())
	}
	return out
}

func TestSetMergesAndMinimizes(t *testing.T) {
	var b Builder
	for _, p := range prefixes(t, "192.0.2.0/25", "192.0.2.128/25", "198.51.100.0/24", "198.51.100.7/32",
		"2001:db8::/33", "2001:db8:8000::/33", "10.0.0.0/8", "10.1.0.0/16") {
		b.AddPrefix(p)
	}
	got := prefixStrings(b.Set())
	want := []string{"10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSetSplitsRangesIntoPrefixes(t *testing.T) {
	var b Builder
	if err := b.AddRange(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.6")); err != nil {
		t.Fatal(err)
	}
	if err := b.AddRange(netip.MustParseAddr("2001:db8::"), netip.MustParseAddr("2001:db8::2")); err != nil {
		t.Fatal(err)
	}
	got := prefixStrings(b.Set())
	want := []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32", "2001:db8::/127", "2001:db8::2/128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if err := b.AddRange(netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.8")); err == nil {
		t.Fatal("a reversed range must be rejected")
	}
	if err := b.AddRange(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::")); err == nil {
		t.Fatal("a range across address families must be rejected")
	}
}

func TestSetWholeAddressSpaces(t *testing.T) {
	var b Builder
	for _, p := range prefixes(t, "0.0.0.0/1", "128.0.0.0/1", "::/0", "2001:db8::/32") {
		b.AddPrefix(p)
	}
	s := b.Set()
	if got := prefixStrings(s); !reflect.DeepEqual(got, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("got %v", got)
	}
	for _, a := range []string{"0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if !s.Contains(netip.MustParseAddr(a)) {
			t.Fatalf("%s must be contained", a)
		}
	}
}

func TestSetUnmapsIPv4MappedAddresses(t *testing.T) {
	var b Builder
	b.AddPrefix(netip.MustParsePrefix("::ffff:192.0.2.0/120"))
	s := b.Set()
	if got := prefixStrings(s); !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("got %v", got)
	}
	if !s.Contains(netip.MustParseAddr("192.0.2.9")) || !s.Contains(netip.MustParseAddr("::ffff:192.0.2.9")) {
		t.Fatal("IPv4 and IPv4-mapped forms of a member must match")
	}
}

func TestSetContainsMatchesInputPrefixes(t *testing.T) {
	rnd := rand.New(rand.NewSource(7)) //nolint:gosec // G404: deterministic test data, not a secret.
	var b Builder
	var input []netip.Prefix
	for i := 0; i < 400; i++ {
		p := netip.PrefixFrom(randomAddr(rnd, 4), 18+rnd.Intn(15)).Masked()
		input = append(input, p)
		b.AddPrefix(p)
	}
	s := b.Set()
	out := s.Prefixes()
	for i := 0; i < 20000; i++ {
		a := randomAddr(rnd, 5)
		want := false
		for _, p := range input {
			if p.Contains(a) {
				want = true
				break
			}
		}
		gotOut := false
		for _, p := range out {
			if p.Contains(a) {
				gotOut = true
				break
			}
		}
		if s.Contains(a) != want || gotOut != want {
			t.Fatalf("%s: set %v, prefixes %v, want %v", a, s.Contains(a), gotOut, want)
		}
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].Overlaps(out[i]) {
			t.Fatalf("output prefixes overlap: %s %s", out[i-1], out[i])
		}
	}
}

// randomAddr returns an address in 10.0.0.0/16 .. 10.(span-1).255.255.
func randomAddr(rnd *rand.Rand, span byte) netip.Addr {
	var b [4]byte
	_, _ = rnd.Read(b[:])
	b[0], b[1] = 10, b[1]%span
	return netip.AddrFrom4(b)
}
