// Package ipgroups maintains named IP groups imported from sing-box rule-sets
// (binary .srs or JSON source) or plain CIDR lists, from operator-mounted
// files or periodically downloaded URLs. Each group is normalized into a
// canonical CIDR list that Coraza reads with @ipMatchFromFile; site policies
// attach block, engine-mode or anomaly-threshold rules to groups.
package ipgroups

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"sort"
)

// u128 is an address as an unsigned integer: IPv4 uses the low 32 bits.
type u128 struct{ hi, lo uint64 }

var maxU128 = u128{^uint64(0), ^uint64(0)}

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

func (a u128) add1() u128 {
	lo := a.lo + 1
	hi := a.hi
	if lo == 0 {
		hi++
	}
	return u128{hi, lo}
}

// blockEnd returns a + 2^k - 1 for an a aligned to 2^k.
func (a u128) blockEnd(k int) u128 {
	switch {
	case k >= 128:
		return maxU128
	case k >= 64:
		return u128{a.hi | (1<<(k-64) - 1), ^uint64(0)}
	default:
		return u128{a.hi, a.lo | (1<<k - 1)}
	}
}

func (a u128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	if a.hi != 0 {
		return 64 + bits.TrailingZeros64(a.hi)
	}
	return 128
}

// span is an inclusive range of one family.
type span struct{ from, to u128 }

func toU128(a netip.Addr) u128 {
	if a.Is4() {
		b := a.As4()
		return u128{0, uint64(binary.BigEndian.Uint32(b[:]))}
	}
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func fromU128(v u128, v4 bool) netip.Addr {
	if v4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v.lo)) //nolint:gosec // G115: IPv4 values hold 32 bits by construction (toU128).
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], v.hi)
	binary.BigEndian.PutUint64(b[8:], v.lo)
	return netip.AddrFrom16(b)
}

// Builder collects prefixes and ranges into a Set.
type Builder struct{ v4, v6 []span }

// AddPrefix adds a prefix. IPv4-mapped IPv6 prefixes are added as IPv4.
func (b *Builder) AddPrefix(p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	from := toU128(p.Addr())
	width := 128
	if p.Addr().Is4() {
		width = 32
	}
	b.add(p.Addr().Is4(), span{from, from.blockEnd(width - p.Bits())})
}

// AddRange adds an inclusive range of one address family.
func (b *Builder) AddRange(from, to netip.Addr) error {
	if from.Is4In6() && to.Is4In6() {
		from, to = from.Unmap(), to.Unmap()
	}
	if !from.IsValid() || !to.IsValid() || from.Is4() != to.Is4() {
		return fmt.Errorf("invalid address range %s-%s", from, to)
	}
	if to.Less(from) {
		return fmt.Errorf("reversed address range %s-%s", from, to)
	}
	b.add(from.Is4(), span{toU128(from), toU128(to)})
	return nil
}

func (b *Builder) add(v4 bool, s span) {
	if v4 {
		b.v4 = append(b.v4, s)
	} else {
		b.v6 = append(b.v6, s)
	}
}

// Set returns the merged set. The builder can be reused.
func (b *Builder) Set() *Set {
	return &Set{v4: merge(b.v4), v6: merge(b.v6)}
}

func merge(in []span) []span {
	if len(in) == 0 {
		return nil
	}
	sorted := append([]span(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].from.less(sorted[j].from) })
	out := []span{sorted[0]}
	for _, s := range sorted[1:] {
		last := &out[len(out)-1]
		if last.to == maxU128 || !last.to.add1().less(s.from) {
			if last.to.less(s.to) {
				last.to = s.to
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// Union returns the addresses held by any of the sets.
func Union(sets ...*Set) *Set {
	var b Builder
	for _, s := range sets {
		if s != nil {
			b.v4 = append(b.v4, s.v4...)
			b.v6 = append(b.v6, s.v6...)
		}
	}
	return b.Set()
}

// Set is an immutable set of addresses: sorted, merged ranges per family.
type Set struct{ v4, v6 []span }

// Empty reports whether the set has no address.
func (s *Set) Empty() bool { return s == nil || len(s.v4) == 0 && len(s.v6) == 0 }

// Contains reports whether the set holds addr (IPv4-mapped IPv6 counts as
// IPv4).
func (s *Set) Contains(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	spans := s.v6
	if addr.Is4() {
		spans = s.v4
	}
	v := toU128(addr)
	i := sort.Search(len(spans), func(i int) bool { return v.less(spans[i].from) })
	return i > 0 && !spans[i-1].to.less(v)
}

// Prefixes returns the minimal CIDR list of the set, IPv4 first.
func (s *Set) Prefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	var out []netip.Prefix
	for _, sp := range s.v4 {
		out = appendPrefixes(out, sp, 32)
	}
	for _, sp := range s.v6 {
		out = appendPrefixes(out, sp, 128)
	}
	return out
}

// appendPrefixes splits a range into the largest aligned blocks.
func appendPrefixes(out []netip.Prefix, s span, width int) []netip.Prefix {
	from := s.from
	for {
		k := min(from.trailingZeros(), width)
		for k > 0 && s.to.less(from.blockEnd(k)) {
			k--
		}
		out = append(out, netip.PrefixFrom(fromU128(from, width == 32), width-k))
		end := from.blockEnd(k)
		if end == s.to {
			return out
		}
		from = end.add1()
	}
}
