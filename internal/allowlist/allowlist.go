package allowlist

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

const BeginMarker = "PROXMOX_DNS_LOCKDOWN_BEGIN"
const EndMarker = "PROXMOX_DNS_LOCKDOWN_END"

// Normalize normalizes a DNS name for comparison.
func Normalize(name string) string {
	s := strings.TrimSpace(strings.ToLower(name))
	s = strings.TrimSuffix(s, ".")
	return s
}

// ParseListed returns FQDNs from non-empty lines, whether allowed or #commented.
func ParseListed(lines []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(line[1:])
		}
		n := Normalize(line)
		if n == "" {
			continue
		}
		out[n] = struct{}{}
	}
	return out
}

// ParseAllowed returns FQDNs that are allow-listed (non-empty, non-comment lines).
func ParseAllowed(innerLines []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, line := range innerLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[Normalize(line)] = struct{}{}
	}
	return out
}

// ExtractBlock returns inner lines only (between marker lines, exclusive).
func ExtractBlock(description string) (inner []string, hasBlock bool) {
	lines := splitLines(description)
	begin := -1
	end := -1
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case BeginMarker:
			begin = i
		case EndMarker:
			end = i
		}
	}
	if begin < 0 || end < 0 || end <= begin {
		return nil, false
	}
	inner = make([]string, 0, end-begin-1)
	for _, l := range lines[begin+1 : end] {
		inner = append(inner, trimTrailingEOL(l))
	}
	return inner, true
}

// SpliceBlock replaces an existing block or appends a new block at the end.
func SpliceBlock(description string, innerLines []string) (string, error) {
	lines := splitLines(description)
	begin := -1
	end := -1
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case BeginMarker:
			begin = i
		case EndMarker:
			end = i
		}
	}
	block := buildBlock(innerLines)
	if begin < 0 || end < 0 || end <= begin {
		d := strings.TrimRight(description, "\n")
		if d == "" {
			return block + "\n", nil
		}
		return d + "\n\n" + block + "\n", nil
	}
	var b bytes.Buffer
	for i := 0; i < begin; i++ {
		b.WriteString(lines[i])
		b.WriteByte('\n')
	}
	b.WriteString(block)
	b.WriteByte('\n')
	for i := end + 1; i < len(lines); i++ {
		b.WriteString(lines[i])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func buildBlock(innerLines []string) string {
	var b strings.Builder
	b.WriteString(BeginMarker)
	b.WriteByte('\n')
	for _, l := range innerLines {
		b.WriteString(trimTrailingEOL(l))
		b.WriteByte('\n')
	}
	b.WriteString(EndMarker)
	return b.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func trimTrailingEOL(s string) string {
	return strings.TrimRight(s, "\r\n")
}

func alreadyListed(inner []string, fqdn string) bool {
	n := Normalize(fqdn)
	for _, l := range inner {
		ls := strings.TrimSpace(l)
		if ls == "" {
			continue
		}
		if strings.HasPrefix(ls, "#") {
			ls = strings.TrimSpace(ls[1:])
		}
		if Normalize(ls) == n {
			return true
		}
	}
	return false
}

// MergeSuggestedLines appends "# fqdn." suggestions for domains in suggested that do not appear in inner.
func MergeSuggestedLines(inner []string, suggested map[string]struct{}) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(inner)+len(suggested))
	add := func(line string) {
		k := strings.TrimSpace(line)
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, strings.TrimRight(line, "\r\n"))
	}
	for _, l := range inner {
		add(l)
	}
	for fqdn := range suggested {
		if alreadyListed(inner, fqdn) {
			continue
		}
		n := Normalize(fqdn)
		if n == "" {
			continue
		}
		add(fmt.Sprintf("# %s.", n))
	}
	sort.Strings(out)
	return out
}

// ErrInvalidMarkers is reserved for stricter validation if needed later.
var ErrInvalidMarkers = fmt.Errorf("allowlist: invalid PROXMOX_DNS_LOCKDOWN markers")
