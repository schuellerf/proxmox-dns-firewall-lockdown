package allowlist

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplicePreservesOutside(t *testing.T) {
	raw := "before\nPROXMOX_DNS_LOCKDOWN_BEGIN\n#x\ny\nPROXMOX_DNS_LOCKDOWN_END\nafter\n"
	got, err := SpliceBlock(raw, []string{"allowed.example"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(strings.TrimSpace(got), "before"))
	require.Contains(t, got, BeginMarker)
	require.Contains(t, got, "allowed.example")
	require.Contains(t, got, "after")
}

func TestParseAllowedSkipsHashes(t *testing.T) {
	inner := []string{"#off", "on."}
	got := ParseAllowed(inner)
	_, yes := got[Normalize("on.")]
	require.True(t, yes)
	_, no := got[Normalize("off")]
	require.False(t, no)
}

func TestMergeSuggestedComments(t *testing.T) {
	inner := []string{"alpha."}
	se := map[string]struct{}{Normalize("beta"): {}}
	got := MergeSuggestedLines(inner, se)
	require.Contains(t, got, "# beta.")
	require.Contains(t, got, "alpha.")
}
