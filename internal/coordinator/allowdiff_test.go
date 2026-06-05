package coordinator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewlyAllowedFQDNs(t *testing.T) {
	oldAllowed := map[string]struct{}{
		"keep.example": {},
	}
	newAllowed := map[string]struct{}{
		"keep.example": {},
		"new1.example": {},
		"znew.example": {},
	}
	got := newlyAllowedFQDNs(oldAllowed, newAllowed)
	require.Equal(t, []string{"new1.example", "znew.example"}, got)
	require.Empty(t, newlyAllowedFQDNs(newAllowed, newAllowed))
	require.Equal(t, []string{"solo.example"}, newlyAllowedFQDNs(nil, map[string]struct{}{"solo.example": {}}))
}

func TestNewlyDeniedFQDNs(t *testing.T) {
	newAllowed := map[string]struct{}{
		"keep.example": {},
	}
	oldAllowed := map[string]struct{}{
		"keep.example":  {},
		"gone1.example": {},
		"zgone.example": {},
	}
	got := newlyDeniedFQDNs(oldAllowed, newAllowed)
	require.Equal(t, []string{"gone1.example", "zgone.example"}, got)
	require.Empty(t, newlyDeniedFQDNs(newAllowed, newAllowed))
	require.Equal(t, []string{"onlyold.example"}, newlyDeniedFQDNs(map[string]struct{}{"onlyold.example": {}}, nil))
}

func TestNewlyRemovedFQDNs(t *testing.T) {
	oldListed := map[string]struct{}{
		"keep.example":    {},
		"gone.example":    {},
		"blocked.example": {},
	}
	newListed := map[string]struct{}{
		"keep.example": {},
	}
	got := newlyRemovedFQDNs(oldListed, newListed)
	require.Equal(t, []string{"blocked.example", "gone.example"}, got)
	require.Empty(t, newlyRemovedFQDNs(newListed, newListed))
	require.Equal(t, []string{"solo.example"}, newlyRemovedFQDNs(map[string]struct{}{"solo.example": {}}, nil))
}

func TestCanonIPsUniqueStable(t *testing.T) {
	require.Empty(t, canonIPsUniqueStable(nil))
	require.Empty(t, canonIPsUniqueStable([]string{"bogus"}))
	got := canonIPsUniqueStable([]string{"1.2.3.4", " 2001:db8::1 ", "1.2.3.4", "::1"})
	require.Equal(t, []string{"1.2.3.4", "2001:db8::1", "::1"}, got)
}
