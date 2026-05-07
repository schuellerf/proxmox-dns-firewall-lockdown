package coordinator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnqueueFwActivities_trimsOldest(t *testing.T) {
	c := &Coordinator{}
	c.snap = ViewState{MergedListText: "stub"}
	for i := range 25 {
		c.enqueueFwActivities([]FirewallActivityRow{{Result: "allow_added", FQDN: fmt.Sprintf("h%d", i)}})
	}
	c.fwLogMu.Lock()
	n := len(c.fwActivity)
	first := c.fwActivity[0].FQDN
	last := c.fwActivity[n-1].FQDN
	c.fwLogMu.Unlock()
	require.Equal(t, maxFwActivityLines, n)
	require.Equal(t, "h5", first)
	require.Equal(t, "h24", last)
}
