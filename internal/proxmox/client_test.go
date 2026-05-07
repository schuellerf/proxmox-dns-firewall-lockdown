package proxmox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetGuestConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		require.Equal(t, "/api2/json/nodes/x/lxc/1/config", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"description": "hi", "digest": "d"},
		})
	}))
	t.Cleanup(srv.Close)

	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)

	m, err := c.GetGuestConfig("lxc", "x", 1)
	require.NoError(t, err)
	require.Equal(t, "hi", m["description"])
}
