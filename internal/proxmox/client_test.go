package proxmox

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func envelopeData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func TestResolveGuestByVMID(t *testing.T) {
	data := []map[string]any{
		{"type": "node", "node": "pve"},
		{"type": "lxc", "vmid": 100, "node": "n1"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api2/json/cluster/resources", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		envelopeData(w, data)
	}))
	t.Cleanup(srv.Close)

	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	node, gt, err := c.ResolveGuestByVMID(100)
	require.NoError(t, err)
	require.Equal(t, "n1", node)
	require.Equal(t, "lxc", gt)
}

func TestResolveGuestByVMID_qemu(t *testing.T) {
	data := []map[string]any{
		{"type": "qemu", "vmid": 200, "node": "n2"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelopeData(w, data)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	node, gt, err := c.ResolveGuestByVMID(200)
	require.NoError(t, err)
	require.Equal(t, "n2", node)
	require.Equal(t, "qemu", gt)
}

func TestResolveGuestByVMID_notFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelopeData(w, []map[string]any{})
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	_, _, err = c.ResolveGuestByVMID(99)
	require.ErrorIs(t, err, ErrGuestVMIDNotFound)
}

func TestResolveGuestByVMID_ambiguous(t *testing.T) {
	data := []map[string]any{
		{"type": "lxc", "vmid": 100, "node": "n1"},
		{"type": "lxc", "vmid": 100, "node": "n2"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelopeData(w, data)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	_, _, err = c.ResolveGuestByVMID(100)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrGuestVMIDAmbiguous))
}

func TestResolveGuestByVMID_forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	_, _, err = c.ResolveGuestByVMID(1)
	require.ErrorIs(t, err, ErrClusterResourcesForbidden)
}

func TestResolveGuestByVMID_compositeIDOnly(t *testing.T) {
	data := []map[string]any{
		{"type": "qemu", "id": "qemu/116", "node": "proxmox-node1"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelopeData(w, data)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	node, gt, err := c.ResolveGuestByVMID(116)
	require.NoError(t, err)
	require.Equal(t, "proxmox-node1", node)
	require.Equal(t, "qemu", gt)
}

func TestResolveGuestByVMID_vmidJSONString(t *testing.T) {
	data := []map[string]any{
		{"type": "qemu", "vmid": "116", "node": "proxmox-node1"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelopeData(w, data)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	node, gt, err := c.ResolveGuestByVMID(116)
	require.NoError(t, err)
	require.Equal(t, "proxmox-node1", node)
	require.Equal(t, "qemu", gt)
}

func TestResolveGuestByVMID_uppercaseType(t *testing.T) {
	data := []map[string]any{
		{"type": "QEMU", "vmid": 116, "node": "proxmox-node1"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelopeData(w, data)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	_, gt, err := c.ResolveGuestByVMID(116)
	require.NoError(t, err)
	require.Equal(t, "qemu", gt)
}

func TestGuestTargetDisplay(t *testing.T) {
	require.Equal(t, "116 (web01)", GuestTargetDisplay(116, map[string]any{"hostname": "web01"}))
	require.Equal(t, "200 (srv)", GuestTargetDisplay(200, map[string]any{"name": "srv"}))
	require.Equal(t, "1 (web)", GuestTargetDisplay(1, map[string]any{"hostname": "web", "name": "other"}))
	require.Equal(t, "9 (-)", GuestTargetDisplay(9, map[string]any{}))
	require.Equal(t, "0 (-)", GuestTargetDisplay(0, nil))
}

func TestGetVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api2/json/version", r.URL.Path)
		envelopeData(w, map[string]string{
			"version": "9.0.0",
			"release": "9.0",
			"repoid":  "abc",
		})
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "u@s!tok", "sec", false)
	require.NoError(t, err)
	v, err := c.GetVersion()
	require.NoError(t, err)
	require.Equal(t, "9.0.0", v.Version)
	require.Equal(t, "9.0", v.Release)
}

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
