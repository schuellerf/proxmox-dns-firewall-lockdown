package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// GuestType selects Proxmox API paths.
type GuestType string

const (
	GuestLXC  GuestType = "lxc"
	GuestQEMU GuestType = "qemu"
)

// Settings persists operator-editable options (0600 on disk recommended).
type Settings struct {
	PVEHost       string    `json:"pve_host"`        // e.g. https://192.168.1.1:8006
	PVENode       string    `json:"pve_node"`        // hostname of node
	PVEVMID       int       `json:"pve_vmid"`
	GuestType     GuestType `json:"guest_type"`      // lxc | qemu
	TokenID       string    `json:"token_id"`        // user@pam!tokenid
	TokenSecret   string    `json:"token_secret"`    // secret
	InsecureTLS   bool      `json:"insecure_tls"`    // skip TLS verify (lab)
	ConfigPath    string    `json:"-"`               // where Settings was loaded from

	// LOCKDOWN_SERVICE_IP optional — public IPv4 this resolver uses for bootstrap rules.
	ServiceIPv4 string `json:"service_ipv4,omitempty"`
}

// DefaultConfigPath is the default JSON path for settings.
const DefaultConfigPath = "/etc/pve-dns-lockdown/config.json"

// Load reads settings from path; missing file returns zero settings (not an error).
func Load(path string) (Settings, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Settings{ConfigPath: path}, nil
		}
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, err
	}
	s.TokenID = strings.TrimSpace(s.TokenID)
	s.TokenSecret = strings.TrimSpace(s.TokenSecret)
	s.PVENode = strings.TrimSpace(s.PVENode)
	s.PVEHost = strings.TrimSpace(strings.TrimRight(s.PVEHost, "/"))
	s.GuestType = GuestType(strings.ToLower(string(s.GuestType)))
	if s.GuestType != GuestLXC && s.GuestType != GuestQEMU {
		s.GuestType = GuestLXC
	}
	s.ConfigPath = path
	return s, nil
}

// Save atomic write (best-effort chmod 0600).
func Save(path string, s Settings) error {
	if path == "" {
		path = DefaultConfigPath
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod settings: %w", err)
	}
	return nil
}

// Loaded reports whether essentials are configured.
func (s Settings) Loaded() bool {
	return s.PVEHost != "" && s.PVENode != "" && s.TokenID != "" && s.TokenSecret != "" && s.PVEVMID > 0
}
