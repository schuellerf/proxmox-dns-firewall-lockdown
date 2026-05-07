package proxmox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Client is a minimal Proxmox JSON API helper.
type Client struct {
	Base        *url.URL
	TokenID     string
	TokenSecret string

	hc *http.Client
}

// New parses base like https://host:8006 — adds / if needed.
func New(base, tokenID, tokenSecret string, insecureTLS bool) (*Client, error) {
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureTLS, //nolint:gosec // deliberate lab option
		},
	}
	return &Client{
		Base:        u,
		TokenID:     strings.TrimSpace(tokenID),
		TokenSecret: strings.TrimSpace(tokenSecret),
		hc: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
	}, nil
}

type apiEnvelope struct {
	Data json.RawMessage `json:"data"`
}

func (c *Client) authorized(req *http.Request) {
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", c.TokenID, c.TokenSecret))
}

func (c *Client) getJSON(path string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.Base.String()+path, nil)
	if err != nil {
		return err
	}
	c.authorized(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var env apiEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

func (c *Client) reqForm(method, path string, form url.Values, out interface{}) error {
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequest(method, c.Base.String()+path, body)
	if err != nil {
		return err
	}
	c.authorized(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if out == nil || len(bytes.TrimSpace(rb)) == 0 {
		return nil
	}
	var env apiEnvelope
	if err := json.Unmarshal(rb, &env); err != nil {
		return nil // some endpoints return non-envelope
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// FirewallRule is a loose subset of PVE guest firewall rule fields.
type FirewallRule struct {
	Action  string `json:"action"`
	Type    string `json:"type"`
	Proto   string `json:"proto,omitempty"`
	Dest    string `json:"dest,omitempty"`
	DPort   string `json:"dport,omitempty"`
	SPort   string `json:"sport,omitempty"`
	Comment string `json:"comment,omitempty"`
	Log     string `json:"log,omitempty"`
	Enable  int    `json:"enable"` // 1|0
	Digest  string `json:"digest,omitempty"`
}

// RulePos is returned from list APIs.
type RulePos struct {
	Pos     int    `json:"pos"`
	Action  string `json:"action"`
	Type    string `json:"type"`
	Proto   string `json:"proto,omitempty"`
	Dest    string `json:"dest,omitempty"`
	DPort   string `json:"dport,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func (r *RulePos) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	r.Pos = intFromAny(m["pos"])
	r.Action = asString(m["action"])
	r.Type = asString(m["type"])
	r.Proto = asString(m["proto"])
	r.Dest = asString(m["dest"])
	r.DPort = asString(m["dport"])
	r.Comment = asString(m["comment"])
	return nil
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	case string:
		var n int
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	default:
		return 0
	}
}

func guestPath(guestType, node string, vmid int) string {
	switch strings.ToLower(strings.TrimSpace(guestType)) {
	case "lxc":
		return fmt.Sprintf("/api2/json/nodes/%s/lxc/%d", url.PathEscape(node), vmid)
	default:
		return fmt.Sprintf("/api2/json/nodes/%s/qemu/%d", url.PathEscape(node), vmid)
	}
}

// GetGuestConfig returns map of config keys.
func (c *Client) GetGuestConfig(guestType, node string, vmid int) (map[string]any, error) {
	base := guestPath(guestType, node, vmid)
	var m map[string]any
	err := c.getJSON(base+"/config", &m)
	return m, err
}

// PutDescription updates VM description only (merges with current config digest if present).
func (c *Client) PutDescription(guestType, node string, vmid int, description string, digest string) error {
	base := guestPath(guestType, node, vmid)
	form := url.Values{}
	form.Set("description", description)
	if digest != "" {
		form.Set("digest", digest)
	}
	return c.reqForm(http.MethodPut, base+"/config", form, nil)
}

// VMNameLabel returns a display name from guest config.
func VMNameLabel(cfg map[string]any) string {
	if cfg == nil {
		return ""
	}
	name, _ := cfg["name"].(string)
	host, _ := cfg["hostname"].(string)
	switch {
	case name != "" && host != "" && name != host:
		return fmt.Sprintf("%s (%s)", name, host)
	case name != "":
		return name
	default:
		return host
	}
}

// FirewallOptions holds outbound policy.
type FirewallOptions struct {
	PolicyOut string `json:"policy_out,omitempty"`
	Enable    int    `json:"enable,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

func (c *Client) GetFirewallOptions(guestType, node string, vmid int) (FirewallOptions, error) {
	base := guestPath(guestType, node, vmid) + "/firewall/options"
	var reply struct {
		Data struct {
			PolicyOut string `json:"policy_out"`
			Enable    int    `json:"enable,omitempty"`
			Digest    string `json:"digest,omitempty"`
		} `json:"data"`
	}
	b, err := c.getRaw(base)
	if err != nil {
		return FirewallOptions{}, err
	}
	if err := json.Unmarshal(b, &reply); err != nil {
		return FirewallOptions{}, err
	}
	return FirewallOptions{
		PolicyOut: reply.Data.PolicyOut,
		Enable:    reply.Data.Enable,
		Digest:    reply.Data.Digest,
	}, nil
}

func (c *Client) getRaw(rel string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.Base.String()+rel, nil)
	if err != nil {
		return nil, err
	}
	c.authorized(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ListFirewallRules returns firewall rules with positions.
func (c *Client) ListFirewallRules(guestType, node string, vmid int) ([]RulePos, error) {
	base := guestPath(guestType, node, vmid) + "/firewall/rules"
	var rules []RulePos
	if err := c.getJSON(base, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// DeleteFirewallRule deletes rule at position.
func (c *Client) DeleteFirewallRule(guestType, node string, vmid int, pos int) error {
	path := fmt.Sprintf("%s/firewall/rules/%d", guestPath(guestType, node, vmid), pos)
	req, err := http.NewRequest(http.MethodDelete, c.Base.String()+path, nil)
	if err != nil {
		return err
	}
	c.authorized(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE %s: %d %s", path, resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) CreateFirewallRule(guestType, node string, vmid int, r FirewallRule) error {
	form := url.Values{}
	form.Set("action", r.Action)
	form.Set("type", r.Type)
	if r.Proto != "" {
		form.Set("proto", r.Proto)
	}
	if r.Dest != "" {
		form.Set("dest", r.Dest)
	}
	if r.DPort != "" {
		form.Set("dport", r.DPort)
	}
	if r.SPort != "" {
		form.Set("sport", r.SPort)
	}
	if r.Comment != "" {
		form.Set("comment", r.Comment)
	}
	form.Set("enable", fmt.Sprintf("%d", r.Enable))

	path := guestPath(guestType, node, vmid) + "/firewall/rules"
	return c.reqForm(http.MethodPost, path, form, nil)
}

const RuleTagPrefix = "pve-dns-lockdown:"
const BootstrapComment = "pve-dns-lockdown:bootstrap:dns-server"

// SyncOutboundAllow ensures ACCEPT out rule exists for dest IP tagged with fqdn/ip.
func (c *Client) SyncOutboundAllow(guestType, node string, vmid int, fqdn string, ip string, cache *RuleSyncCache) error {
	wantComment := RuleTagPrefix + fqdn + ":" + ip
	rules, err := cache.list(c, guestType, node, vmid)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Comment == wantComment && strings.EqualFold(r.Dest, ip) && strings.EqualFold(r.Action, "ACCEPT") && strings.EqualFold(r.Type, "out") {
			return nil
		}
	}
	if err := c.CreateFirewallRule(guestType, node, vmid, FirewallRule{
		Action:  "ACCEPT",
		Type:    "out",
		Dest:    ip,
		Comment: wantComment,
		Enable:  1,
	}); err != nil {
		return err
	}
	cache.invalidate()
	return nil
}

// RemoveDynamicRules removes rules tagged by us that match fqdn/ip pair or dest-only matches.
func (c *Client) RemoveDynamicRules(guestType, node string, vmid int, fqdn string, ip string, cache *RuleSyncCache) error {
	rules, err := cache.list(c, guestType, node, vmid)
	if err != nil {
		return err
	}
	want := RuleTagPrefix + fqdn + ":" + ip
	todel := map[int]struct{}{}
	for _, r := range rules {
		if !strings.HasPrefix(r.Comment, RuleTagPrefix) {
			continue
		}
		if r.Comment == want || (strings.Contains(r.Comment, ":"+ip) && strings.Contains(r.Comment, fqdn)) {
			todel[r.Pos] = struct{}{}
		}
	}
	var poses []int
	for p := range todel {
		poses = append(poses, p)
	}
	sort.Slice(poses, func(i, j int) bool { return poses[i] > poses[j] })
	for _, pos := range poses {
		if err := c.DeleteFirewallRule(guestType, node, vmid, pos); err != nil {
			return err
		}
		cache.invalidate()
	}
	return nil
}

// EnsureBootstrapDNS allows UDP+TCP :53 outbound to resolverIP.
func (c *Client) EnsureBootstrapDNS(guestType, node string, vmid int, resolverIP string, cache *RuleSyncCache) error {
	rules, err := cache.list(c, guestType, node, vmid)
	if err != nil {
		return err
	}
	wantDest := resolverIP
	for _, proto := range []string{"udp", "tcp"} {
		ok := false
		for _, r := range rules {
			if r.Comment == BootstrapComment && strings.EqualFold(r.Proto, proto) && r.DPort == "53" && r.Dest == wantDest {
				ok = true
				break
			}
		}
		if ok {
			continue
		}
		if err := c.CreateFirewallRule(guestType, node, vmid, FirewallRule{
			Action:  "ACCEPT",
			Type:    "out",
			Proto:   proto,
			Dest:    wantDest,
			DPort:   "53",
			Comment: BootstrapComment,
			Enable:  1,
		}); err != nil {
			return err
		}
		cache.invalidate()
	}
	// Remove stale bootstrap rules pointed at old IP.
	for _, r := range rules {
		if r.Comment == BootstrapComment && r.Dest != "" && r.Dest != wantDest {
			if err := c.DeleteFirewallRule(guestType, node, vmid, r.Pos); err != nil {
				return err
			}
			cache.invalidate()
			return c.EnsureBootstrapDNS(guestType, node, vmid, resolverIP, cache)
		}
	}
	return nil
}

// RuleSyncCache avoids hammering list during bursts.
type RuleSyncCache struct {
	mu    sync.Mutex
	until time.Time
	rules []RulePos
}

func (rc *RuleSyncCache) list(c *Client, guestType, node string, vmid int) ([]RulePos, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if time.Now().Before(rc.until) && rc.rules != nil {
		return rc.rules, nil
	}
	rules, err := c.ListFirewallRules(guestType, node, vmid)
	if err != nil {
		return nil, err
	}
	rc.rules = rules
	rc.until = time.Now().Add(2 * time.Second)
	return rules, nil
}

func (rc *RuleSyncCache) invalidate() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.rules = nil
	rc.until = time.Time{}
}

// NewRuleSyncCache returns a cache for rule list lookups.
func NewRuleSyncCache() *RuleSyncCache { return &RuleSyncCache{} }
