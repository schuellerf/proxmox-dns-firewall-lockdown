package proxmox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

// Errors from ResolveGuestByVMID and cluster resource reads.
var (
	ErrClusterResourcesForbidden = errors.New("proxmox: forbidden to read cluster resources")
	ErrGuestVMIDNotFound         = errors.New("proxmox: guest vmid not found in cluster resources")
	ErrGuestVMIDAmbiguous        = errors.New("proxmox: multiple guests match vmid")
)

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

// VersionInfo is the subset of GET /version needed for UI probes.
type VersionInfo struct {
	Version string `json:"version"`
	Release string `json:"release"`
	RepID   string `json:"repoid"`
}

// GetVersion calls GET /api2/json/version with API authentication.
func (c *Client) GetVersion() (VersionInfo, error) {
	var v VersionInfo
	if err := c.getJSON("/api2/json/version", &v); err != nil {
		return VersionInfo{}, err
	}
	return v, nil
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

// ResolveGuestByVMID maps VMID → node name and guest api type ("lxc" | "qemu") using GET /cluster/resources.
func (c *Client) ResolveGuestByVMID(vmid int) (node string, guestType string, err error) {
	if vmid <= 0 {
		return "", "", fmt.Errorf("invalid vmid %d", vmid)
	}
	req, err := http.NewRequest(http.MethodGet, c.Base.String()+"/api2/json/cluster/resources", nil)
	if err != nil {
		return "", "", err
	}
	c.authorized(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	switch resp.StatusCode {
	case http.StatusForbidden:
		return "", "", ErrClusterResourcesForbidden
	case http.StatusOK:
	default:
		return "", "", fmt.Errorf("GET /api2/json/cluster/resources: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", "", fmt.Errorf("cluster resources envelope: %w", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(env.Data, &rows); err != nil {
		return "", "", fmt.Errorf("cluster resources decode: %w", err)
	}
	type hit struct {
		node string
		typ  string
	}
	seen := make(map[string]struct{})
	var hits []hit
	for _, row := range rows {
		guestKind := guestKindFromClusterRow(row)
		if guestKind != "lxc" && guestKind != "qemu" {
			continue
		}
		id := vmidFromClusterRow(row)
		if id != vmid {
			continue
		}
		node := strings.TrimSpace(asString(row["node"]))
		if node == "" {
			continue
		}
		key := guestKind + "\x00" + node
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		hits = append(hits, hit{node: node, typ: guestKind})
	}
	switch len(hits) {
	case 0:
		return "", "", ErrGuestVMIDNotFound
	case 1:
		return hits[0].node, hits[0].typ, nil
	default:
		return "", "", fmt.Errorf("%w: vmid=%d matched %d guests", ErrGuestVMIDAmbiguous, vmid, len(hits))
	}
}

// vmidFromClusterRow returns VMID from numeric/string vmid key or from composite id (e.g. qemu/116).
func vmidFromClusterRow(m map[string]any) int {
	if v := intFromAny(m["vmid"]); v > 0 {
		return v
	}
	return vmidFromCompositeResourceID(asString(m["id"]))
}

func vmidFromCompositeResourceID(id string) int {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0
	}
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return intFromAny(id[i+1:])
	}
	return intFromAny(id)
}

// guestKindFromClusterRow maps a row to api guest path segment "lxc" or "qemu".
func guestKindFromClusterRow(m map[string]any) string {
	t := strings.ToLower(strings.TrimSpace(asString(m["type"])))
	switch t {
	case "lxc", "qemu":
		return t
	}
	p := strings.ToLower(strings.TrimSpace(asString(m["id"])))
	switch {
	case strings.HasPrefix(p, "lxc/"):
		return "lxc"
	case strings.HasPrefix(p, "qemu/"):
		return "qemu"
	default:
		return t
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

// GuestTargetDisplay returns "vmid (hostname)" style text like Proxmox resource lists.
// Uses config hostname when set; otherwise falls back to the guest name field (often set for QEMU).
func GuestTargetDisplay(vmid int, cfg map[string]any) string {
	host := ""
	name := ""
	if cfg != nil {
		host = strings.TrimSpace(asString(cfg["hostname"]))
		name = strings.TrimSpace(asString(cfg["name"]))
	}
	label := host
	if label == "" {
		label = name
	}
	if label == "" {
		label = "-"
	}
	return fmt.Sprintf("%d (%s)", vmid, label)
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

// IP family tokens stored in dynamic rule comments (after fqdn).
const (
	IPFamilyFour = "ipv4"
	IPFamilySix  = "ipv6"
)

// IPFamilyFromIP returns IPFamilyFour or IPFamilySix.
func IPFamilyFromIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return IPFamilyFour
	}
	return IPFamilySix
}

// CanonicalIPString parses s as IP and returns canonical form, or s if unparseable.
func CanonicalIPString(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

func fqdnOutboundTag(fqdn, family string) string {
	return RuleTagPrefix + fqdn + ":" + family
}

func ruleManagedForFQDNFamily(comment, fqdn, family string) bool {
	if !strings.HasPrefix(comment, RuleTagPrefix+fqdn+":") {
		return false
	}
	rest := strings.TrimPrefix(comment, RuleTagPrefix+fqdn+":")
	if rest == IPFamilyFour || rest == IPFamilySix {
		return rest == family
	}
	if lip := net.ParseIP(rest); lip != nil {
		return IPFamilyFromIP(lip) == family
	}
	return false
}

// dynamicRuleMatchesDest reports whether r is our dynamic egress allow for fqdn with canonical dest canon and family.
func dynamicRuleMatchesDest(r RulePos, fqdn, canon, family string) bool {
	if !strings.HasPrefix(r.Comment, RuleTagPrefix) || r.Comment == BootstrapComment {
		return false
	}
	if !strings.EqualFold(r.Action, "ACCEPT") || !strings.EqualFold(r.Type, "out") {
		return false
	}
	if CanonicalIPString(r.Dest) != canon {
		return false
	}
	if !strings.HasPrefix(r.Comment, RuleTagPrefix+fqdn+":") {
		return false
	}
	rest := strings.TrimPrefix(r.Comment, RuleTagPrefix+fqdn+":")
	if rest == IPFamilyFour || rest == IPFamilySix {
		return rest == family
	}
	if lip := net.ParseIP(rest); lip != nil {
		return IPFamilyFromIP(lip) == family && lip.String() == canon
	}
	return false
}

// SyncOutboundAllow ensures ACCEPT out rule exists for dest IP tagged with fqdn and IP family (ipv4|ipv6).
// changed is true when a new firewall rule was created; false means the rule already existed (no-op).
func (c *Client) SyncOutboundAllow(guestType, node string, vmid int, fqdn string, ip string, cache *RuleSyncCache) (changed bool, err error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, fmt.Errorf("sync outbound allow: invalid IP %q", ip)
	}
	family := IPFamilyFromIP(parsed)
	canon := parsed.String()
	wantComment := fqdnOutboundTag(fqdn, family)
	rules, err := cache.list(c, guestType, node, vmid)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if dynamicRuleMatchesDest(r, fqdn, canon, family) {
			return false, nil
		}
	}
	if err := c.CreateFirewallRule(guestType, node, vmid, FirewallRule{
		Action:  "ACCEPT",
		Type:    "out",
		Dest:    canon,
		Comment: wantComment,
		Enable:  1,
	}); err != nil {
		return false, err
	}
	cache.invalidate()
	return true, nil
}

// RemoveDynamicRules removes dynamic allow rules for fqdn+ip (new fqdn:ipv4|ipv6 comment or legacy fqdn:ip).
// removed is true when at least one rule was deleted.
func (c *Client) RemoveDynamicRules(guestType, node string, vmid int, fqdn string, ip string, cache *RuleSyncCache) (removed bool, err error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, nil
	}
	canon := parsed.String()
	family := IPFamilyFromIP(parsed)
	rules, err := cache.list(c, guestType, node, vmid)
	if err != nil {
		return false, err
	}
	todel := map[int]struct{}{}
	for _, r := range rules {
		if dynamicRuleMatchesDest(r, fqdn, canon, family) {
			todel[r.Pos] = struct{}{}
		}
	}
	var poses []int
	for p := range todel {
		poses = append(poses, p)
	}
	sort.Slice(poses, func(i, j int) bool { return poses[i] > poses[j] })
	if len(poses) == 0 {
		return false, nil
	}
	for _, pos := range poses {
		if err := c.DeleteFirewallRule(guestType, node, vmid, pos); err != nil {
			return true, err
		}
		cache.invalidate()
	}
	return true, nil
}

// PruneStaleOutboundAllowsForFQDN deletes managed ACCEPT out rules for fqdn+family whose dest is not in desiredDests
// (canonical keys). If desiredDests is empty, deletes all managed rules for that fqdn+family.
// Returns canonical dest strings removed. Only rules matching new (fqdn:ipv4|ipv6) or legacy (fqdn:ip) comments are touched.
func (c *Client) PruneStaleOutboundAllowsForFQDN(guestType, node string, vmid int, fqdn, family string, desiredDests map[string]struct{}, cache *RuleSyncCache) (removed []string, err error) {
	if family != IPFamilyFour && family != IPFamilySix {
		return nil, fmt.Errorf("prune: invalid family %q", family)
	}
	rules, err := cache.list(c, guestType, node, vmid)
	if err != nil {
		return nil, err
	}
	todel := map[int]string{} // pos -> canonical dest removed
	for _, r := range rules {
		if !strings.HasPrefix(r.Comment, RuleTagPrefix) || r.Comment == BootstrapComment {
			continue
		}
		if !strings.EqualFold(r.Action, "ACCEPT") || !strings.EqualFold(r.Type, "out") {
			continue
		}
		if !ruleManagedForFQDNFamily(r.Comment, fqdn, family) {
			continue
		}
		dIP := net.ParseIP(r.Dest)
		if dIP == nil {
			continue
		}
		if IPFamilyFromIP(dIP) != family {
			continue
		}
		canon := dIP.String()
		if len(desiredDests) > 0 {
			if _, ok := desiredDests[canon]; ok {
				continue
			}
		}
		todel[r.Pos] = canon
	}
	var poses []int
	for pos := range todel {
		poses = append(poses, pos)
	}
	sort.Slice(poses, func(i, j int) bool { return poses[i] > poses[j] })
	for _, pos := range poses {
		if err := c.DeleteFirewallRule(guestType, node, vmid, pos); err != nil {
			return removed, err
		}
		removed = append(removed, todel[pos])
		cache.invalidate()
	}
	return removed, nil
}

// RemoveAllManagedEgressForFQDN deletes all dynamic ACCEPT out rules for fqdn (both IPv4 and IPv6 comment families,
// including legacy fqdn:ip comments). Returns canonical dest IPs removed (sorted, deduplicated).
func (c *Client) RemoveAllManagedEgressForFQDN(guestType, node string, vmid int, fqdn string, cache *RuleSyncCache) (removed []string, err error) {
	wantEmpty := map[string]struct{}{}
	r4, err := c.PruneStaleOutboundAllowsForFQDN(guestType, node, vmid, fqdn, IPFamilyFour, wantEmpty, cache)
	if err != nil {
		return nil, err
	}
	r6, err := c.PruneStaleOutboundAllowsForFQDN(guestType, node, vmid, fqdn, IPFamilySix, wantEmpty, cache)
	if err != nil {
		return r4, err
	}
	combined := append(append([]string(nil), r4...), r6...)
	uniq := make(map[string]struct{}, len(combined))
	for _, ip := range combined {
		if ip == "" {
			continue
		}
		if _, ok := uniq[ip]; ok {
			continue
		}
		uniq[ip] = struct{}{}
		removed = append(removed, ip)
	}
	sort.Strings(removed)
	return removed, nil
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
