package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/allowlist"
	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/config"
	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/netdetect"
	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/proxmox"

	"github.com/miekg/dns"
)

const maxFwActivityLines = 20

// ErrNotConfigured is returned when credentials are incomplete.
var ErrNotConfigured = errors.New("coordinator: proxmox not configured")

// ErrBadSettingsRequest wraps resolve / validation failures the operator can fix (HTTP 422).
var ErrBadSettingsRequest = errors.New("bad settings request")

// Default is wired from main — used by the CoreDNS plugin.
var Default *Coordinator

// dnsJournal writes to stderr so lines reach systemd/journal even when CoreDNS
// configures the global log.Logger differently.
var dnsJournal = log.New(os.Stderr, "pve-dns-lockdown: dns ", log.LstdFlags|log.Lmicroseconds)

// Coordinator shares Proxmox state, SSE pushes, DNS-side effects.
type Coordinator struct {
	settings config.Settings
	mu       sync.Mutex
	px       *proxmox.Client

	ruleSync *proxmox.RuleSyncCache
	Seen     map[string]struct{}

	// rejectedResolveIPs caches last canonical A/AAAA answers per fqdn while the name is not allowlisted
	// (used to open firewall immediately when the operator saves an enabled line without waiting for DNS again).
	rejectedResolveIPs map[string][]string

	revision atomic.Uint64

	lastDesc         string
	lastConfigDigest string

	// lastMergedAllowText is newline-separated textarea content ParseAllowed-compatible.
	// Refreshed on successful Refresh; updated immediately on SaveMergedList so ApplyDNS matches
	// the operator list even when GetGuestConfig keeps failing after a successful PUT.
	lastMergedAllowText string

	snapMu sync.RWMutex
	snap   ViewState

	subsMu sync.Mutex
	subs   map[chan []byte]struct{}

	finalMu sync.Mutex // serialize finalizeView — Refresh vs DNS rebroadcast

	fwLogMu    sync.Mutex
	fwActivity []FirewallActivityRow
}

// FirewallActivityRow is one DNS-triggered egress firewall reconcile line for the UI.
type FirewallActivityRow struct {
	Time   string `json:"time"`
	FQDN   string `json:"fqdn"`
	IP     string `json:"ip,omitempty"`
	Result string `json:"result"` // allow_added | allow_failed | allow_pruned | dynamic_removed | remove_failed
	Err    string `json:"error,omitempty"`
}

// ViewState is sent to browsers over SSE as JSON objects.
type ViewState struct {
	Revision         uint64                `json:"revision"`
	MergedListText   string                `json:"merged_list_text"`
	VMDisplay        string                `json:"vm_display"`
	PolicyOut        string                `json:"policy_out"`
	PolicyUnknown    bool                  `json:"policy_unknown"`
	LastRefreshErr   string                `json:"last_refresh_err,omitempty"`
	FirewallActivity []FirewallActivityRow `json:"firewall_activity"`
	Form             Form                  `json:"form"`
}

// Form holds non-secret form defaults for the HTML UI.
type Form struct {
	PVEHost       string `json:"pve_host"`
	PVENode       string `json:"pve_node"`
	PVEVMID       int    `json:"pve_vmid"`
	GuestType     string `json:"guest_type"`
	TokenID       string `json:"token_id"`
	InsecureTLS   bool   `json:"insecure_tls"`
	SecretPresent bool   `json:"token_secret_present"`
}

// New loads settings JSON and starts background helpers.
func New(cfgPath string) (*Coordinator, error) {
	path := cfgPath
	if path == "" {
		path = os.Getenv("PVE_DNS_LOCKDOWN_CONFIG")
		if path == "" {
			path = config.DefaultConfigPath
		}
	}
	s, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	c := &Coordinator{
		settings:           s,
		Seen:               make(map[string]struct{}),
		rejectedResolveIPs: make(map[string][]string),
		ruleSync:           proxmox.NewRuleSyncCache(),
		subs:               make(map[chan []byte]struct{}),
	}
	c.reloadClientLocked()

	go func() {
		time.Sleep(time.Second)
		c.runBootstrap()
		c.Refresh()
	}()
	go c.periodicBootstrap()
	go c.periodicRefresh()
	return c, nil
}

func (c *Coordinator) reloadClientLocked() {
	s := c.settings
	if !s.Loaded() {
		c.px = nil
		return
	}
	cl, err := proxmox.New(s.PVEHost, s.TokenID, s.TokenSecret, s.InsecureTLS)
	if err != nil {
		c.px = nil
		return
	}
	c.px = cl
}

// Settings returns a copy of current settings (includes secrets — internal use only).
func (c *Coordinator) Settings() config.Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settings
}

// UpdateSettings persists settings merged with existing secrets/path.
// When auto-resolve of node/guest from VMID fails but merged settings include a non-empty node, it returns a non-empty warning and nil error.
// connectionOK is non-empty only after a successful authenticated GET /version probe against the saved API endpoint.
func (c *Coordinator) UpdateSettings(patch config.Settings) (warning string, connectionOK string, err error) {
	c.mu.Lock()
	merged, wpath := c.mergeSettingsPatchLocked(patch)
	c.mu.Unlock()

	warn, merged, err := c.resolveNodeGuestIfPossible(merged)
	if err != nil {
		return "", "", err
	}

	if err := config.Save(wpath, merged); err != nil {
		return "", "", err
	}
	c.mu.Lock()
	c.settings = merged
	c.reloadClientLocked()
	c.mu.Unlock()

	c.runBootstrap()
	c.Refresh()

	var connLine string
	c.mu.Lock()
	px := c.px
	snap := c.settings
	c.mu.Unlock()
	if px != nil {
		if vi, verr := px.GetVersion(); verr == nil {
			connLine = formatAPIConnectionOK(snap.PVEHost, snap.PVENode, vi)
		}
	}
	return warn, connLine, nil
}

func formatAPIConnectionOK(pveHost, pveNode string, v proxmox.VersionInfo) string {
	host := apiURLHost(pveHost)
	ver := strings.TrimSpace(v.Version)
	if strings.TrimSpace(v.Release) != "" && !strings.Contains(ver, v.Release) {
		if ver != "" {
			ver = ver + " (" + strings.TrimSpace(v.Release) + ")"
		} else {
			ver = strings.TrimSpace(v.Release)
		}
	}
	if ver == "" {
		ver = strings.TrimSpace(v.RepID)
		if ver == "" {
			ver = "unknown"
		}
	}
	return fmt.Sprintf("API OK — Proxmox %s · %s · node %q", ver, host, strings.TrimSpace(pveNode))
}

func apiURLHost(raw string) string {
	raw = strings.TrimSpace(strings.TrimRight(raw, "/"))
	if raw == "" {
		return "(no host)"
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

func (c *Coordinator) mergeSettingsPatchLocked(patch config.Settings) (merged config.Settings, wpath string) {
	wpath = strings.TrimSpace(patch.ConfigPath)
	if wpath == "" {
		wpath = os.Getenv("PVE_DNS_LOCKDOWN_CONFIG")
	}
	if wpath == "" {
		wpath = c.settings.ConfigPath
	}
	if wpath == "" {
		wpath = config.DefaultConfigPath
	}
	merged = patch
	if strings.TrimSpace(patch.TokenSecret) == "" {
		merged.TokenSecret = c.settings.TokenSecret
	}
	if strings.TrimSpace(patch.TokenID) == "" {
		merged.TokenID = c.settings.TokenID
	}
	if strings.TrimSpace(patch.PVEHost) == "" {
		merged.PVEHost = c.settings.PVEHost
	}
	if strings.TrimSpace(patch.PVENode) == "" {
		merged.PVENode = c.settings.PVENode
	}
	if patch.PVEVMID <= 0 {
		merged.PVEVMID = c.settings.PVEVMID
	}
	merged.ConfigPath = wpath

	if merged.GuestType != config.GuestLXC && merged.GuestType != config.GuestQEMU {
		merged.GuestType = c.settings.GuestType
	}
	if merged.GuestType == "" {
		merged.GuestType = config.GuestLXC
	}
	merged.PVEHost = strings.TrimSpace(strings.TrimRight(merged.PVEHost, "/"))
	merged.TokenID = strings.TrimSpace(merged.TokenID)
	merged.PVENode = strings.TrimSpace(merged.PVENode)
	return merged, wpath
}

// resolveNodeGuestIfPossible calls cluster/resources when host, token, secret, and VMID are complete; otherwise it returns merged unchanged.
func (c *Coordinator) resolveNodeGuestIfPossible(merged config.Settings) (warn string, out config.Settings, err error) {
	out = merged
	tryResolve := merged.PVEHost != "" && merged.TokenID != "" && merged.TokenSecret != "" && merged.PVEVMID > 0
	if !tryResolve {
		return "", out, nil
	}
	cl, err := proxmox.New(merged.PVEHost, merged.TokenID, merged.TokenSecret, merged.InsecureTLS)
	if err != nil {
		return "", out, fmt.Errorf("proxmox client: %w", err)
	}
	node, gt, rerr := cl.ResolveGuestByVMID(merged.PVEVMID)
	if rerr == nil {
		out.PVENode = node
		lg := strings.ToLower(strings.TrimSpace(gt))
		if lg == string(config.GuestLXC) || lg == string(config.GuestQEMU) {
			out.GuestType = config.GuestType(lg)
		}
		return "", out, nil
	}
	detail := resolveErrDetail(rerr)
	if out.PVENode == "" {
		return "", out, fmt.Errorf(
			"could not resolve VMID %d from cluster resources (%s). Set Proxmox Node and Guest manually, or allow the token to GET /api2/json/cluster/resources: %w",
			merged.PVEVMID, detail, ErrBadSettingsRequest,
		)
	}
	warnMsg := fmt.Sprintf(
		"Could not resolve VMID %d automatically (%s). Saved your Node (%q) and guest type (%s).",
		merged.PVEVMID, detail, out.PVENode, out.GuestType,
	)
	return warnMsg, out, nil
}

func resolveErrDetail(err error) string {
	switch {
	case errors.Is(err, proxmox.ErrClusterResourcesForbidden):
		return "HTTP 403 on cluster/resources"
	case errors.Is(err, proxmox.ErrGuestVMIDNotFound):
		return "no matching QEMU/LXC in cluster resources"
	case errors.Is(err, proxmox.ErrGuestVMIDAmbiguous):
		return "ambiguous match (multiple guests)"
	default:
		return err.Error()
	}
}

func (c *Coordinator) SubscribeSSE(buf int) chan []byte {
	ch := make(chan []byte, buf)
	c.subsMu.Lock()
	c.subs[ch] = struct{}{}
	c.subsMu.Unlock()
	return ch
}

func (c *Coordinator) UnsubscribeSSE(ch chan []byte) {
	c.subsMu.Lock()
	delete(c.subs, ch)
	c.subsMu.Unlock()
	close(ch)
}

func (c *Coordinator) broadcast(payload []byte) {
	c.subsMu.Lock()
	out := make([]chan []byte, 0, len(c.subs))
	for ch := range c.subs {
		out = append(out, ch)
	}
	c.subsMu.Unlock()
	for _, ch := range out {
		func(ch chan []byte) {
			defer func() {
				if recover() != nil {
					/* send on closed subscriber */
				}
			}()
			select {
			case ch <- payload:
			default:
			}
		}(ch)
	}
}

func (c *Coordinator) Snapshot() ViewState {
	c.snapMu.RLock()
	defer c.snapMu.RUnlock()
	return c.snap
}

func (c *Coordinator) snapshotFwActivity() []FirewallActivityRow {
	c.fwLogMu.Lock()
	defer c.fwLogMu.Unlock()
	out := make([]FirewallActivityRow, len(c.fwActivity))
	copy(out, c.fwActivity)
	return out
}

func (c *Coordinator) finalizeView(vs ViewState) {
	c.finalMu.Lock()
	defer c.finalMu.Unlock()

	vs.FirewallActivity = c.snapshotFwActivity()

	vs.Revision = c.revision.Add(1)
	b, err := json.Marshal(vs)
	if err != nil {
		return
	}
	payload := append(append([]byte(`data: `), b...), '\n', '\n')

	c.snapMu.Lock()
	c.snap = vs
	c.snapMu.Unlock()

	c.broadcast(payload)
}

// enqueueFwActivities appends firewall activity rows (newest appended) and rebroadcasts the last snapshot via SSE.
func (c *Coordinator) enqueueFwActivities(rows []FirewallActivityRow) {
	if len(rows) == 0 {
		return
	}
	nowRFC := time.Now().UTC().Format(time.RFC3339Nano)
	c.fwLogMu.Lock()
	for i := range rows {
		row := rows[i]
		if strings.TrimSpace(row.Time) == "" {
			row.Time = nowRFC
		}
		c.fwActivity = append(c.fwActivity, row)
	}
	if len(c.fwActivity) > maxFwActivityLines {
		c.fwActivity = c.fwActivity[len(c.fwActivity)-maxFwActivityLines:]
	}
	c.fwLogMu.Unlock()

	c.snapMu.RLock()
	prev := c.snap
	c.snapMu.RUnlock()

	c.finalizeView(prev)
}

// Refresh pulls Proxmox and pushes SSE.
func (c *Coordinator) Refresh() {
	c.mu.Lock()
	px := c.px
	s := c.settings
	c.mu.Unlock()

	vs := ViewState{
		Form: Form{
			PVEHost:       s.PVEHost,
			PVENode:       s.PVENode,
			PVEVMID:       s.PVEVMID,
			GuestType:     string(s.GuestType),
			TokenID:       s.TokenID,
			InsecureTLS:   s.InsecureTLS,
			SecretPresent: s.TokenSecret != "",
		},
		PolicyUnknown: true,
	}

	if px == nil {
		vs.LastRefreshErr = "proxmox client not configured — save settings below"
		c.finalizeView(vs)
		return
	}

	cfg, err := px.GetGuestConfig(string(s.GuestType), s.PVENode, s.PVEVMID)
	if err != nil {
		vs.LastRefreshErr = err.Error()
		c.finalizeView(vs)
		return
	}
	desc, _ := cfg["description"].(string)
	digest, _ := cfg["digest"].(string)
	inner, _ := allowlist.ExtractBlock(desc)
	merged := strings.Join(allowlist.MergeSuggestedLines(inner, c.copySeen()), "\n")

	vs.VMDisplay = proxmox.GuestTargetDisplay(s.PVEVMID, cfg)

	fw, err := px.GetFirewallOptions(string(s.GuestType), s.PVENode, s.PVEVMID)
	if err != nil {
		vs.PolicyUnknown = true
		vs.LastRefreshErr = err.Error()
	} else {
		vs.PolicyUnknown = false
		vs.PolicyOut = strings.ToUpper(strings.TrimSpace(fw.PolicyOut))
		vs.LastRefreshErr = ""
	}

	vs.MergedListText = merged

	c.mu.Lock()
	c.lastDesc = desc
	c.lastConfigDigest = digest
	c.lastMergedAllowText = merged
	c.mu.Unlock()

	c.finalizeView(vs)
}

func (c *Coordinator) copySeen() map[string]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]struct{}, len(c.Seen))
	for k := range c.Seen {
		out[k] = struct{}{}
	}
	return out
}

// SaveMergedList replaces inner lockdown lines from the editor textarea.
func (c *Coordinator) SaveMergedList(text string) error {
	c.mu.Lock()
	oldMerged := c.lastMergedAllowText
	px := c.px
	s := c.settings
	desc := c.lastDesc
	digest := c.lastConfigDigest
	c.mu.Unlock()

	if px == nil {
		return ErrNotConfigured
	}
	oldLines := splitAllowLines(oldMerged)
	oldAllowed := allowlist.ParseAllowed(oldLines)
	normalizedText := normalizeAllowlistMultiline(text)
	lines := strings.Split(normalizedText, "\n")
	newAllowed := allowlist.ParseAllowed(lines)
	newListed := allowlist.ParseListed(lines)
	newly := newlyAllowedFQDNs(oldAllowed, newAllowed)
	newlyDenied := newlyDeniedFQDNs(oldAllowed, newAllowed)
	removed := newlyRemovedFQDNs(allowlist.ParseListed(oldLines), newListed)

	newDesc, err := allowlist.SpliceBlock(desc, lines)
	if err != nil {
		return err
	}
	if err := px.PutDescription(string(s.GuestType), s.PVENode, s.PVEVMID, newDesc, digest); err != nil {
		return err
	}

	var rows []FirewallActivityRow
	gt := string(s.GuestType)
	vmid := s.PVEVMID
	node := s.PVENode

	for _, fqdn := range removed {
		removedCanon, perr := px.RemoveAllManagedEgressForFQDN(gt, node, vmid, fqdn, c.ruleSync)
		for _, rip := range removedCanon {
			dnsJournal.Printf("fqdn=%q ip=%s allowlisted=false save_reconcile=true result=allow_pruned removed=true", fqdn, rip)
			rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: rip, Result: "allow_pruned"})
		}
		if perr != nil {
			dnsJournal.Printf("fqdn=%q allowlisted=false save_reconcile=true result=prune_failed removed=true err=%v", fqdn, perr)
			rows = append(rows, FirewallActivityRow{FQDN: fqdn, Result: "allow_failed", Err: fmt.Sprintf("remove prune: %v", perr)})
		}
		c.mu.Lock()
		delete(c.Seen, fqdn)
		delete(c.rejectedResolveIPs, fqdn)
		c.mu.Unlock()
	}

	for _, fqdn := range newlyDenied {
		if _, stillListed := newListed[fqdn]; !stillListed {
			continue
		}
		removedCanon, perr := px.RemoveAllManagedEgressForFQDN(gt, node, vmid, fqdn, c.ruleSync)
		for _, rip := range removedCanon {
			dnsJournal.Printf("fqdn=%q ip=%s allowlisted=false save_reconcile=true result=allow_pruned", fqdn, rip)
			rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: rip, Result: "allow_pruned"})
		}
		if perr != nil {
			dnsJournal.Printf("fqdn=%q allowlisted=false save_reconcile=true result=prune_failed err=%v", fqdn, perr)
			rows = append(rows, FirewallActivityRow{FQDN: fqdn, Result: "allow_failed", Err: fmt.Sprintf("disable prune: %v", perr)})
		}
		c.mu.Lock()
		c.Seen[fqdn] = struct{}{}
		if canon := canonIPsUniqueStable(removedCanon); len(canon) > 0 {
			c.rejectedResolveIPs[fqdn] = canon
		}
		c.mu.Unlock()
	}

	type fwJob struct {
		fqdn string
		ips  []string
	}
	var jobs []fwJob
	c.mu.Lock()
	c.lastDesc = newDesc
	c.lastMergedAllowText = normalizedText
	for _, fqdn := range newly {
		ips := c.rejectedResolveIPs[fqdn]
		delete(c.rejectedResolveIPs, fqdn)
		if len(ips) == 0 {
			continue
		}
		jobs = append(jobs, fwJob{fqdn: fqdn, ips: append([]string(nil), ips...)})
	}
	c.mu.Unlock()

	for _, j := range jobs {
		for _, ip := range j.ips {
			changed, syncErr := px.SyncOutboundAllow(gt, node, vmid, j.fqdn, ip, c.ruleSync)
			switch {
			case syncErr != nil:
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true save_reconcile=true result=allow_failed err=%v", j.fqdn, ip, syncErr)
				rows = append(rows, FirewallActivityRow{FQDN: j.fqdn, IP: ip, Result: "allow_failed", Err: syncErr.Error()})
			case changed:
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true save_reconcile=true result=rule_added", j.fqdn, ip)
				rows = append(rows, FirewallActivityRow{FQDN: j.fqdn, IP: ip, Result: "allow_added"})
			default:
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true save_reconcile=true result=rule_unchanged", j.fqdn, ip)
			}
		}
	}
	if len(rows) > 0 {
		c.enqueueFwActivities(rows)
	}

	c.Refresh()
	return nil
}

func normalizeAllowlistMultiline(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")), "\r", "\n")
	s = strings.TrimSpace(s)
	return s
}

func splitAllowLines(mergedAllow string) []string {
	mergedAllow = normalizeAllowlistMultiline(mergedAllow)
	if mergedAllow == "" {
		return nil
	}
	return strings.Split(mergedAllow, "\n")
}

// newlyAllowedFQDNs returns fqdns present in newAllowed but not in oldAllowed (normalized keys).
func newlyAllowedFQDNs(oldAllowed, newAllowed map[string]struct{}) []string {
	out := make([]string, 0, len(newAllowed))
	for fqdn := range newAllowed {
		if _, ok := oldAllowed[fqdn]; ok {
			continue
		}
		out = append(out, fqdn)
	}
	sort.Strings(out)
	return out
}

// newlyRemovedFQDNs returns fqdns listed before save (allowed or #commented) but absent after.
func newlyRemovedFQDNs(oldListed, newListed map[string]struct{}) []string {
	out := make([]string, 0, len(oldListed))
	for fqdn := range oldListed {
		if _, ok := newListed[fqdn]; ok {
			continue
		}
		out = append(out, fqdn)
	}
	sort.Strings(out)
	return out
}

// newlyDeniedFQDNs returns fqdns present in oldAllowed but not in newAllowed (normalized keys).
func newlyDeniedFQDNs(oldAllowed, newAllowed map[string]struct{}) []string {
	out := make([]string, 0, len(oldAllowed))
	for fqdn := range oldAllowed {
		if _, ok := newAllowed[fqdn]; ok {
			continue
		}
		out = append(out, fqdn)
	}
	sort.Strings(out)
	return out
}

// canonIPsUniqueStable parses and deduplicates IP strings; order is first-seen.
func canonIPsUniqueStable(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, raw := range ips {
		p := net.ParseIP(strings.TrimSpace(raw))
		if p == nil {
			continue
		}
		c := p.String()
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func (c *Coordinator) periodicRefresh() {
	t := time.NewTicker(3 * time.Second)
	for range t.C {
		c.Refresh()
	}
}

func (c *Coordinator) periodicBootstrap() {
	t := time.NewTicker(45 * time.Second)
	for range t.C {
		c.runBootstrap()
	}
}

func (c *Coordinator) runBootstrap() {
	c.mu.Lock()
	px := c.px
	s := c.settings
	c.mu.Unlock()
	if px == nil || !s.Loaded() {
		return
	}
	ip := netdetect.PreferredServiceIPv4()
	if ip == "" {
		return
	}
	if s.ServiceIPv4 != "" {
		ip = strings.TrimSpace(s.ServiceIPv4)
	}
	_ = px.EnsureBootstrapDNS(string(s.GuestType), s.PVENode, s.PVEVMID, ip, c.ruleSync)
}

// ApplyDNS runs egress firewall reconcile after upstream answered.
func (c *Coordinator) ApplyDNS(qname string, msg *dns.Msg) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		return
	}

	c.mu.Lock()
	px := c.px
	s := c.settings
	mergedAllow := c.lastMergedAllowText
	c.mu.Unlock()

	allowed := allowlist.ParseAllowed(splitAllowLines(mergedAllow))
	fqdn := allowlist.Normalize(qname)
	_, ok := allowed[fqdn]

	var seenA, seenAAAA bool
	for _, a := range msg.Answer {
		switch a.(type) {
		case *dns.A:
			seenA = true
		case *dns.AAAA:
			seenAAAA = true
		}
	}

	var ips []string
	for _, a := range msg.Answer {
		switch rr := a.(type) {
		case *dns.A:
			if rr.A.To4() != nil {
				ips = append(ips, rr.A.String())
			}
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}

	desired4 := make(map[string]struct{})
	desired6 := make(map[string]struct{})
	for _, ip := range ips {
		p := net.ParseIP(ip)
		if p == nil {
			continue
		}
		if p.To4() != nil {
			desired4[p.String()] = struct{}{}
		} else {
			desired6[p.String()] = struct{}{}
		}
	}

	if px == nil || !s.Loaded() {
		dnsJournal.Printf("reconcile skipped: proxmox not configured")
		return
	}

	if len(ips) == 0 {
		dnsJournal.Printf("reconcile fqdn=%q: no A/AAAA in answer", fqdn)
	}

	if !ok {
		c.mu.Lock()
		c.Seen[fqdn] = struct{}{}
		if len(ips) > 0 {
			if canon := canonIPsUniqueStable(ips); len(canon) > 0 {
				c.rejectedResolveIPs[fqdn] = canon
			}
		}
		c.mu.Unlock()
	}

	var rows []FirewallActivityRow
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			continue
		}
		if ok {
			changed, err := px.SyncOutboundAllow(string(s.GuestType), s.PVENode, s.PVEVMID, fqdn, ip, c.ruleSync)
			switch {
			case err != nil:
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true result=allow_failed err=%v", fqdn, ip, err)
				rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: ip, Result: "allow_failed", Err: err.Error()})
			case changed:
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true result=rule_added", fqdn, ip)
				rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: ip, Result: "allow_added"})
			default:
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true result=rule_unchanged", fqdn, ip)
			}
			continue
		}
		removed, err := px.RemoveDynamicRules(string(s.GuestType), s.PVENode, s.PVEVMID, fqdn, ip, c.ruleSync)
		switch {
		case err != nil:
			dnsJournal.Printf("fqdn=%q ip=%s allowlisted=false result=remove_failed err=%v", fqdn, ip, err)
			rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: ip, Result: "remove_failed", Err: err.Error()})
		case removed:
			dnsJournal.Printf("fqdn=%q ip=%s allowlisted=false result=dynamic_removed", fqdn, ip)
			rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: ip, Result: "dynamic_removed"})
		default:
			dnsJournal.Printf("fqdn=%q ip=%s allowlisted=false result=dynamic_unchanged", fqdn, ip)
		}
	}

	if ok && (seenA || seenAAAA) {
		if seenA {
			pruned, perr := px.PruneStaleOutboundAllowsForFQDN(string(s.GuestType), s.PVENode, s.PVEVMID, fqdn, proxmox.IPFamilyFour, desired4, c.ruleSync)
			for _, rip := range pruned {
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true family=ipv4 result=allow_pruned", fqdn, rip)
				rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: rip, Result: "allow_pruned"})
			}
			if perr != nil {
				dnsJournal.Printf("fqdn=%q allowlisted=true family=ipv4 result=prune_failed err=%v", fqdn, perr)
				rows = append(rows, FirewallActivityRow{FQDN: fqdn, Result: "allow_failed", Err: fmt.Sprintf("prune ipv4: %v", perr)})
			}
		}
		if seenAAAA {
			pruned, perr := px.PruneStaleOutboundAllowsForFQDN(string(s.GuestType), s.PVENode, s.PVEVMID, fqdn, proxmox.IPFamilySix, desired6, c.ruleSync)
			for _, rip := range pruned {
				dnsJournal.Printf("fqdn=%q ip=%s allowlisted=true family=ipv6 result=allow_pruned", fqdn, rip)
				rows = append(rows, FirewallActivityRow{FQDN: fqdn, IP: rip, Result: "allow_pruned"})
			}
			if perr != nil {
				dnsJournal.Printf("fqdn=%q allowlisted=true family=ipv6 result=prune_failed err=%v", fqdn, perr)
				rows = append(rows, FirewallActivityRow{FQDN: fqdn, Result: "allow_failed", Err: fmt.Sprintf("prune ipv6: %v", perr)})
			}
		}
	}
	if len(rows) > 0 {
		c.enqueueFwActivities(rows)
	}
}
