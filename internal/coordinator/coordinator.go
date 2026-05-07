package coordinator

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
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

// ErrNotConfigured is returned when credentials are incomplete.
var ErrNotConfigured = errors.New("coordinator: proxmox not configured")

// Default is wired from main — used by the CoreDNS plugin.
var Default *Coordinator

// Coordinator shares Proxmox state, SSE pushes, DNS-side effects.
type Coordinator struct {
	settings config.Settings
	mu       sync.Mutex
	px       *proxmox.Client

	ruleSync *proxmox.RuleSyncCache
	Seen     map[string]struct{}

	revision atomic.Uint64

	lastDesc         string
	lastConfigDigest string

	snapMu sync.RWMutex
	snap   ViewState

	subsMu sync.Mutex
	subs   map[chan []byte]struct{}
}

// ViewState is sent to browsers over SSE as JSON objects.
type ViewState struct {
	Revision       uint64 `json:"revision"`
	MergedListText string `json:"merged_list_text"`
	VMDisplay      string `json:"vm_display"`
	PolicyOut      string `json:"policy_out"`
	PolicyUnknown  bool   `json:"policy_unknown"`
	LastRefreshErr string `json:"last_refresh_err,omitempty"`
	Form           Form   `json:"form"`
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
		settings: s,
		Seen:     make(map[string]struct{}),
		ruleSync: proxmox.NewRuleSyncCache(),
		subs:     make(map[chan []byte]struct{}),
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
func (c *Coordinator) UpdateSettings(patch config.Settings) error {
	wpath := strings.TrimSpace(patch.ConfigPath)
	if wpath == "" {
		wpath = os.Getenv("PVE_DNS_LOCKDOWN_CONFIG")
	}
	c.mu.Lock()
	if wpath == "" {
		wpath = c.settings.ConfigPath
	}
	if wpath == "" {
		wpath = config.DefaultConfigPath
	}
	if strings.TrimSpace(patch.TokenSecret) == "" {
		patch.TokenSecret = c.settings.TokenSecret
	}
	if strings.TrimSpace(patch.TokenID) == "" {
		patch.TokenID = c.settings.TokenID
	}
	if strings.TrimSpace(patch.PVEHost) == "" {
		patch.PVEHost = c.settings.PVEHost
	}
	if strings.TrimSpace(patch.PVENode) == "" {
		patch.PVENode = c.settings.PVENode
	}
	if patch.PVEVMID <= 0 {
		patch.PVEVMID = c.settings.PVEVMID
	}
	next := patch
	next.ConfigPath = wpath

	if next.GuestType != config.GuestLXC && next.GuestType != config.GuestQEMU {
		next.GuestType = c.settings.GuestType
	}
	if next.GuestType == "" {
		next.GuestType = config.GuestLXC
	}
	s := next
	s.PVEHost = strings.TrimSpace(s.PVEHost)
	s.TokenID = strings.TrimSpace(s.TokenID)
	c.mu.Unlock()

	if err := config.Save(wpath, s); err != nil {
		return err
	}
	c.mu.Lock()
	c.settings = s
	c.reloadClientLocked()
	c.mu.Unlock()

	c.runBootstrap()
	c.Refresh()
	return nil
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

// Snapshot returns the latest view model.
func (c *Coordinator) Snapshot() ViewState {
	c.snapMu.RLock()
	defer c.snapMu.RUnlock()
	return c.snap
}

func (c *Coordinator) finalizeView(vs ViewState) {
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

	label := proxmox.VMNameLabel(cfg)
	if label == "" {
		label = "-"
	}
	vs.VMDisplay = label + " — vmid " + strconv.Itoa(s.PVEVMID)

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
	px := c.px
	s := c.settings
	desc := c.lastDesc
	digest := c.lastConfigDigest
	c.mu.Unlock()

	if px == nil {
		return ErrNotConfigured
	}
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n")), "\r", "\n"), "\n")
	newDesc, err := allowlist.SpliceBlock(desc, lines)
	if err != nil {
		return err
	}
	if err := px.PutDescription(string(s.GuestType), s.PVENode, s.PVEVMID, newDesc, digest); err != nil {
		return err
	}
	c.Refresh()
	return nil
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
	inner, _ := allowlist.ExtractBlock(c.lastDesc)
	allowed := allowlist.ParseAllowed(inner)
	fqdn := allowlist.Normalize(qname)
	_, ok := allowed[fqdn]

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
	c.mu.Unlock()

	if px == nil || !s.Loaded() {
		return
	}

	if !ok {
		c.mu.Lock()
		c.Seen[fqdn] = struct{}{}
		c.mu.Unlock()
	}

	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			continue
		}
		if ok {
			_ = px.SyncOutboundAllow(string(s.GuestType), s.PVENode, s.PVEVMID, fqdn, ip, c.ruleSync)
		} else {
			_ = px.RemoveDynamicRules(string(s.GuestType), s.PVENode, s.PVEVMID, fqdn, ip, c.ruleSync)
		}
	}
}
