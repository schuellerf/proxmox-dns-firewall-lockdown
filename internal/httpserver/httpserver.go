package httpserver

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/config"
	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/coordinator"
)

// Listen starts the admin HTTP server on addr (typically ":80").
func Listen(addr string, c *coordinator.Coordinator) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, pageHTML())
	})

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush support", http.StatusBadRequest)
			return
		}
		hdr := w.Header()
		hdr.Set("Content-Type", "text/event-stream")
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		ch := c.SubscribeSSE(8)

		payload := marshalEvent(c.Snapshot())
		_, _ = w.Write(payload)
		flusher.Flush()

		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		defer c.UnsubscribeSSE(ch)

		for {
			select {
			case <-r.Context().Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				if _, err := w.Write(msg); err != nil {
					return
				}
				flusher.Flush()
			case <-ticker.C:
				if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		jsonSnapshot(w, c.Snapshot())
	})

	mux.HandleFunc("/api/save-list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		body := normalizeNewlines(string(b))
		if err := c.SaveMergedList(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var form struct {
			PVEHost     string `json:"pve_host"`
			PVENode     string `json:"pve_node"`
			PVEVMID     int    `json:"pve_vmid"`
			GuestType   string `json:"guest_type"`
			TokenID     string `json:"token_id"`
			TokenSecret string `json:"token_secret"`
			InsecureTLS bool   `json:"insecure_tls"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&form); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		patch := config.Settings{
			PVEHost:     strings.TrimSpace(form.PVEHost),
			PVENode:     strings.TrimSpace(form.PVENode),
			PVEVMID:     form.PVEVMID,
			GuestType:   config.GuestType(strings.ToLower(strings.TrimSpace(form.GuestType))),
			TokenID:     strings.TrimSpace(form.TokenID),
			TokenSecret: strings.TrimSpace(form.TokenSecret),
			InsecureTLS: form.InsecureTLS,
		}
		if patch.GuestType != config.GuestLXC && patch.GuestType != config.GuestQEMU {
			patch.GuestType = config.GuestLXC
		}
		if err := c.UpdateSettings(patch); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin http on %s: %v", addr, err)
		}
	}()
	return srv
}

func jsonSnapshot(w http.ResponseWriter, v coordinator.ViewState) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func marshalEvent(v coordinator.ViewState) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("data: {}\n\n")
	}
	return append(append([]byte(`data: `), b...), '\n', '\n')
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func pageHTML() string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>pve-dns-lockdown</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:1rem auto;padding:0 1rem}
textarea{width:100%;min-height:14rem;font-family:ui-monospace,monospace}
.danger{background:#f8d7da;border:1px solid #721c24;padding:.5rem 1rem;margin:.5rem 0}
.muted{background:#e2e3e5;border:1px solid #383d41;padding:.5rem 1rem;margin:.5rem 0}
label{display:block;margin-top:.5rem}
button{margin-top:.5rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}
small{color:#444}
</style>
</head>
<body>
<h1>pve-dns-lockdown</h1>
<p id="vm">vm: …</p>
<div id="banner"></div>
<h2>Allow list <small>(remove leading # to enable a name; Save applies)</small></h2>
<textarea id="list" spellcheck="false"></textarea>
<p>
<button id="save" disabled>Save</button>
<button id="revert" type="button" disabled>Revert</button>
<span id="status"></span>
</p>
<h2>Proxmox API</h2>
<div class="grid">
<label>PVE host <input id="pve_host" placeholder="https://192.168.1.10:8006"/></label>
<label>Node <input id="pve_node"/></label>
<label>VMID <input id="pve_vmid" type="number"/></label>
<label>Guest <select id="guest_type"><option value="lxc">lxc</option><option value="qemu">qemu</option></select></label>
<label>Token ID <input id="token_id" autocomplete="username" placeholder="user@pam!id"/></label>
<label>Token secret <input id="token_secret" type="password" autocomplete="current-password" placeholder="unchanged if empty"/></label>
<label><input id="insecure_tls" type="checkbox"/> Insecure TLS (lab)</label>
</div>
<button id="save_settings">Save settings</button>
<script>
const el=(id)=>document.getElementById(id);
let dirty=false,lastClean='';
const list=el('list'),saveBtn=el('save'),revertBtn=el('revert'),banner=el('banner');
function policyBanner(s){
  banner.innerHTML='';
  if(s.policy_unknown){
    const d=document.createElement('div');
    d.className='muted';
    d.textContent='Could not verify outbound firewall policy (API error, token scope, or firewall disabled). See docs/proxmox-setup.md.';
    banner.appendChild(d);return;
  }
  if((s.policy_out||'').toUpperCase() !== 'DROP'){
    const d=document.createElement('div');
    d.className='danger';
    d.textContent='Outbound policy is not DROP ('+(s.policy_out||'(empty)')+'). DNS allow listing will not restrict egress as intended. Set Output policy to DROP (see docs/proxmox-setup.md).';
    banner.appendChild(d);
  }
}
function applyState(s){
  el('vm').textContent='Target: '+(s.vm_display||'-');
  policyBanner(s);
  el('pve_host').value=s.form.pve_host||'';
  el('pve_node').value=s.form.pve_node||'';
  el('pve_vmid').value=s.form.pve_vmid||'';
  el('guest_type').value=(s.form.guest_type||'lxc');
  el('token_id').value=s.form.token_id||'';
  el('token_secret').value='';
  el('token_secret').placeholder=s.form.token_secret_present?'●●●● leave blank to keep':'token secret';
  el('insecure_tls').checked=!!s.form.insecure_tls;
  if(!dirty){
    list.value=s.merged_list_text||'';lastClean=list.value;
    saveBtn.disabled=true;revertBtn.disabled=true;
  }
}
list.addEventListener('input',()=>{
  dirty=true;saveBtn.disabled=(list.value===lastClean);revertBtn.disabled=!dirty;
});
el('revert').addEventListener('click',()=>{
  list.value=lastClean;dirty=false;saveBtn.disabled=true;revertBtn.disabled=true;
});
el('save').addEventListener('click',async()=>{
  el('status').textContent='Saving…';
  const r=await fetch('/api/save-list',{method:'POST',body:list.value});
  if(!r.ok){el('status').textContent=await r.text();return;}
  dirty=false;lastClean=list.value;saveBtn.disabled=true;revertBtn.disabled=true;
  el('status').textContent='Saved';
});
el('save_settings').addEventListener('click',async()=>{
  const body={
    pve_host: el('pve_host').value.trim(),
    pve_node: el('pve_node').value.trim(),
    pve_vmid: parseInt(el('pve_vmid').value||'0',10),
    guest_type: el('guest_type').value,
    token_id: el('token_id').value.trim(),
    token_secret: el('token_secret').value,
    insecure_tls: el('insecure_tls').checked
  };
  el('status').textContent='Saving settings…';
  const r=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  el('status').textContent=r.ok?'Settings saved':await r.text();
});
const es = new EventSource('/stream');
es.onmessage = (ev)=>{ try{ applyState(JSON.parse(ev.data)); }catch(_){} };
es.onerror = ()=>{ el('status').textContent='SSE interrupted (retrying…)'; };
fetch('/api/snapshot').then(r=>r.json()).then(applyState).catch(()=>{});
</script></body></html>`
}
