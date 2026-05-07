package httpserver

import (
	"encoding/json"
	"errors"
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
			writeJSONSaveErr(w, err)
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
		warn, connOK, err := c.UpdateSettings(patch)
		if err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, coordinator.ErrBadSettingsRequest) {
				code = http.StatusUnprocessableEntity
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":           false,
				"error":        err.Error(),
				"error_detail": proxmoxErrorHint(err.Error()),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"ok": true}
		if warn != "" {
			out["warning"] = warn
		}
		if connOK != "" {
			out["connection_ok"] = connOK
		}
		_ = json.NewEncoder(w).Encode(out)
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

// writeJSONSaveErr returns a JSON body so the SPA can show the full Proxmox error (permissions, TLS, …).
func writeJSONSaveErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	code := http.StatusBadGateway
	if errors.Is(err, coordinator.ErrNotConfigured) {
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	msg := err.Error()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":           false,
		"error":        msg,
		"error_detail": proxmoxErrorHint(msg),
	})
}

// proxmoxErrorHint adds a short operator hint when the message looks like a PVE ACL denial.
func proxmoxErrorHint(msg string) string {
	msg = strings.ToLower(msg)
	if !strings.Contains(msg, "permission check failed") && !strings.Contains(msg, "http 403") {
		return ""
	}
	return "Proxmox denied this API call: grant the needed privilege on /vms/<VMID> for **both** the backing user (`user@realm`) and the API token (`…!tokenid`); privsep tokens intersect ACLs with the user. Often add VM.Config.Options for guest notes/description PUT, plus firewall/rule privileges as in docs/proxmox-setup.md. The 403 lists alternatives separated by | — you only need one of them, not every item."
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
#settings_msg:empty{display:none}
#settings_msg.warn{background:#fff3cd;border:1px solid #856404;padding:.5rem 1rem;margin:.5rem 0}
#settings_msg.err{background:#f8d7da;border:1px solid #721c24;padding:.5rem 1rem;margin:.5rem 0}
#settings_msg_ok:empty{display:none}
#settings_msg_ok.ok{font-size:87.5%;line-height:1.35;color:#155724;background:#d4edda;border:1px solid #c3e6cb;padding:.4rem .75rem;margin:.35rem 0 0 0}
#proxmox_err:empty,#allowlist_msg:empty{display:none}
#proxmox_err.err,#allowlist_msg.err{font-size:93%;white-space:pre-wrap;word-break:break-word;line-height:1.35;background:#f8d7da;border:1px solid #721c24;padding:.75rem 1rem;margin:.5rem 0}
.settings-form input:invalid,.settings-form select:invalid{box-shadow:0 0 0 2px #c00;border-color:#c00}
#firewall_activity{list-style:none;padding:0;margin:0;max-height:16rem;overflow:auto;font-family:ui-monospace,monospace;font-size:82%;line-height:1.35}
#firewall_activity li{margin:.25rem 0;padding:.35rem .5rem;border:1px solid #ccc;border-radius:4px;background:#fafafa;word-break:break-word}
#firewall_activity li.fw-err{background:#f8d7da;border-color:#721c24}
#firewall_activity li.fw-ok{border-color:#c3e6cb;background:#e8f5e9}
#firewall_activity li.fw-empty{background:#f5f5f5;border-color:#ddd;color:#444}
</style>
</head>
<body>
<h1 id="page_title">pve-dns-lockdown</h1>
<div id="proxmox_err" role="alert" aria-live="polite"></div>
<div id="banner"></div>
<h2>Allow list <small>(remove leading # to enable a name; Save applies)</small></h2>
<textarea id="list" spellcheck="false"></textarea>
<div id="allowlist_msg" role="status"></div>
<p>
<button id="save" disabled>Save</button>
<button id="revert" type="button" disabled>Revert</button>
<span id="status"></span>
</p>
<h2>Egress firewall <small>(DNS → Proxmox rules)</small></h2>
<p class="muted" style="font-size:87%">Only names enabled in the allow list above are opened on the firewall. Reconcile uses this list immediately after Save, and refreshes from the VM when guest config reads succeed — so it still tracks the textarea even when Proxmox read fails intermittently. Outcomes listed are mutations or API errors only (duplicate lookups with an unchanged rule stay quiet).</p>
<ul id="firewall_activity" aria-live="polite"></ul>
<h2>Settings</h2>
<div id="settings_msg" role="status"></div>
<div id="settings_msg_ok" role="status"></div>
<form id="settings_form" class="settings-form">
<div class="grid">
<label>PVE host <input id="pve_host" name="pve_host" required placeholder="https://192.168.1.10:8006"/></label>
<label>Node <input id="pve_node" name="pve_node"/></label>
<label>VMID <input id="pve_vmid" name="pve_vmid" type="number"/></label>
<label>Guest <select id="guest_type" name="guest_type"><option value="lxc">lxc</option><option value="qemu">qemu</option></select></label>
<label>Token ID <input id="token_id" name="token_id" required autocomplete="username" placeholder="user@pam!id"/></label>
<label>Token secret <input id="token_secret" name="token_secret" type="password" autocomplete="current-password" placeholder="unchanged if empty"/></label>
<label><input id="insecure_tls" name="insecure_tls" type="checkbox"/> Insecure TLS (lab)</label>
</div>
<p><button type="submit" id="save_settings">Save settings</button></p>
</form>
<script>
const el=(id)=>document.getElementById(id);
let dirty=false,lastClean='',settingsDirty=false;
const list=el('list'),saveBtn=el('save'),revertBtn=el('revert'),banner=el('banner');
function clearSettingsMsg(){
  ['settings_msg','settings_msg_ok'].forEach((id)=>{
    const n=el(id); n.className=''; n.textContent='';
  });
}
function setProxmoxErr(s){
  const pe=el('proxmox_err');
  const msg=(s.last_refresh_err||'').trim();
  if(!msg){ pe.className=''; pe.textContent=''; pe.removeAttribute('aria-label'); return; }
  pe.className='err';
  pe.setAttribute('aria-label','Host error');
  pe.textContent=msg;
}
function syncCredRequired(s){el('token_secret').required=!s.form.token_secret_present;}
function policyBanner(s){
  banner.innerHTML='';
  const hasDetail=(s.last_refresh_err||'').trim().length>0;
  const detailRef=hasDetail?' See the red error panel near the page title for the server message.':'';
  if(s.policy_unknown){
    const d=document.createElement('div');
    d.className='muted';
    d.textContent='Could not verify outbound firewall policy for this guest (narrow token ACL on firewall endpoints, firewall disabled/misconfigured, or other Proxmox error).'+detailRef+' docs/proxmox-setup.md.';
    banner.appendChild(d);return;
  }
  if((s.policy_out||'').toUpperCase() !== 'DROP'){
    const d=document.createElement('div');
    d.className='danger';
    d.textContent='Outbound policy is not DROP ('+(s.policy_out||'(empty)')+'). DNS allow listing will not restrict egress as intended. Set Output policy to DROP (see docs/proxmox-setup.md).';
    banner.appendChild(d);
  }
}
function renderFirewallActivity(s){
  const ul=el('firewall_activity');
  const rows=Array.isArray(s.firewall_activity)?s.firewall_activity:[];
  ul.replaceChildren();
  const labels={allow_added:'ACCEPT out rule added',allow_failed:'Allow rule failed',allow_pruned:'Stale allow rule removed',dynamic_removed:'Dynamic rule(s) removed',remove_failed:'Remove rule(s) failed'};
  if(rows.length===0){
    const li=document.createElement('li');
    li.className='fw-empty';
    li.textContent='No recent firewall changes (mutations or API errors only).';
    ul.appendChild(li);
    return;
  }
  for(let i=rows.length-1;i>=0;i--){
    const r=rows[i];
    const li=document.createElement('li');
    const bad=!!(r.error&&String(r.error).trim());
    li.className=bad?'fw-err':'fw-ok';
    const head=(labels[r.result]||r.result)+' · '+(r.fqdn||'?')+(r.ip?' → '+r.ip:'');
    li.textContent=(r.time||'')+'  '+head+(bad?('  — '+r.error):'');
    ul.appendChild(li);
  }
}
function pageHeading(s){
  const disp=(s.vm_display||'').trim();
  if(disp!==''){
    document.title='pve-dns-lockdown of '+disp;
    el('page_title').textContent='pve-dns-lockdown of '+disp;
    return;
  }
  const v=s.form&&(s.form.pve_vmid|0)||0;
  if(v>0){
    document.title='pve-dns-lockdown of '+v+' (-)';
    el('page_title').textContent='pve-dns-lockdown of '+v+' (-)';
    return;
  }
  document.title='pve-dns-lockdown';
  el('page_title').textContent='pve-dns-lockdown';
}
function applyState(s){
  pageHeading(s);
  setProxmoxErr(s);
  policyBanner(s);
  renderFirewallActivity(s);
  if(!settingsDirty){
    el('pve_host').value=s.form.pve_host||'';
    el('pve_node').value=s.form.pve_node||'';
    el('pve_vmid').value=s.form.pve_vmid||'';
    el('guest_type').value=(s.form.guest_type||'lxc');
    el('token_id').value=s.form.token_id||'';
    el('token_secret').value='';
    el('token_secret').placeholder=s.form.token_secret_present?'●●●● leave blank to keep':'token secret';
    el('insecure_tls').checked=!!s.form.insecure_tls;
  }
  syncCredRequired(s);
  if(!dirty){
    list.value=s.merged_list_text||'';lastClean=list.value;
    saveBtn.disabled=true;revertBtn.disabled=true;
  }
}
el('settings_form').addEventListener('input',()=>{settingsDirty=true;clearSettingsMsg();});
el('settings_form').addEventListener('change',()=>{settingsDirty=true;clearSettingsMsg();});
list.addEventListener('input',()=>{
  dirty=true;saveBtn.disabled=(list.value===lastClean);revertBtn.disabled=!dirty;
  el('allowlist_msg').className=''; el('allowlist_msg').textContent='';
});
el('revert').addEventListener('click',()=>{
  list.value=lastClean;dirty=false;saveBtn.disabled=true;revertBtn.disabled=true;
  el('allowlist_msg').className=''; el('allowlist_msg').textContent='';
});
el('save').addEventListener('click',async()=>{
  el('status').textContent='Saving…';
  const msgEl=el('allowlist_msg');
  msgEl.className=''; msgEl.textContent='';
  const r=await fetch('/api/save-list',{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:list.value});
  const text=await r.text();
  let j=null; try{ j=JSON.parse(text);}catch(_){}
  if(!r.ok){
    const body=(j&&j.error)||text||('HTTP '+r.status);
    const hint=(j&&j.error_detail)?('\n\n'+j.error_detail):'';
    msgEl.className='err';
    msgEl.textContent=body+hint;
    el('status').textContent='Allow list save failed ('+r.status+')';
    return;
  }
  dirty=false;lastClean=list.value;saveBtn.disabled=true;revertBtn.disabled=true;
  el('status').textContent='Saved';
});
el('settings_form').addEventListener('submit',async(ev)=>{
  ev.preventDefault();
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
  const text=await r.text();
  let j=null; try{ j=JSON.parse(text);}catch(_){}
  if(!r.ok){
    const msg=(j&&j.error)||text||('HTTP '+r.status);
    const hint=(j&&j.error_detail)?('\n\n'+j.error_detail):'';
    el('settings_msg').className='err';
    el('settings_msg').textContent=msg+hint;
    el('settings_msg_ok').className='';
    el('settings_msg_ok').textContent='';
    el('status').textContent='Settings save failed';
    return;
  }
  const okLine=(j&&j.connection_ok)?String(j.connection_ok).trim():'';
  el('settings_msg_ok').className='';
  el('settings_msg_ok').textContent='';
  if(j&&j.warning){
    el('settings_msg').className='warn';
    el('settings_msg').textContent=j.warning;
    el('status').textContent='Settings saved (see note above)';
  }else{
    el('settings_msg').className='';
    el('settings_msg').textContent='';
    el('status').textContent='Settings saved';
  }
  if(okLine){
    el('settings_msg_ok').className='ok';
    el('settings_msg_ok').textContent=okLine;
  }
  settingsDirty=false;
  try{
    const snap=await fetch('/api/snapshot').then(rr=>rr.json());
    applyState(snap);
  }catch(_){}
});
const es = new EventSource('/stream');
es.onmessage = (ev)=>{ try{ applyState(JSON.parse(ev.data)); }catch(_){} };
es.onerror = ()=>{ el('status').textContent='SSE interrupted (retrying…)'; };
fetch('/api/snapshot').then(r=>r.json()).then(applyState).catch(()=>{});
</script></body></html>`
}
