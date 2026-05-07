# Proxmox setup (brief)

Goals: enable the API for **one** locked guest only, outgoing default **DROP**, DNS → `pve-lockdown`, and token scope as small as tolerable.

## 1. Guest firewall: default deny egress

In Proxmox: select the locked guest → **Firewall** → **Options**.

- Enable the guest firewall.
- Set **Outbound Policy** (**Output policy**) to **DROP**.
- Ensure **Inbound Policy** matches your admin/SSH rules (outside this doc).

If outbound policy is not `DROP`, the web UI for `pve-lockdown` shows a warning; relying on DNS allow‑listing without DROP is ineffective.

Official reference: firewall chapter in current [Proxmox VE administration guide](https://pve.proxmox.com/wiki/Proxmox_VE_Nodes#getting-more-information).

## 2. Locked guest DNS

Point resolver at this container’s IP (prefer static IP): use guest **DNS** field or DHCP option. **TCP and UDP** 53 against this host must be allowed (bootstrap rules applied by `pve-lockdown`).

## 3. Least‑privilege API token (narrow as possible)

Rough recipe (adapt to your ACL model—UI names move slightly across versions):

1. Create a dedicated **realm user** (e.g. `pvednslockdown@pam`) intended for automation.
2. Create a **custom role** granting only privileges needed:
   - Read/write firewall for **that VM only** (`VM.Firewall`‑style scopes on the guest path — exact strings differ by release; mirror what the API denies with `403` until satisfied).
   - Read/write VM **configuration / description** (`VM.Config.Options`‑style scopes) for the guest `GET/PUT` on `nodes/{node}/lxc|qemu/{vmid}/config`.
3. Add an **API token** under that user. Store **secret** separately; revoke on rotation.
4. Under **Permissions**, map the token (or group) **only** to resource paths that resolve to `/nodes/your-node/.../your-vmid/` — avoid datacenter‑wide Administrator.

Tips:

- Trim permissions until startup errors; widen one privilege at a time (`403` texts name the verb).
- Document token creation in your password manager / runbook — not inside Proxmox `description`.

More context: **User Management**, **Privileges**, **API Tokens** sections in [Proxmox VE wiki](https://pve.proxmox.com/wiki/User_Management), and confirm calls in the [JSON API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/) for `/nodes/{node}/{lxc|qemu}/{vmid}/firewall/rules` and `firewall/options`, plus `GET/PUT` `config` with `description`.

## 4. Allow list block placement

If absent, saving from the UI **appends** this block after any existing note text:

```
PROXMOX_DNS_LOCKDOWN_BEGIN
# example-disabled.example
PROXMOX_DNS_LOCKDOWN_END
```

Anything **outside** the markers is untouched by the tool.
