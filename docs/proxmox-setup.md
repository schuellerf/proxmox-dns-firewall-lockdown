# Proxmox setup (brief)

Goals: enable the API for **one** locked guest only, outgoing default **DROP**, DNS → **pve-dns-lockdown**, and token scope as small as tolerable.

## 1. Guest firewall: default deny egress

In Proxmox: select the locked guest → **Firewall** → **Options**.

- Enable the guest firewall.
- Set **Outbound Policy** (**Output policy**) to **DROP**.
- Ensure **Inbound Policy** matches your admin/SSH rules (outside this doc).

If outbound policy is not `DROP`, the web UI for **pve-dns-lockdown** shows a warning; relying on DNS allow‑listing without DROP is ineffective.

Official reference: firewall chapter in current [Proxmox VE administration guide](https://pve.proxmox.com/wiki/Proxmox_VE_Nodes#getting-more-information).

## 2. Locked guest DNS

Point resolver at this container’s IP (prefer static IP): use guest **DNS** field or DHCP option. **TCP and UDP** 53 against this host must be allowed (bootstrap rules applied by **pve-dns-lockdown**).

## 3. Least‑privilege API token (narrow as possible)

Rough recipe (adapt to your ACL model—UI names move slightly across versions):

1. Create a dedicated **realm user** (e.g. `pvednslockdown@pam`) intended for automation.
2. Create a **custom role** with only the privileges this tool needs (names are **exact** strings in Proxmox; there is **no** privilege called `VM.Firewall`):
   - **`VM.Audit`** — *view VM config* ([privilege list](https://pve.proxmox.com/pve-docs/chapter-pveum.html)). Needed to read guest config (e.g. description) and firewall option endpoints the app calls.
   - **`VM.Config.Options`** — *modify any other VM configuration* (same chapter). Needed to change guest **description** / notes and **guest-level firewall** rules and options via the API (anything not covered by a finer `VM.Config.*` privilege).
3. Add an **API token** under that user. Store **secret** separately; revoke on rotation.
4. Under **Permissions**, map the token (or group) **only** to **`/vms/<VMID>`** (and optionally the node path if your version requires it for some calls) — avoid datacenter‑wide **Administrator**. **Privilege‑separated tokens:** Proxmox intersects token rights with the **backing user**, and **the token cannot exceed the user** — assign your role **`/vms/<VMID>`** (and any other paths you need) on **both** `user@realm` **and** `user@realm!tokenid`, not on the token alone.

Official reference: **[Permission Management](https://pve.proxmox.com/pve-docs/chapter-pveum.html)** (roles, paths like `/vms/{vmid}`, and the privilege table). Use **`pveum`** / the GUI **Permissions → Roles** editor to mirror what the API denies with `403` until satisfied.

**HTTP 403 on `PUT …/config` (e.g. when saving the allow list):** The app only sends **`description`** (and **`digest`**) to the guest config API, but Proxmox applies the same permission gate as for any VM config update. The denial lists privileges separated by **`|`** — logical **OR**: you need **one** of them on **`/vms/<VMID>`**, not every item named in the message. For Notes/description and similar “other” settings, grant **`VM.Config.Options`** ([privilege list](https://pve.proxmox.com/pve-docs/chapter-pveum.html)).

Tips:

- Unexpected **403** after widening the token: duplicate the **`/vms/<VMID>`** role onto the **`user@realm`** as well (privsep intersection).
- Document token creation in your password manager / runbook — not inside Proxmox `description`.
- **Optional (VMID → node / guest auto-resolve):** `GET /api2/json/cluster/resources` only returns guests the subject may **audit**. For **that VM only**, grant **`VM.Audit`** on **`/vms/<VMID>`** (same privilege: *view VM config*). If you prefer a predefined read-only bundle, the built-in **`PVEAuditor`** role is documented for read-only / monitoring-style access; narrow it to **`/vms/<VMID>`** instead of `/` or `/vms`. See the *Auditors* and *Limited API Token for Monitoring* examples in [User Management](https://pve.proxmox.com/pve-docs/chapter-pveum.html). If the call returns **403** or your VMID does not appear, set **Node** and **Guest** manually in this app; saved settings still work and the UI shows a warning.

More context: **User Management**, **Privileges**, **API Tokens** sections in [Proxmox VE wiki](https://pve.proxmox.com/wiki/User_Management), and confirm calls in the [JSON API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/) for `/nodes/{node}/{lxc|qemu}/{vmid}/firewall/rules` and `firewall/options`, plus `GET/PUT` `config` with `description`.

## 4. Allow list block placement

If absent, saving from the UI **appends** this block after any existing note text:

```
PROXMOX_DNS_LOCKDOWN_BEGIN
# example-disabled.example
PROXMOX_DNS_LOCKDOWN_END
```

Anything **outside** the markers is untouched by the tool.
