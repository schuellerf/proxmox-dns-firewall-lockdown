# LXC / container hints

Operational notes only; adjust for your distro.

## Process

Single binary listens on DNS (Corefile‑defined, usually `:53/tcp+udp`) and HTTP `:80`.

Every successful DNS answer (`NOERROR`) can emit one or more **`pve-dns-lockdown: dns`** lines to the journal (per resolved IP); busy guests may be chatty — filter with e.g. `journalctl -u pve-dns-lockdown -g 'pve-dns-lockdown: dns'`.

If you only see CoreDNS **`[INFO]`** lines and **no** `pve-dns-lockdown: dns` lines after upgrading: **rebuild the binary** (`make build-coredns`); the **`pve-dns-lockdown` entry must appear before `forward` in `.build/<coredns>/plugin.cfg`** (the `scripts/patch-coredns-vendor.py` helper does this — appending the plugin last breaks the hook). At startup you should see **`pve-dns-lockdown: plugin pve-dns-lockdown: registered`** when the Corefile stanza `pve-dns-lockdown {}` is present.

## Ports

Bind **53** needs capability or root (`CAP_NET_BIND_SERVICE` helps if non‑root).

## Paths

Suggested config layout:

- `/etc/pve-dns-lockdown/config.json` — Proxmox URL, node, VMID, guest type, tokens (chmod `0600`). **ACLs:** put the same role on **`user@realm` and the API token** (see [proxmox-setup.md](proxmox-setup.md)).
- Token env or file readable only by root — see README / application flags.

Ship a **Corefile** (see [Corefile.example](../Corefile.example)) referencing the plugin stanza appropriate to your resolver.

## IP address

Prefer a **static** IP for stable bootstrap firewall rules targeting this host.

## Proxmox CT template (vztmpl)

[Proxmox **system container templates**](https://pve.proxmox.com/pve-docs/chapter-pct.html) are **tar archives of a full root filesystem** (what you get from this export), not an OCI image or a layered `podman save` / `docker save` archive.

Build the **`.tar.gz`** from this repository:

```bash
make proxmox-ct
```

That writes `dist/pve-dns-lockdown_ct-template_<yyyymmdd_hhmmss>_<arch>.tar.gz` (timestamp is **local** machine time when `make proxmox-ct` ran; example: `_20260507_153045_amd64` on x86_64).

You can set **`TEMPLATE_STAMP`** when invoking [`scripts/export-proxmox-ct-rootfs.sh`](scripts/export-proxmox-ct-rootfs.sh) directly; **`make proxmox-ct`** passes a single stamp for that run.

**Import in the GUI:** open a storage pool that includes **`vztmpl`** in its content types (often **`local`**), go to **CT Templates**, use **Upload**, and pick the file. The dialog accepts **`.tar.gz`**, **`.tar.xz`**, and **`.tar.zst`** (current Proxmox UI). **Create CT** from the web UI and select the template you uploaded.

The template runtime is **Debian Bookworm with systemd**, **`ifupdown`**, and **`dhclient`** so **`eth0` can use DHCP** from your bridge (matching a small **appliance CT**, not minimal slim). **pve-dns-lockdown** runs as **`pve-dns-lockdown.service`** after **`networking.service`**.

Proxmox still starts **`/sbin/init`** (systemd). Prefer a **privileged** CT for least friction with systemd inside LXC; if boot stalls, enable **nesting** and/or retry **privileged** under **Features**. You may still assign a **static IP** in the CT network tab—Proxmox can replace **`/etc/network/interfaces`** accordingly.

## Console (GUI) and logs

Upstream documents **`pct console`** versus **`pct enter`** ([pct chapter](https://pve.proxmox.com/pve-docs/chapter-pct.html)): **`pct console`** is normally a **login session on a TTY** (getty on **`tty1`**… — option **`tty`** counts how many consoles exist); **`pct enter`** is a **root shell without login** when the CT is running.

The template unit uses **`StandardOutput=journal+console`** so messages also go to **`/dev/console`**. Default web **Console** often uses **`cmode: tty`**, which is **not** the same as **`/dev/console`**. To see **pve-dns-lockdown** lines in the GUI Console, set **`cmode: console`** on the CT (see **`cmode`** in the same pct docs — **`console`** vs **`tty`** vs **`shell`**). Logs always appear in **`journalctl`** regardless:

```bash
pct exec <VMID> -- journalctl -u pve-dns-lockdown.service -f
```

**OCI** application containers (registry / pull in the UI) are a separate path; use them only if you explicitly want that workflow instead of a classic vztmpl rootfs.
