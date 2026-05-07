# LXC / container hints

Operational notes only; adjust for your distro.

## Process

Single binary listens on DNS (Corefile‑defined, usually `:53/tcp+udp`) and HTTP `:80`.

## Ports

Bind **53** needs capability or root (`CAP_NET_BIND_SERVICE` helps if non‑root).

## Paths

Suggested config layout:

- `/etc/pve-dns-lockdown/config.json` — Proxmox URL, node, VMID, guest type, tokens (chmod `0600`).
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

That writes `dist/debian-12-pve-lockdown_ct-template_<arch>.tar.gz` (for example `_amd64` on x86_64).

**Import in the GUI:** open a storage pool that includes **`vztmpl`** in its content types (often **`local`**), go to **CT Templates**, use **Upload**, and pick the file. The dialog accepts **`.tar.gz`**, **`.tar.xz`**, and **`.tar.zst`** (current Proxmox UI). **Create CT** from the web UI and select the template you uploaded.

If the guest does not start the daemon you expect, set **`--entrypoint /usr/local/bin/pve-lockdown`** in the CT options (same binary as the image default).

**OCI** application containers (registry / pull in the UI) are a separate path; use them only if you explicitly want that workflow instead of a classic vztmpl rootfs.
