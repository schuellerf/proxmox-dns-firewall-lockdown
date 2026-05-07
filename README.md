# Proxmox DNS + dynamic egress firewall

This is a DNS resolver (CoreDNS + custom plugin) for Proxmox which locks outbound traffic of a given guest VM by modifying the guest's firewall rules.

You have to grant access to a specific guest VM’s Proxmox config and firewall APIs: put the narrow role **`/vms/<VMID>`** on **both** the realm **user** and the **API token** (privsep tokens intersect permissions; the token cannot exceed the user). Details: [docs/proxmox-setup.md](docs/proxmox-setup.md). Bootstrap rules initially allow DNS to **this** host on port **53**.

When the guest resolves a name, it get's on the list of names to be approved (in our web UI).
If the name is approved (by you, un-commenting it in the web UI), the resolved IPs are **allowed** automatically on that guest’s **outgoing Proxmox firewall** even if the IPs would change. Direct access to IPs without an allowed DNS name will be blocked unless you manually add a rule to allow it in the proxmox outgoing firewall rules.

## Flow

1. Target VM/LXC uses this container as its DNS resolver.
2. The allow list lives in that guest’s Proxmox `description`, between `PROXMOX_DNS_LOCKDOWN_BEGIN` and `PROXMOX_DNS_LOCKDOWN_END` (optional `#` prefixes disable names). Other text in `description` is preserved.
3. Commenting out a name and **Save** removes **all** dynamic egress allows for that name immediately (IPv4 and IPv6); removed destinations are cached like a rejected lookup so **re-enabling + Save** can reopen them without waiting for DNS. On each successful DNS reply, allowed names still trigger **ACCEPT egress** rules (comment `pve-dns-lockdown:` + name + `:ipv4` or `:ipv6`); stale addresses for **that RR family only** drop when DNS no longer lists them — an IPv4 answer does not prune IPv6 rules for the same name. Disallowed names remove **our** tagged rules for those IPs so default **DROP** outbound policy applies.
4. **Port 80** serves a minimal editor, settings, and warns if outbound policy is not `DROP`.
5. This service reconciles bootstrap rules so the guest may reach **this** host on **53/udp,tcp** (and updates if our IP changes).

## Build

Requires Go (see CoreDNS upstream) and Git. From the repo root:

```bash
make proxmox-ct
```

This compiles the binary and builds an OCI image for Proxmox.
You can upload this image to "CT Templates" in Proxmox to create a new container (CT) with it.

## Configure

- **CoreDNS:** See [Corefile.example](Corefile.example). Real plugin order comes from **`plugin.cfg` in the CoreDNS checkout** (`pve-dns-lockdown` must be **before** `forward` there—`scripts/patch-coredns-vendor.py` enforces this). Rebuild with `make build-coredns` after any clone or script change; shuffling lines in the Corefile alone will not fix a mis-ordered `plugin.cfg`.

**Upgrading from older builds:** change the Corefile stanza from `lockdown {}` to `pve-dns-lockdown {}`, run `make vendor-coredns` (or `make build-coredns`), replace the binary with `bin/pve-dns-lockdown`, swap **`pve-lockdown.service`** for **`pve-dns-lockdown.service`** (and `ExecStart` → `/usr/local/bin/pve-dns-lockdown`), then `systemctl daemon-reload && systemctl enable --now pve-dns-lockdown.service`.
- **Proxmox + token + firewall:** [docs/proxmox-setup.md](docs/proxmox-setup.md).
- **LXC / container layout:** [docs/lxc-install.md](docs/lxc-install.md).

## License

MIT — see [LICENSE](LICENSE).

## References

Please read [references.md](references.md) when something needs external input.
Shared norms of this project are in [principles.md](principles.md).
