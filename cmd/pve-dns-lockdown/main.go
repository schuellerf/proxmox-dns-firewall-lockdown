package main

import (
	"log"
	"os"

	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/coordinator"
	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/httpserver"

	"github.com/coredns/coredns/coremain"

	_ "github.com/coredns/coredns/core/plugin"
	_ "github.com/schuellerf/proxmox-dns-firewall-lockdown/plugin/pve-dns-lockdown"
)

func main() {
	c, err := coordinator.New("")
	if err != nil {
		log.Fatal(err)
	}
	coordinator.Default = c

	addr := os.Getenv("PVE_DNS_LOCKDOWN_HTTP_ADDR")
	if addr == "" {
		addr = ":80"
	}
	_ = httpserver.Listen(addr, c)

	coremain.Run()
}
