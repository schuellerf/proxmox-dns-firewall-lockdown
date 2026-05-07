package lockdown

import (
	"context"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/coordinator"

	"github.com/miekg/dns"
)

func init() { plugin.Register("lockdown", setup) }

func setup(c *caddy.Controller) error {
	for c.Next() {
		for c.NextBlock() {
			return plugin.Error("lockdown", c.Errf("unknown directive %s", c.Val()))
		}
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Lockdown{Next: next}
	})
	return nil
}

// Lockdown wraps responses after forward resolves upstream.
type Lockdown struct {
	Next plugin.Handler
}

// Name implements plugin.Handler.
func (lk Lockdown) Name() string { return "lockdown" }

type respWrap struct {
	dns.ResponseWriter
	req *dns.Msg
}

func (w *respWrap) WriteMsg(m *dns.Msg) error {
	if coordinator.Default != nil && w.req != nil && len(w.req.Question) > 0 {
		coordinator.Default.ApplyDNS(w.req.Question[0].Name, m)
	}
	return w.ResponseWriter.WriteMsg(m)
}

// ServeDNS forwards to the chain with a wrapping writer.
func (lk Lockdown) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return plugin.NextOrFailure(lk.Name(), lk.Next, ctx, &respWrap{ResponseWriter: w, req: r}, r)
}
