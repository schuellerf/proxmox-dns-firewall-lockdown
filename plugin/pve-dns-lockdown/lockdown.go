package pvednslockdown

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/coordinator"

	"github.com/miekg/dns"
)

const directive = "pve-dns-lockdown"

func init() { plugin.Register(directive, setup) }

// pluginLog uses stderr so startup lines always reach journald (CoreDNS may swap the default logger).
var pluginLog = log.New(os.Stderr, "pve-dns-lockdown: ", log.LstdFlags|log.Lmicroseconds)

func setup(c *caddy.Controller) error {
	for c.Next() {
		for c.NextBlock() {
			return plugin.Error(directive, c.Errf("unknown directive %s", c.Val()))
		}
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Lockdown{Next: next}
	})
	pluginLog.Println("plugin pve-dns-lockdown: registered — must be declared before forward in plugin.cfg (sorted before forward in the handler chain)")
	return nil
}

// Lockdown wraps responses after forward resolves upstream.
type Lockdown struct {
	Next plugin.Handler
}

// Name implements plugin.Handler.
func (lk Lockdown) Name() string { return directive }

type respWrap struct {
	dns.ResponseWriter
	req *dns.Msg
}

var warnNilCoordinator sync.Once

func (w *respWrap) WriteMsg(m *dns.Msg) error {
	if w.req != nil && len(w.req.Question) > 0 {
		if coordinator.Default != nil {
			coordinator.Default.ApplyDNS(w.req.Question[0].Name, m)
		} else {
			warnNilCoordinator.Do(func() {
				pluginLog.Println("WriteMsg: Coordinator.Default is nil; main did not set coordinator.Default before CoreDNS started")
			})
		}
	}
	return w.ResponseWriter.WriteMsg(m)
}

// ServeDNS forwards to the chain with a wrapping writer.
func (lk Lockdown) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return plugin.NextOrFailure(lk.Name(), lk.Next, ctx, &respWrap{ResponseWriter: w, req: r}, r)
}
