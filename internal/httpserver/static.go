package httpserver

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"github.com/schuellerf/proxmox-dns-firewall-lockdown/internal/version"
)

const defaultWWWRoot = "/usr/share/pve-dns-lockdown/www"

func wwwRoot() string {
	if v := os.Getenv("PVE_DNS_LOCKDOWN_WWW"); v != "" {
		return v
	}
	return defaultWWWRoot
}

func registerStaticRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/assets/banner.png", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		path := filepath.Join(wwwRoot(), "banner.png")
		if _, err := os.Stat(path); err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, path)
	})

	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		panic("httpserver: embed static: " + err.Error())
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))

	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"stamp":             version.Stamp,
			"template_basename": version.TemplateBasename,
		})
	})
}
