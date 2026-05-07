.DEFAULT_GOAL := help
.PHONY: help vendor-coredns build-coredns test clean proxmox-ct clean-dist

ROOT := $(abspath .)
CONTAINER_RUNTIME ?= podman
IMAGE_TAG ?= localhost/pve-dns-lockdown:bookworm
DIST_DIR := $(ROOT)/dist
TEMPLATE_BASENAME ?= debian-12-pve-lockdown_ct-template
COREDNS_VER := v1.12.4
GO_MODULE := github.com/schuellerf/proxmox-dns-firewall-lockdown

BUILD_DIR := $(ROOT)/.build
COREDNS_SRC := $(BUILD_DIR)/coredns
COREDNS_HEAD := $(COREDNS_SRC)/coredns.go

# Targets documented for `make help` list the text after "##" on the same line as the rule.
help: ## List targets documented with "##" on the rule line (this listing)
	@printf 'Usage: make <target>\n\n'
	@awk '/^#/ { next } \
	  /^[[:space:]]/ { next } \
	  { n = index($$0, " ## "); \
	    if (n <= 0) next; \
	    pre = substr($$0, 1, n - 1); \
	    doc = substr($$0, n + length(" ## ")); \
	    sub(/^[[:blank:]]+/, "", doc); \
	    split(pre, q, ":"); \
	    printf "  %-20s  %s\n", q[1], doc \
	  }' "$(firstword $(MAKEFILE_LIST))"

# Build directory (real target, not .PHONY).
$(BUILD_DIR):
	mkdir -p $@

# Clone CoreDNS when the sentinel file is missing.
$(COREDNS_HEAD): | $(BUILD_DIR)
	@test -f $(COREDNS_HEAD) || git clone --depth 1 --branch $(COREDNS_VER) https://github.com/coredns/coredns "$(COREDNS_SRC)"

vendor-coredns: $(COREDNS_HEAD) ## Clone CoreDNS (if missing) and run scripts/patch-coredns-vendor.py
	python3 "$(ROOT)/scripts/patch-coredns-vendor.py" \
	  --coredns "$(COREDNS_SRC)" \
	  --module "$(GO_MODULE)" \
	  --replace-path "$(ROOT)"

build-coredns: vendor-coredns ## Build bin/pve-lockdown (runs go generate inside CoreDNS checkout)
	cd "$(COREDNS_SRC)" && GOFLAGS=-buildvcs=false go generate coredns.go && GOFLAGS=-buildvcs=false go get ./...
	mkdir -p "$(ROOT)/bin"
	cd "$(ROOT)" && GOFLAGS=-buildvcs=false go build -o "$(ROOT)/bin/pve-lockdown" ./cmd/pve-lockdown

test: vendor-coredns ## Run go test for this repo
	cd "$(COREDNS_SRC)" && GOFLAGS=-buildvcs=false go generate coredns.go && GOFLAGS=-buildvcs=false go get ./...
	cd "$(ROOT)" && GOFLAGS=-buildvcs=false go test ./...

clean: ## Remove bin/ and cloned CoreDNS under .build/coredns
	rm -rf "$(ROOT)/bin" "$(COREDNS_SRC)"

proxmox-ct: ## Build OCI image and export gzip rootfs tarball for Proxmox vztmpl
	@ROOT="$(ROOT)" CONTAINER_RUNTIME="$(CONTAINER_RUNTIME)" IMAGE_TAG="$(IMAGE_TAG)" \
		DIST_DIR="$(DIST_DIR)" TEMPLATE_BASENAME="$(TEMPLATE_BASENAME)" \
		sh "$(ROOT)/scripts/export-proxmox-ct-rootfs.sh"

clean-dist: ## Remove generated dist/ CT template tarballs
	rm -rf "$(DIST_DIR)"
