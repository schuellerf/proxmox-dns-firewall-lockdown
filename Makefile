.DEFAULT_GOAL := help
.PHONY: help vendor-coredns build-coredns test clean proxmox-ct-image proxmox-ct clean-dist

ROOT := $(abspath .)
CONTAINER_RUNTIME ?= podman
IMAGE_TAG ?= localhost/pve-dns-lockdown:bookworm
DIST_DIR := $(ROOT)/dist
TEMPLATE_BASENAME ?= pve-dns-lockdown_ct-template
COREDNS_VER := v1.12.4
GO_MODULE := github.com/schuellerf/proxmox-dns-firewall-lockdown
BUILD_STAMP ?= dev
LDFLAGS := -X $(GO_MODULE)/internal/version.Stamp=$(BUILD_STAMP)

BUILD_DIR := $(ROOT)/.build
# Versioned tree so bumping COREDNS_VER automatically reclones; go.mod replace still points at ./.build/coredns
COREDNS_STAGE := $(BUILD_DIR)/$(COREDNS_VER)/coredns
COREDNS_HEAD := $(COREDNS_STAGE)/coredns.go
COREDNS_SRC := $(BUILD_DIR)/coredns

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

# Clone CoreDNS under .build/<COREDNS_VER>/ when that revision is missing; symlink .build/coredns for go.mod replace.
$(COREDNS_HEAD): | $(BUILD_DIR)
	@test -f "$(COREDNS_HEAD)" || git clone --depth 1 --branch $(COREDNS_VER) https://github.com/coredns/coredns "$(COREDNS_STAGE)"
	@cd "$(BUILD_DIR)" && ln -sfnT "$(COREDNS_VER)/coredns" coredns

vendor-coredns: $(COREDNS_HEAD) ## Fetch CoreDNS into .build/$(COREDNS_VER)/; bumping version reclones + patch-coredns-vendor.py
	python3 "$(ROOT)/scripts/patch-coredns-vendor.py" \
	  --coredns "$(COREDNS_SRC)" \
	  --module "$(GO_MODULE)" \
	  --replace-path "$(ROOT)"

build-coredns: vendor-coredns ## Build bin/pve-dns-lockdown (runs go generate inside CoreDNS checkout)
	cd "$(COREDNS_SRC)" && GOFLAGS=-buildvcs=false go generate coredns.go && GOFLAGS=-buildvcs=false go get ./...
	mkdir -p "$(ROOT)/bin"
	cd "$(ROOT)" && GOFLAGS=-buildvcs=false go build -ldflags "$(LDFLAGS)" -o "$(ROOT)/bin/pve-dns-lockdown" ./cmd/pve-dns-lockdown

test: vendor-coredns ## Run go test for this repo
	cd "$(COREDNS_SRC)" && GOFLAGS=-buildvcs=false go generate coredns.go && GOFLAGS=-buildvcs=false go get ./...
	cd "$(ROOT)" && GOFLAGS=-buildvcs=false go test ./...

clean: clean-dist ## Remove bin/, dist/, and entire .build/ (CoreDNS checkout)
	rm -rf "$(ROOT)/bin" "$(BUILD_DIR)"

proxmox-ct-image: vendor-coredns ## Build OCI image from Containerfile tagged as $(IMAGE_TAG)
	"$(CONTAINER_RUNTIME)" build -f "$(ROOT)/Containerfile" \
		--build-arg BUILD_STAMP="$(BUILD_STAMP)" \
		-t "$(IMAGE_TAG)" "$(ROOT)"

proxmox-ct: ## Host binary + OCI image + gzip rootfs tarball for Proxmox vztmpl (single BUILD_STAMP)
	@STAMP=$$(date +%Y%m%d_%H%M%S); \
	$(MAKE) build-coredns BUILD_STAMP=$$STAMP; \
	"$(CONTAINER_RUNTIME)" build -f "$(ROOT)/Containerfile" \
		--build-arg BUILD_STAMP=$$STAMP \
		-t "$(IMAGE_TAG)" "$(ROOT)"; \
	ROOT="$(ROOT)" CONTAINER_RUNTIME="$(CONTAINER_RUNTIME)" IMAGE_TAG="$(IMAGE_TAG)" \
		DIST_DIR="$(DIST_DIR)" TEMPLATE_BASENAME="$(TEMPLATE_BASENAME)" TEMPLATE_STAMP=$$STAMP \
		sh "$(ROOT)/scripts/export-proxmox-ct-rootfs.sh"

clean-dist: ## Remove generated dist/ CT template tarballs
	rm -rf "$(DIST_DIR)"
