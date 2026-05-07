#!/bin/sh
# Export an existing container image ($IMAGE_TAG): create ephemeral container,
# flattened rootfs tar, gzip to dist/ for Proxmox vztmpl storage. Requires a prior container build.
# Env: CONTAINER_RUNTIME (default podman), ROOT (repo root), IMAGE_TAG, DIST_DIR,
#      TEMPLATE_BASENAME (prefix), TEMPLATE_STAMP (yyyymmdd_hhmmss — default: build host local date + time).
# Output: ${DIST_DIR}/${TEMPLATE_BASENAME}_${STAMP}_${ARCH}.tar.gz
set -eu

RT="${CONTAINER_RUNTIME:-podman}"
ROOT="${ROOT:-.}"
IMAGE_TAG="${IMAGE_TAG:-localhost/pve-dns-lockdown:bookworm}"
DIST_DIR="${DIST_DIR:-${ROOT}/dist}"
TEMPLATE_BASENAME="${TEMPLATE_BASENAME:-pve-dns-lockdown_ct-template}"
STAMP="${TEMPLATE_STAMP:-$(date +%Y%m%d_%H%M%S)}"

if ! command -v "$RT" >/dev/null 2>&1; then
	echo "export-proxmox-ct-rootfs: '$RT' not in PATH" >&2
	exit 1
fi

arch_tag() {
	m="$(uname -m)"
	case "$m" in
	x86_64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	armv7l) echo armhf ;;
	*) echo "$m" ;;
	esac
}

ARCH="$(arch_tag)"
mkdir -p "$DIST_DIR"
OUT="${DIST_DIR}/${TEMPLATE_BASENAME}_${STAMP}_${ARCH}.tar.gz"

cid=""
cleanup() {
	if [ -n "${cid}" ]; then
		"$RT" rm -f "$cid" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT HUP TERM

cid="$("$RT" create "$IMAGE_TAG")"
tmpdir="${TMPDIR:-/tmp}"
tmp="$tmpdir/pve-dns-lockdown-rootfs.$$.$RANDOM.tar"
"$RT" export "$cid" -o "$tmp"

gzip -9 -c "$tmp" >"$OUT"
rm -f "$tmp"

echo "Wrote $OUT"
