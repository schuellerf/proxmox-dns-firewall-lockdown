#!/bin/sh
# Build [Containerfile], export a flattened rootfs tarball, gzip for Proxmox vztmpl storage.
# Env: CONTAINER_RUNTIME (default podman), ROOT (repo root), IMAGE_TAG, DIST_DIR,
#      TEMPLATE_BASENAME (output name prefix before _${arch}.tar.gz).
set -eu

RT="${CONTAINER_RUNTIME:-podman}"
ROOT="${ROOT:-.}"
IMAGE_TAG="${IMAGE_TAG:-localhost/pve-dns-lockdown:bookworm}"
DIST_DIR="${DIST_DIR:-${ROOT}/dist}"
TEMPLATE_BASENAME="${TEMPLATE_BASENAME:-debian-12-pve-lockdown_ct-template}"

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
OUT="${DIST_DIR}/${TEMPLATE_BASENAME}_${ARCH}.tar.gz"
CONTAINERFILE="${ROOT}/Containerfile"
if [ ! -f "$CONTAINERFILE" ]; then
	echo "export-proxmox-ct-rootfs: missing $CONTAINERFILE" >&2
	exit 1
fi

cid=""
cleanup() {
	if [ -n "${cid}" ]; then
		"$RT" rm -f "$cid" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT HUP TERM

"$RT" build -f "$CONTAINERFILE" -t "$IMAGE_TAG" "$ROOT"

cid="$("$RT" create "$IMAGE_TAG")"
tmpdir="${TMPDIR:-/tmp}"
tmp="$tmpdir/pve-lockdown-rootfs.$$.$RANDOM.tar"
"$RT" export "$cid" -o "$tmp"

gzip -9 -c "$tmp" >"$OUT"
rm -f "$tmp"

echo "Wrote $OUT"
