#!/usr/bin/env bash
# Scan and copy one immutable OCI layout; no registry write before scan success.
set -euo pipefail

layout=$1
report_dir=$2
shift 2
if [ "$#" -eq 0 ]; then
  echo 'At least one destination is required' >&2
  exit 2
fi
mkdir -p "$report_dir"
# Fingerprint all files and paths, and reject symlinks outside the layout.
layout_fingerprint() {
  test -d "$layout" || return 1
  if [ -L "$layout" ] || [ -n "$(find "$layout" -type l -print -quit)" ]; then
    echo 'OCI layout must not contain symlinks' >&2
    return 1
  fi
  find "$layout" -type f -exec sha256sum {} + | LC_ALL=C sort | sha256sum | cut -d ' ' -f 1
}
layout_hash=$(layout_fingerprint)
skopeo inspect --raw "oci:$layout" > "$report_dir/manifest.json"
manifest_digest="sha256:$(sha256sum "$report_dir/manifest.json" | cut -d ' ' -f 1)"
printf '%s\n' "$layout_hash" > "$report_dir/layout.sha256"
printf '%s\n' "$manifest_digest" > "$report_dir/manifest-digest.txt"

# A vulnerability, scanner error or interruption exits before any copy.
trivy image --input "$layout" --scanners vuln --severity CRITICAL \
  --ignore-unfixed --exit-code 1 --format json \
  --output "$report_dir/trivy-critical.json"

index=0
for destination in "$@"; do
  test "$(layout_fingerprint)" = "$layout_hash"
  # --all includes the attestation manifests; no rebuild or format conversion.
  skopeo copy --all --preserve-digests \
    --digestfile "$report_dir/copied-$index.digest" \
    "oci:$layout" "$destination"
  test "$(cat "$report_dir/copied-$index.digest")" = "$manifest_digest"
  index=$((index + 1))
done
