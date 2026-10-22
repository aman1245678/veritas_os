#!/usr/bin/env bash
# Scan and copy one immutable OCI archive; no registry write before scan success.
set -euo pipefail

archive=$1
report_dir=$2
shift 2
if [ "$#" -eq 0 ]; then
  echo 'At least one destination is required' >&2
  exit 2
fi
mkdir -p "$report_dir"
archive_hash=$(sha256sum "$archive" | cut -d ' ' -f 1)
skopeo inspect --raw "oci-archive:$archive" > "$report_dir/manifest.json"
manifest_digest="sha256:$(sha256sum "$report_dir/manifest.json" | cut -d ' ' -f 1)"
printf '%s\n' "$archive_hash" > "$report_dir/archive.sha256"
printf '%s\n' "$manifest_digest" > "$report_dir/manifest-digest.txt"

# A vulnerability, scanner error or interruption exits before any copy.
trivy image --input "$archive" --scanners vuln --severity CRITICAL \
  --ignore-unfixed --exit-code 1 --format json \
  --output "$report_dir/trivy-critical.json"

index=0
for destination in "$@"; do
  test "$(sha256sum "$archive" | cut -d ' ' -f 1)" = "$archive_hash"
  # --all includes the attestation manifests; no rebuild or format conversion.
  skopeo copy --all --preserve-digests \
    --digestfile "$report_dir/copied-$index.digest" \
    "oci-archive:$archive" "$destination"
  test "$(cat "$report_dir/copied-$index.digest")" = "$manifest_digest"
  index=$((index + 1))
done
