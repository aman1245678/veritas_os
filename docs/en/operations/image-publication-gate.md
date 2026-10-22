# Docker image publication gate

The GHCR workflow builds a single `linux/amd64` OCI directory layout without publishing
it. It retains BuildKit provenance and SBOM attestations. Trivy reads this local
layout, rather than an image already pushed to the registry.

`scripts/ci/publish_scanned_oci.sh` records layout and manifest file-content fingerprints, then runs
the existing actionable-Critical policy: vulnerability scanner only, CRITICAL,
ignore unfixed findings, exit code 1 on matching findings. Scanner errors also
stop the script. No registry copy runs before successful scanner completion.
The informational HIGH/CRITICAL SARIF report remains separate from this gate.

After success, the script checks the layout hash before each copy. Skopeo copies
all manifests with `--all --preserve-digests`, including the attestations, and
checks the resulting digest. There is no rebuild between inspection and copying.
The SHA tag is copied first; failure or a digest mismatch stops before `latest`.
The two tags are not an atomic transaction: a later failure can leave the SHA tag
published while `latest` is unchanged. Existing published images are not removed.

Only the main-branch workflow has package-write permissions and registry login.
Manual runs on other refs cannot reach publication. The PR verification workflow
has contents-read permission only, performs the same real layout scan, and
copies into another local OCI layout. It checks that the copied manifest digest
matches. It does not log in to GHCR or publish a registry image.

Evidence artifacts contain tested source SHA, layout hash, source/copy manifest
digests and the Critical report. The layout itself and credentials are not
uploaded. Missing evidence or a failed CI run is not successful publication proof.

Controlled process tests exercise findings, scanner errors, manifest inspection
errors, layout mutation and failed/mismatched copies. They prove the script's
refusal ordering using stub executables. PR CI separately tests real BuildKit,
Trivy and Skopeo compatibility. A successful local-copy PR run does not establish
successful GHCR publication; the exact main SHA needs its own successful run.
The policy does not reject every HIGH or unfixed vulnerability and does not
establish production safety or downstream deployment of the image.
