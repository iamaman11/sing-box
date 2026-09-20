#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required" >&2
    exit 2
  fi
}

for name in GH_TOKEN REPOSITORY ACCEPTED_REVISION OUTPUT_DIR; do
  require_env "$name"
done

[[ "$REPOSITORY" = "iamaman11/sing-box" ]]
[[ "$ACCEPTED_REVISION" =~ ^[0-9a-f]{40}$ ]]
if [[ -n "${EXPECTED_RELEASE_TAG:-}" ]]; then
  [[ "$EXPECTED_RELEASE_TAG" =~ ^edge-release-[0-9a-f]{64}$ ]]
fi

out="$OUTPUT_DIR"
rm -rf "$out"
install -d -m 0755 "$out"

expected_assets=(
  acceptance.json
  edge-agent-linux-amd64
  edge-agent-linux-amd64.sha256
  edge-controller-linux-amd64
  edge-controller-linux-amd64.sha256
  edge-platform-windows.zip
  edge-platform-windows.zip.sha256
  edge-release-set-linux-amd64
  edge-release-set-linux-amd64.sha256
  release-set.pb
  release-set.pb.sha256
)

candidate_releases="${out}/.candidate-releases.jsonl"
matching_releases="${out}/.matching-releases.jsonl"
: > "$candidate_releases"
: > "$matching_releases"

page=1
while :; do
  page_json="$(gh api "repos/${REPOSITORY}/releases?per_page=100&page=${page}")"
  jq -c '
    .[]
    | select(.draft == false)
    | select(.prerelease == false)
    | select(.tag_name | test("^edge-release-[0-9a-f]{64}$"))
  ' <<<"$page_json" >> "$candidate_releases"
  page_count="$(jq 'length' <<<"$page_json")"
  [[ "$page_count" =~ ^[0-9]+$ ]]
  if (( page_count < 100 )); then
    break
  fi
  ((page += 1))
done

while IFS= read -r candidate_release; do
  [[ -n "$candidate_release" ]] || continue
  candidate_tag="$(jq -er '.tag_name' <<<"$candidate_release")"
  ref_json="$(gh api "repos/${REPOSITORY}/git/ref/tags/${candidate_tag}")"
  test "$(jq -er '.object.type' <<<"$ref_json")" = "commit"
  ref_sha="$(jq -er '.object.sha' <<<"$ref_json")"
  [[ "$ref_sha" =~ ^[0-9a-f]{40}$ ]]
  if [[ "$ref_sha" = "$ACCEPTED_REVISION" ]]; then
    printf '%s\n' "$candidate_release" >> "$matching_releases"
  fi
done < "$candidate_releases"

match_count="$(grep -c . "$matching_releases" || true)"
test "$match_count" -eq 1 || {
  echo "expected exactly one published canonical release for accepted revision $ACCEPTED_REVISION, found $match_count" >&2
  exit 1
}

release_stub="$(cat "$matching_releases")"
release_id="$(jq -er '.id' <<<"$release_stub")"
[[ "$release_id" =~ ^[0-9]+$ ]]
release_tag="$(jq -er '.tag_name' <<<"$release_stub")"
[[ "$release_tag" =~ ^edge-release-[0-9a-f]{64}$ ]]
release_set_sha="${release_tag#edge-release-}"
[[ "$release_set_sha" =~ ^[0-9a-f]{64}$ ]]

if [[ -n "${EXPECTED_RELEASE_TAG:-}" ]]; then
  test "$release_tag" = "$EXPECTED_RELEASE_TAG" || {
    echo "durable release changed after verification: expected $EXPECTED_RELEASE_TAG, got $release_tag" >&2
    exit 1
  }
fi

release_json="$(gh api "repos/${REPOSITORY}/releases/${release_id}")"
test "$(jq -er '.id' <<<"$release_json")" = "$release_id"
test "$(jq -er '.tag_name' <<<"$release_json")" = "$release_tag"
test "$(jq -r '.draft' <<<"$release_json")" = "false"
test "$(jq -r '.prerelease' <<<"$release_json")" = "false"

mapfile -t actual_assets < <(jq -r '.assets[].name' <<<"$release_json" | sort)
mapfile -t sorted_expected_assets < <(printf '%s\n' "${expected_assets[@]}" | sort)
test "${#actual_assets[@]}" -eq "${#sorted_expected_assets[@]}"
if ! diff -u <(printf '%s\n' "${sorted_expected_assets[@]}") <(printf '%s\n' "${actual_assets[@]}"); then
  echo "durable release asset contract mismatch" >&2
  exit 1
fi

download_asset() {
  local name="$1"
  local destination="${out}/${name}"
  local asset_json
  local asset_id
  local api_digest
  local actual_digest

  asset_json="$(jq -cer --arg name "$name" '
    [.assets[] | select(.name == $name)]
    | if length == 1 then .[0] else error("asset cardinality mismatch") end
  ' <<<"$release_json")"
  asset_id="$(jq -er '.id' <<<"$asset_json")"
  api_digest="$(jq -er '.digest' <<<"$asset_json")"
  [[ "$asset_id" =~ ^[0-9]+$ ]]
  [[ "$api_digest" =~ ^sha256:[0-9a-f]{64}$ ]]

  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --proto-redir '=https' \
    --header "Authorization: Bearer ${GH_TOKEN}" \
    --header "Accept: application/octet-stream" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    --output "$destination" \
    "https://api.github.com/repos/${REPOSITORY}/releases/assets/${asset_id}"

  actual_digest="$(sha256sum "$destination" | awk '{print $1}')"
  test "sha256:${actual_digest}" = "$api_digest" || {
    echo "GitHub asset digest mismatch: $name" >&2
    exit 1
  }
}

for name in \
  acceptance.json \
  edge-agent-linux-amd64 \
  edge-agent-linux-amd64.sha256 \
  edge-controller-linux-amd64 \
  edge-controller-linux-amd64.sha256 \
  edge-release-set-linux-amd64 \
  edge-release-set-linux-amd64.sha256 \
  release-set.pb \
  release-set.pb.sha256; do
  download_asset "$name"
done

verify_sidecar() {
  local file="$1"
  local sidecar="$2"
  local name="$3"
  local digest
  digest="$(sha256sum "$file" | awk '{print $1}')"
  test "$(cat "$sidecar")" = "${digest}  ${name}" || {
    echo "SHA-256 sidecar mismatch: $name" >&2
    exit 1
  }
}

verify_sidecar "${out}/edge-agent-linux-amd64" "${out}/edge-agent-linux-amd64.sha256" "edge-agent-linux-amd64"
verify_sidecar "${out}/edge-controller-linux-amd64" "${out}/edge-controller-linux-amd64.sha256" "edge-controller-linux-amd64"
verify_sidecar "${out}/edge-release-set-linux-amd64" "${out}/edge-release-set-linux-amd64.sha256" "edge-release-set-linux-amd64"

test "$(cat "${out}/release-set.pb.sha256")" = "${release_set_sha}  release-set.pb"
test "$(sha256sum "${out}/release-set.pb" | awk '{print $1}')" = "$release_set_sha"

acceptance="${out}/acceptance.json"
test "$(jq -er '.schema' "$acceptance")" = "1"
test "$(jq -er '.accepted_revision' "$acceptance")" = "$ACCEPTED_REVISION"
candidate_revision="$(jq -er '.candidate_revision' "$acceptance")"
source_tree="$(jq -er '.source_tree' "$acceptance")"
candidate_run_id="$(jq -r '.candidate_run_id' "$acceptance")"
[[ "$candidate_revision" =~ ^[0-9a-f]{40}$ ]]
[[ "$source_tree" =~ ^[0-9a-f]{40}$ ]]
[[ "$candidate_run_id" =~ ^[0-9]+$ ]]

accepted_commit="$(gh api "repos/${REPOSITORY}/git/commits/${ACCEPTED_REVISION}")"
candidate_commit="$(gh api "repos/${REPOSITORY}/git/commits/${candidate_revision}")"
test "$(jq -er '.tree.sha' <<<"$accepted_commit")" = "$source_tree"
test "$(jq -er '.tree.sha' <<<"$candidate_commit")" = "$source_tree"

verifier="${out}/edge-release-set-linux-amd64"
chmod 0755 "$verifier"
verify_output="$("$verifier" verify-vm \
  --input "${out}/release-set.pb" \
  --sha256-file "${out}/release-set.pb.sha256" \
  --source-revision "$candidate_revision" \
  --edge-agent "${out}/edge-agent-linux-amd64" \
  --edge-controller "${out}/edge-controller-linux-amd64")"
printf '%s\n' "$verify_output"

extract_single() {
  local key="$1"
  local value
  value="$(sed -n "s/^${key}=//p" <<<"$verify_output")"
  test "$(grep -c . <<<"$value")" -eq 1
  test -n "$value"
  printf '%s' "$value"
}

verified_release_set_sha="$(extract_single release_set_sha256)"
schema_version="$(extract_single schema_version)"
verified_source_revision="$(extract_single source_revision)"
agent_sha="$(extract_single edge_agent_sha256)"
controller_sha="$(extract_single edge_controller_sha256)"
gateway_image="$(extract_single sing_box_image)"
warp_image="$(extract_single warp_egress_image)"
mesh_image="$(extract_single mesh_image)"
docker_engine_version="$(extract_single docker_engine_version)"
containerd_version="$(extract_single containerd_version)"
compose_version="$(extract_single compose_version)"

for package_version in "$docker_engine_version" "$containerd_version" "$compose_version"; do
  [[ "$package_version" =~ ^[A-Za-z0-9.+:~_-]+$ ]]
done

test "$verified_release_set_sha" = "$release_set_sha"
test "$schema_version" = "2"
test "$verified_source_revision" = "$candidate_revision"
[[ "$agent_sha" =~ ^[0-9a-f]{64}$ ]]
[[ "$controller_sha" =~ ^[0-9a-f]{64}$ ]]
test "$agent_sha" = "$(sha256sum "${out}/edge-agent-linux-amd64" | awk '{print $1}')"
test "$controller_sha" = "$(sha256sum "${out}/edge-controller-linux-amd64" | awk '{print $1}')"
[[ "$gateway_image" =~ ^ghcr\.io/iamaman11/vultr-edge-gateway@sha256:[0-9a-f]{64}$ ]]
[[ "$warp_image" =~ ^ghcr\.io/iamaman11/vultr-warp-egress@sha256:[0-9a-f]{64}$ ]]
[[ "$mesh_image" =~ ^docker\.io/cloudflare/mesh@sha256:[0-9a-f]{64}$ ]]

cat > "${out}/resolved.env" <<EOF
EDGE_ACCEPTED_REVISION=$ACCEPTED_REVISION
EDGE_CANDIDATE_REVISION=$candidate_revision
EDGE_SOURCE_TREE=$source_tree
EDGE_RELEASE_ID=$release_id
EDGE_RELEASE_TAG=$release_tag
EDGE_RELEASE_SET_SHA256=$release_set_sha
EDGE_CONTROLLER_SHA256=$controller_sha
EDGE_AGENT_SHA256=$agent_sha
EDGE_GATEWAY_IMAGE=$gateway_image
EDGE_WARP_EGRESS_IMAGE=$warp_image
EDGE_MESH_IMAGE=$mesh_image
EDGE_DOCKER_ENGINE_VERSION=$docker_engine_version
EDGE_CONTAINERD_VERSION=$containerd_version
EDGE_COMPOSE_VERSION=$compose_version
EOF
chmod 0644 "${out}/resolved.env"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'release_id=%s\n' "$release_id"
    printf 'release_tag=%s\n' "$release_tag"
    printf 'release_set_sha256=%s\n' "$release_set_sha"
    printf 'candidate_revision=%s\n' "$candidate_revision"
  } >> "$GITHUB_OUTPUT"
fi

printf 'release_id=%s\n' "$release_id"
printf 'release_tag=%s\n' "$release_tag"
printf 'release_set_sha256=%s\n' "$release_set_sha"
printf 'candidate_revision=%s\n' "$candidate_revision"
