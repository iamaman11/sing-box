#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required" >&2
    exit 2
  fi
}

for name in   GH_TOKEN   REPOSITORY   ACCEPTED_REVISION   CANDIDATE_REVISION   CANDIDATE_RUN_ID   WINDOWS_DIR   LINUX_DIR   RELEASE_SET_DIR   OUTPUT_DIR; do
  require_env "$name"
done

[[ "$REPOSITORY" = "iamaman11/sing-box" ]]
[[ "$ACCEPTED_REVISION" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_REVISION" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_RUN_ID" =~ ^[0-9]+$ ]]

windows="$WINDOWS_DIR"
linux="$LINUX_DIR"
authority="$RELEASE_SET_DIR"
stage="$OUTPUT_DIR"
verify_dir="${stage}.verify"

test -f "${windows}/edge-platform-windows.zip"
test -f "${linux}/edge-agent"
test -f "${linux}/edge-controller"
test -f "${linux}/edge-release-set"
test -f "${authority}/release-set.pb"
test -f "${authority}/release-set.pb.sha256"
test -f "${authority}/acceptance.json"

(
  cd "$authority"
  sha256sum -c release-set.pb.sha256
)

release_set_sha="$(awk 'NR == 1 { print $1 }' "${authority}/release-set.pb.sha256")"
[[ "$release_set_sha" =~ ^[0-9a-f]{64}$ ]]
test "$(awk 'END { print NR }' "${authority}/release-set.pb.sha256")" -eq 1
test "$(awk 'NR == 1 { print $2 }' "${authority}/release-set.pb.sha256")" = "release-set.pb"

test "$(jq -er '.accepted_revision' "${authority}/acceptance.json")" = "$ACCEPTED_REVISION"
test "$(jq -er '.candidate_revision' "${authority}/acceptance.json")" = "$CANDIDATE_REVISION"
test "$(jq -er '.candidate_run_id' "${authority}/acceptance.json")" = "$CANDIDATE_RUN_ID"

rm -rf "$stage" "$verify_dir"
install -d -m 0755 "$stage" "$verify_dir"
install -m 0644 "${authority}/release-set.pb" "${stage}/release-set.pb"
install -m 0644 "${authority}/release-set.pb.sha256" "${stage}/release-set.pb.sha256"
install -m 0644 "${authority}/acceptance.json" "${stage}/acceptance.json"
install -m 0644 "${windows}/edge-platform-windows.zip" "${stage}/edge-platform-windows.zip"
install -m 0644 "${linux}/edge-agent" "${stage}/edge-agent-linux-amd64"
install -m 0644 "${linux}/edge-controller" "${stage}/edge-controller-linux-amd64"
install -m 0644 "${linux}/edge-release-set" "${stage}/edge-release-set-linux-amd64"

(
  cd "$stage"
  sha256sum edge-platform-windows.zip > edge-platform-windows.zip.sha256
  sha256sum edge-agent-linux-amd64 > edge-agent-linux-amd64.sha256
  sha256sum edge-controller-linux-amd64 > edge-controller-linux-amd64.sha256
  sha256sum edge-release-set-linux-amd64 > edge-release-set-linux-amd64.sha256
)

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

release_tag="edge-release-${release_set_sha}"
release_title="Edge Platform release ${release_set_sha:0:16}"
notes="${stage}/release-notes.md"
cat > "$notes" <<EOF
Canonical Edge Platform release.

- ReleaseSet SHA-256: \`$release_set_sha\`
- accepted main revision: \`$ACCEPTED_REVISION\`
- candidate source revision: \`$CANDIDATE_REVISION\`
- candidate Actions run: \`$CANDIDATE_RUN_ID\`

The authority is the exact published \`release-set.pb\` bytes. Text and GitHub metadata are display/evidence only.
EOF

ref_error="${stage}/ref-error.txt"
if ref_json="$(gh api "repos/${REPOSITORY}/git/ref/tags/${release_tag}" 2>"$ref_error")"; then
  test "$(jq -er '.object.type' <<<"$ref_json")" = "commit"
  test "$(jq -er '.object.sha' <<<"$ref_json")" = "$ACCEPTED_REVISION"
else
  if ! grep -qiE '404|Not Found' "$ref_error"; then
    cat "$ref_error" >&2
    exit 1
  fi
  gh api --method POST "repos/${REPOSITORY}/git/refs"     -f ref="refs/tags/${release_tag}"     -f sha="$ACCEPTED_REVISION" >/dev/null
fi

release_error="${stage}/release-error.txt"
if ! release_json="$(gh api "repos/${REPOSITORY}/releases/tags/${release_tag}" 2>"$release_error")"; then
  if ! grep -qiE '404|Not Found' "$release_error"; then
    cat "$release_error" >&2
    exit 1
  fi
  gh release create "$release_tag"     --repo "$REPOSITORY"     --verify-tag     --draft     --latest=false     --title "$release_title"     --notes-file "$notes"
  release_json="$(gh api "repos/${REPOSITORY}/releases/tags/${release_tag}")"
fi

test "$(jq -er '.tag_name' <<<"$release_json")" = "$release_tag"
test "$(jq -er '.prerelease' <<<"$release_json")" = "false"
draft="$(jq -er '.draft' <<<"$release_json")"

is_expected_asset() {
  local candidate="$1"
  local expected
  for expected in "${expected_assets[@]}"; do
    if [[ "$candidate" = "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

mapfile -t existing_assets < <(jq -r '.assets[].name' <<<"$release_json" | sort)
for asset in "${existing_assets[@]}"; do
  if ! is_expected_asset "$asset"; then
    echo "unexpected asset already exists in immutable release: $asset" >&2
    exit 1
  fi
  gh release download "$release_tag" --repo "$REPOSITORY" --pattern "$asset" --dir "$verify_dir"
  cmp --silent "${stage}/${asset}" "${verify_dir}/${asset}" || {
    echo "existing release asset bytes differ: $asset" >&2
    exit 1
  }
  rm -f "${verify_dir}/${asset}"
done

if [[ "$draft" = "false" ]]; then
  test "${#existing_assets[@]}" -eq "${#expected_assets[@]}"
else
  for asset in "${expected_assets[@]}"; do
    if ! printf '%s\n' "${existing_assets[@]}" | grep -Fxq "$asset"; then
      gh release upload "$release_tag" "${stage}/${asset}" --repo "$REPOSITORY"
    fi
  done

  release_json="$(gh api "repos/${REPOSITORY}/releases/tags/${release_tag}")"
  mapfile -t final_assets < <(jq -r '.assets[].name' <<<"$release_json" | sort)
  test "${#final_assets[@]}" -eq "${#expected_assets[@]}"
  for asset in "${final_assets[@]}"; do
    is_expected_asset "$asset"
    gh release download "$release_tag" --repo "$REPOSITORY" --pattern "$asset" --dir "$verify_dir"
    cmp --silent "${stage}/${asset}" "${verify_dir}/${asset}"
    rm -f "${verify_dir}/${asset}"
  done

  gh release edit "$release_tag" --repo "$REPOSITORY" --draft=false >/dev/null
fi

release_json="$(gh api "repos/${REPOSITORY}/releases/tags/${release_tag}")"
test "$(jq -er '.draft' <<<"$release_json")" = "false"
test "$(jq -er '.prerelease' <<<"$release_json")" = "false"
mapfile -t published_assets < <(jq -r '.assets[].name' <<<"$release_json" | sort)
test "${#published_assets[@]}" -eq "${#expected_assets[@]}"
for asset in "${published_assets[@]}"; do
  is_expected_asset "$asset"
done

ref_json="$(gh api "repos/${REPOSITORY}/git/ref/tags/${release_tag}")"
test "$(jq -er '.object.type' <<<"$ref_json")" = "commit"
test "$(jq -er '.object.sha' <<<"$ref_json")" = "$ACCEPTED_REVISION"

printf 'release_tag=%s\n' "$release_tag"
printf 'release_set_sha256=%s\n' "$release_set_sha"
printf 'durable_assets=%s\n' "${#published_assets[@]}"
