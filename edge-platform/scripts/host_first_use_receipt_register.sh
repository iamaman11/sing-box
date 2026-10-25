#!/usr/bin/env bash
# Only the existing protected host workflow may run this exact one-file PR.
# This file is *copied before checkout of the ORIGINAL accepted release*.
set -euo pipefail
test "${GITHUB_REPOSITORY}" = "iamaman11/sing-box"
test "${GITHUB_EVENT_NAME}" = "issue_comment"
test "${GITHUB_RUN_ATTEMPT}" = "1"
test "${ORIGINAL_BRANCH}" = "host-receipt-${TARGET_MACHINE}-${SOURCE_COMMENT_ID}"
test -n "${PUBLIC_ROOT_KEY_HEX}" && [[ "${PUBLIC_ROOT_KEY_HEX}" =~ ^[0-9a-f]{64}$ ]]
test -f "${EDGE_RELEASE_CONTEXT_PATH}"
# No new or alternate receipt owner; identical source as first-use finalizer.
set -euo pipefail
test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq '.object.sha')" = "${GITHUB_SHA}"
[[ "${SOURCE_COMMENT_ID}" =~ ^[1-9][0-9]*$ ]]
branch="${ORIGINAL_BRANCH}"
pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=iamaman11:${branch}" |
  jq -er --arg branch "${branch}" '[.[] | select(.head.ref == $branch and .base.ref == "main" and .head.repo.full_name == "iamaman11/sing-box" and .draft == true)] | if length == 1 then .[0].number else empty end')"
[[ "${pr}" =~ ^[1-9][0-9]*$ ]]
bin="${RUNNER_TEMP}/host-release/edge-orchestrator-linux-amd64"
fleet="${RUNNER_TEMP}/host-release/fleet-registry.pb"
candidate="${RUNNER_TEMP}/native-receipt-registration.pb"
"${bin}" host --hosts-pb "${fleet}" \
  --hosts-sha256 "$(sha256sum "${fleet}" | cut -d' ' -f1)" \
  register-receipt "${TARGET_MACHINE}" \
  --receipt-public-key-hex "${PUBLIC_ROOT_KEY_HEX}" \
  --output-path "${candidate}"
buf="${RUNNER_TEMP}/buf"
curl --fail --silent --show-error --location \
  "https://github.com/bufbuild/buf/releases/download/v1.73.0/buf-Linux-x86_64" -o "${buf}"
printf '%s  %s\n' '8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1' "${buf}" | sha256sum --check --status
chmod 0755 "${buf}"
target="${RUNNER_TEMP}/native-registered-hosts.textproto"
(cd edge-platform && "${buf}" convert proto/edge/platform/v1/fleet.proto \
  --type edge.platform.v1.FleetDesiredState \
  --from "${candidate}#format=binpb" --to "${target}#format=txtpb")
(cd edge-platform && "${buf}" convert proto/edge/platform/v1/fleet.proto \
  --type edge.platform.v1.FleetDesiredState \
  --from "${target}#format=txtpb" \
  --to "${RUNNER_TEMP}/registered-roundtrip.pb#format=binpb")
"${bin}" host --hosts-pb "${fleet}" \
  --hosts-sha256 "$(sha256sum "${fleet}" | cut -d' ' -f1)" \
  verify-receipt "${TARGET_MACHINE}" \
  --receipt-public-key-hex "${PUBLIC_ROOT_KEY_HEX}" \
  --candidate-path "${RUNNER_TEMP}/registered-roundtrip.pb"
sha="$(gh api "repos/${GITHUB_REPOSITORY}/contents/infra/hosts/hosts.textproto?ref=${branch}" --jq '.sha')"
gh api -X PUT "repos/${GITHUB_REPOSITORY}/contents/infra/hosts/hosts.textproto" \
  -f "branch=${branch}" -f "sha=${sha}" \
  -f "message=host: register native receipt for ${TARGET_MACHINE}" \
  -f "content=$(base64 -w0 < "${target}")" >/dev/null
gh api "repos/${GITHUB_REPOSITORY}/contents/infra/hosts/hosts.textproto?ref=${branch}" \
  --jq '.content' | base64 --decode | cmp -s - "${target}"
node="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr}" --jq '.node_id')"
test -n "${node}"
if ! gh api graphql -f 'query=mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{isDraft}}}' -f "id=${node}" |
    jq -e '(.errors == null) and (.data.markPullRequestReadyForReview.pullRequest.isDraft == false)' >/dev/null; then
  echo HOST_NATIVE_RECEIPT_DRAFT_REVIEW_REQUIRED
fi
echo "HOST_FIRST_USE=AWAITING_PROTECTED_PUBLIC_RECEIPT_MERGE"
echo "HOST_SIGNED_INSTALL=NOT_YET_AUTHORIZED"
