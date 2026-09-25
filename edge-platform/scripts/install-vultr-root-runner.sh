#!/usr/bin/env bash
set -euo pipefail

RUNNER_VERSION="2.337.0"
RUNNER_SHA256="70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"
RUNNER_ARCHIVE="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_ARCHIVE}"
RUNNER_REPOSITORY_URL="https://github.com/iamaman11/sing-box"
RUNNER_USER="github-runner"
RUNNER_HOME="/var/lib/github-runner"
RUNNER_DIR="/opt/actions-runner"

machine_id="${1:-}"
if [[ ! "${machine_id}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]]; then
  echo "invalid machine id" >&2
  exit 2
fi

IFS= read -r registration_token || true
if [[ -z "${registration_token}" || "${registration_token}" == *[[:space:]]* ]]; then
  echo "runner registration token is empty or malformed" >&2
  exit 3
fi

runner_name="sing-box-${machine_id}"
runner_labels="vultr-root,test-vm,${machine_id}"
diagnostic_log="/tmp/singbox-root-runner-bootstrap-diagnostic.log"
stage="prepare-user"
diagnostic_emitted=0

cleanup_diagnostic_log() {
  rm -f "${diagnostic_log}"
}

emit_diagnostic_failure() {
  local rc="$1"
  local output=""
  diagnostic_emitted=1
  if [[ -s "${diagnostic_log}" ]]; then
    output="$(tail -c 4096 "${diagnostic_log}" 2>/dev/null || true)"
    if [[ -n "${registration_token:-}" ]]; then
      output="${output//${registration_token}/[REDACTED]}"
    fi
  fi
  printf 'root runner bootstrap failed: stage=%s exit=%s\n' "${stage}" "${rc}" >&2
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}" >&2
  fi
}

run_logged() {
  stage="$1"
  shift
  diagnostic_emitted=0
  : > "${diagnostic_log}"
  chmod 0600 "${diagnostic_log}"
  if "$@" > "${diagnostic_log}" 2>&1; then
    : > "${diagnostic_log}"
    return 0
  else
    local rc=$?
    emit_diagnostic_failure "${rc}"
    return "${rc}"
  fi
}

trap cleanup_diagnostic_log EXIT
trap 'rc=$?; if [[ "${diagnostic_emitted}" != "1" ]]; then printf "root runner bootstrap failed: stage=%s exit=%s\n" "${stage}" "${rc}" >&2; fi' ERR

if ! id "${RUNNER_USER}" >/dev/null 2>&1; then
  useradd --create-home --home-dir "${RUNNER_HOME}" --shell /bin/bash "${RUNNER_USER}"
fi

stage="configure-sudo"
install -d -m 0755 /etc/sudoers.d
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${RUNNER_USER}" > /etc/sudoers.d/github-runner
chmod 0440 /etc/sudoers.d/github-runner
visudo -cf /etc/sudoers.d/github-runner >/dev/null

stage="prepare-runner-dir"
install -d -o "${RUNNER_USER}" -g "${RUNNER_USER}" -m 0755 "${RUNNER_DIR}"
archive="/tmp/${RUNNER_ARCHIVE}"
if [[ ! -f "${RUNNER_DIR}/config.sh" ]]; then
  run_logged download-runner curl --fail --location --silent --show-error --retry 3 --connect-timeout 10 --max-time 300 \
    "${RUNNER_URL}" --output "${archive}"
  stage="verify-runner-archive"
  if ! printf '%s  %s\n' "${RUNNER_SHA256}" "${archive}" | sha256sum -c -; then
    printf 'root runner bootstrap failed: stage=%s exit=1\n' "${stage}" >&2
    exit 1
  fi
  run_logged extract-runner tar -xzf "${archive}" -C "${RUNNER_DIR}"
  rm -f "${archive}"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_DIR}"
fi

cd "${RUNNER_DIR}"

if [[ ! -f .runner ]]; then
  run_logged configure-runner sudo -u "${RUNNER_USER}" ./config.sh \
    --unattended \
    --url "${RUNNER_REPOSITORY_URL}" \
    --token "${registration_token}" \
    --name "${runner_name}" \
    --labels "${runner_labels}" \
    --work "_work" \
    --replace
fi

unset registration_token

if [[ ! -f .service ]]; then
  run_logged install-service ./svc.sh install "${RUNNER_USER}"
fi
run_logged start-service ./svc.sh start
run_logged verify-service ./svc.sh status

stage="verify-runner-state"
test -f .runner
test -f .credentials
test "$(sudo -u "${RUNNER_USER}" sudo -n id -u)" = "0"
pgrep -u "${RUNNER_USER}" -f 'Runner.Listener' >/dev/null

echo "runner_name=${runner_name}"
echo "runner_user=${RUNNER_USER}"
echo "root_authority=PASS"
echo "service=PASS"
