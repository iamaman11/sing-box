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

if ! id "${RUNNER_USER}" >/dev/null 2>&1; then
  useradd --create-home --home-dir "${RUNNER_HOME}" --shell /bin/bash "${RUNNER_USER}"
fi

install -d -m 0755 /etc/sudoers.d
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${RUNNER_USER}" > /etc/sudoers.d/github-runner
chmod 0440 /etc/sudoers.d/github-runner
visudo -cf /etc/sudoers.d/github-runner >/dev/null

install -d -o "${RUNNER_USER}" -g "${RUNNER_USER}" -m 0755 "${RUNNER_DIR}"
archive="/tmp/${RUNNER_ARCHIVE}"
if [[ ! -f "${RUNNER_DIR}/config.sh" ]]; then
  curl --fail --location --silent --show-error --retry 3 --connect-timeout 10 --max-time 300 \
    "${RUNNER_URL}" --output "${archive}"
  printf '%s  %s\n' "${RUNNER_SHA256}" "${archive}" | sha256sum -c -
  tar -xzf "${archive}" -C "${RUNNER_DIR}"
  rm -f "${archive}"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_DIR}"
fi

cd "${RUNNER_DIR}"

if [[ ! -f .runner ]]; then
  sudo -u "${RUNNER_USER}" ./config.sh \
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
  ./svc.sh install "${RUNNER_USER}"
fi
./svc.sh start
./svc.sh status >/dev/null

test -f .runner
test -f .credentials
test "$(sudo -u "${RUNNER_USER}" sudo -n id -u)" = "0"
pgrep -u "${RUNNER_USER}" -f 'Runner.Listener' >/dev/null

echo "runner_name=${runner_name}"
echo "runner_user=${RUNNER_USER}"
echo "root_authority=PASS"
echo "service=PASS"
