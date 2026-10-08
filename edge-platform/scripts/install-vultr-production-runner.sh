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
LOCAL_OWNER="/usr/local/libexec/sing-box/edge-agent"
SUDOERS_FILE="/etc/sudoers.d/sing-box-runtime-owner"
CREDENTIAL_IDENTITY_DIR="/opt/vultr-edge-stack/runtime-secrets"
CREDENTIAL_IDENTITY_FILE="${CREDENTIAL_IDENTITY_DIR}/credential-access-v1.env"

machine_id="${1:-}"
if [[ ! "${machine_id}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]]; then
  echo "invalid machine id" >&2
  exit 2
fi

IFS= read -r registration_token || true
IFS= read -r credential_access_client_id || true
IFS= read -r credential_access_client_secret || true
if [[ -z "${registration_token}" || "${registration_token}" == *[[:space:]]* ]]; then
  echo "runner registration token is empty or malformed" >&2
  exit 3
fi
if [[ -z "${credential_access_client_id}" || "${credential_access_client_id}" == *[[:space:]]* ]]; then
  echo "credential Access client id is empty or malformed" >&2
  exit 3
fi
if [[ -z "${credential_access_client_secret}" || "${credential_access_client_secret}" == *[[:space:]]* ]]; then
  echo "credential Access client secret is empty or malformed" >&2
  exit 3
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "production runner bootstrap requires root" >&2
  exit 4
fi
if [[ ! -x "${LOCAL_OWNER}" ]]; then
  echo "exact local runtime owner is not installed" >&2
  exit 5
fi
if [[ "$(stat -c '%U:%G:%a' "${LOCAL_OWNER}")" != "root:root:755" ]]; then
  echo "local runtime owner must be root:root mode 0755" >&2
  exit 6
fi

if ! id "${RUNNER_USER}" >/dev/null 2>&1; then
  useradd --create-home --home-dir "${RUNNER_HOME}" --shell /bin/bash "${RUNNER_USER}"
fi
install -d -o "${RUNNER_USER}" -g "${RUNNER_USER}" -m 0750 "${RUNNER_HOME}"
install -d -o root -g root -m 0755 /etc/sudoers.d
install -d -o root -g root -m 0700 "${CREDENTIAL_IDENTITY_DIR}"
identity_stage="${CREDENTIAL_IDENTITY_FILE}.new"
umask 077
printf 'CF_ACCESS_CLIENT_ID=%s\nCF_ACCESS_CLIENT_SECRET=%s\n' \
  "${credential_access_client_id}" "${credential_access_client_secret}" > "${identity_stage}"
chown root:root "${identity_stage}"
chmod 0600 "${identity_stage}"
mv -f "${identity_stage}" "${CREDENTIAL_IDENTITY_FILE}"
unset credential_access_client_id credential_access_client_secret

cat > "${SUDOERS_FILE}" <<EOF
Cmnd_Alias SING_BOX_RUNTIME_READ = ${LOCAL_OWNER} local status, ${LOCAL_OWNER} local verify, ${LOCAL_OWNER} local diagnose, ${LOCAL_OWNER} local quality-line2, ${LOCAL_OWNER} local bundle-verify, ${LOCAL_OWNER} local mesh-verify, ${LOCAL_OWNER} local credential-state
Cmnd_Alias SING_BOX_RUNTIME_MUTATE = ${LOCAL_OWNER} local bootstrap-base, ${LOCAL_OWNER} local bootstrap-tunnel, ${LOCAL_OWNER} local bootstrap-full, ${LOCAL_OWNER} local bundle-converge, ${LOCAL_OWNER} local bundle-rollback, ${LOCAL_OWNER} local mesh-cleanup, ${LOCAL_OWNER} local credential-stage *, ${LOCAL_OWNER} local credential-transition *
${RUNNER_USER} ALL=(root) NOPASSWD: SING_BOX_RUNTIME_READ, SING_BOX_RUNTIME_MUTATE
EOF
chmod 0440 "${SUDOERS_FILE}"
visudo -cf "${SUDOERS_FILE}" >/dev/null

if sudo -u "${RUNNER_USER}" sudo -n id -u >/dev/null 2>&1; then
  echo "runner unexpectedly has generic root authority" >&2
  exit 7
fi
if getent group docker | cut -d: -f4 | tr ',' '\n' | grep -Fxq "${RUNNER_USER}"; then
  echo "runner must not be a member of docker group" >&2
  exit 8
fi
if sudo -u "${RUNNER_USER}" test -r /var/run/docker.sock 2>/dev/null; then
  echo "runner must not have direct Docker socket authority" >&2
  exit 9
fi
sudo -u "${RUNNER_USER}" sudo -n "${LOCAL_OWNER}" local status >/dev/null

if systemctl cat edge-agent.service >/dev/null 2>&1; then
  systemctl disable --now edge-agent.service >/dev/null
fi
if ss -ltnH 'sport = :50061' 2>/dev/null | grep -q .; then
  echo "production enrollment must leave no edge-agent RPC listener on :50061" >&2
  exit 10
fi

archive="/tmp/${RUNNER_ARCHIVE}"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https'   --output "${archive}" "${RUNNER_URL}"
echo "${RUNNER_SHA256}  ${archive}" | sha256sum --check --status

if [[ ! -d "${RUNNER_DIR}" ]]; then
  install -d -o "${RUNNER_USER}" -g "${RUNNER_USER}" -m 0755 "${RUNNER_DIR}"
  tar -xzf "${archive}" -C "${RUNNER_DIR}"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_DIR}"
fi
rm -f "${archive}"

cd "${RUNNER_DIR}"
./bin/installdependencies.sh >/dev/null

runner_name="sing-box-production-${machine_id}"
runner_labels="sing-box-production-vm,${machine_id}"
if [[ ! -f .runner ]]; then
  sudo -u "${RUNNER_USER}" ./config.sh     --unattended     --url "${RUNNER_REPOSITORY_URL}"     --token "${registration_token}"     --name "${runner_name}"     --labels "${runner_labels}"     --work "_work"     --replace >/dev/null
fi
unset registration_token

if [[ ! -f .service ]]; then
  ./svc.sh install "${RUNNER_USER}" >/dev/null
fi
./svc.sh start >/dev/null
./svc.sh status >/dev/null

echo "runner_name=${runner_name}"
echo "runner_user=${RUNNER_USER}"
echo "generic_root_authority=false"
echo "bounded_runtime_dispatch=true"
echo "docker_socket_authority=false"
echo "acceptance_rpc_service_enabled=false"
echo "tcp_50061_listener=false"
echo "local_owner=${LOCAL_OWNER}"
echo "registration_token_persisted=false"
echo "credential_access_identity_installed=true"
echo "runner_credential_access=false"
