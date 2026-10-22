#!/usr/bin/env bash
# Compile one checked-out Git-owned FleetVmHostDesired for the native Rust owner.
# Shared by first-use, existing-host trust and deep VM capability observation.
# The .binpb is ephemeral derived input, never an alternative desired registry.
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ ]]; then
  echo "HOST_VM_TYPED_SPEC_NAME_INVALID" >&2
  exit 2
fi
machine="$1"
spec="infra/hosts/specs/${machine}.textproto"
compiled="infra/hosts/specs/${machine}.binpb"
if [[ ! -f "${spec}" || -L "${spec}" || -L infra/hosts/specs || -L infra/hosts ]]; then
  echo "HOST_VM_TYPED_SOURCE_UNREADABLE" >&2
  exit 2
fi
if [[ -e "${compiled}" || -L "${compiled}" ]]; then
  echo "HOST_VM_TYPED_DERIVED_ALREADY_PRESENT" >&2
  exit 2
fi
source_bytes="$(stat -c %s "${spec}")"
if (( source_bytes < 1 || source_bytes > 131072 )); then
  echo "HOST_VM_TYPED_SOURCE_INVALID_SIZE" >&2
  exit 2
fi

# One pinned compiler and one typed conversion for every VM entry path.
compiler="${RUNNER_TEMP:?}/host-vm-buf"
if [[ -L "${compiler}" ]]; then
  echo "HOST_VM_TYPED_COMPILER_INVALID" >&2
  exit 2
fi
if [[ ! -f "${compiler}" ]]; then
  curl --fail --silent --show-error --location \
    "https://github.com/bufbuild/buf/releases/download/v1.73.0/buf-Linux-x86_64" \
    --output "${compiler}"
fi
echo "8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1  ${compiler}" | sha256sum --check --status
chmod 0755 "${compiler}"
if [[ "$("${compiler}" --version)" != "1.73.0" ]]; then
  echo "HOST_VM_TYPED_COMPILER_VERSION_MISMATCH" >&2
  exit 2
fi
(cd edge-platform && "${compiler}" convert proto/edge/platform/v1/fleet.proto \
  --type edge.platform.v1.FleetVmHostDesired \
  --from "../${spec}#format=txtpb" \
  --to "../${compiled}#format=binpb")
if [[ ! -f "${compiled}" || -L "${compiled}" ]]; then
  echo "HOST_VM_TYPED_COMPILED_ABSENT" >&2
  exit 2
fi
compiled_bytes="$(stat -c %s "${compiled}")"
if (( compiled_bytes < 1 || compiled_bytes > 131072 )); then
  echo "HOST_VM_TYPED_COMPILED_INVALID_SIZE" >&2
  exit 2
fi
echo "host_vm_typed_desired=PINNED_PROTOBUF_PREPARED"
