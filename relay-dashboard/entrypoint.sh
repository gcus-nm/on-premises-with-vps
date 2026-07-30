#!/bin/sh

set -eu
umask 077

readonly SOURCE_ROOT="/run/relay-secrets"
readonly RUNTIME_HOME="/run/relay-home"
readonly SOURCE_RELAY_SCRIPT="/workspace/scripts/wg-relay.sh"
readonly RUNTIME_RELAY_SCRIPT="${RUNTIME_HOME}/wg-relay.sh"

install -d -m 0700 \
  "${RUNTIME_HOME}" \
  "${RUNTIME_HOME}/.oci" \
  "${RUNTIME_HOME}/.ssh"

for required_file in \
  "${SOURCE_ROOT}/oci/config" \
  "${SOURCE_ROOT}/oci/oci_api_key.pem" \
  "${SOURCE_ROOT}/ssh/config" \
  "${SOURCE_ROOT}/ssh/oci-relay" \
  "${SOURCE_ROOT}/ssh/known_hosts"; do
  if [ ! -f "${required_file}" ]; then
    printf 'relay-dashboard: required secret file is missing: %s\n' "${required_file}" >&2
    exit 1
  fi
done

if [ ! -f "${SOURCE_RELAY_SCRIPT}" ]; then
  printf 'relay-dashboard: relay script is missing: %s\n' "${SOURCE_RELAY_SCRIPT}" >&2
  exit 1
fi

install -m 0600 "${SOURCE_ROOT}/oci/config" "${RUNTIME_HOME}/.oci/config"
install -m 0600 "${SOURCE_ROOT}/oci/oci_api_key.pem" "${RUNTIME_HOME}/.oci/oci_api_key.pem"
install -m 0600 "${SOURCE_ROOT}/ssh/config" "${RUNTIME_HOME}/.ssh/config"
install -m 0600 "${SOURCE_ROOT}/ssh/oci-relay" "${RUNTIME_HOME}/.ssh/oci-relay"
install -m 0600 "${SOURCE_ROOT}/ssh/known_hosts" "${RUNTIME_HOME}/.ssh/known_hosts"
sed 's/\r$//' "${SOURCE_RELAY_SCRIPT}" >"${RUNTIME_RELAY_SCRIPT}"
chmod 0600 "${RUNTIME_RELAY_SCRIPT}"

export HOME="${RUNTIME_HOME}"
export RELAY_SCRIPT="${RUNTIME_RELAY_SCRIPT}"
exec python3 -m dashboard.server
