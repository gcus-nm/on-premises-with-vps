#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
readonly PROJECT_DIR="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REMOTE_SCRIPT="${SCRIPT_DIR}/wg-relay-remote.sh"
readonly REMOTE_PATH="/usr/local/sbin/wg-relay"
readonly SSH_HOST="${WG_RELAY_SSH_HOST:-oci-relay}"
readonly GENERATED_DIR="${PROJECT_DIR}/generated/wireguard"

log() {
  printf 'wg-relay: %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  ./scripts/wg-relay.sh install
  ./scripts/wg-relay.sh init [--server-address CIDR] [--listen-port PORT] [--endpoint HOST:PORT]
  ./scripts/wg-relay.sh add NAME --address IPV4/32 [--output FILE]
  ./scripts/wg-relay.sh update NAME --address IPV4/32 [--output FILE]
  ./scripts/wg-relay.sh delete NAME [--yes]
  ./scripts/wg-relay.sh list
  ./scripts/wg-relay.sh status
  ./scripts/wg-relay.sh public-key
  ./scripts/wg-relay.sh forward add NAME --protocol tcp|udp --listen-port PORT --target-address IPV4 --target-port PORT
  ./scripts/wg-relay.sh forward update NAME --protocol tcp|udp --listen-port PORT --target-address IPV4 --target-port PORT
  ./scripts/wg-relay.sh forward delete NAME [--yes]
  ./scripts/wg-relay.sh forward list
  ./scripts/wg-relay.sh forward status

Environment:
  WG_RELAY_SSH_HOST  SSH config host used for the relay (default: oci-relay)
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

remote_command() {
  ssh "${SSH_HOST}" sudo "${REMOTE_PATH}" "$@"
}

install_remote() {
  local remote_temporary
  require_command scp
  [ -f "${REMOTE_SCRIPT}" ] || die "remote manager script not found: ${REMOTE_SCRIPT}"

  remote_temporary="$(ssh "${SSH_HOST}" mktemp /tmp/wg-relay.XXXXXX)"
  case "${remote_temporary}" in
    /tmp/wg-relay.*) ;;
    *) die "unexpected remote temporary path: ${remote_temporary}" ;;
  esac

  if ! scp -q "${REMOTE_SCRIPT}" "${SSH_HOST}:${remote_temporary}"; then
    ssh "${SSH_HOST}" rm -f "${remote_temporary}" || true
    die "failed to upload remote manager"
  fi

  ssh "${SSH_HOST}" sudo install -o root -g root -m 0755 "${remote_temporary}" "${REMOTE_PATH}"
  ssh "${SSH_HOST}" rm -f "${remote_temporary}"
  log "installed ${REMOTE_PATH} on ${SSH_HOST}"
}

terraform_endpoint() {
  local endpoint
  endpoint="$(cd "${PROJECT_DIR}" && terraform output -raw wireguard_endpoint_ipv4 2>/dev/null)" ||
    die "could not read wireguard_endpoint_ipv4; pass --endpoint explicitly"
  printf '%s\n' "${endpoint}"
}

init_remote() {
  local server_address="10.99.0.1/24"
  local listen_port="51820"
  local endpoint=""

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --server-address)
        [ "$#" -ge 2 ] || die "--server-address requires a value"
        server_address="$2"
        shift 2
        ;;
      --listen-port)
        [ "$#" -ge 2 ] || die "--listen-port requires a value"
        listen_port="$2"
        shift 2
        ;;
      --endpoint)
        [ "$#" -ge 2 ] || die "--endpoint requires a value"
        endpoint="$2"
        shift 2
        ;;
      *) die "unknown init option: $1" ;;
    esac
  done

  if [ -z "${endpoint}" ]; then
    endpoint="$(terraform_endpoint)"
  fi
  remote_command init \
    --server-address "${server_address}" \
    --listen-port "${listen_port}" \
    --endpoint "${endpoint}"
}

generate_client_config() {
  local operation="$1"
  shift
  local name="${1:-}"
  shift || true
  local address=""
  local output=""
  local output_directory
  local temporary_output

  [ -n "${name}" ] || die "${operation} requires NAME"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --address)
        [ "$#" -ge 2 ] || die "--address requires a value"
        address="$2"
        shift 2
        ;;
      --output)
        [ "$#" -ge 2 ] || die "--output requires a value"
        output="$2"
        shift 2
        ;;
      *) die "unknown ${operation} option: $1" ;;
    esac
  done

  [ -n "${address}" ] || die "${operation} requires --address IPV4/32"
  if [ -z "${output}" ]; then
    output="${GENERATED_DIR}/${name}.conf"
  fi

  output_directory="$(dirname -- "${output}")"
  if [ ! -d "${output_directory}" ]; then
    mkdir -p "${output_directory}"
    chmod 0700 "${output_directory}"
  fi
  temporary_output="${output}.tmp.$$"
  rm -f "${temporary_output}"

  if remote_command "${operation}" "${name}" --address "${address}" >"${temporary_output}"; then
    if chmod 0600 "${temporary_output}" && mv -f "${temporary_output}" "${output}"; then
      log "saved Windows client configuration to ${output}"
    else
      rm -f "${temporary_output}"
      die "peer was changed, but the client configuration could not be saved; run update to rotate it again"
    fi
  else
    rm -f "${temporary_output}"
    die "failed to ${operation} peer ${name}"
  fi
}

delete_remote_peer() {
  local name="${1:-}"
  local confirmed="${2:-}"
  local reply

  [ -n "${name}" ] || die "delete requires NAME"
  if [ "${confirmed}" != "--yes" ]; then
    [ -t 0 ] || die "non-interactive deletion requires --yes"
    printf 'Delete WireGuard peer %s? [y/N] ' "${name}" >&2
    read -r reply
    case "${reply}" in
      y | Y | yes | YES) ;;
      *) log "deletion cancelled"; exit 0 ;;
    esac
  fi
  remote_command delete "${name}"
}

forward_remote() {
  local operation="${1:-}"
  shift || true
  local name confirmed reply

  case "${operation}" in
    add | update)
      [ "$#" -ge 1 ] || die "forward ${operation} requires NAME"
      remote_command forward "${operation}" "$@"
      ;;
    delete)
      name="${1:-}"
      confirmed="${2:-}"
      [ -n "${name}" ] || die "forward delete requires NAME"
      [ "$#" -le 2 ] || die "usage: ./scripts/wg-relay.sh forward delete NAME [--yes]"
      if [ "${confirmed}" != "--yes" ]; then
        [ -t 0 ] || die "non-interactive deletion requires --yes"
        printf 'Delete port forward %s? [y/N] ' "${name}" >&2
        read -r reply
        case "${reply}" in
          y | Y | yes | YES) ;;
          *) log "deletion cancelled"; exit 0 ;;
        esac
      fi
      remote_command forward delete "${name}"
      ;;
    list | status)
      [ "$#" -eq 0 ] || die "forward ${operation} does not accept arguments"
      remote_command forward "${operation}"
      ;;
    *) die "usage: ./scripts/wg-relay.sh forward add|update|delete|list|status ..." ;;
  esac
}

main() {
  local command_name="${1:-help}"
  shift || true
  require_command ssh

  case "${command_name}" in
    help | --help | -h)
      usage
      ;;
    install)
      [ "$#" -eq 0 ] || die "usage: ./scripts/wg-relay.sh install"
      install_remote
      ;;
    init)
      init_remote "$@"
      ;;
    add | update)
      generate_client_config "${command_name}" "$@"
      ;;
    delete)
      [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "usage: ./scripts/wg-relay.sh delete NAME [--yes]"
      delete_remote_peer "$@"
      ;;
    list | status | public-key)
      [ "$#" -eq 0 ] || die "${command_name} does not accept arguments"
      remote_command "${command_name}"
      ;;
    forward)
      forward_remote "$@"
      ;;
    *)
      usage >&2
      die "unknown command: ${command_name}"
      ;;
  esac
}

main "$@"
