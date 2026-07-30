#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
readonly PROJECT_DIR="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REMOTE_SCRIPT="${SCRIPT_DIR}/mydns-notify-remote.py"
readonly SERVICE_FILE="${PROJECT_DIR}/systemd/mydns-notify.service"
readonly TIMER_FILE="${PROJECT_DIR}/systemd/mydns-notify.timer"
readonly REMOTE_PATH="/usr/local/sbin/mydns-notify"
readonly SSH_HOST="${MYDNS_NOTIFY_SSH_HOST:-oci-relay}"
SSH_CONFIG="${MYDNS_NOTIFY_SSH_CONFIG:-}"
if [ -z "${SSH_CONFIG}" ] && [ -n "${HOME:-}" ] && [ -f "${HOME}/.ssh/config" ]; then
  SSH_CONFIG="${HOME}/.ssh/config"
fi
readonly SSH_CONFIG

log() {
  printf 'mydns-notify: %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  ./scripts/mydns-notify.sh install
  ./scripts/mydns-notify.sh configure HOSTNAME
  ./scripts/mydns-notify.sh notify
  ./scripts/mydns-notify.sh status
  ./scripts/mydns-notify.sh logs

Environment:
  MYDNS_NOTIFY_SSH_HOST    SSH config host used for the relay (default: oci-relay)
  MYDNS_NOTIFY_SSH_CONFIG SSH config path (default: $HOME/.ssh/config when present)

configure prompts for the MyDNS.JP Child ID and password over the SSH terminal.
The credentials are not passed as command-line arguments or stored locally.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

relay_ssh() {
  if [ -n "${SSH_CONFIG}" ]; then
    ssh -F "${SSH_CONFIG}" "${SSH_HOST}" "$@"
  else
    ssh "${SSH_HOST}" "$@"
  fi
}

relay_ssh_tty() {
  if [ -n "${SSH_CONFIG}" ]; then
    ssh -F "${SSH_CONFIG}" -t "${SSH_HOST}" "$@"
  else
    ssh -t "${SSH_HOST}" "$@"
  fi
}

relay_scp() {
  local source="$1"
  local remote_path="$2"
  if [ -n "${SSH_CONFIG}" ]; then
    scp -F "${SSH_CONFIG}" -q "${source}" "${SSH_HOST}:${remote_path}"
  else
    scp -q "${source}" "${SSH_HOST}:${remote_path}"
  fi
}

remote_command() {
  relay_ssh sudo "${REMOTE_PATH}" "$@"
}

install_remote() {
  local remote_directory
  local local_file
  local remote_file

  require_command scp
  for local_file in "${REMOTE_SCRIPT}" "${SERVICE_FILE}" "${TIMER_FILE}"; do
    [ -f "${local_file}" ] || die "required installation file not found: ${local_file}"
  done

  remote_directory="$(relay_ssh mktemp -d /tmp/mydns-notify.XXXXXX)"
  case "${remote_directory}" in
    /tmp/mydns-notify.*) ;;
    *) die "unexpected remote temporary directory: ${remote_directory}" ;;
  esac

  for local_file in "${REMOTE_SCRIPT}" "${SERVICE_FILE}" "${TIMER_FILE}"; do
    remote_file="${remote_directory}/$(basename -- "${local_file}")"
    if ! relay_scp "${local_file}" "${remote_file}"; then
      relay_ssh rm -f "${remote_directory}/mydns-notify-remote.py" \
        "${remote_directory}/mydns-notify.service" \
        "${remote_directory}/mydns-notify.timer" || true
      relay_ssh rmdir "${remote_directory}" || true
      die "failed to upload $(basename -- "${local_file}")"
    fi
  done

  relay_ssh sudo install -o root -g root -m 0755 \
    "${remote_directory}/mydns-notify-remote.py" "${REMOTE_PATH}"
  relay_ssh sudo install -o root -g root -m 0644 \
    "${remote_directory}/mydns-notify.service" /etc/systemd/system/mydns-notify.service
  relay_ssh sudo install -o root -g root -m 0644 \
    "${remote_directory}/mydns-notify.timer" /etc/systemd/system/mydns-notify.timer
  relay_ssh sudo systemctl daemon-reload

  relay_ssh rm -f "${remote_directory}/mydns-notify-remote.py" \
    "${remote_directory}/mydns-notify.service" \
    "${remote_directory}/mydns-notify.timer"
  relay_ssh rmdir "${remote_directory}"
  log "installed MyDNS.JP notifier on ${SSH_HOST}; the timer remains unchanged"
}

validate_hostname() {
  local hostname="$1"
  [[ "${hostname}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] ||
    die "HOSTNAME must be a fully qualified DNS name"
  [[ "${hostname}" == *.* ]] || die "HOSTNAME must contain at least one dot"
}

configure_remote() {
  local hostname="${1:-}"
  [ "$#" -eq 1 ] || die "usage: ./scripts/mydns-notify.sh configure HOSTNAME"
  validate_hostname "${hostname}"
  [ -t 0 ] || die "configure requires an interactive terminal"

  relay_ssh_tty sudo "${REMOTE_PATH}" configure --hostname "${hostname}"
  remote_command notify
  relay_ssh sudo systemctl enable --now mydns-notify.timer
  log "enabled the daily MyDNS.JP notification timer"
}

show_status() {
  remote_command show
  relay_ssh sudo systemctl show mydns-notify.timer \
    --property=LoadState \
    --property=ActiveState \
    --property=UnitFileState \
    --property=LastTriggerUSec \
    --property=NextElapseUSecRealtime \
    --no-pager
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
      [ "$#" -eq 0 ] || die "usage: ./scripts/mydns-notify.sh install"
      install_remote
      ;;
    configure)
      configure_remote "$@"
      ;;
    notify)
      [ "$#" -eq 0 ] || die "usage: ./scripts/mydns-notify.sh notify"
      remote_command notify
      ;;
    status)
      [ "$#" -eq 0 ] || die "usage: ./scripts/mydns-notify.sh status"
      show_status
      ;;
    logs)
      [ "$#" -eq 0 ] || die "usage: ./scripts/mydns-notify.sh logs"
      relay_ssh sudo journalctl -u mydns-notify.service --no-pager -n 100
      ;;
    *)
      usage >&2
      die "unknown command: ${command_name}"
      ;;
  esac
}

main "$@"
