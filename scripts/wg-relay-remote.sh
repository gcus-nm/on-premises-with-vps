#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly WG_DIR="/etc/wireguard"
readonly STATE_DIR="${WG_DIR}/relay.d"
readonly PEER_DIR="${STATE_DIR}/peers"
readonly FORWARD_DIR="${STATE_DIR}/forwards"
readonly PEER_FORWARD_DIR="${STATE_DIR}/peer-forwards"
readonly SETTINGS_FILE="${STATE_DIR}/settings"
readonly PRIVATE_KEY_FILE="${WG_DIR}/private.key"
readonly PUBLIC_KEY_FILE="${WG_DIR}/public.key"
readonly WG_CONFIG="${WG_DIR}/wg0.conf"
readonly LOCK_FILE="/run/lock/wg-relay.lock"
readonly MANAGED_MARKER="# Managed by wg-relay. Do not edit directly."
readonly FIREWALL_COMMENT="wg-relay-listen"
readonly FORWARD_FILTER_CHAIN="WG_RELAY_FORWARD"
readonly FORWARD_PREROUTING_CHAIN="WG_RELAY_PREROUTING"
readonly FORWARD_POSTROUTING_CHAIN="WG_RELAY_POSTROUTING"

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
  wg-relay init --server-address CIDR --listen-port PORT --endpoint HOST:PORT
  wg-relay add NAME --address IPV4/32
  wg-relay update NAME --address IPV4/32
  wg-relay delete NAME
  wg-relay list
  wg-relay status
  wg-relay public-key
  wg-relay forward add NAME --protocol tcp|udp --listen-port PORT --target-address IPV4 --target-port PORT
  wg-relay forward update NAME --protocol tcp|udp --listen-port PORT --target-address IPV4 --target-port PORT
  wg-relay forward delete NAME
  wg-relay forward list
  wg-relay forward status
  wg-relay peer-forward add NAME --protocol tcp|udp --source-address IPV4 --target-address IPV4 --target-port PORT
  wg-relay peer-forward update NAME --protocol tcp|udp --source-address IPV4 --target-address IPV4 --target-port PORT
  wg-relay peer-forward delete NAME
  wg-relay peer-forward list
  wg-relay peer-forward status

add and update print an importable WireGuard client configuration to stdout.
All status messages are written to stderr.
EOF
}

require_root() {
  [ "${EUID}" -eq 0 ] || die "run this command through sudo"
}

require_commands() {
  local command_name
  for command_name in flock ip iptables mktemp python3 systemctl wg wg-quick; do
    command -v "${command_name}" >/dev/null 2>&1 || die "required command not found: ${command_name}"
  done
}

validate_name() {
  local name="$1"
  [[ "${name}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$ ]] ||
    die "NAME must contain 1-32 letters, numbers, underscores, or hyphens"
}

validate_server_address() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_interface(sys.argv[1])
except ValueError as exc:
    raise SystemExit(str(exc))

if address.version != 4 or address.network.prefixlen > 30:
    raise SystemExit("server address must be an IPv4 interface with a prefix length from 0 through 30")
PY
}

validate_client_address() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_interface(sys.argv[1])
except ValueError as exc:
    raise SystemExit(str(exc))

if address.version != 4 or address.network.prefixlen != 32:
    raise SystemExit("client address must be an IPv4 /32 interface")
PY
}

validate_client_in_server_network() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

server = ipaddress.ip_interface(sys.argv[1])
client = ipaddress.ip_interface(sys.argv[2])
if client.ip == server.ip:
    raise SystemExit("client address must differ from the server address")
if client.ip not in server.network:
    raise SystemExit(f"client address must be inside {server.network}")
PY
}

validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] || die "port must be an integer"
  [ "${port}" -ge 1 ] && [ "${port}" -le 65535 ] || die "port must be between 1 and 65535"
}

validate_protocol() {
  case "$1" in
    tcp | udp) ;;
    *) die "protocol must be tcp or udp" ;;
  esac
}

validate_target_address() {
  python3 - "$1" "$(read_setting SERVER_ADDRESS)" <<'PY'
import ipaddress
import sys

try:
    target = ipaddress.ip_address(sys.argv[1])
    server = ipaddress.ip_interface(sys.argv[2])
except ValueError as exc:
    raise SystemExit(str(exc))

if target.version != 4:
    raise SystemExit("target address must be an IPv4 address")
if target == server.ip:
    raise SystemExit("target address must differ from the relay address")
if target not in server.network:
    raise SystemExit(f"target address must be inside {server.network}")
PY
}

validate_endpoint() {
  python3 - "$1" <<'PY'
import re
import sys

endpoint = sys.argv[1]
if any(char.isspace() for char in endpoint):
    raise SystemExit("endpoint must not contain whitespace")

match = re.fullmatch(r"(?:\[[^\]]+\]|[^:]+):([0-9]+)", endpoint)
if not match:
    raise SystemExit("endpoint must be HOST:PORT or [IPV6]:PORT")

port = int(match.group(1))
if not 1 <= port <= 65535:
    raise SystemExit("endpoint port must be between 1 and 65535")
PY
}

read_setting() {
  local key="$1"
  awk -F= -v key="${key}" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "${SETTINGS_FILE}"
}

ensure_initialized() {
  [ -f "${SETTINGS_FILE}" ] || die "relay is not initialized; run init first"
  [ -s "${PRIVATE_KEY_FILE}" ] || die "server private key is missing"
  [ -s "${PUBLIC_KEY_FILE}" ] || die "server public key is missing"
}

ensure_server_keys() {
  local derived_public_key

  install -d -m 0700 "${WG_DIR}"
  if [ ! -s "${PRIVATE_KEY_FILE}" ]; then
    wg genkey >"${PRIVATE_KEY_FILE}"
  fi
  chmod 0600 "${PRIVATE_KEY_FILE}"

  derived_public_key="$(wg pubkey <"${PRIVATE_KEY_FILE}")"
  if [ -s "${PUBLIC_KEY_FILE}" ] && [ "$(tr -d '\r\n' <"${PUBLIC_KEY_FILE}")" != "${derived_public_key}" ]; then
    die "public.key does not match private.key"
  fi
  printf '%s\n' "${derived_public_key}" >"${PUBLIC_KEY_FILE}"
  chmod 0644 "${PUBLIC_KEY_FILE}"
}

render_config() {
  local server_address listen_port private_key peer_file temporary_file
  server_address="$(read_setting SERVER_ADDRESS)"
  listen_port="$(read_setting LISTEN_PORT)"
  private_key="$(tr -d '\r\n' <"${PRIVATE_KEY_FILE}")"
  temporary_file="$(mktemp --suffix=.conf "${WG_DIR}/wg0tmpXXXXXX")"

  {
    printf '%s\n' "${MANAGED_MARKER}"
    printf '[Interface]\n'
    printf 'Address = %s\n' "${server_address}"
    printf 'ListenPort = %s\n' "${listen_port}"
    printf 'PrivateKey = %s\n' "${private_key}"
    printf 'PostUp = %s firewall-sync\n' "$0"
    printf 'PostDown = %s firewall-clear\n' "$0"

    for peer_file in "${PEER_DIR}"/*.conf; do
      [ -f "${peer_file}" ] || continue
      printf '\n'
      cat "${peer_file}"
    done
  } >"${temporary_file}"

  chmod 0600 "${temporary_file}"
  if ! wg-quick strip "${temporary_file}" >/dev/null; then
    rm -f "${temporary_file}"
    log "generated WireGuard configuration is invalid"
    return 1
  fi
  install -o root -g root -m 0600 "${temporary_file}" "${WG_CONFIG}"
  rm -f "${temporary_file}"
}

ensure_firewall_rule() {
  local listen_port
  listen_port="$(read_setting LISTEN_PORT)"

  if ! iptables -C INPUT -p udp --dport "${listen_port}" -m comment --comment "${FIREWALL_COMMENT}" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p udp --dport "${listen_port}" -m comment --comment "${FIREWALL_COMMENT}" -j ACCEPT
  fi
}

public_interface() {
  local interface_name
  interface_name="$(ip -4 route get 1.1.1.1 | awk '{ for (field = 1; field <= NF; field++) if ($field == "dev") { print $(field + 1); exit } }')"
  [ -n "${interface_name}" ] || die "could not determine the public IPv4 interface"
  printf '%s\n' "${interface_name}"
}

read_forward_setting() {
  local key="$1"
  local file="$2"
  awk -F= -v key="${key}" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "${file}"
}

ensure_chain() {
  local table="$1"
  local chain="$2"
  iptables -w -t "${table}" -N "${chain}" 2>/dev/null || true
  iptables -w -t "${table}" -F "${chain}"
}

ensure_jump() {
  local table="$1"
  local source_chain="$2"
  local target_chain="$3"
  if ! iptables -w -t "${table}" -C "${source_chain}" -j "${target_chain}" 2>/dev/null; then
    iptables -w -t "${table}" -I "${source_chain}" 1 -j "${target_chain}"
  fi
}

remove_jump() {
  local table="$1"
  local source_chain="$2"
  local target_chain="$3"
  while iptables -w -t "${table}" -C "${source_chain}" -j "${target_chain}" 2>/dev/null; do
    iptables -w -t "${table}" -D "${source_chain}" -j "${target_chain}"
  done
}

remove_chain() {
  local table="$1"
  local chain="$2"
  if iptables -w -t "${table}" -S "${chain}" >/dev/null 2>&1; then
    iptables -w -t "${table}" -F "${chain}"
    iptables -w -t "${table}" -X "${chain}"
  fi
}

firewall_sync() {
  local listen_port server_address relay_address interface_name forward_file peer_forward_file
  local protocol public_port source_address target_address target_port peer_forward_name

  ensure_initialized
  listen_port="$(read_setting LISTEN_PORT)"
  server_address="$(read_setting SERVER_ADDRESS)"
  relay_address="${server_address%/*}"
  interface_name="$(public_interface)"

  ensure_firewall_rule
  ensure_chain filter "${FORWARD_FILTER_CHAIN}"
  ensure_chain nat "${FORWARD_PREROUTING_CHAIN}"
  ensure_chain nat "${FORWARD_POSTROUTING_CHAIN}"
  ensure_jump filter FORWARD "${FORWARD_FILTER_CHAIN}"
  ensure_jump nat PREROUTING "${FORWARD_PREROUTING_CHAIN}"
  ensure_jump nat POSTROUTING "${FORWARD_POSTROUTING_CHAIN}"

  iptables -w -t filter -A "${FORWARD_FILTER_CHAIN}" \
    -i wg0 -o "${interface_name}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  for forward_file in "${FORWARD_DIR}"/*.conf; do
    [ -f "${forward_file}" ] || continue
    protocol="$(read_forward_setting PROTOCOL "${forward_file}")"
    public_port="$(read_forward_setting LISTEN_PORT "${forward_file}")"
    target_address="$(read_forward_setting TARGET_ADDRESS "${forward_file}")"
    target_port="$(read_forward_setting TARGET_PORT "${forward_file}")"

    iptables -w -t nat -A "${FORWARD_PREROUTING_CHAIN}" \
      -i "${interface_name}" -p "${protocol}" --dport "${public_port}" \
      -j DNAT --to-destination "${target_address}:${target_port}"
    iptables -w -t filter -A "${FORWARD_FILTER_CHAIN}" \
      -i "${interface_name}" -o wg0 -p "${protocol}" -d "${target_address}" --dport "${target_port}" \
      -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -w -t nat -A "${FORWARD_POSTROUTING_CHAIN}" \
      -o wg0 -p "${protocol}" -d "${target_address}" --dport "${target_port}" \
      -j SNAT --to-source "${relay_address}"
  done

  for peer_forward_file in "${PEER_FORWARD_DIR}"/*.conf; do
    [ -f "${peer_forward_file}" ] || continue
    peer_forward_name="$(basename "${peer_forward_file}" .conf)"
    protocol="$(read_forward_setting PROTOCOL "${peer_forward_file}")"
    source_address="$(read_forward_setting SOURCE_ADDRESS "${peer_forward_file}")"
    target_address="$(read_forward_setting TARGET_ADDRESS "${peer_forward_file}")"
    target_port="$(read_forward_setting TARGET_PORT "${peer_forward_file}")"

    iptables -w -t filter -A "${FORWARD_FILTER_CHAIN}" \
      -i wg0 -o wg0 -p "${protocol}" -s "${source_address}" -d "${target_address}" --dport "${target_port}" \
      -m conntrack --ctstate NEW,ESTABLISHED \
      -m comment --comment "peer-forward:${peer_forward_name}" -j ACCEPT
    iptables -w -t filter -A "${FORWARD_FILTER_CHAIN}" \
      -i wg0 -o wg0 -p "${protocol}" -s "${target_address}" -d "${source_address}" \
      -m conntrack --ctstate RELATED,ESTABLISHED \
      -m comment --comment "peer-forward:${peer_forward_name}:return" -j ACCEPT
  done

  iptables -w -t filter -A "${FORWARD_FILTER_CHAIN}" -j RETURN
  iptables -w -t nat -A "${FORWARD_PREROUTING_CHAIN}" -j RETURN
  iptables -w -t nat -A "${FORWARD_POSTROUTING_CHAIN}" -j RETURN
}

firewall_clear() {
  local listen_port=""

  if [ -f "${SETTINGS_FILE}" ]; then
    listen_port="$(read_setting LISTEN_PORT)"
  fi
  if [ -n "${listen_port}" ]; then
    while iptables -w -C INPUT -p udp --dport "${listen_port}" -m comment --comment "${FIREWALL_COMMENT}" -j ACCEPT 2>/dev/null; do
      iptables -w -D INPUT -p udp --dport "${listen_port}" -m comment --comment "${FIREWALL_COMMENT}" -j ACCEPT
    done
  fi

  remove_jump filter FORWARD "${FORWARD_FILTER_CHAIN}"
  remove_jump nat PREROUTING "${FORWARD_PREROUTING_CHAIN}"
  remove_jump nat POSTROUTING "${FORWARD_POSTROUTING_CHAIN}"
  remove_chain filter "${FORWARD_FILTER_CHAIN}"
  remove_chain nat "${FORWARD_PREROUTING_CHAIN}"
  remove_chain nat "${FORWARD_POSTROUTING_CHAIN}"
}

sync_interface() {
  if systemctl is-active --quiet wg-quick@wg0; then
    wg syncconf wg0 <(wg-quick strip "${WG_CONFIG}")
  else
    systemctl enable --now wg-quick@wg0 >&2
  fi
  firewall_sync
}

check_address_available() {
  local address="$1"
  local excluded_name="${2:-}"
  local peer_file existing_address existing_name

  for peer_file in "${PEER_DIR}"/*.conf; do
    [ -f "${peer_file}" ] || continue
    existing_name="$(basename "${peer_file}" .conf)"
    [ "${existing_name}" = "${excluded_name}" ] && continue
    existing_address="$(awk -F'= ' '/^AllowedIPs = / { print $2; exit }' "${peer_file}")"
    [ "${existing_address}" != "${address}" ] || die "address is already assigned to peer ${existing_name}"
  done
}

client_allowed_ips() {
  local server_address
  server_address="$(read_setting SERVER_ADDRESS)"
  python3 - "${server_address}" <<'PY'
import ipaddress
import sys

print(ipaddress.ip_interface(sys.argv[1]).network)
PY
}

write_client_config() {
  local client_private_key="$1"
  local client_address="$2"
  local endpoint server_public_key
  endpoint="$(read_setting PUBLIC_ENDPOINT)"
  server_public_key="$(tr -d '\r\n' <"${PUBLIC_KEY_FILE}")"

  cat <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_address}

[Peer]
PublicKey = ${server_public_key}
Endpoint = ${endpoint}
AllowedIPs = $(client_allowed_ips)
PersistentKeepalive = 25
EOF
}

apply_peer() {
  local mode="$1"
  local name="$2"
  local address="$3"
  local peer_file client_private_key client_public_key temporary_peer backup_peer action_label existing_peer_address

  ensure_initialized
  validate_name "${name}"
  validate_client_address "${address}"
  validate_client_in_server_network "$(read_setting SERVER_ADDRESS)" "${address}"
  check_address_available "${address}" "${name}"

  peer_file="${PEER_DIR}/${name}.conf"
  if [ "${mode}" = "add" ] && [ -e "${peer_file}" ]; then
    die "peer already exists: ${name}"
  fi
  if [ "${mode}" = "update" ] && [ ! -e "${peer_file}" ]; then
    die "peer does not exist: ${name}"
  fi
  if [ "${mode}" = "update" ]; then
    existing_peer_address="$(awk -F'= ' '/^AllowedIPs = / { print $2; exit }' "${peer_file}")"
    if [ "${existing_peer_address}" != "${address}" ]; then
      ensure_peer_address_not_referenced "${existing_peer_address}"
    fi
  fi

  client_private_key="$(wg genkey)"
  client_public_key="$(printf '%s' "${client_private_key}" | wg pubkey)"
  temporary_peer="$(mktemp "${PEER_DIR}/.${name}.XXXXXX")"
  backup_peer=""

  {
    printf '# Managed peer: %s\n' "${name}"
    printf '[Peer]\n'
    printf 'PublicKey = %s\n' "${client_public_key}"
    printf 'AllowedIPs = %s\n' "${address}"
  } >"${temporary_peer}"

  if [ -e "${peer_file}" ]; then
    backup_peer="$(mktemp "${PEER_DIR}/.${name}.backup.XXXXXX")"
    cp "${peer_file}" "${backup_peer}"
  fi

  install -o root -g root -m 0600 "${temporary_peer}" "${peer_file}"
  rm -f "${temporary_peer}"

  if ! render_config || ! sync_interface; then
    log "peer change failed; restoring the previous configuration"
    if [ -n "${backup_peer}" ]; then
      install -o root -g root -m 0600 "${backup_peer}" "${peer_file}"
    else
      rm -f "${peer_file}"
    fi
    render_config
    sync_interface || true
    rm -f "${backup_peer}"
    die "could not apply peer change"
  fi

  rm -f "${backup_peer}"
  write_client_config "${client_private_key}" "${address}"
  if [ "${mode}" = "add" ]; then
    action_label="added"
  else
    action_label="updated"
  fi
  log "${action_label} peer ${name} (${address})"
}

delete_peer() {
  local name="$1"
  local peer_file backup_peer peer_address

  ensure_initialized
  validate_name "${name}"
  peer_file="${PEER_DIR}/${name}.conf"
  [ -e "${peer_file}" ] || die "peer does not exist: ${name}"
  peer_address="$(awk -F'= ' '/^AllowedIPs = / { print $2; exit }' "${peer_file}")"
  ensure_peer_address_not_referenced "${peer_address}"

  backup_peer="$(mktemp "${PEER_DIR}/.${name}.backup.XXXXXX")"
  cp "${peer_file}" "${backup_peer}"
  rm -f "${peer_file}"

  if ! render_config || ! sync_interface; then
    log "peer deletion failed; restoring the previous configuration"
    install -o root -g root -m 0600 "${backup_peer}" "${peer_file}"
    render_config
    sync_interface || true
    rm -f "${backup_peer}"
    die "could not delete peer"
  fi

  rm -f "${backup_peer}"
  log "deleted peer ${name}"
}

check_forward_available() {
  local protocol="$1"
  local listen_port="$2"
  local excluded_name="${3:-}"
  local forward_file existing_name existing_protocol existing_port

  for forward_file in "${FORWARD_DIR}"/*.conf; do
    [ -f "${forward_file}" ] || continue
    existing_name="$(basename "${forward_file}" .conf)"
    [ "${existing_name}" = "${excluded_name}" ] && continue
    existing_protocol="$(read_forward_setting PROTOCOL "${forward_file}")"
    existing_port="$(read_forward_setting LISTEN_PORT "${forward_file}")"
    if [ "${existing_protocol}" = "${protocol}" ] && [ "${existing_port}" = "${listen_port}" ]; then
      die "${protocol}/${listen_port} is already assigned to forward ${existing_name}"
    fi
  done
}

apply_forward() {
  local mode="$1"
  local name="$2"
  shift 2
  local protocol=""
  local listen_port=""
  local target_address=""
  local target_port=""
  local forward_file temporary_file backup_file action_label

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --protocol)
        [ "$#" -ge 2 ] || die "--protocol requires a value"
        protocol="$2"
        shift 2
        ;;
      --listen-port)
        [ "$#" -ge 2 ] || die "--listen-port requires a value"
        listen_port="$2"
        shift 2
        ;;
      --target-address)
        [ "$#" -ge 2 ] || die "--target-address requires a value"
        target_address="$2"
        shift 2
        ;;
      --target-port)
        [ "$#" -ge 2 ] || die "--target-port requires a value"
        target_port="$2"
        shift 2
        ;;
      *) die "unknown forward option: $1" ;;
    esac
  done

  ensure_initialized
  validate_name "${name}"
  [ -n "${protocol}" ] || die "--protocol is required"
  [ -n "${listen_port}" ] || die "--listen-port is required"
  [ -n "${target_address}" ] || die "--target-address is required"
  [ -n "${target_port}" ] || die "--target-port is required"
  validate_protocol "${protocol}"
  validate_port "${listen_port}"
  validate_target_address "${target_address}"
  validate_port "${target_port}"
  check_forward_available "${protocol}" "${listen_port}" "${name}"

  forward_file="${FORWARD_DIR}/${name}.conf"
  if [ "${mode}" = "add" ] && [ -e "${forward_file}" ]; then
    die "forward already exists: ${name}"
  fi
  if [ "${mode}" = "update" ] && [ ! -e "${forward_file}" ]; then
    die "forward does not exist: ${name}"
  fi

  temporary_file="$(mktemp "${FORWARD_DIR}/.${name}.XXXXXX")"
  backup_file=""
  {
    printf 'PROTOCOL=%s\n' "${protocol}"
    printf 'LISTEN_PORT=%s\n' "${listen_port}"
    printf 'TARGET_ADDRESS=%s\n' "${target_address}"
    printf 'TARGET_PORT=%s\n' "${target_port}"
  } >"${temporary_file}"

  if [ -e "${forward_file}" ]; then
    backup_file="$(mktemp "${FORWARD_DIR}/.${name}.backup.XXXXXX")"
    cp "${forward_file}" "${backup_file}"
  fi
  install -o root -g root -m 0600 "${temporary_file}" "${forward_file}"
  rm -f "${temporary_file}"

  if ! firewall_sync; then
    log "forward change failed; restoring the previous configuration"
    if [ -n "${backup_file}" ]; then
      install -o root -g root -m 0600 "${backup_file}" "${forward_file}"
    else
      rm -f "${forward_file}"
    fi
    firewall_sync || true
    rm -f "${backup_file}"
    die "could not apply forward change"
  fi

  rm -f "${backup_file}"
  if [ "${mode}" = "add" ]; then
    action_label="added"
  else
    action_label="updated"
  fi
  log "${action_label} forward ${name}: ${protocol}/${listen_port} -> ${target_address}:${target_port}"
}

delete_forward() {
  local name="$1"
  local forward_file backup_file

  ensure_initialized
  validate_name "${name}"
  forward_file="${FORWARD_DIR}/${name}.conf"
  [ -e "${forward_file}" ] || die "forward does not exist: ${name}"

  backup_file="$(mktemp "${FORWARD_DIR}/.${name}.backup.XXXXXX")"
  cp "${forward_file}" "${backup_file}"
  rm -f "${forward_file}"

  if ! firewall_sync; then
    log "forward deletion failed; restoring the previous configuration"
    install -o root -g root -m 0600 "${backup_file}" "${forward_file}"
    firewall_sync || true
    rm -f "${backup_file}"
    die "could not delete forward"
  fi

  rm -f "${backup_file}"
  log "deleted forward ${name}"
}

list_forwards() {
  local forward_file name protocol listen_port target_address target_port
  ensure_initialized
  printf 'NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n'
  for forward_file in "${FORWARD_DIR}"/*.conf; do
    [ -f "${forward_file}" ] || continue
    name="$(basename "${forward_file}" .conf)"
    protocol="$(read_forward_setting PROTOCOL "${forward_file}")"
    listen_port="$(read_forward_setting LISTEN_PORT "${forward_file}")"
    target_address="$(read_forward_setting TARGET_ADDRESS "${forward_file}")"
    target_port="$(read_forward_setting TARGET_PORT "${forward_file}")"
    printf '%s\t%s\t%s\t%s:%s\n' "${name}" "${protocol}" "${listen_port}" "${target_address}" "${target_port}"
  done
}

forward_status() {
  list_forwards
  printf '\nFilter rules:\n'
  iptables -w -t filter -S "${FORWARD_FILTER_CHAIN}" 2>/dev/null || printf '(not applied)\n'
  printf '\nDNAT rules:\n'
  iptables -w -t nat -S "${FORWARD_PREROUTING_CHAIN}" 2>/dev/null || printf '(not applied)\n'
  printf '\nSNAT rules:\n'
  iptables -w -t nat -S "${FORWARD_POSTROUTING_CHAIN}" 2>/dev/null || printf '(not applied)\n'
}

forward_command() {
  local operation="${1:-}"
  shift || true

  case "${operation}" in
    add | update)
      [ "$#" -ge 1 ] || die "forward ${operation} requires NAME"
      apply_forward "${operation}" "$@"
      ;;
    delete)
      [ "$#" -eq 1 ] || die "usage: wg-relay forward delete NAME"
      delete_forward "$1"
      ;;
    list)
      [ "$#" -eq 0 ] || die "usage: wg-relay forward list"
      list_forwards
      ;;
    status)
      [ "$#" -eq 0 ] || die "usage: wg-relay forward status"
      forward_status
      ;;
    *) die "usage: wg-relay forward add|update|delete|list|status ..." ;;
  esac
}

ensure_registered_peer_address() {
  local address="$1"
  local peer_file peer_address

  for peer_file in "${PEER_DIR}"/*.conf; do
    [ -f "${peer_file}" ] || continue
    peer_address="$(awk -F'= ' '/^AllowedIPs = / { print $2; exit }' "${peer_file}")"
    if [ "${peer_address}" = "${address}/32" ]; then
      return 0
    fi
  done
  die "peer address is not registered: ${address}"
}

ensure_peer_address_not_referenced() {
  local address="${1%/*}"
  local peer_forward_file source_address target_address peer_forward_name

  for peer_forward_file in "${PEER_FORWARD_DIR}"/*.conf; do
    [ -f "${peer_forward_file}" ] || continue
    source_address="$(read_forward_setting SOURCE_ADDRESS "${peer_forward_file}")"
    target_address="$(read_forward_setting TARGET_ADDRESS "${peer_forward_file}")"
    if [ "${source_address}" = "${address}" ] || [ "${target_address}" = "${address}" ]; then
      peer_forward_name="$(basename "${peer_forward_file}" .conf)"
      die "peer address is referenced by peer-forward ${peer_forward_name}; delete that rule first"
    fi
  done
}

check_peer_forward_available() {
  local protocol="$1"
  local source_address="$2"
  local target_address="$3"
  local target_port="$4"
  local excluded_name="${5:-}"
  local peer_forward_file existing_name existing_protocol existing_source existing_target existing_port

  for peer_forward_file in "${PEER_FORWARD_DIR}"/*.conf; do
    [ -f "${peer_forward_file}" ] || continue
    existing_name="$(basename "${peer_forward_file}" .conf)"
    [ "${existing_name}" = "${excluded_name}" ] && continue
    existing_protocol="$(read_forward_setting PROTOCOL "${peer_forward_file}")"
    existing_source="$(read_forward_setting SOURCE_ADDRESS "${peer_forward_file}")"
    existing_target="$(read_forward_setting TARGET_ADDRESS "${peer_forward_file}")"
    existing_port="$(read_forward_setting TARGET_PORT "${peer_forward_file}")"
    if [ "${existing_protocol}" = "${protocol}" ] &&
      [ "${existing_source}" = "${source_address}" ] &&
      [ "${existing_target}" = "${target_address}" ] &&
      [ "${existing_port}" = "${target_port}" ]; then
      die "the same peer-forward is already assigned to ${existing_name}"
    fi
  done
}

apply_peer_forward() {
  local mode="$1"
  local name="$2"
  shift 2
  local protocol=""
  local source_address=""
  local target_address=""
  local target_port=""
  local peer_forward_file temporary_file backup_file action_label

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --protocol)
        [ "$#" -ge 2 ] || die "--protocol requires a value"
        protocol="$2"
        shift 2
        ;;
      --source-address)
        [ "$#" -ge 2 ] || die "--source-address requires a value"
        source_address="$2"
        shift 2
        ;;
      --target-address)
        [ "$#" -ge 2 ] || die "--target-address requires a value"
        target_address="$2"
        shift 2
        ;;
      --target-port)
        [ "$#" -ge 2 ] || die "--target-port requires a value"
        target_port="$2"
        shift 2
        ;;
      *) die "unknown peer-forward option: $1" ;;
    esac
  done

  ensure_initialized
  validate_name "${name}"
  [ -n "${protocol}" ] || die "--protocol is required"
  [ -n "${source_address}" ] || die "--source-address is required"
  [ -n "${target_address}" ] || die "--target-address is required"
  [ -n "${target_port}" ] || die "--target-port is required"
  validate_protocol "${protocol}"
  validate_target_address "${source_address}"
  validate_target_address "${target_address}"
  [ "${source_address}" != "${target_address}" ] || die "source and target addresses must differ"
  validate_port "${target_port}"
  ensure_registered_peer_address "${source_address}"
  ensure_registered_peer_address "${target_address}"
  check_peer_forward_available "${protocol}" "${source_address}" "${target_address}" "${target_port}" "${name}"

  peer_forward_file="${PEER_FORWARD_DIR}/${name}.conf"
  if [ "${mode}" = "add" ] && [ -e "${peer_forward_file}" ]; then
    die "peer-forward already exists: ${name}"
  fi
  if [ "${mode}" = "update" ] && [ ! -e "${peer_forward_file}" ]; then
    die "peer-forward does not exist: ${name}"
  fi

  temporary_file="$(mktemp "${PEER_FORWARD_DIR}/.${name}.XXXXXX")"
  backup_file=""
  {
    printf 'PROTOCOL=%s\n' "${protocol}"
    printf 'SOURCE_ADDRESS=%s\n' "${source_address}"
    printf 'TARGET_ADDRESS=%s\n' "${target_address}"
    printf 'TARGET_PORT=%s\n' "${target_port}"
  } >"${temporary_file}"

  if [ -e "${peer_forward_file}" ]; then
    backup_file="$(mktemp "${PEER_FORWARD_DIR}/.${name}.backup.XXXXXX")"
    cp "${peer_forward_file}" "${backup_file}"
  fi
  install -o root -g root -m 0600 "${temporary_file}" "${peer_forward_file}"
  rm -f "${temporary_file}"

  if ! firewall_sync; then
    log "peer-forward change failed; restoring the previous configuration"
    if [ -n "${backup_file}" ]; then
      install -o root -g root -m 0600 "${backup_file}" "${peer_forward_file}"
    else
      rm -f "${peer_forward_file}"
    fi
    firewall_sync || true
    rm -f "${backup_file}"
    die "could not apply peer-forward change"
  fi

  rm -f "${backup_file}"
  if [ "${mode}" = "add" ]; then
    action_label="added"
  else
    action_label="updated"
  fi
  log "${action_label} peer-forward ${name}: ${source_address} -> ${target_address} ${protocol}/${target_port}"
}

delete_peer_forward() {
  local name="$1"
  local peer_forward_file backup_file

  ensure_initialized
  validate_name "${name}"
  peer_forward_file="${PEER_FORWARD_DIR}/${name}.conf"
  [ -e "${peer_forward_file}" ] || die "peer-forward does not exist: ${name}"

  backup_file="$(mktemp "${PEER_FORWARD_DIR}/.${name}.backup.XXXXXX")"
  cp "${peer_forward_file}" "${backup_file}"
  rm -f "${peer_forward_file}"

  if ! firewall_sync; then
    log "peer-forward deletion failed; restoring the previous configuration"
    install -o root -g root -m 0600 "${backup_file}" "${peer_forward_file}"
    firewall_sync || true
    rm -f "${backup_file}"
    die "could not delete peer-forward"
  fi

  rm -f "${backup_file}"
  log "deleted peer-forward ${name}"
}

list_peer_forwards() {
  local peer_forward_file name protocol source_address target_address target_port
  ensure_initialized
  printf 'NAME\tPROTOCOL\tSOURCE\tTARGET\n'
  for peer_forward_file in "${PEER_FORWARD_DIR}"/*.conf; do
    [ -f "${peer_forward_file}" ] || continue
    name="$(basename "${peer_forward_file}" .conf)"
    protocol="$(read_forward_setting PROTOCOL "${peer_forward_file}")"
    source_address="$(read_forward_setting SOURCE_ADDRESS "${peer_forward_file}")"
    target_address="$(read_forward_setting TARGET_ADDRESS "${peer_forward_file}")"
    target_port="$(read_forward_setting TARGET_PORT "${peer_forward_file}")"
    printf '%s\t%s\t%s\t%s:%s\n' "${name}" "${protocol}" "${source_address}" "${target_address}" "${target_port}"
  done
}

peer_forward_status() {
  list_peer_forwards
  printf '\nFilter rules:\n'
  iptables -w -t filter -S "${FORWARD_FILTER_CHAIN}" 2>/dev/null |
    grep -F 'peer-forward:' || printf '(not applied)\n'
}

peer_forward_command() {
  local operation="${1:-}"
  shift || true

  case "${operation}" in
    add | update)
      [ "$#" -ge 1 ] || die "peer-forward ${operation} requires NAME"
      apply_peer_forward "${operation}" "$@"
      ;;
    delete)
      [ "$#" -eq 1 ] || die "usage: wg-relay peer-forward delete NAME"
      delete_peer_forward "$1"
      ;;
    list)
      [ "$#" -eq 0 ] || die "usage: wg-relay peer-forward list"
      list_peer_forwards
      ;;
    status)
      [ "$#" -eq 0 ] || die "usage: wg-relay peer-forward status"
      peer_forward_status
      ;;
    *) die "usage: wg-relay peer-forward add|update|delete|list|status ..." ;;
  esac
}

init_relay() {
  local server_address=""
  local listen_port=""
  local endpoint=""
  local temporary_settings

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

  [ -n "${server_address}" ] || die "--server-address is required"
  [ -n "${listen_port}" ] || die "--listen-port is required"
  [ -n "${endpoint}" ] || die "--endpoint is required"
  validate_server_address "${server_address}"
  validate_port "${listen_port}"
  validate_endpoint "${endpoint}"

  if [ -e "${WG_CONFIG}" ] && ! grep -Fqx "${MANAGED_MARKER}" "${WG_CONFIG}"; then
    die "${WG_CONFIG} exists and is not managed by wg-relay"
  fi

  install -d -m 0700 "${STATE_DIR}" "${PEER_DIR}" "${FORWARD_DIR}" "${PEER_FORWARD_DIR}"
  ensure_server_keys
  temporary_settings="$(mktemp "${STATE_DIR}/.settings.XXXXXX")"
  {
    printf 'SERVER_ADDRESS=%s\n' "${server_address}"
    printf 'LISTEN_PORT=%s\n' "${listen_port}"
    printf 'PUBLIC_ENDPOINT=%s\n' "${endpoint}"
  } >"${temporary_settings}"
  install -o root -g root -m 0600 "${temporary_settings}" "${SETTINGS_FILE}"
  rm -f "${temporary_settings}"

  render_config
  systemctl enable wg-quick@wg0 >&2
  systemctl restart wg-quick@wg0
  firewall_sync
  log "initialized relay at ${server_address}, endpoint ${endpoint}"
  printf '%s\n' "$(tr -d '\r\n' <"${PUBLIC_KEY_FILE}")"
}

list_peers() {
  local peer_file name address public_key
  ensure_initialized
  printf 'NAME\tADDRESS\tPUBLIC_KEY\n'
  for peer_file in "${PEER_DIR}"/*.conf; do
    [ -f "${peer_file}" ] || continue
    name="$(basename "${peer_file}" .conf)"
    address="$(awk -F'= ' '/^AllowedIPs = / { print $2; exit }' "${peer_file}")"
    public_key="$(awk -F'= ' '/^PublicKey = / { print $2; exit }' "${peer_file}")"
    printf '%s\t%s\t%s\n' "${name}" "${address}" "${public_key}"
  done
}

main() {
  local command_name="${1:-help}"
  shift || true

  case "${command_name}" in
    help | --help | -h)
      usage
      exit 0
      ;;
  esac

  require_root
  require_commands

  case "${command_name}" in
    firewall-sync)
      [ "$#" -eq 0 ] || die "firewall-sync does not accept arguments"
      firewall_sync
      exit 0
      ;;
    firewall-clear)
      [ "$#" -eq 0 ] || die "firewall-clear does not accept arguments"
      firewall_clear
      exit 0
      ;;
  esac

  install -d -m 0700 "${STATE_DIR}" "${PEER_DIR}" "${FORWARD_DIR}" "${PEER_FORWARD_DIR}"
  exec 9>"${LOCK_FILE}"
  flock -x 9

  case "${command_name}" in
    init)
      init_relay "$@"
      ;;
    add | update)
      [ "$#" -eq 3 ] && [ "$2" = "--address" ] || die "usage: wg-relay ${command_name} NAME --address IPV4/32"
      apply_peer "${command_name}" "$1" "$3"
      ;;
    delete)
      [ "$#" -eq 1 ] || die "usage: wg-relay delete NAME"
      delete_peer "$1"
      ;;
    list)
      [ "$#" -eq 0 ] || die "usage: wg-relay list"
      list_peers
      ;;
    status)
      [ "$#" -eq 0 ] || die "usage: wg-relay status"
      ensure_initialized
      if systemctl is-active --quiet wg-quick@wg0; then
        wg show wg0
      else
        printf 'wg0 is inactive\n'
      fi
      ;;
    public-key)
      [ "$#" -eq 0 ] || die "usage: wg-relay public-key"
      ensure_initialized
      cat "${PUBLIC_KEY_FILE}"
      ;;
    forward)
      forward_command "$@"
      ;;
    peer-forward)
      peer_forward_command "$@"
      ;;
    *)
      usage >&2
      die "unknown command: ${command_name}"
      ;;
  esac
}

main "$@"
