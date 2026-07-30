#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
readonly PROJECT_DIR="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"
exec docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml up -d --build --force-recreate
