#!/usr/bin/env bash
set -e

CAPTURE_IFACE="${CAPTURE_IFACE:-ens34}"
WEB_PORT="${WEB_PORT:-8081}"

echo "[INFO] Starting sngrep capture on interface ${CAPTURE_IFACE}..."
sngrep -d "${CAPTURE_IFACE}" -N -q -H udp:127.0.0.1:9060 &

echo "[INFO] Starting SIP Flow & QoS Web Dashboard on port ${WEB_PORT}..."
exec uvicorn main:app --host 0.0.0.0 --port "${WEB_PORT}"
