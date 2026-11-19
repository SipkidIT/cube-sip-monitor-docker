#!/usr/bin/env bash
set -e

CAPTURE_IFACE="${CAPTURE_IFACE:-ens34}"
WEB_PORT="${WEB_PORT:-8081}"
CERT_DIR="/app/certs"

mkdir -p "${CERT_DIR}"
if [ ! -f "${CERT_DIR}/cert.pem" ] || [ ! -f "${CERT_DIR}/key.pem" ]; then
    echo "[INFO] Generating self-signed TLS certificate for HTTPS..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        -days 3650 \
        -subj "/CN=cube-sip-monitor" \
        -addext "subjectAltName=IP:10.2.12.6,IP:127.0.0.1"
fi

echo "[INFO] Starting sngrep capture on interface ${CAPTURE_IFACE}..."
sngrep -d "${CAPTURE_IFACE}" -N -q -H udp:127.0.0.1:9060 &

echo "[INFO] Starting HTTPS SIP Flow & QoS Web Dashboard on port ${WEB_PORT}..."
exec uvicorn main:app --host 0.0.0.0 --port "${WEB_PORT}" \
    --ssl-keyfile "${CERT_DIR}/key.pem" \
    --ssl-certfile "${CERT_DIR}/cert.pem"
