# Cisco CUBE SIP Flow & QoS Monitor (Docker)

A lightweight, containerized SIP call flow and QoS dashboard built with **sngrep**, **FastAPI**, and **SQLite**. It captures live SIP signaling from a mirrored network interface on Ubuntu, indexes call metadata and Cisco CUBE `X-RTP-Stat` QoS metrics, and renders clickable `sngrep`-style ladder diagrams in a web browser.

---

## Features
- **Real-Time Call Table:** Displays **Calling Number**, **Called Number**, **Connect Time**, **Disconnect Time**, **Duration**, and **QoS** (MOS, Jitter, Packet Loss).
- **Expandable SIP Ladder Diagrams:** Click any call row to expand an interactive node-to-node SIP sequence diagram and inspect raw SIP headers/SDP payloads.
- **Direct Interface Capture (`sngrep`):** Captures unencapsulated SIP frames directly on a host NIC (e.g., `ens34`, `ens192`, `eth0`) via `network_mode: host` and streams them locally over HEPv3 (`127.0.0.1:9060`).
- **Zero-Database Overhead:** Stores call history in a persistent local SQLite database (`./data/sip_calls.db`).

---

## Quick Start

### 1. Configure Environment Variables
Copy the example environment file and set your Ubuntu host capture interface and web port:
```bash
cp .env.example .env
nano .env
```

Example `.env` configuration:
```env
CAPTURE_IFACE=ens34
WEB_PORT=8081
```
*(Tip: Run `ip -br addr` on your Ubuntu host to verify your active interface name such as `ens34` or `ens192`.)*

### 2. Build and Start the Container
```bash
docker compose up -d --build
```

### 3. Open the Web Dashboard
Navigate to:
```text
http://<YOUR_UBUNTU_IP>:8081
```
If Ubuntu `ufw` is enabled, allow incoming TCP traffic on port `8081`:
```bash
sudo ufw allow 8081/tcp
```

---

## Mirroring Traffic from Cisco CUBE
Because `sngrep` listens directly on the host interface (`CAPTURE_IFACE`), mirror unencapsulated SIP traffic to your Ubuntu collector NIC:

- **Virtual Cisco CUBE (Catalyst 8000V / CSR1000v on VMware):** Configure **Distributed Port Mirroring** on your vSphere Distributed Switch (VDS), setting the CUBE voice vNIC as the **Source** and the Ubuntu collector vNIC (`ens34`) as the **Destination**.
- **Physical Cisco CUBE (ISR 4000 / Catalyst 8300):** Configure a **SPAN or RSPAN** session on the upstream switch mirroring CUBE SIP traffic (UDP/TCP 5060) to the Ubuntu collector port.

---

## Troubleshooting & Maintenance

- **View Container Logs:**
  ```bash
  docker logs -f cube-sip-monitor
  ```
- **Run Interactive `sngrep` Inside the Container:**
  ```bash
  docker exec -it cube-sip-monitor sngrep -d ens34
  ```
- **Architecture & Runtime Notes:**
  - Uses direct host NIC capture (`sngrep -d $CAPTURE_IFACE`) rather than GRE/ERSPAN kernel tunnels to avoid `ip_gre` interface collisions (`erspan0@NONE`).
  - Defaults to web port **8081** to avoid conflicts with services running on port `8080`.
  - Runs Uvicorn against `main:app` bound to `0.0.0.0:8081`.
