# Cisco CUBE SIP Flow & QoS Monitor (Docker)

A containerized SIP call flow and QoS dashboard utilizing **sngrep**, **FastAPI**, and **SQLite** to capture live SIP signaling, decode Cisco `Cisco-Guid` headers into Cisco CDR **`ConfID`** values, translate Q.850 cause codes, and display interactive call trees.

---

## Features
- **Real-Time Call Table:** Tracks Calling, Called, Connect/Disconnect times, duration, status, and QoS.
- **Cisco CDR `ConfID` Correlation:** Maps CUBE `Cisco-Guid` values into uppercase hex `ConfID` formats across inbound and outbound legs.
- **SIP & Q.850 Cause Code Translation:** Converts response codes and `Reason: Q.850;cause=X` headers into plain English.
- **Noise Filtering:** Automatically filters non-call SIP dialogs (`OPTIONS`, `REGISTER`, `SUBSCRIBE`) to keep the database focused on voice calls.
- **Interactive Ladder Diagrams:** View node-to-node SIP flows and raw headers.
- **HTTPS & Basic Authentication:** Encrypts web traffic with an auto-generated TLS certificate (`./certs/`) and protects the dashboard with configurable `.env` credentials.
- **One-Click HTML Call Flow Export:** Download any call leg as a self-contained dark-mode `.html` report containing call metadata, ladder timeline, and full raw SIP/SDP packets.

---

## Quick Start & Setup
- **Environment Configuration:** Configure `CAPTURE_IFACE` and `WEB_PORT` in your `.env` file.
- **NIC Offloading:** Disable GRO, LRO, TSO, and GSO on your capture interface using `ethtool` and install the systemd service to persist settings across reboots.
- **CUBE & Network Mirroring:** Ensure upstream SPAN/RSPAN mirrors traffic to your capture interface and enable `header-passing` under `voice service voip -> sip` on your Cisco CUBE.
- **Container Deployment:** Run `docker compose up -d --build` to build and start the service.

---

## Troubleshooting & Notes
1. **Direct Host NIC vs. GRE/ERSPAN:** Capturing directly on host interfaces avoids Linux `erspan0` interface conflicts.
2. **Missing Outbound TCP `INVITE` Legs:** Resolved via the persistent `ethtool` offload disable script.
3. **B2BUA Correlation:** CUBE dual `Call-ID`s are linked automatically via the authoritative `Cisco-Guid` `ConfID`.
4. **Permissions & Timezone:** Ensure proper file permissions and timezone alignment.
5. **CLI Inspection:** Run `docker exec -it cube-sip-monitor sngrep -d <interface>` for live packet views.

---

## Resetting the Database

To clear all captured call records and reset the ID counter back to `1` without deleting the database file:

```bash
sudo python3 -c '
import sqlite3
conn = sqlite3.connect("data/sip_calls.db")
conn.execute("DELETE FROM sip_calls")
conn.execute("DELETE FROM sqlite_sequence WHERE name=\"sip_calls\"")
conn.commit()
conn.close()
print("[OK] Cleared all call records and reset ID counter.")
'
```

---

## Exporting Call Flows (HTML)

To save or share a SIP trace for troubleshooting (e.g., Cisco TAC or carrier tickets):
1. Click **Expand SIP Flow** on any call row in the dashboard (`https://<YOUR_UBUNTU_IP>:8081`).
2. Click the **Download HTML** button next to the disconnect cause.
3. Open the downloaded `.html` file offline in any browser to view the complete call summary, SIP ladder timeline, and full raw SIP/SDP headers.

---

## Cisco CUBE ERSPAN Source Configuration

To mirror SIP traffic directly from a Cisco CUBE (`172.16.10.40`) to the Ubuntu monitoring server (`10.2.12.6`) over Layer 3 using ERSPAN, configure the following monitor session on the CUBE:

```ios
monitor session 1 type erspan-source
 source interface Gi1
 destination
  erspan-id 10
  mtu 1464
  ip address 10.2.12.6
  origin ip address 172.16.10.40
```

*(Note: When using ERSPAN across Layer-3 subnets, decapsulate the incoming GRE tunnel on Ubuntu using an `erspan` interface matching `erspan-id 10` and set `CAPTURE_IFACE` to that tunnel interface in `.env`, or use VMware/switch SPAN mirroring to send unencapsulated frames directly to your host NIC such as `ens34`.)*

---

## Security & HTTPS Access

- **HTTPS Encryption:** On first startup, `entrypoint.sh` automatically generates a 10-year self-signed TLS certificate inside `./certs/` (`cert.pem` and `key.pem`, excluded from Git via `.gitignore`). Accept the browser security prompt once when visiting `https://<YOUR_UBUNTU_IP>:8081`.
- **Login Credentials:** Set `WEB_USER` and `WEB_PASSWORD` in your `.env` file before starting the container. Every web page and `/api/calls` endpoint requires HTTP Basic Authentication.
- **Custom Certificates:** To use an internal CA-signed certificate instead of the auto-generated self-signed one, replace `./certs/cert.pem` and `./certs/key.pem` and run `docker compose restart`.


## Master Prompt (Recreate everything in One Shot)
```
Prompt:
Build a complete, downloadable Docker project (docker-compose.yml, Dockerfile, entrypoint.sh, .env.example, .gitignore, requirements.txt, app/main.py, app/cause_codes.py, app/templates/index.html, and README.md) for a Cisco CUBE SIP Flow & QoS Monitor on Ubuntu.
Architecture & Runtime Requirements:
• Capture Engine: Use network_mode: host and run sngrep -d ${CAPTURE_IFACE} -N -q -H udp:127.0.0.1:9060 in the background, streaming HEPv3 packets to a Python FastAPI + aiosqlite backend (app/main.py). Capture directly on a host NIC (default CAPTURE_IFACE=ens34, not GRE/ERSPAN).
• Timezone & Port: Set TZ=America/Los_Angeles (install tzdata in the container) and run Uvicorn on 0.0.0.0:${WEB_PORT} (default WEB_PORT=8081).
• Security: Auto-generate a self-signed TLS certificate (./certs/cert.pem and key.pem) via openssl in entrypoint.sh so Uvicorn serves HTTPS, and protect all routes with HTTP Basic Authentication configured via WEB_USER and WEB_PASSWORD in .env.
SIP Parsing & Database Logic (SQLite in ./data/sip_calls.db):
• Noise Filtering: Drop all requests and responses where CSeq method or request method is OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, or PUBLISH.
• Cisco CDR ConfID Correlation: Decode the Cisco-Guid header (4 decimal 32-bit integers) into Cisco CDR hex format XXXXXXXX XXXXXXXX XX XXXXXXXX (using the low byte nums[2] & 0xFF for the 3rd field). For outbound CUBE legs lacking Cisco-Guid, parse the Call-ID prefix (<8hex>-<8hex>-<dec>-<hex>@<ip>) and sync both legs to the authoritative Cisco-Guid ConfID.
• Cause Codes & QoS: Map both SIP status codes (4xx/5xx/6xx) and Reason: Q.850;cause=X headers into plain-English disconnect descriptions. Parse Cisco X-RTP-Stat / P-RTP-Stat headers for MOS, jitter, and packet loss.
Web Dashboard (Tailwind CSS + index.html):
• Dark-mode call table showing ID, Calling, Called, Invite/Connect/Disconnect times (PST), Duration, Status badge, QoS, and an Expand SIP Flow toggle that stays open during 4-second auto-refresh polling.
• Inside each expanded row: display Call-ID, a clickable ConfID pill that filters the search bar by the shared 17-character prefix to show both inbound/outbound CUBE legs, a Download HTML button (/api/calls/{id}/export) that downloads a self-contained offline .html report, and a clickable node-to-node SIP ladder with raw SIP/SDP packet inspection.
• Include README.md instructions for disabling NIC offloading (ethtool -K ens34 gro off lro off tso off gso off) via a persistent systemd service and resetting the SQLite database.
```
