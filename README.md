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
