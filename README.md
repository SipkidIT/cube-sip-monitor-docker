# Cisco CUBE SIP Flow & QoS Monitor (Docker)

A containerized SIP call flow and QoS dashboard utilizing **sngrep**, **FastAPI**, and **SQLite** to capture live SIP signaling, decode Cisco `Cisco-Guid` headers into Cisco CDR **`ConfID`** values, translate Q.850 cause codes, and display interactive call trees.

---

## Features
- **Real-Time Call Table:** Tracks Calling, Called, Connect/Disconnect times, duration, status, and QoS.
- **Cisco CDR `ConfID` Correlation:** Maps CUBE `Cisco-Guid` values into uppercase hex `ConfID` formats across inbound and outbound legs.
- **SIP & Q.850 Cause Code Translation:** Converts response codes and `Reason: Q.850;cause=X` headers into plain English.
- **Noise Filtering:** Automatically filters non-call SIP dialogs (`OPTIONS`, `REGISTER`, `SUBSCRIBE`) to keep the database focused on voice calls.
- **Interactive Ladder Diagrams:** View node-to-node SIP flows and raw headers.

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
