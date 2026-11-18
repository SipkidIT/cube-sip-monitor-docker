from cause_codes import format_disconnect_reason
import asyncio
import json
import os
import re
import socket
import struct
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

import aiosqlite
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

DB_PATH = os.getenv("DB_PATH", "/app/data/sip_calls.db")
HEP_HOST = os.getenv("HEP_LISTEN_HOST", "127.0.0.1")
HEP_PORT = int(os.getenv("HEP_LISTEN_PORT", "9060"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))

app = FastAPI(title="Cisco CUBE SIP Flow & QoS Monitor")
templates = Jinja2Templates(directory="/app/templates")

# In-memory active dialog tracker keyed by Call-ID
active_dialogs: Dict[str, dict] = {}


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sip_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT UNIQUE NOT NULL,
            session_id TEXT,
                calling_number TEXT,
                called_number TEXT,
                invite_time TEXT,
                connect_time TEXT,
                disconnect_time TEXT,
                duration_sec INTEGER,
                status TEXT,
                disconnect_cause TEXT,
                qos_mos REAL,
                qos_jitter_ms REAL,
                qos_packet_loss INTEGER,
                qos_raw TEXT,
                sip_ladder_json TEXT
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_invite_time ON sip_calls(invite_time DESC)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_calling ON sip_calls(calling_number)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_called ON sip_calls(called_number)")
        try:
            await db.execute('ALTER TABLE sip_calls ADD COLUMN session_id TEXT')
        except Exception:
            pass
        await db.commit()


def parse_hepv3(data: bytes) -> Optional[Tuple[str, str, str, float]]:
    """Parse HEPv3 packet and return (src_ip, dst_ip, sip_payload, timestamp)."""
    if len(data) < 6 or data[:4] != b"HEP3":
        # Fallback if raw SIP text was sent
        try:
            text = data.decode("utf-8", errors="ignore")
            if "SIP/2.0" in text:
                return ("0.0.0.0", "0.0.0.0", text, time.time())
        except Exception:
            pass
        return None

    total_len = struct.unpack("!H", data[4:6])[0]
    offset = 6
    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    ts_sec = None
    ts_usec = 0
    payload = ""

    while offset + 6 <= min(len(data), total_len):
        vendor_id, chunk_type, chunk_len = struct.unpack("!HHH", data[offset:offset + 6])
        if chunk_len < 6 or offset + chunk_len > len(data):
            break
        val = data[offset + 6:offset + chunk_len]

        if chunk_type == 0x0003 and len(val) == 4:  # IPv4 src
            src_ip = socket.inet_ntoa(val)
        elif chunk_type == 0x0004 and len(val) == 4:  # IPv4 dst
            dst_ip = socket.inet_ntoa(val)
        elif chunk_type == 0x0005 and len(val) == 16:  # IPv6 src
            src_ip = socket.inet_ntop(socket.AF_INET6, val)
        elif chunk_type == 0x0006 and len(val) == 16:  # IPv6 dst
            dst_ip = socket.inet_ntop(socket.AF_INET6, val)
        elif chunk_type == 0x0009 and len(val) == 4:  # Timestamp sec
            ts_sec = struct.unpack("!I", val)[0]
        elif chunk_type == 0x000a and len(val) == 4:  # Timestamp usec
            ts_usec = struct.unpack("!I", val)[0]
        elif chunk_type == 0x000f:  # UTF8 Payload
            payload = val.decode("utf-8", errors="replace")

        offset += chunk_len

    if not payload or "SIP/2.0" not in payload:
        return None

    timestamp = (ts_sec + ts_usec / 1_000_000.0) if ts_sec else time.time()
    return (src_ip, dst_ip, payload, timestamp)


def extract_header(lines: List[str], header_names: Tuple[str, ...]) -> Optional[str]:
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() in header_names:
                return v.strip()
    return None


def extract_user_part(uri_header: Optional[str]) -> str:
    if not uri_header:
        return "Unknown"
    m = re.search(r"(?:sip|sips|tel):([^@;>\s]+)", uri_header, re.IGNORECASE)
    if m:
        return m.group(1)
    return uri_header[:32]


def parse_cisco_qos(lines: List[str]) -> Tuple[Optional[float], Optional[float], Optional[int], Optional[str]]:
    """Extract MOS, Jitter, and Packet Loss from Cisco CUBE X-RTP-Stat / P-RTP-Stat headers."""
    raw_stat = extract_header(lines, ("x-rtp-stat", "p-rtp-stat", "rtp-stat"))
    if not raw_stat:
        return (None, None, None, None)

    mos = None
    jitter = None
    loss = None

    m_mos = re.search(r"(?:MOS|MLQ|CQ)=([0-9.]+)", raw_stat, re.IGNORECASE)
    if m_mos:
        try:
            mos = float(m_mos.group(1))
        except ValueError:
            pass

    m_jit = re.search(r"(?:JI|Jit|Jitter)=([0-9.]+)", raw_stat, re.IGNORECASE)
    if m_jit:
        try:
            jitter = float(m_jit.group(1))
        except ValueError:
            pass

    m_loss = re.search(r"(?:PL|Lost|Loss)=([0-9]+)", raw_stat, re.IGNORECASE)
    if m_loss:
        try:
            loss = int(m_loss.group(1))
        except ValueError:
            pass

    return (mos, jitter, loss, raw_stat)


def cisco_guid_to_confid(guid_str: str) -> str:
    """Convert Cisco-Guid (4 decimal 32-bit ints) to CDR ConfID hex format: XXXXXXXX XXXXXXXX XX XXXXXXXX."""
    parts = [p.strip() for p in guid_str.split("-") if p.strip().isdigit()]
    if len(parts) == 4:
        nums = [int(p) & 0xFFFFFFFF for p in parts]
        w0 = f"{nums[0]:08X}"
        w1 = f"{nums[1]:08X}"
        w2 = f"{nums[2] & 0xFF:02X}"
        w3 = f"{nums[3]:08X}"
        return f"{w0} {w1} {w2} {w3}"
    return guid_str.strip()


def extract_session_id(lines: list[str]) -> Optional[str]:
    guid = extract_header(lines, ("cisco-guid",))
    if guid:
        return cisco_guid_to_confid(guid)
    # CUBE outbound Call-ID format: <8hex>-<8hex>-<dec>-<hex>@<ip> (shares first 16 hex chars with ConfID)
    cid = extract_header(lines, ("call-id", "i")) or ""
    m = re.match(r"^([0-9a-fA-F]{8})-([0-9a-fA-F]{8})-(\d+)-([0-9a-fA-F]{1,8})@", cid.strip())
    if m:
        w0 = m.group(1).upper()
        w1 = m.group(2).upper()
        w2 = f"{int(m.group(3)) & 0xFF:02X}"
        w3 = m.group(4).upper().zfill(8)
        return f"{w0} {w1} {w2} {w3}"
    sid = extract_header(lines, ("session-id",))
    if sid:
        return sid.split(";").strip()
    return None


async def persist_dialog(dialog: dict):
    invite_dt = dialog.get("invite_ts")
    connect_dt = dialog.get("connect_ts")
    disconnect_dt = dialog.get("disconnect_ts")

    duration = None
    if connect_dt and disconnect_dt and disconnect_dt >= connect_dt:
        duration = round(disconnect_dt - connect_dt)

    def fmt_ts(ts: Optional[float]) -> Optional[str]:
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO sip_calls (
                call_id, session_id, calling_number, called_number,
                invite_time, connect_time, disconnect_time,
                duration_sec, status, disconnect_cause,
                qos_mos, qos_jitter_ms, qos_packet_loss, qos_raw,
                sip_ladder_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(call_id) DO UPDATE SET
                session_id=COALESCE(excluded.session_id, sip_calls.session_id),
                calling_number=excluded.calling_number,
                called_number=excluded.called_number,
                invite_time=COALESCE(sip_calls.invite_time, excluded.invite_time),
                connect_time=COALESCE(excluded.connect_time, sip_calls.connect_time),
                disconnect_time=COALESCE(excluded.disconnect_time, sip_calls.disconnect_time),
                duration_sec=COALESCE(excluded.duration_sec, sip_calls.duration_sec),
                status=excluded.status,
                disconnect_cause=COALESCE(excluded.disconnect_cause, sip_calls.disconnect_cause),
                qos_mos=COALESCE(excluded.qos_mos, sip_calls.qos_mos),
                qos_jitter_ms=COALESCE(excluded.qos_jitter_ms, sip_calls.qos_jitter_ms),
                qos_packet_loss=COALESCE(excluded.qos_packet_loss, sip_calls.qos_packet_loss),
                qos_raw=COALESCE(excluded.qos_raw, sip_calls.qos_raw),
                sip_ladder_json=excluded.sip_ladder_json
        """, (
            dialog["call_id"],
            dialog.get("session_id"),
            dialog["calling"],
            dialog["called"],
            fmt_ts(invite_dt),
            fmt_ts(connect_dt),
            fmt_ts(disconnect_dt),
            duration,
            dialog["status"],
            dialog.get("cause"),
            dialog.get("qos_mos"),
            dialog.get("qos_jitter"),
            dialog.get("qos_loss"),
            dialog.get("qos_raw"),
            json.dumps(dialog["messages"])
        ))
        sid = dialog.get("session_id")
        if sid and len(sid) == 29 and not sid.startswith(("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F")) is False:
            prefix = sid[:17]
            # Only propagate if this leg carries the authoritative Cisco-Guid header
            if dialog.get("has_cisco_guid"):
                await db.execute(
                    "UPDATE sip_calls SET session_id = ? WHERE session_id LIKE ? AND session_id != ?",
                    (sid, f"{prefix}%", sid)
                )
            else:
                # Otherwise inherit the authoritative Cisco-Guid ConfID if the paired leg was already saved
                cur = await db.execute(
                    "SELECT session_id FROM sip_calls WHERE session_id LIKE ? AND session_id != ? LIMIT 1",
                    (f"{prefix}%", sid)
                )
                row = await cur.fetchone()
                if row and row[0]:
                    await db.execute(
                        "UPDATE sip_calls SET session_id = ? WHERE call_id = ?",
                        (row[0], dialog["call_id"])
                    )
        await db.commit()


async def process_sip_packet(src_ip: str, dst_ip: str, payload: str, ts: float):
    lines = payload.splitlines()
    if not lines:
        return
    first_line = lines[0].strip()
    call_id = extract_header(lines, ("call-id", "i"))
    if not call_id:
        return

    cseq = extract_header(lines, ("cseq",)) or ""
    cseq_method = cseq.split()[-1].upper() if cseq.split() else ""

    # Ignore non-call SIP dialogs (OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH)
    ignored_methods = ("OPTIONS", "REGISTER", "SUBSCRIBE", "NOTIFY", "PUBLISH")
    if cseq_method in ignored_methods or first_line.split()[0].upper() in ignored_methods:
        return

    is_request = not first_line.startswith("SIP/2.0")
    method_or_status = first_line.split()[0] if is_request else " ".join(first_line.split()[1:3])

    if call_id not in active_dialogs:
        # Ignore stray OPTIONS/REGISTER unless part of call
        if is_request and method_or_status in ("OPTIONS", "REGISTER", "NOTIFY", "SUBSCRIBE"):
            return
        from_hdr = extract_header(lines, ("from", "f"))
        to_hdr = extract_header(lines, ("to", "t"))
        active_dialogs[call_id] = {
            "call_id": call_id,
            "session_id": extract_session_id(lines),
            "has_cisco_guid": bool(extract_header(lines, ("cisco-guid",))),
            "calling": extract_user_part(from_hdr),
            "called": extract_user_part(to_hdr),
            "invite_ts": ts,
            "connect_ts": None,
            "disconnect_ts": None,
            "status": "Ringing / Setup",
            "cause": None,
            "qos_mos": None,
            "qos_jitter": None,
            "qos_loss": None,
            "qos_raw": None,
            "last_seen": ts,
            "messages": []
        }

    dialog = active_dialogs[call_id]
    dialog["last_seen"] = ts
    if extract_header(lines, ("cisco-guid",)):
        dialog["session_id"] = extract_session_id(lines)
        dialog["has_cisco_guid"] = True
    elif not dialog.get("session_id"):
        dialog["session_id"] = extract_session_id(lines)

    rel_ms = round((ts - dialog["invite_ts"]) * 1000)
    ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%H:%M:%S.%f")[:-3]

    dialog["messages"].append({
        "seq": len(dialog["messages"]) + 1,
        "time": ts_str,
        "offset_ms": rel_ms,
        "src": src_ip,
        "dst": dst_ip,
        "label": first_line,
        "is_request": is_request,
        "raw": payload
    })

    # Extract QoS if present on any message (commonly BYE or 200 OK to BYE)
    mos, jitter, loss, raw_stat = parse_cisco_qos(lines)
    if raw_stat:
        dialog["qos_raw"] = raw_stat
    if mos is not None:
        dialog["qos_mos"] = mos
    if jitter is not None:
        dialog["qos_jitter"] = jitter
    if loss is not None:
        dialog["qos_loss"] = loss

    # State transitions
    if not is_request:
        parts = first_line.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if code == 200 and cseq_method == "INVITE" and not dialog["connect_ts"]:
            dialog["connect_ts"] = ts
            dialog["status"] = "Connected"
        elif code >= 400 and cseq_method == "INVITE" and not dialog["connect_ts"]:
            dialog["disconnect_ts"] = ts
            dialog["status"] = "Failed"
            dialog["cause"] = format_disconnect_reason(code, payload)
    else:
        if method_or_status == "BYE":
            dialog["disconnect_ts"] = ts
            dialog["status"] = "Completed"
            dialog["cause"] = format_disconnect_reason(200, payload)
        elif method_or_status == "CANCEL" and not dialog["connect_ts"]:
            dialog["disconnect_ts"] = ts
            dialog["status"] = "Canceled"
            dialog["cause"] = format_disconnect_reason(487, payload)

    await persist_dialog(dialog)


class HEPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        parsed = parse_hepv3(data)
        if parsed:
            src_ip, dst_ip, payload, ts = parsed
            asyncio.create_task(process_sip_packet(src_ip, dst_ip, payload, ts))


async def maintenance_worker():
    """Flush stale active dialogs from memory and enforce DB retention."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        stale = [cid for cid, d in active_dialogs.items() if now - d["last_seen"] > 300]
        for cid in stale:
            active_dialogs.pop(cid, None)

        if RETENTION_DAYS > 0:
            cutoff = (datetime.now(timezone.utc).astimezone() - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute("DELETE FROM sip_calls WHERE invite_time < ?", (cutoff,))
                    await db.commit()
            except Exception:
                pass


@app.on_event("startup")
async def on_startup():
    await init_db()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: HEPProtocol(), local_addr=(HEP_HOST, HEP_PORT))
    asyncio.create_task(maintenance_worker())


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/calls")
async def get_calls(q: str = Query("", max_length=128), limit: int = Query(100, ge=1, le=500)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if q.strip():
            like = f"%{q.strip()}%"
            cursor = await db.execute("""
                SELECT id, call_id, session_id, calling_number, called_number, invite_time,
                       connect_time, disconnect_time, duration_sec, status,
                       disconnect_cause, qos_mos, qos_jitter_ms, qos_packet_loss
                FROM sip_calls
                WHERE calling_number LIKE ? OR called_number LIKE ? OR call_id LIKE ? OR session_id LIKE ? OR status LIKE ?
                ORDER BY invite_time DESC LIMIT ?
            """, (like, like, like, like, like, limit))
        else:
            cursor = await db.execute("""
                SELECT id, call_id, session_id, calling_number, called_number, invite_time,
                       connect_time, disconnect_time, duration_sec, status,
                       disconnect_cause, qos_mos, qos_jitter_ms, qos_packet_loss
                FROM sip_calls
                ORDER BY invite_time DESC LIMIT ?
            """, (limit,))
        rows = [dict(r) for r in await cursor.fetchall()]
    return JSONResponse(rows)


@app.get("/api/calls/{call_db_id}")
async def get_call_detail(call_db_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM sip_calls WHERE id = ?", (call_db_id,))
        row = await cursor.fetchone()
        if not row:
            return JSONResponse({"error": "Call not found"}, status_code=404)
        data = dict(row)
        data["messages"] = json.loads(data.pop("sip_ladder_json") or "[]")
    return JSONResponse(data)
