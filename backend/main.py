"""
CTIMS FastAPI Backend
Real-time API server for Cyber Threat Intelligence Management System
Connects to Neon PostgreSQL via asyncpg (async, fast).
Run: uvicorn main:app --reload --port 8000
"""

import os, sys, json, tempfile, asyncio, collections, threading, subprocess
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

import asyncpg
from fastapi import (
    FastAPI, UploadFile, File, Query,
    HTTPException, WebSocket, WebSocketDisconnect, Body
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Wireshark for pyshark ──────────────────────────────────────────────
os.environ["PATH"] += r";C:\Program Files\Wireshark"

# ── Neon DB connection ─────────────────────────────────────────────────
DB_DSN = os.getenv("DATABASE_URL")

pool: asyncpg.Pool = None
live_clients: list[WebSocket] = []   # WebSocket subscribers

# ── App lifecycle ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=15)
    yield
    await pool.close()

app = FastAPI(title="CTIMS API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helper ─────────────────────────────────────────────────────────────
async def qry(sql: str, *args) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *args)
        return [dict(r) for r in rows]

async def qry_one(sql: str, *args) -> Optional[dict]:
    rows = await qry(sql, *args)
    return rows[0] if rows else None

async def broadcast(event: str, data: dict):
    dead = []
    for ws in live_clients:
        try:
            await ws.send_text(json.dumps({"event": event, "data": data}))
        except Exception:
            dead.append(ws)
    for ws in dead:
        live_clients.remove(ws)


# ═══════════════════════════════════════════════════════════════════════
# STATS  —  GET /api/stats
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/stats")
async def get_stats():
    dashboard      = await qry_one("SELECT * FROM vw_dashboard")
    severity_stats = await qry(
        "SELECT indicator_type, severity, total_count, malicious_count "
        "FROM vw_severity_stats "
        "ORDER BY indicator_type, CASE severity "
        "WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END"
    )
    recent_indicators = await qry(
        "SELECT indicator_id, indicator_type, indicator_value, severity, status, "
        "confidence_score, is_malicious, created_at "
        "FROM indicators ORDER BY created_at DESC LIMIT 10"
    )
    recent_incidents = await qry(
        "SELECT incident_id, incident_title, severity, status, discovered_at "
        "FROM incidents ORDER BY discovered_at DESC LIMIT 5"
    )
    type_breakdown = await qry(
        "SELECT indicator_type AS name, COUNT(*) AS value "
        "FROM indicators WHERE is_malicious = TRUE GROUP BY indicator_type"
    )
    actor_activity = await qry(
        "SELECT actor_name AS name, total_indicators AS value "
        "FROM vw_actor_summary ORDER BY total_indicators DESC LIMIT 6"
    )
    return {
        "dashboard":         dashboard,
        "severityStats":     severity_stats,
        "recentIndicators":  recent_indicators,
        "recentIncidents":   recent_incidents,
        "typeBreakdown":     type_breakdown,
        "actorActivity":     actor_activity,
    }


# ═══════════════════════════════════════════════════════════════════════
# INDICATORS  —  GET /api/indicators  |  POST /api/indicators
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/indicators")
async def get_indicators(
    type: Optional[str]     = Query(None),
    severity: Optional[str] = Query(None),
):
    sql = (
        "SELECT i.indicator_id, i.indicator_type, i.indicator_value, "
        "i.severity, i.status, i.confidence_score, i.is_malicious, "
        "i.context, i.created_at, "
        "COALESCE(ta.actor_name,'Unknown') AS actor "
        "FROM indicators i "
        "LEFT JOIN threat_actors ta ON i.actor_id = ta.actor_id WHERE 1=1"
    )
    args = []
    idx = 1
    if type and type != "all":
        sql += f" AND i.indicator_type = ${idx}"; args.append(type); idx += 1
    if severity and severity != "all":
        sql += f" AND i.severity = ${idx}";     args.append(severity); idx += 1
    sql += (
        " ORDER BY CASE i.severity "
        "WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,"
        " i.created_at DESC LIMIT 100"
    )
    return await qry(sql, *args)


class IndicatorIn(BaseModel):
    indicator_type:   str
    indicator_value:  str
    severity:         str
    is_malicious:     bool          = True
    confidence_score: int           = 70
    context:          str           = ""
    actor_id:         Optional[int] = None
    submitted_by:     str           = ""   # analyst username for notifications


@app.post("/api/indicators")
async def create_indicator(body: IndicatorIn):
    row = await qry_one(
        "INSERT INTO indicators "
        "(indicator_type, indicator_value, severity, status, is_malicious, "
        " confidence_score, context, actor_id, reported_by) "
        "VALUES ($1,$2,$3,'Active',$4,$5,$6,$7,1) RETURNING indicator_id",
        body.indicator_type, body.indicator_value, body.severity,
        body.is_malicious, body.confidence_score,
        body.context, body.actor_id,
    )
    ioc_id = row["indicator_id"]
    import datetime
    await broadcast("new_indicator", {
        "id":           ioc_id,
        "type":         body.indicator_type,
        "value":        body.indicator_value,
        "severity":     body.severity,
        "confidence":   body.confidence_score,
        "context":      body.context,
        "submitted_by": body.submitted_by or "analyst",
        "timestamp":    datetime.datetime.now().strftime("%H:%M:%S"),
    })
    return {"success": True, "id": ioc_id}


# ═══════════════════════════════════════════════════════════════════════
# ACTORS  —  GET /api/actors
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/actors")
async def get_actors():
    return await qry(
        "SELECT * FROM vw_actor_summary ORDER BY total_indicators DESC"
    )


# ═══════════════════════════════════════════════════════════════════════
# INCIDENTS  —  GET /api/incidents
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/incidents")
async def get_incidents():
    return await qry(
        "SELECT * FROM vw_open_incidents ORDER BY discovered_at DESC LIMIT 50"
    )


# ═══════════════════════════════════════════════════════════════════════
# PCAP ANALYSIS  —  POST /api/analyze-pcap
# ═══════════════════════════════════════════════════════════════════════
def _run_analysis(pcap_path: str) -> dict:
    """Synchronous pyshark analysis — runs in a thread executor."""
    # pyshark internally uses asyncio; give this thread its own event loop
    import asyncio as _aio
    _loop = _aio.new_event_loop()
    _aio.set_event_loop(_loop)

    try:
        import pyshark
    except ImportError:
        _loop.close()
        return {"error": "pyshark not installed. Run: pip install pyshark"}

    SUSPICIOUS_PORTS = {
        4444:  "Metasploit default",
        1337:  "Common C2",
        6667:  "IRC (botnet)",
        6666:  "IRC (botnet)",
        31337: "Elite backdoor",
        12345: "NetBus backdoor",
        27374: "Sub7 backdoor",
        1433:  "MSSQL",
        3389:  "RDP (brute force?)",
        23:    "Telnet (insecure)",
    }
    SUSPICIOUS_TLDS = {".xyz", ".tk", ".top", ".pw", ".cc", ".su", ".ru", ".ml", ".ga"}

    src_ips   = collections.Counter()
    dst_ips   = collections.Counter()
    protocols = collections.Counter()
    ports     = collections.Counter()
    dns_queries, http_hosts, suspicious = [], [], []
    total = 0

    try:
        cap = pyshark.FileCapture(pcap_path, only_summaries=False, keep_packets=False)
        for pkt in cap:
            total += 1
            if total > 5000:
                break
            try:
                protocols[pkt.highest_layer] += 1
                if hasattr(pkt, "ip"):
                    src_ips[pkt.ip.src] += 1
                    dst_ips[pkt.ip.dst] += 1
                def _port(layer, attr1, attr2):
                    for a in (attr1, attr2):
                        try:
                            v = getattr(layer, a, None)
                            if v is not None:
                                return int(v)
                        except Exception:
                            pass
                    return 0

                if hasattr(pkt, "tcp"):
                    dp = _port(pkt.tcp, "dstport", "dport")
                    if dp:
                        ports[dp] += 1
                        if dp in SUSPICIOUS_PORTS:
                            src = pkt.ip.src if hasattr(pkt, "ip") else "?"
                            sev = "Critical" if dp in (4444, 1337, 31337) else "High"
                            suspicious.append({
                                "type": "Suspicious Port",
                                "detail": f"TCP {dp} ({SUSPICIOUS_PORTS[dp]}) from {src}",
                                "severity": sev,
                            })
                if hasattr(pkt, "udp"):
                    dp = _port(pkt.udp, "dstport", "dport")
                    if dp:
                        ports[dp] += 1
                if hasattr(pkt, "dns"):
                    q = None
                    for attr in ("qry_name", "qryname", "dns_qry_name"):
                        try:
                            v = getattr(pkt.dns, attr, None)
                            if v:
                                q = str(v); break
                        except Exception:
                            pass
                    if q:
                        dns_queries.append(q)
                        for tld in SUSPICIOUS_TLDS:
                            if q.endswith(tld):
                                suspicious.append({
                                    "type": "Suspicious DNS",
                                    "detail": f"Query to suspicious TLD: {q}",
                                    "severity": "High",
                                })
                if hasattr(pkt, "http"):
                    for attr in ("host", "request_full_uri"):
                        try:
                            v = getattr(pkt.http, attr, None)
                            if v:
                                http_hosts.append(str(v)); break
                        except Exception:
                            pass
            except Exception:
                continue
        cap.close()
    except Exception as e:
        _loop.close()
        return {"error": str(e)}
    finally:
        try:
            _loop.close()
        except Exception:
            pass

    def dedup_suspicious(items):
        seen, out = set(), []
        for s in items:
            if s["detail"] not in seen:
                seen.add(s["detail"]); out.append(s)
        return out[:25]

    top_dst = [{"ip": ip, "count": c} for ip, c in dst_ips.most_common(10)]

    # Build suggested IOCs
    private = ("10.", "192.168.", "172.", "127.", "0.", "255.")
    suggested = []
    for e in top_dst[:5]:
        if not any(e["ip"].startswith(p) for p in private):
            suggested.append({
                "type": "IP", "value": e["ip"],
                "count": e["count"], "severity": "Medium",
                "reason": f"Frequent destination — {e['count']} packets",
            })
    for d in list(dict.fromkeys(dns_queries))[:5]:
        if any(d.endswith(t) for t in SUSPICIOUS_TLDS):
            suggested.append({
                "type": "Domain", "value": d,
                "count": 1, "severity": "High",
                "reason": "Suspicious TLD in DNS query",
            })

    return {
        "total_packets":      total,
        "top_source_ips":     [{"ip": ip, "count": c} for ip, c in src_ips.most_common(10)],
        "top_dest_ips":       top_dst,
        "protocol_breakdown": [{"name": p, "count": c} for p, c in protocols.most_common(10)],
        "top_ports":          [{"port": p, "count": c} for p, c in ports.most_common(10)],
        "dns_queries":        list(dict.fromkeys(dns_queries))[:20],
        "http_hosts":         list(dict.fromkeys(http_hosts))[:20],
        "suspicious_activity": dedup_suspicious(suspicious),
        "suggested_iocs":     suggested,
    }


@app.post("/api/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ("pcap", "pcapng", "cap"):
        raise HTTPException(400, "Only .pcap / .pcapng / .cap files allowed")

    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        loop   = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _run_analysis, tmp_path)
        if "error" in result:
            raise HTTPException(500, result["error"])

        await broadcast("pcap_analyzed", {
            "filename": file.filename,
            "packets":  result["total_packets"],
            "threats":  len(result["suspicious_activity"]),
        })
        return {"success": True, "filename": file.filename, "analysis": result}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
# SAVE IOC  —  POST /api/save-ioc
# ═══════════════════════════════════════════════════════════════════════
@app.delete("/api/indicators/{indicator_id}")
async def delete_indicator(indicator_id: int):
    row = await qry_one(
        "SELECT severity, status FROM indicators WHERE indicator_id = $1", indicator_id
    )
    if not row:
        raise HTTPException(404, "Indicator not found")
    if row["severity"] == "Critical" and row["status"] == "Active":
        raise HTTPException(403, "Cannot delete an Active Critical indicator (trigger protection)")
    await qry_one(
        "DELETE FROM indicators WHERE indicator_id = $1 RETURNING indicator_id", indicator_id
    )
    return {"success": True, "deleted_id": indicator_id}


# ═══════════════════════════════════════════════════════════════════════
# MALWARE  —  GET /api/malware
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/malware")
async def get_malware():
    return await qry(
        "SELECT m.malware_id, m.malware_name, m.malware_type, m.severity, "
        "m.first_seen, m.last_seen, m.is_active, "
        "COALESCE(ta.actor_name,'Unknown') AS actor "
        "FROM malware m "
        "LEFT JOIN threat_actors ta ON m.actor_id = ta.actor_id "
        "ORDER BY m.severity DESC, m.last_seen DESC LIMIT 50"
    )


# ═══════════════════════════════════════════════════════════════════════
# VULNERABILITIES  —  GET /api/vulns
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/vulns")
async def get_vulns():
    return await qry(
        "SELECT vuln_id, cve_id, vuln_title, severity, cvss_score, "
        "affected_product, patch_status, published_date "
        "FROM vulnerabilities ORDER BY cvss_score DESC NULLS LAST LIMIT 50"
    )


# ═══════════════════════════════════════════════════════════════════════
# AUDIT LOG  —  GET /api/audit
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/audit")
async def get_audit():
    return await qry(
        "SELECT log_id, table_name, operation, record_id, "
        "performed_by, performed_at, old_data, new_data "
        "FROM audit_log ORDER BY performed_at DESC LIMIT 100"
    )


# ═══════════════════════════════════════════════════════════════════════
# REAL-TIME WEBSOCKET  —  ws://localhost:8000/ws/live
# Push events to all connected dashboard tabs in real time
# ═══════════════════════════════════════════════════════════════════════
@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    live_clients.append(ws)
    try:
        # Send current stats immediately on connect
        stats = await get_stats()
        await ws.send_text(json.dumps({"event": "init", "data": stats}))

        # Keep alive — listen for pings
        while True:
            msg = await asyncio.wait_for(ws.receive_text(), timeout=30)
            if msg == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        if ws in live_clients:
            live_clients.remove(ws)


# ═══════════════════════════════════════════════════════════════════════
# AUTH  —  POST /api/login
# ═══════════════════════════════════════════════════════════════════════
class LoginIn(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(body: LoginIn):
    row = await qry_one(
        "SELECT user_id, username, role, email, department "
        "FROM ctims_users WHERE username=$1 AND password_hash=$2",
        body.username, body.password,
    )
    if not row:
        raise HTTPException(401, "Invalid username or password")
    return {"success": True, "user": dict(row)}

class CreateUserIn(BaseModel):
    username:   str
    password:   str
    email:      str       = ""
    department: str       = "Threat Intelligence"
    role:       str       = "analyst"

@app.post("/api/users")
async def create_user(body: CreateUserIn):
    existing = await qry_one("SELECT user_id FROM ctims_users WHERE username=$1", body.username)
    if existing:
        raise HTTPException(400, f"Username '{body.username}' already exists")
    row = await qry_one(
        "INSERT INTO ctims_users (username, password_hash, email, role, department, is_active) "
        "VALUES ($1,$2,$3,$4,$5,TRUE) RETURNING user_id",
        body.username, body.password,
        body.email or f"{body.username}@ctims.local",
        body.role.lower(), body.department,
    )
    return {"success": True, "user_id": row["user_id"], "username": body.username}

@app.get("/api/users")
async def list_users():
    return await qry(
        "SELECT user_id, username, role, email, department, is_active, created_at "
        "FROM ctims_users ORDER BY user_id"
    )

@app.get("/api/me")
async def me_info(username: str = Query(...)):
    row = await qry_one(
        "SELECT user_id, username, role, email, department FROM ctims_users WHERE username=$1",
        username,
    )
    if not row:
        raise HTTPException(404, "User not found")
    return dict(row)


# ═══════════════════════════════════════════════════════════════════════
# LIVE CAPTURE — GET /api/interfaces
# Returns network interfaces from tshark -D
# ═══════════════════════════════════════════════════════════════════════
@app.get("/api/interfaces")
async def get_interfaces():
    TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
    try:
        result = subprocess.run(
            [TSHARK, "-D"],
            capture_output=True, text=True, timeout=10,
        )
        interfaces = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "1. \Device\NPF_{...} (Wi-Fi)"
            dot = line.find(". ")
            if dot == -1:
                continue
            idx  = line[:dot]
            rest = line[dot+2:]
            if "(" in rest and rest.endswith(")"):
                name   = rest[rest.rfind("(")+1:-1]
                device = rest[:rest.rfind("(")].strip()
            else:
                name   = rest
                device = rest
            interfaces.append({"id": idx, "device": device, "name": name or device})
        return interfaces
    except Exception as e:
        return [{"id": "1", "device": "auto", "name": f"Default interface (tshark error: {e})"}]


# ── Packet formatter for live capture ─────────────────────────────────
def _fmt_live_packet(pkt, pkt_no: int, t0: float) -> dict:
    SUSP = {4444, 1337, 6667, 6666, 31337, 12345, 27374}
    try:
        src   = pkt.ip.src  if hasattr(pkt, "ip")  else (pkt.ipv6.src if hasattr(pkt, "ipv6") else "")
        dst   = pkt.ip.dst  if hasattr(pkt, "ip")  else (pkt.ipv6.dst if hasattr(pkt, "ipv6") else "")
        proto = pkt.highest_layer
        try:   length = int(pkt.length)
        except Exception: length = 0
        try:   ts = float(pkt.sniff_timestamp) - t0
        except Exception: ts = 0.0

        info = ""
        suspicious = False

        if hasattr(pkt, "dns"):
            for a in ("qry_name", "qryname"):
                try:
                    q = getattr(pkt.dns, a, None)
                    if q:
                        info = f"Query: {q}"
                        SUSP_TLD = (".xyz",".tk",".ru",".top",".pw",".cc",".su",".ml")
                        if any(str(q).endswith(t) for t in SUSP_TLD):
                            suspicious = True
                        break
                except Exception:
                    pass

        elif hasattr(pkt, "http"):
            for a in ("request_full_uri", "host", "response_code"):
                try:
                    v = getattr(pkt.http, a, None)
                    if v:
                        info = str(v); break
                except Exception:
                    pass

        elif hasattr(pkt, "tcp"):
            try:
                sp = int(getattr(pkt.tcp, "srcport", None) or getattr(pkt.tcp, "sport", 0))
                dp = int(getattr(pkt.tcp, "dstport", None) or getattr(pkt.tcp, "dport", 0))
                try:  flags = pkt.tcp.flags
                except Exception: flags = ""
                info = f"{sp} → {dp}  [{flags}]"
                if dp in SUSP or sp in SUSP:
                    suspicious = True
            except Exception:
                info = "TCP"

        elif hasattr(pkt, "udp"):
            try:
                sp = int(getattr(pkt.udp, "srcport", None) or 0)
                dp = int(getattr(pkt.udp, "dstport", None) or 0)
                info = f"{sp} → {dp}"
            except Exception:
                info = "UDP"
        elif hasattr(pkt, "arp"):
            try: info = f"ARP {pkt.arp.opcode}: {pkt.arp.src_proto_ipv4} → {pkt.arp.dst_proto_ipv4}"
            except Exception: info = "ARP"
        elif hasattr(pkt, "icmp"):
            try: info = f"ICMP type={pkt.icmp.type}"
            except Exception: info = "ICMP"

        return {
            "no": pkt_no, "time": round(ts, 6),
            "src": src, "dst": dst,
            "proto": proto, "len": length,
            "info": info or proto,
            "suspicious": suspicious,
        }
    except Exception:
        return {"no": pkt_no, "time": 0, "src": "?", "dst": "?",
                "proto": "?", "len": 0, "info": "", "suspicious": False}


# ═══════════════════════════════════════════════════════════════════════
# LIVE CAPTURE WEBSOCKET — ws://localhost:8000/ws/capture
# Protocol:
#   Client → {"cmd":"start","iface":"1","filter":"tcp port 80"}
#   Server → {"type":"packet","data":{...}}   (stream)
#   Server → {"type":"alert","data":{...}}    (suspicious packet)
#   Client → {"cmd":"stop"}
#   Server → {"type":"stopped","total":N}
# ═══════════════════════════════════════════════════════════════════════
@app.websocket("/ws/capture")
async def ws_capture(ws: WebSocket):
    await ws.accept()

    # Wait for start command
    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=15)
        cmd = json.loads(raw)
    except Exception:
        await ws.close()
        return

    if cmd.get("cmd") != "start":
        await ws.close()
        return

    iface      = str(cmd.get("iface", "1"))
    bpf_filter = str(cmd.get("filter", "")).strip()
    max_pkts   = int(cmd.get("max", 5000))

    pkt_queue  = asyncio.Queue(maxsize=1000)
    stop_flag  = threading.Event()
    main_loop  = asyncio.get_running_loop()
    pkt_count  = 0
    t0         = [0.0]   # mutable for thread closure

    def capture_worker():
        worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(worker_loop)
        try:
            import pyshark
            cap_kwargs: dict = {"interface": iface}
            if bpf_filter:
                cap_kwargs["bpf_filter"] = bpf_filter
            cap = pyshark.LiveCapture(**cap_kwargs)
            first = True
            count = [0]
            for pkt in cap.sniff_continuously():
                if stop_flag.is_set() or count[0] >= max_pkts:
                    break
                count[0] += 1
                try:
                    if first:
                        try: t0[0] = float(pkt.sniff_timestamp)
                        except Exception: t0[0] = 0.0
                        first = False
                    data = _fmt_live_packet(pkt, count[0], t0[0])
                    def push(d=data):
                        try:
                            pkt_queue.put_nowait(d)
                        except asyncio.QueueFull:
                            pass
                    main_loop.call_soon_threadsafe(push)
                except Exception:
                    pass
        except Exception as e:
            def push_err(err=str(e)):
                try:
                    pkt_queue.put_nowait({"__error__": err})
                except Exception:
                    pass
            main_loop.call_soon_threadsafe(push_err)
        finally:
            worker_loop.close()

    thread = threading.Thread(target=capture_worker, daemon=True)
    thread.start()

    await ws.send_text(json.dumps({"type": "started", "iface": iface}))

    try:
        while True:
            # Check for stop command (non-blocking)
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=0.05)
                if json.loads(raw).get("cmd") == "stop":
                    break
            except asyncio.TimeoutError:
                pass
            except (WebSocketDisconnect, Exception):
                break

            # Drain the queue — batch up to 20 packets per tick
            batch = []
            for _ in range(20):
                try:
                    item = pkt_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if "__error__" in item:
                    await ws.send_text(json.dumps({"type": "error", "msg": item["__error__"]}))
                    stop_flag.set()
                    return
                batch.append(item)

            for data in batch:
                pkt_count += 1
                await ws.send_text(json.dumps({"type": "packet", "data": data}))
                if data.get("suspicious"):
                    await ws.send_text(json.dumps({"type": "alert", "data": data}))

            await asyncio.sleep(0.05)

    except WebSocketDisconnect:
        pass
    finally:
        stop_flag.set()
        try:
            await ws.send_text(json.dumps({"type": "stopped", "total": pkt_count}))
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════
@app.get("/health")
async def health():
    try:
        row = await qry_one("SELECT COUNT(*) AS c FROM indicators")
        return {"status": "ok", "indicators": row["c"]}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
