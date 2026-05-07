"""
PacketIQ Web Application — FastAPI backend.

Provides:
  POST /api/upload          — upload a PCAP file, returns job_id
  WS   /ws/{job_id}         — real-time analysis progress stream
  GET  /api/results/{job_id}— complete analysis results as JSON
  GET  /api/sigma/{job_id}/rules.zip — download SIGMA rules bundle
  GET  /                    — serve the single-page application
"""

import asyncio
import io
import json
import os
import uuid
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

UPLOAD_DIR = Path("/tmp/packetiq_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = 10_240  # 10 GB

# In-memory job registry
# job = {status, queue, result, error, filename, size_mb, pcap_path}
_jobs: dict[str, dict] = {}

TEMPLATE = Path(__file__).parent / "templates" / "index.html"


# ── Serialisers ───────────────────────────────────────────────────────────────

def _ser_event(e) -> dict:
    from packetiq.utils.helpers import ts_to_str
    return {
        "event_type":   e.event_type.value,
        "severity":     e.severity.value,
        "src_ip":       e.src_ip or "",
        "dst_ip":       e.dst_ip or "",
        "dst_port":     e.dst_port or 0,
        "protocol":     e.protocol or "",
        "timestamp":    e.timestamp,
        "ts_str":       ts_to_str(e.timestamp) if e.timestamp else "",
        "packet_count": e.packet_count,
        "confidence":   round(float(e.confidence) * 100),
        "description":  e.description,
        "evidence":     e.evidence,
    }


def _ser_chain(c) -> dict:
    from packetiq.utils.helpers import ts_to_str
    return {
        "chain_id":     c.chain_id,
        "name":         c.name,
        "description":  c.description,
        "severity":     c.severity.value,
        "confidence":   round(c.confidence * 100),
        "attacker_ips": sorted(c.attacker_ips),
        "target_ips":   sorted(c.target_ips),
        "event_count":  c.event_count,
        "first_seen":   ts_to_str(c.first_seen) if c.first_seen else "",
        "last_seen":    ts_to_str(c.last_seen)  if c.last_seen  else "",
        "phases":       list(c.kill_chain_phases),
        "mitre":        [{"id": t.technique_id, "name": t.technique_name}
                         for t in c.mitre_techniques],
    }


def _ser_tl(e) -> dict:
    ts = e.ts_str
    return {
        "ts":          e.timestamp,
        "ts_str":      ts[11:23] if len(ts) > 11 else ts,
        "category":    e.category,
        "phase":       e.phase or "",
        "description": e.description,
        "src_ip":      e.src_ip or "",
        "dst_ip":      e.dst_ip or "",
        "severity":    e.severity.value if e.severity else "",
        "mitre_id":    e.mitre_id or "",
    }


def _ser_fp(f) -> dict:
    return {
        "src_ip":       f.src_ip,
        "os_guess":     f.os_guess,
        "os_icon":      f.os_icon,
        "observed_ttl": f.observed_ttl,
        "initial_ttl":  f.initial_ttl,
        "hops":         f.hops,
        "is_external":  f.is_external,
    }


def _ser_attr(a) -> dict:
    return {
        "name":           a.actor_name,
        "aliases":        a.aliases[:3],
        "origin":         a.origin,
        "motivation":     a.motivation,
        "confidence":     round(a.confidence * 100),
        "matched_ttps":   a.matched_ttps,
        "description":    a.description,
        "icon":           a.icon,
        "color":          a.color,
        "mitre_group":    a.mitre_group,
        "target_sectors": a.target_sectors,
    }


# ── Core analysis (runs in thread pool) ──────────────────────────────────────

def _run_analysis(job_id: str, pcap_path: str, loop: asyncio.AbstractEventLoop) -> Optional[dict]:
    """Full PacketIQ pipeline — blocking, call via run_in_executor."""
    from packetiq.parser.pcap_parser import PCAPParser
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.detection.engine import DetectionEngine
    from packetiq.correlation.engine import CorrelationEngine
    from packetiq.timeline.builder import TimelineBuilder
    from packetiq.sigma.generator import SigmaGenerator
    from packetiq.attribution.engine import AttributionEngine
    from packetiq.utils.helpers import format_bytes, format_duration, ts_to_str

    queue = _jobs[job_id]["queue"]

    def push(**kwargs):
        asyncio.run_coroutine_threadsafe(queue.put(kwargs), loop)

    def progress(step: str, pct: int, label: str):
        push(type="progress", step=step, percent=pct, label=label)

    try:
        # ── Parse ──────────────────────────────────────────────────────
        progress("parse", 5, "Parsing PCAP packets…")
        parser    = PCAPParser(pcap_path)
        extractor = DataExtractor()
        count     = 0
        for rec in parser.stream():
            extractor.feed(rec)
            count += 1
            if count % 10_000 == 0:
                pct = min(28, 5 + count // 5_000)
                progress("parse", pct, f"Parsed {count:,} packets…")

        result    = extractor.finalize()
        file_meta = parser.file_summary()
        progress("parse", 30, f"Parsed {count:,} packets — extraction complete.")

        # ── Detect ─────────────────────────────────────────────────────
        STEP_MAP = {
            "brute_force":        (34, "Brute-force detector…"),
            "port_scan":          (39, "Port-scan detector…"),
            "dns_anomaly":        (44, "DNS anomaly analysis…"),
            "protocol_misuse":    (49, "Protocol misuse detector…"),
            "beacon_analysis":    (54, "C2 beacon periodicity analysis…"),
            "credential_exposure":(60, "Credential exposure scan…"),
            "ja3_fingerprinting": (65, "JA3/JA3S TLS fingerprinting…"),
            "os_fingerprinting":  (70, "Passive OS fingerprinting…"),
            "risk_scoring":       (75, "Computing risk score…"),
        }

        def cb(step: str):
            if step in STEP_MAP:
                progress(step, *STEP_MAP[step])

        engine             = DetectionEngine()
        events, risk, fps  = engine.run(result, pcap_path, progress_callback=cb)
        progress("detect_done", 76, f"{len(events)} threat event(s) detected.")

        # ── Correlate ──────────────────────────────────────────────────
        progress("correlate", 82, "Correlating attack chains…")
        chains = CorrelationEngine().correlate(events)
        progress("correlate", 84, f"{len(chains)} attack chain(s) identified.")

        # ── Timeline ───────────────────────────────────────────────────
        progress("timeline", 87, "Reconstructing kill-chain timeline…")
        tl = TimelineBuilder().build(result, events, chains)

        # ── SIGMA ──────────────────────────────────────────────────────
        progress("sigma", 91, "Generating SIGMA detection rules…")
        sigma = SigmaGenerator().generate(events, chains)

        # ── Attribution ────────────────────────────────────────────────
        progress("attribution", 95, "Threat actor attribution…")
        attrs = AttributionEngine().attribute(events, chains)

        progress("finalize", 99, "Finalising results…")

        # ── Serialise ──────────────────────────────────────────────────
        dur = max(0.0, result.capture_end - result.capture_start)
        dns_counts: dict = {}
        for q in result.dns_queries:
            d = q.get("qname", "")
            dns_counts[d] = dns_counts.get(d, 0) + 1

        data = {
            "meta": {
                "filename":      _jobs[job_id]["filename"],
                "size_mb":       _jobs[job_id]["size_mb"],
                "total_packets": result.total_packets,
                "total_bytes":   result.total_bytes,
                "bytes_fmt":     format_bytes(result.total_bytes),
                "capture_start": ts_to_str(result.capture_start),
                "capture_end":   ts_to_str(result.capture_end),
                "duration":      format_duration(dur),
                "unique_flows":  len(result.flows),
                "unique_src":    len(result.unique_src_ips),
                "unique_dst":    len(result.unique_dst_ips),
                "dns_queries":   len(result.dns_queries),
                "http_requests": len(result.http_requests),
                "external_ips":  len(result.external_ips),
            },
            "risk": {
                "score":       risk.score,
                "tier":        risk.tier,
                "summary":     risk.summary,
                "breakdown":   risk.by_severity,
                "event_count": risk.event_count,
                "top_sources": risk.top_sources[:5],
                "top_targets": risk.top_targets[:5],
            },
            "protocols":    result.protocol_counts,
            "top_ports":    [{"port": p, "count": c}
                             for p, c in sorted(result.dst_port_counts.items(),
                                                key=lambda x: -x[1])[:20]],
            "top_src_ips":  [{"ip": ip, "count": c}
                             for ip, c in sorted(result.ip_src_counts.items(),
                                                 key=lambda x: -x[1])[:15]],
            "top_dst_ips":  [{"ip": ip, "count": c}
                             for ip, c in sorted(result.ip_dst_counts.items(),
                                                 key=lambda x: -x[1])[:15]],
            "dns_top":      sorted(dns_counts.items(), key=lambda x: -x[1])[:50],
            "http_requests":[{"method": r.get("method", ""), "host": r.get("host", ""),
                               "path": r.get("path", ""),  "src": r.get("src", "")}
                             for r in result.http_requests[:100]],
            "events":       [_ser_event(e) for e in events],
            "chains":       [_ser_chain(c) for c in chains],
            "timeline":     [_ser_tl(e) for e in tl.events[:400]],
            "activity_bar": {
                "buckets":     tl.activity_bar.buckets if tl.activity_bar else [],
                "bucket_secs": round(tl.activity_bar.bucket_secs, 2) if tl.activity_bar else 0,
                "total":       tl.activity_bar.total_events if tl.activity_bar else 0,
            },
            "phases_seen":   tl.phases_seen,
            "fingerprints":  [_ser_fp(f) for f in fps],
            "sigma_rules":   [{"title": r.title, "level": r.level, "yaml": r.raw_yaml}
                              for r in sigma],
            "attributions":  [_ser_attr(a) for a in attrs],
        }

        push(type="complete")
        return data

    except Exception as exc:
        import traceback
        push(type="error", message=f"{type(exc).__name__}: {exc}",
             traceback=traceback.format_exc())
        return None


# ── Background coroutine ──────────────────────────────────────────────────────

async def _analyze_task(job_id: str, pcap_path: str):
    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, _run_analysis, job_id, pcap_path, loop)
    _jobs[job_id]["result"] = data
    _jobs[job_id]["status"] = "complete" if data is not None else "error"
    try:
        Path(pcap_path).unlink(missing_ok=True)
    except Exception:
        pass


# ── Chat helpers ──────────────────────────────────────────────────────────────

_CHAT_SYSTEM = """You are PacketIQ Copilot, an expert AI assistant embedded in a \
network forensics and SOC (Security Operations Centre) analysis platform.

Your expertise covers:
- Network protocol analysis (TCP/IP, DNS, HTTP, SMB, FTP, SMTP, ICMP)
- Threat hunting and incident response
- MITRE ATT&CK framework and kill chain analysis
- Malware indicators: C2 beaconing, DGA, data exfiltration techniques
- Brute force, port scanning, lateral movement detection

Communication style:
- Direct, technical, and actionable — no filler text
- Use SOC terminology precisely (IOC, TTP, TTL, lateral movement, C2, etc.)
- Prioritise findings by business risk and severity
- When uncertain, say so explicitly — analysts rely on accurate confidence levels
- Always end threat assessments with prioritised immediate actions
- Format responses with **bold**, bullet lists, and headers for readability

You have been loaded with the complete automated analysis of a PCAP capture file.
The context contains: capture metadata, protocol stats, top IPs/ports, all detection
events with evidence, correlated attack chains with MITRE mappings, DNS intelligence,
HTTP activity, threat actor attribution, and pre-computed IOCs.

Answer questions as a senior SOC analyst who has reviewed this capture in full.
If something is not in the context, say so rather than speculate."""


def _build_chat_context(result: dict) -> str:
    """Build a structured text context from the serialised result dict for Claude."""
    m = result.get("meta", {})
    r = result.get("risk", {})
    events = result.get("events", [])
    chains = result.get("chains", [])
    attrs  = result.get("attributions", [])

    lines = []

    # Header
    lines += [
        "=== PACKETIQ ANALYSIS CONTEXT ===",
        f"File        : {m.get('filename', '?')}",
        f"Size        : {m.get('bytes_fmt', '?')}  ({m.get('size_mb', 0):.2f} MB)",
        f"Packets     : {m.get('total_packets', 0):,}",
        f"Duration    : {m.get('duration', '?')}",
        f"Capture     : {m.get('capture_start', '?')} → {m.get('capture_end', '?')}",
        f"Risk Score  : {r.get('score', 0)}/100  [{r.get('tier', '?')}]",
        f"Risk Summary: {r.get('summary', '')}",
    ]

    # Capture stats
    lines += [
        "\n=== CAPTURE STATISTICS ===",
        f"Unique Source IPs  : {m.get('unique_src', 0)}",
        f"Unique Dest IPs    : {m.get('unique_dst', 0)}",
        f"External IPs       : {m.get('external_ips', 0)}",
        f"Unique Flows       : {m.get('unique_flows', 0)}",
        f"DNS Queries        : {m.get('dns_queries', 0)}",
        f"HTTP Requests      : {m.get('http_requests', 0)}",
    ]

    # Severity breakdown
    brk = r.get("breakdown", {})
    if brk:
        lines.append("\n=== SEVERITY BREAKDOWN ===")
        for sev, cnt in brk.items():
            lines.append(f"  {sev}: {cnt}")

    # Protocol distribution
    protos = result.get("protocols", {})
    if protos:
        lines.append("\n=== PROTOCOL DISTRIBUTION ===")
        for p, cnt in sorted(protos.items(), key=lambda x: -x[1])[:12]:
            lines.append(f"  {p:<12} {cnt:>8,}")

    # Top source / dest IPs
    top_src = result.get("top_src_ips", [])
    if top_src:
        lines.append("\n=== TOP SOURCE IPs ===")
        for item in top_src[:15]:
            lines.append(f"  {item['ip']:<22} {item['count']:>8,} pkts")

    top_dst = result.get("top_dst_ips", [])
    if top_dst:
        lines.append("\n=== TOP DESTINATION IPs ===")
        for item in top_dst[:15]:
            lines.append(f"  {item['ip']:<22} {item['count']:>8,} pkts")

    # Top ports
    top_ports = result.get("top_ports", [])
    if top_ports:
        lines.append("\n=== TOP DESTINATION PORTS ===")
        for item in top_ports[:15]:
            lines.append(f"  Port {item['port']:<8} {item['count']:>8,} pkts")

    # Detection events
    lines.append(f"\n=== DETECTION EVENTS ({len(events)} total) ===")
    if not events:
        lines.append("  None detected.")
    for i, e in enumerate(events[:60], 1):
        dst = f"{e.get('dst_ip','')}:{e.get('dst_port','')}" if e.get('dst_ip') else "—"
        lines += [
            f"\n[{i}] [{e.get('severity','')}] {e.get('event_type','')}",
            f"    Source      : {e.get('src_ip','—')}",
            f"    Destination : {dst}",
            f"    Protocol    : {e.get('protocol','—')}",
            f"    Confidence  : {e.get('confidence',0)}%",
            f"    Description : {e.get('description','')}",
            f"    Time        : {e.get('ts_str','')}",
        ]
        ev = e.get("evidence", {})
        if ev:
            for k, v in list(ev.items())[:4]:
                lines.append(f"    {k:<16}: {v}")

    # Attack chains
    lines.append(f"\n=== ATTACK CHAINS ({len(chains)} identified) ===")
    if not chains:
        lines.append("  No multi-stage chains correlated.")
    for i, c in enumerate(chains, 1):
        mitre = ", ".join(f"{t['id']} {t['name']}" for t in c.get("mitre", []))
        lines += [
            f"\n[CHAIN {i}] {c.get('name','')}",
            f"  Severity    : {c.get('severity','')}",
            f"  Confidence  : {c.get('confidence',0)}%",
            f"  Events      : {c.get('event_count',0)}",
            f"  Attackers   : {', '.join(c.get('attacker_ips',[]))}",
            f"  Targets     : {', '.join(c.get('target_ips',[]))}",
            f"  Kill Chain  : {' → '.join(c.get('phases',[]))}",
            f"  MITRE       : {mitre}",
            f"  Description : {c.get('description','')}",
        ]

    # DNS top queries
    dns_top = result.get("dns_top", [])
    if dns_top:
        lines.append(f"\n=== TOP DNS QUERIES ===")
        for name, cnt in dns_top[:25]:
            lines.append(f"  {name:<50} {cnt}x")

    # HTTP activity
    http = result.get("http_requests", [])
    if http:
        lines.append(f"\n=== HTTP REQUESTS (first {min(len(http),30)}) ===")
        for req in http[:30]:
            lines.append(f"  {req.get('method','?'):<6} {req.get('src','?'):<18} → {req.get('host','')}{req.get('path','')}")

    # Threat attribution
    if attrs:
        lines.append("\n=== THREAT ACTOR ATTRIBUTION ===")
        for a in attrs:
            lines += [
                f"\n  Actor       : {a.get('name','')}",
                f"  Confidence  : {a.get('confidence',0)}%",
                f"  Origin      : {a.get('origin','')}",
                f"  Motivation  : {a.get('motivation','')}",
                f"  Matched TTPs: {', '.join(a.get('matched_ttps',[]))}",
            ]

    return "\n".join(lines)


def _read_env() -> dict:
    """Read all key=value pairs from .env files."""
    env: dict = {}
    for path in (".", ".."):
        env_file = Path(path) / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip().strip('"').strip("'")
            break
    return env


def _detect_provider(skip: Optional[set] = None) -> dict:
    """
    Detect which AI provider to use, prioritising free ones.
    Returns {"provider": "gemini"|"groq"|"anthropic"|None, "key": str|None, "model": str}
    Priority: GEMINI_API_KEY > GROQ_API_KEY > ANTHROPIC_API_KEY
    Pass skip={"gemini"} to fall through to the next available provider.
    """
    env = _read_env()
    skip = skip or set()

    def get(name: str) -> Optional[str]:
        return os.environ.get(name) or env.get(name)

    if "gemini" not in skip:
        gemini_key = get("GEMINI_API_KEY")
        if gemini_key:
            return {"provider": "gemini", "key": gemini_key, "model": "gemini-2.0-flash"}

    if "groq" not in skip:
        groq_key = get("GROQ_API_KEY")
        if groq_key:
            return {"provider": "groq", "key": groq_key, "model": "llama-3.3-70b-versatile"}

    if "anthropic" not in skip:
        anthropic_key = get("ANTHROPIC_API_KEY")
        if anthropic_key:
            return {"provider": "anthropic", "key": anthropic_key, "model": "claude-sonnet-4-6"}

    return {"provider": None, "key": None, "model": ""}


async def _stream_ai(provider: str, key: str, model: str,
                     system: str, context: str,
                     messages: list) -> "AsyncGenerator[str, None]":
    """Unified async streaming across all providers. Yields text chunks."""
    import warnings, traceback

    if provider == "gemini":
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from google import genai as _genai
            from google.genai import types as _gtypes
        client = _genai.Client(api_key=key)
        system_full = system + "\n\n<pcap_analysis>\n" + context + "\n</pcap_analysis>"
        gemini_msgs = [
            _gtypes.Content(
                role="user" if m["role"] == "user" else "model",
                parts=[_gtypes.Part(text=m["content"])]
            )
            for m in messages
        ]
        async for chunk in await client.aio.models.generate_content_stream(
            model   = model,
            contents= gemini_msgs,
            config  = _gtypes.GenerateContentConfig(
                system_instruction = system_full,
                max_output_tokens  = 2048,
                temperature        = 0.4,
            ),
        ):
            if chunk.text:
                yield chunk.text

    elif provider == "groq":
        from groq import AsyncGroq
        client = AsyncGroq(api_key=key)
        groq_messages = [
            {"role": "system", "content": system + "\n\n<pcap_analysis>\n" + context + "\n</pcap_analysis>"}
        ] + messages
        stream = await client.chat.completions.create(
            model      = model,
            messages   = groq_messages,
            max_tokens = 2048,
            temperature= 0.4,
            stream     = True,
        )
        async for chunk in stream:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text

    elif provider == "anthropic":
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=key)
        system_blocks = [
            {"type": "text", "text": system},
            {"type": "text", "text": f"<pcap_analysis>\n{context}\n</pcap_analysis>",
             "cache_control": {"type": "ephemeral"}},
        ]
        async with client.messages.stream(
            model      = model,
            max_tokens = 2048,
            system     = system_blocks,
            messages   = messages,
        ) as stream:
            async for chunk in stream.text_stream:
                yield chunk


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(title="PacketIQ", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(TEMPLATE.read_text(encoding="utf-8"))

    @app.post("/api/upload")
    async def upload(file: UploadFile = File(...)):
        fname = file.filename or "upload.pcap"
        if not fname.lower().endswith((".pcap", ".pcapng", ".cap")):
            raise HTTPException(400, "Upload a .pcap, .pcapng, or .cap file.")

        content = await file.read()
        size_mb = len(content) / (1024 * 1024)
        if size_mb > MAX_UPLOAD_MB:
            raise HTTPException(413, f"File too large ({size_mb:.0f} MB). Max {MAX_UPLOAD_MB} MB.")
        if len(content) < 24:
            raise HTTPException(400, "File is too small to be a valid PCAP.")

        job_id    = str(uuid.uuid4())
        pcap_path = UPLOAD_DIR / f"{job_id}.pcap"
        pcap_path.write_bytes(content)

        _jobs[job_id] = {
            "status":    "running",
            "queue":     asyncio.Queue(),
            "result":    None,
            "error":     None,
            "filename":  fname,
            "size_mb":   round(size_mb, 2),
            "pcap_path": str(pcap_path),
        }

        asyncio.create_task(_analyze_task(job_id, str(pcap_path)))
        return {"job_id": job_id, "filename": fname, "size_mb": round(size_mb, 2)}

    @app.websocket("/ws/{job_id}")
    async def ws_progress(websocket: WebSocket, job_id: str):
        if job_id not in _jobs:
            await websocket.close(1008)
            return
        await websocket.accept()
        job = _jobs[job_id]

        # Already finished before WS connected
        if job["status"] == "complete":
            await websocket.send_text(json.dumps({"type": "complete"}))
            await websocket.close()
            return
        if job["status"] == "error":
            await websocket.send_text(json.dumps({"type": "error", "message": job.get("error", "Unknown error")}))
            await websocket.close()
            return

        queue = job["queue"]
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=600)
                await websocket.send_text(json.dumps(msg))
                if msg.get("type") in ("complete", "error"):
                    break
        except (asyncio.TimeoutError, WebSocketDisconnect):
            pass
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    @app.get("/api/results/{job_id}")
    async def results(job_id: str):
        if job_id not in _jobs:
            raise HTTPException(404, "Job not found.")
        job = _jobs[job_id]
        if job["status"] == "error":
            raise HTTPException(500, job.get("error") or "Analysis failed.")
        if job["status"] != "complete" or job["result"] is None:
            raise HTTPException(202, "Analysis still in progress.")
        return JSONResponse(job["result"])

    @app.get("/api/sigma/{job_id}/rules.zip")
    async def sigma_download(job_id: str):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        rules = _jobs[job_id]["result"].get("sigma_rules", [])
        if not rules:
            raise HTTPException(404, "No SIGMA rules generated.")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i, r in enumerate(rules):
                zf.writestr(f"rule_{i:03d}_{r['level']}.yml", r["yaml"])
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/zip",
            headers={"Content-Disposition":
                     f'attachment; filename="packetiq_sigma_{job_id[:8]}.zip"'},
        )

    @app.get("/api/chat/{job_id}/status")
    async def chat_status(job_id: str):
        """Check whether AI chat is available and which provider is active."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Job not found or not complete.")
        p = _detect_provider()
        return {
            "available": p["provider"] is not None,
            "provider":  p["provider"],
            "model":     p["model"],
        }

    @app.post("/api/chat/{job_id}")
    async def chat_endpoint(job_id: str, request: Request):
        """Stream an AI response for a chat message about the PCAP analysis."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Job not found or not complete.")

        p = _detect_provider()
        if not p["provider"]:
            raise HTTPException(
                503,
                "No AI API key configured. Add GEMINI_API_KEY (free) or GROQ_API_KEY (free) "
                "to your .env file. See .env.example for setup instructions."
            )

        body = await request.json()
        message: str = body.get("message", "").strip()
        history: list = body.get("history", [])
        if not message:
            raise HTTPException(400, "message is required.")

        result  = _jobs[job_id]["result"]
        context = _build_chat_context(result)
        messages = history + [{"role": "user", "content": message}]

        _LABEL = {"gemini": "Google Gemini", "groq": "Groq", "anthropic": "Anthropic"}

        async def event_stream():
            skipped: set[str] = set()
            current = p

            while current["provider"]:
                label = _LABEL.get(current["provider"], current["provider"])
                try:
                    async for chunk in _stream_ai(
                        current["provider"], current["key"], current["model"],
                        _CHAT_SYSTEM, context, messages
                    ):
                        yield f"data: {json.dumps({'text': chunk})}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                except Exception as exc:
                    msg = str(exc)
                    is_rate_limit = "429" in msg or "RESOURCE_EXHAUSTED" in msg or "quota" in msg.lower()

                    if is_rate_limit:
                        # Try the next configured provider automatically
                        skipped.add(current["provider"])
                        fallback = _detect_provider(skip=skipped)
                        if fallback["provider"]:
                            fallback_label = _LABEL.get(fallback["provider"], fallback["provider"])
                            notice = f"*({label} quota reached — switching to {fallback_label}...)*\n\n"
                            yield f"data: {json.dumps({'text': notice})}\n\n"
                            current = fallback
                            continue
                        # All providers exhausted
                        friendly = (
                            "**All AI providers have hit their rate limits.**\n\n"
                            "Wait a minute and try again, or check your API keys in `.env`."
                        )
                    elif "401" in msg or "invalid" in msg.lower() or "authentication" in msg.lower():
                        friendly = (
                            f"**{label} API key is invalid.**\n\n"
                            "Check your API key in the `.env` file and restart the server."
                        )
                    elif "403" in msg or "permission" in msg.lower():
                        friendly = f"**{label} permission denied.** Check your API key has the correct permissions."
                    else:
                        friendly = f"**AI error ({label}):** {msg[:200]}"
                    yield f"data: {json.dumps({'error': friendly})}\n\n"
                    return

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app
