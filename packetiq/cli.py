"""
PacketIQ CLI — Entry point for all commands.

Usage:
    packetiq analyze <file.pcap>
    packetiq report  <file.pcap>
    packetiq chat    <file.pcap>
    packetiq version
"""

import sys
import click
from pathlib import Path

from packetiq.display.terminal import TerminalUI
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.detection.engine import DetectionEngine
from packetiq.detection.models import Severity
from packetiq.correlation.engine import CorrelationEngine
from packetiq.utils.helpers import format_bytes, format_duration


def _run_pipeline(pcap_path: Path, ui: TerminalUI, quiet: bool = False) -> tuple:
    """
    Shared parse → extract → detect → correlate pipeline.
    Returns (file_meta, result, events, risk, chains, fingerprints).
    quiet=True suppresses section headers (used by fuse command).
    """
    if not quiet:
        ui.print_status(f"Target: {pcap_path}", status="info")
        ui.print_status(f"Size:   {format_bytes(pcap_path.stat().st_size)}", status="info")

    # ── Parse ─────────────────────────────────────────────────
    if not quiet:
        ui.print_section("PCAP PARSING", "layer 1 — packet ingestion")
    try:
        parser = PCAPParser(str(pcap_path))
    except FileNotFoundError as e:
        ui.print_status(str(e), status="error")
        sys.exit(1)

    extractor = DataExtractor()
    packet_count = 0

    with ui.make_progress("Parsing packets...") as progress:
        task = progress.add_task("Parsing packets...", total=None)
        for record in parser.stream():
            extractor.feed(record)
            packet_count += 1
            if packet_count % 1000 == 0:
                progress.update(task, description=f"Parsed {packet_count:,} packets...")

    result = extractor.finalize()
    file_meta = parser.file_summary()
    file_meta["packet_count"] = packet_count
    if not quiet:
        ui.print_status(f"Parsed {packet_count:,} packets successfully.", status="ok")

    # ── Detect ────────────────────────────────────────────────
    if not quiet:
        ui.print_section("THREAT DETECTION", "running all detectors")
    engine = DetectionEngine()
    detection_steps = {
        "brute_force":        "Brute force detector...",
        "port_scan":          "Port scan detector...",
        "dns_anomaly":        "DNS anomaly detector...",
        "protocol_misuse":    "Protocol misuse detector...",
        "beacon_analysis":    "Beacon periodicity analysis...",
        "credential_exposure":"Credential exposure scan...",
        "ja3_fingerprinting": "JA3/JA3S TLS fingerprinting...",
        "os_fingerprinting":  "Passive OS fingerprinting...",
        "risk_scoring":       "Computing risk score...",
    }
    with ui.make_progress() as progress:
        task = progress.add_task("Running detectors...", total=len(detection_steps))

        def _cb(step_name: str):
            label = detection_steps.get(step_name, step_name)
            progress.update(task, description=label, advance=1)

        events, risk, fingerprints = engine.run(result, str(pcap_path), progress_callback=_cb)

    if not quiet:
        ui.print_status(
            f"{len(events)} event(s) | Risk: {risk.score}/100 [{risk.tier}]",
            status="warn" if events else "ok",
        )

    # ── Correlate ─────────────────────────────────────────────
    if not quiet:
        ui.print_section("ATTACK CORRELATION", "linking events into chains")
    correlator = CorrelationEngine()
    chains = correlator.correlate(events)
    if not quiet:
        ui.print_status(
            f"{len(chains)} attack chain(s) identified.",
            status="warn" if chains else "ok",
        )

    return file_meta, result, events, risk, chains, fingerprints


ui = TerminalUI()


# ──────────────────────────────────────────────────────────────────────────────
# Root group
# ──────────────────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def main(ctx):
    """
    \b
    PacketIQ — AI PCAP Forensics & SOC Copilot
    Defensive network intelligence for SOC analysts.
    """
    ui.print_banner()
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ──────────────────────────────────────────────────────────────────────────────
# analyze command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("analyze")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--top", "-t", default=10, show_default=True,
              help="Number of top entries to show in each table.")
@click.option("--full", is_flag=True, default=False,
              help="Show all rows (no truncation).")
@click.option("--alert/--no-alert", default=False,
              help="Send Telegram alerts for HIGH/CRITICAL findings.")
@click.option("--alert-threshold",
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
              default="HIGH", show_default=True,
              help="Minimum severity level to alert on.")
@click.option("--timeline/--no-timeline", default=True, show_default=True,
              help="Show attack timeline reconstruction.")
def analyze(pcap_file: str, top: int, full: bool, alert: bool, alert_threshold: str, timeline: bool):
    """
    Parse and analyze a PCAP file.

    \b
    Example:
        packetiq analyze capture.pcap
        packetiq analyze capture.pcap --top 20
        packetiq analyze capture.pcap --alert
        packetiq analyze capture.pcap --alert --alert-threshold CRITICAL
    """
    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    # ── Summary panel ──────────────────────────────────────────────────
    ui.print_section("CAPTURE SUMMARY")
    meta = DataExtractor.capture_metadata(result)
    ui.print_summary_panel("CAPTURE METADATA", meta)

    # ── Protocol distribution ──────────────────────────────────────────
    ui.print_section("PROTOCOL DISTRIBUTION")
    proto_rows = sorted(result.protocol_counts.items(), key=lambda x: x[1], reverse=True)
    total_pkts = result.total_packets or 1
    proto_table_rows = [
        [proto, f"{cnt:,}", f"{(cnt/total_pkts)*100:.1f}%"]
        for proto, cnt in proto_rows
    ]
    ui.print_table(
        "Protocol Breakdown",
        columns=[
            ("Protocol",   "bold green",  "left"),
            ("Packets",    "cyan",        "right"),
            ("% of Total", "dim white",   "right"),
        ],
        rows=proto_table_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top talkers (source IPs) ───────────────────────────────────────
    ui.print_section("TOP TALKERS", "source IPs by packet volume")
    talkers = DataExtractor.top_talkers(result, n=top)
    talker_rows = [
        [t["ip"], f"{t['packets']:,}", f"{(t['packets']/total_pkts)*100:.1f}%",
         "INTERNAL" if _is_private(t["ip"]) else "EXTERNAL"]
        for t in talkers
    ]
    ui.print_table(
        f"Top {top} Source IPs",
        columns=[
            ("IP Address",  "bold green", "left"),
            ("Packets",     "cyan",       "right"),
            ("% Traffic",   "dim white",  "right"),
            ("Scope",       "yellow",     "center"),
        ],
        rows=talker_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top destinations ───────────────────────────────────────────────
    ui.print_section("TOP DESTINATIONS", "destination IPs by packet volume")
    dests = DataExtractor.top_destinations(result, n=top)
    dest_rows = [
        [d["ip"], f"{d['packets']:,}", "INTERNAL" if _is_private(d["ip"]) else "EXTERNAL"]
        for d in dests
    ]
    ui.print_table(
        f"Top {top} Destination IPs",
        columns=[
            ("IP Address", "bold green", "left"),
            ("Packets",    "cyan",       "right"),
            ("Scope",      "yellow",     "center"),
        ],
        rows=dest_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top destination ports ──────────────────────────────────────────
    ui.print_section("PORT ACTIVITY", "destination ports by packet count")
    ports = DataExtractor.top_ports(result, n=top)
    port_rows = [
        [str(p["port"]), p["service"], f"{p['packets']:,}"]
        for p in ports
    ]
    ui.print_table(
        f"Top {top} Destination Ports",
        columns=[
            ("Port",    "bold green", "right"),
            ("Service", "cyan",       "left"),
            ("Packets", "dim white",  "right"),
        ],
        rows=port_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top flows ─────────────────────────────────────────────────────
    ui.print_section("TOP FLOWS", "bidirectional sessions by byte volume")
    flows = DataExtractor.top_flows(result, n=top)
    flow_rows = [
        [
            fl.src_ip,
            str(fl.src_port or "*"),
            fl.dst_ip,
            str(fl.dst_port or "*"),
            fl.protocol,
            fl.service,
            f"{fl.packets:,}",
            format_bytes(fl.bytes_total),
            format_duration(fl.duration),
        ]
        for fl in flows
    ]
    ui.print_table(
        f"Top {top} Flows",
        columns=[
            ("Src IP",    "green",     "left"),
            ("Sport",     "dim white", "right"),
            ("Dst IP",    "cyan",      "left"),
            ("Dport",     "dim white", "right"),
            ("Proto",     "yellow",    "center"),
            ("Service",   "magenta",   "left"),
            ("Pkts",      "dim white", "right"),
            ("Bytes",     "bold cyan", "right"),
            ("Duration",  "dim white", "right"),
        ],
        rows=flow_rows,
        max_rows=top if not full else 9999,
    )

    # ── DNS summary ───────────────────────────────────────────────────
    if result.dns_queries:
        ui.print_section("DNS ACTIVITY", f"{len(result.dns_queries)} queries captured")
        # Deduplicate and count
        dns_counts: dict = {}
        for q in result.dns_queries:
            dns_counts[q["qname"]] = dns_counts.get(q["qname"], 0) + 1
        dns_rows = sorted(dns_counts.items(), key=lambda x: x[1], reverse=True)
        ui.print_table(
            "DNS Query Names",
            columns=[
                ("Domain",  "bold green", "left"),
                ("Queries", "cyan",       "right"),
            ],
            rows=[[d, str(c)] for d, c in dns_rows],
            max_rows=top if not full else 9999,
        )

    # ── HTTP summary ──────────────────────────────────────────────────
    if result.http_requests:
        ui.print_section("HTTP ACTIVITY", f"{len(result.http_requests)} requests captured")
        http_rows = [
            [
                r["method"] or "?",
                r["host"]   or "?",
                r["path"]   or "/",
                r["src"]    or "?",
            ]
            for r in result.http_requests[:top]
        ]
        ui.print_table(
            "HTTP Requests",
            columns=[
                ("Method", "bold yellow", "center"),
                ("Host",   "bold green",  "left"),
                ("Path",   "cyan",        "left"),
                ("From",   "dim white",   "left"),
            ],
            rows=http_rows,
            max_rows=top if not full else 9999,
        )

    # ── External IPs note ─────────────────────────────────────────────
    if result.external_ips:
        ui.print_section("EXTERNAL IP CONTACTS")
        ext_rows = sorted(result.external_ips)
        ui.print_table(
            "External IPs Observed",
            columns=[("IP Address", "bold red", "left")],
            rows=[[ip] for ip in ext_rows],
            max_rows=top if not full else 9999,
        )

    # ── Risk Score Banner ─────────────────────────────────────────────
    ui.print_section("RISK ASSESSMENT")
    risk_data = {
        "Overall Risk Score": f"{risk.score}/100",
        "Risk Tier":          risk.tier,
        "Total Events":       str(risk.event_count),
        "Critical":           str(risk.by_severity.get("CRITICAL", 0)),
        "High":               str(risk.by_severity.get("HIGH", 0)),
        "Medium":             str(risk.by_severity.get("MEDIUM", 0)),
        "Low":                str(risk.by_severity.get("LOW", 0)),
    }
    if risk.top_sources:
        risk_data["Top Attacker IPs"] = ", ".join(risk.top_sources[:3])
    if risk.top_targets:
        risk_data["Top Target IPs"]   = ", ".join(risk.top_targets[:3])

    ui.print_summary_panel(f"RISK SCORE: {risk.score}/100 [{risk.tier}]", risk_data)

    if risk.summary:
        ui.print_alert(risk.tier, risk.summary)

    # ── Detection Events Table ────────────────────────────────────────
    if events:
        ui.print_section("DETECTION EVENTS", f"{len(events)} findings")
        sev_colors = {
            "CRITICAL": "bold red",
            "HIGH":     "bold yellow",
            "MEDIUM":   "bold cyan",
            "LOW":      "bold green",
        }
        event_rows = []
        for e in events:
            sev_tag = f"[{sev_colors.get(e.severity.value, 'white')}]{e.severity.value}[/{sev_colors.get(e.severity.value, 'white')}]"
            dst_info = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
            event_rows.append([
                e.severity.value,
                e.event_type.value.replace("_", " "),
                e.src_ip or "—",
                dst_info,
                e.description[:72] + ("…" if len(e.description) > 72 else ""),
            ])

        ui.print_table(
            "Threat Intelligence Findings",
            columns=[
                ("Severity",    "bold white", "center"),
                ("Type",        "yellow",     "left"),
                ("Source IP",   "red",        "left"),
                ("Destination", "cyan",       "left"),
                ("Description", "dim white",  "left"),
            ],
            rows=event_rows,
            max_rows=top if not full else 9999,
        )
    else:
        ui.print_status("No threats detected in this capture.", status="ok")

    # ── Correlation Engine ────────────────────────────────────────────
    ui.print_section("ATTACK CORRELATION", "linking events into attack chains")

    if chains:
        ui.print_status(f"{len(chains)} attack chain(s) identified.", status="warn")

        for i, chain in enumerate(chains, 1):
            sev_color = {
                "CRITICAL": "red", "HIGH": "yellow",
                "MEDIUM": "cyan",  "LOW": "green",
            }.get(chain.severity.value, "white")

            # Chain header panel
            chain_data = {
                "Chain ID":         chain.chain_id,
                "Severity":         chain.severity.value,
                "Confidence":       f"{chain.confidence * 100:.0f}%",
                "Events Linked":    str(chain.event_count),
                "Attacker IPs":     ", ".join(sorted(chain.attacker_ips)) or "—",
                "Target IPs":       ", ".join(sorted(chain.target_ips)) or "—",
                "Kill Chain Phases": " → ".join(chain.kill_chain_phases) if chain.kill_chain_phases else "—",
                "Primary Phase":    chain.primary_phase or "—",
            }

            # MITRE ATT&CK techniques
            if chain.mitre_techniques:
                techs = "; ".join(
                    f"{t.technique_id} ({t.technique_name})"
                    for t in chain.mitre_techniques[:6]
                )
                chain_data["MITRE Techniques"] = techs

            ui.print_summary_panel(
                f"CHAIN {i}/{len(chains)}: {chain.name}",
                chain_data,
            )

            # Description and analyst note
            ui.print_raw(f"  [dim white]{chain.description}[/dim white]")
            if chain.analyst_note:
                ui.print_raw(f"\n  [bold yellow]► ANALYST NOTE:[/bold yellow]")
                ui.print_raw(f"  [yellow]{chain.analyst_note}[/yellow]")

            # Linked events mini-table
            if chain.events:
                ev_rows = [
                    [
                        e.severity.value,
                        e.event_type.value.replace("_", " "),
                        e.src_ip or "—",
                        f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—"),
                        e.description[:60] + ("…" if len(e.description) > 60 else ""),
                    ]
                    for e in chain.events
                ]
                ui.print_table(
                    "Linked Events",
                    columns=[
                        ("Sev",         "bold white", "center"),
                        ("Type",        "yellow",     "left"),
                        ("Source",      "red",        "left"),
                        ("Target",      "cyan",       "left"),
                        ("Description", "dim white",  "left"),
                    ],
                    rows=ev_rows,
                    max_rows=8 if not full else 9999,
                )
            ui.print_divider(char="·")

    else:
        ui.print_status("No multi-stage attack chains correlated.", status="ok")

    # ── OS Fingerprints ───────────────────────────────────────────────
    if fingerprints:
        ui.print_section("PASSIVE OS FINGERPRINTS", f"{len(fingerprints)} host(s) identified")
        fp_rows = [
            [f.src_ip, f"{f.os_icon} {f.os_guess}", str(f.observed_ttl),
             str(f.initial_ttl), str(f.hops), "EXTERNAL" if f.is_external else "internal"]
            for f in fingerprints[:top]
        ]
        ui.print_table(
            "Device OS Signatures",
            columns=[
                ("Source IP",    "bold green", "left"),
                ("OS Guess",     "cyan",       "left"),
                ("Observed TTL", "dim white",  "right"),
                ("Initial TTL",  "dim white",  "right"),
                ("Hops",         "dim white",  "right"),
                ("Scope",        "yellow",     "center"),
            ],
            rows=fp_rows,
            max_rows=top if not full else 9999,
        )

    # ── Timeline Engine ───────────────────────────────────────────────
    if timeline:
        ui.print_section("ATTACK TIMELINE", "chronological event reconstruction")
        from packetiq.timeline import TimelineBuilder, TimelineRenderer
        tl = TimelineBuilder().build(result, events, chains)
        TimelineRenderer(ui).render(tl, max_events=60 if not full else 9999)

    # ── Telegram Alerts ───────────────────────────────────────────────
    if alert:
        _send_telegram_alerts(
            pcap_path=pcap_path,
            result=result,
            events=events,
            chains=chains,
            risk=risk,
            threshold=alert_threshold,
        )

    # ── Done ──────────────────────────────────────────────────────────
    ui.print_divider()
    ui.print_status(
        f"Analysis complete — {len(events)} events | "
        f"{len(chains)} chain(s) | Risk: {risk.score}/100 [{risk.tier}]",
        status="ok",
    )
    ui.print_status("Run 'packetiq report' to generate a full SOC report.", status="info")
    ui.print_divider()


# ──────────────────────────────────────────────────────────────────────────────
# report command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("report")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None,
              help="Output file path for the report (default: report_<name>_<ts>.md).")
@click.option("--alert/--no-alert", default=False,
              help="Send Telegram alerts + attach report file after generation.")
def report(pcap_file: str, out: str, alert: bool):
    """
    Run full analysis and generate an AI SOC report.

    \b
    Example:
        packetiq report capture.pcap
        packetiq report capture.pcap --out /tmp/incident_report.md
        packetiq report capture.pcap --alert
    """
    from packetiq.copilot import CopilotClient, build_context, load_api_key

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("AI SOC REPORT GENERATION", "powered by Claude")

    api_key = load_api_key()
    if not api_key:
        ui.print_status(
            "ANTHROPIC_API_KEY not found. Set it in .env or export in shell.",
            status="error",
        )
        sys.exit(1)

    ui.print_status("Building PCAP context for AI...", status="loading")
    context = build_context(file_meta, result, events, chains, risk.score, risk.tier)

    try:
        client = CopilotClient(api_key=api_key)
        client.load_context(context)
    except Exception as e:
        ui.print_status(f"Copilot init failed: {e}", status="error")
        sys.exit(1)

    ui.print_status("Generating SOC report (this may take 30–60 seconds)...", status="loading")

    from packetiq.copilot.prompts import SLASH_PROMPTS
    try:
        report_text = client.single_message(SLASH_PROMPTS["report"])
    except Exception as e:
        ui.print_status(f"Report generation failed: {e}", status="error")
        sys.exit(1)

    # Save report
    if out:
        out_path = Path(out)
    else:
        from datetime import datetime
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = pcap_path.stem
        out_path = pcap_path.parent / f"report_{stem}_{ts}.md"

    out_path.write_text(report_text, encoding="utf-8")
    ui.print_status(f"Report saved: {out_path.resolve()}", status="ok")

    if alert:
        _send_telegram_alerts(
            pcap_path   = pcap_path,
            result      = result,
            events      = events,
            chains      = chains,
            risk        = risk,
            threshold   = "HIGH",
            report_path = str(out_path),
        )

    ui.print_divider()


# ──────────────────────────────────────────────────────────────────────────────
# chat command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("chat")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
def chat(pcap_file: str):
    """
    Run full analysis then open an AI chat session about the PCAP.

    \b
    Example:
        packetiq chat capture.pcap
    """
    from packetiq.copilot import CopilotClient, build_context, load_api_key, InteractiveChat

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("AI COPILOT", "loading analysis context")

    api_key = load_api_key()
    if not api_key:
        ui.print_status(
            "ANTHROPIC_API_KEY not found. Set it in .env or export it in your shell.",
            status="error",
        )
        sys.exit(1)

    ui.print_status("Building PCAP context for AI (prompt caching enabled)...", status="loading")
    context = build_context(file_meta, result, events, chains, risk.score, risk.tier)
    ui.print_status(
        f"Context built: {len(context):,} chars | {len(context.split()) :,} tokens (approx).",
        status="ok",
    )

    try:
        client = CopilotClient(api_key=api_key)
        client.load_context(context)
    except Exception as e:
        ui.print_status(f"Copilot init failed: {e}", status="error")
        sys.exit(1)

    ui.print_status("Copilot ready. Starting interactive session.", status="ok")

    session = InteractiveChat(
        client     = client,
        pcap_name  = pcap_path.name,
        report_dir = str(pcap_path.parent),
    )
    session.run()


@main.command("timeline")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--full", is_flag=True, default=False,
              help="Show all timeline events (no truncation).")
def timeline_cmd(pcap_file: str, full: bool):
    """
    Run full analysis and display the attack timeline.

    \b
    Example:
        packetiq timeline capture.pcap
    """
    from packetiq.timeline import TimelineBuilder, TimelineRenderer

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("ATTACK TIMELINE", "chronological event reconstruction")
    tl = TimelineBuilder().build(result, events, chains)
    TimelineRenderer(ui).render(tl, max_events=9999 if full else 80)

    ui.print_divider()
    ui.print_status(
        f"Timeline: {len(tl.events)} events | {len(tl.phases_seen)} kill chain phase(s) | "
        f"{len(tl.pivot_points)} pivot(s)",
        status="ok",
    )
    ui.print_divider()


@main.command("sigma")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None,
              help="Directory to write .yml rule files (default: print to stdout).")
@click.option("--min-level", default="medium",
              type=click.Choice(["low","medium","high","critical"], case_sensitive=False),
              show_default=True, help="Minimum severity level to generate rules for.")
def sigma_cmd(pcap_file: str, out: str, min_level: str):
    """
    Generate SIGMA detection rules from PCAP analysis.

    \b
    Example:
        packetiq sigma capture.pcap
        packetiq sigma capture.pcap --out ./sigma_rules/
        packetiq sigma capture.pcap --min-level high
    """
    from packetiq.sigma import SigmaGenerator

    level_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_ord     = level_order[min_level.lower()]

    pcap_path = Path(pcap_file).resolve()
    _, _, events, _, chains, _ = _run_pipeline(pcap_path, ui)

    ui.print_section("SIGMA RULE GENERATOR")
    gen   = SigmaGenerator()
    rules = [r for r in gen.generate(events, chains) if level_order.get(r.level, 0) >= min_ord]
    ui.print_status(f"Generated {len(rules)} SIGMA rule(s) (min level: {min_level.upper()})", status="ok")

    if not out:
        for r in rules:
            ui.print_raw(f"\n[bold cyan]─── {r.title} [{r.level.upper()}] ───[/bold cyan]")
            ui.print_raw(f"[dim white]{r.raw_yaml}[/dim white]")
    else:
        import os
        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, r in enumerate(rules):
            filename = out_dir / f"packetiq_{i:03d}_{r.level}.yml"
            filename.write_text(r.raw_yaml, encoding="utf-8")
        ui.print_status(f"Wrote {len(rules)} rule files → {out_dir.resolve()}", status="ok")

    ui.print_divider()


@main.command("dashboard")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--port", "-p", default=8080, show_default=True,
              help="Port to serve the dashboard on.")
@click.option("--no-browser", is_flag=True, default=False,
              help="Don't open the browser automatically.")
def dashboard(pcap_file: str, port: int, no_browser: bool):
    """
    Launch the interactive 3D web dashboard for a PCAP file.

    \b
    Runs the full analysis pipeline and serves a real-time hacker-themed
    web dashboard at http://localhost:<port>/

    Example:
        packetiq dashboard capture.pcap
        packetiq dashboard capture.pcap --port 9090
    """
    from packetiq.dashboard.server import launch_dashboard

    pcap_path = Path(pcap_file).resolve()
    ui.print_status(
        f"Launching dashboard for {pcap_path.name} → http://127.0.0.1:{port}/",
        status="info",
    )
    launch_dashboard(str(pcap_path), port=port, open_browser=not no_browser)


@main.command("fuse")
@click.argument("pcap_files", nargs=-1, required=True,
                type=click.Path(exists=True, readable=True))
@click.option("--top", "-t", default=10, show_default=True)
@click.option("--full", is_flag=True, default=False)
def fuse(pcap_files, top: int, full: bool):
    """
    Fuse multiple PCAP files into a unified campaign timeline.

    Deduplicates events by attacker IP + event type across captures,
    merges attack chains, and produces a single consolidated analysis.

    \b
    Example:
        packetiq fuse day1.pcap day2.pcap day3.pcap
        packetiq fuse *.pcap --full
    """
    from packetiq.timeline import TimelineBuilder, TimelineRenderer
    from packetiq.correlation.engine import CorrelationEngine

    if len(pcap_files) < 2:
        ui.print_status("Provide at least 2 PCAP files to fuse.", status="error")
        return

    ui.print_section("MULTI-PCAP CAMPAIGN FUSION", f"{len(pcap_files)} capture(s)")

    all_events: list = []
    all_chains: list = []
    all_results: list = []
    earliest_ts = float("inf")
    latest_ts   = 0.0

    for pcap_file in pcap_files:
        pcap_path = Path(pcap_file).resolve()
        ui.print_status(f"Processing: {pcap_path.name}", status="loading")
        try:
            _, result, events, risk, chains, fps = _run_pipeline(pcap_path, ui, quiet=True)
            all_events.extend(events)
            all_chains.extend(chains)
            all_results.append(result)
            if result.capture_start: earliest_ts = min(earliest_ts, result.capture_start)
            if result.capture_end:   latest_ts   = max(latest_ts, result.capture_end)
            ui.print_status(
                f"  {pcap_path.name}: {len(events)} events, {len(chains)} chains, Risk {risk.score}/100",
                status="ok",
            )
        except Exception as e:
            ui.print_status(f"  Failed: {pcap_path.name} — {e}", status="error")

    # ── Deduplicate events ────────────────────────────────────────────────────
    ui.print_section("CAMPAIGN FUSION", "deduplicating across captures")
    seen_keys: set = set()
    deduped: list  = []
    for ev in sorted(all_events, key=lambda e: e.timestamp):
        key = (ev.event_type, ev.src_ip, ev.dst_ip, ev.dst_port)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(ev)

    # ── Re-correlate merged events ────────────────────────────────────────────
    merged_chains = CorrelationEngine().correlate(deduped)

    from packetiq.detection.risk_scorer import score as risk_score
    campaign_risk = risk_score(deduped)

    duration = max(0.0, latest_ts - earliest_ts)
    ui.print_summary_panel("CAMPAIGN SUMMARY", {
        "PCAP Files Fused":   str(len(pcap_files)),
        "Total Events":       str(len(all_events)),
        "Deduplicated Events":str(len(deduped)),
        "Attack Chains":      str(len(merged_chains)),
        "Campaign Risk":      f"{campaign_risk.score}/100 [{campaign_risk.tier}]",
        "Campaign Duration":  format_duration(duration),
        "Unique Attackers":   str(len({e.src_ip for e in deduped if e.src_ip})),
    })

    # ── Build merged extraction result for timeline ───────────────────────────
    if all_results:
        merged_result = all_results[0]
        merged_result.capture_start = earliest_ts
        merged_result.capture_end   = latest_ts
        for r in all_results[1:]:
            merged_result.dns_queries.extend(r.dns_queries)
            merged_result.http_requests.extend(r.http_requests)

        ui.print_section("CAMPAIGN TIMELINE", "unified event reconstruction")
        tl = TimelineBuilder().build(merged_result, deduped, merged_chains)
        TimelineRenderer(ui).render(tl, max_events=9999 if full else 80)

    # ── Attribution across campaign ───────────────────────────────────────────
    from packetiq.attribution.engine import AttributionEngine
    attrs = AttributionEngine().attribute(deduped, merged_chains)
    if attrs:
        ui.print_section("CAMPAIGN ATTRIBUTION", "threat actor analysis")
        for a in attrs[:3]:
            bar = "█" * int(a.confidence * 20) + "░" * (20 - int(a.confidence * 20))
            ui.print_raw(
                f"  {a.icon} [{a.color}]{a.actor_name:<22}[/{a.color}]  "
                f"[green]{bar}[/green]  "
                f"[bold white]{int(a.confidence*100):3d}%[/bold white]  "
                f"[dim]{a.origin}[/dim]"
            )

    ui.print_divider()
    ui.print_status(
        f"Campaign fusion complete — {len(pcap_files)} PCAP(s) | "
        f"{len(deduped)} events | {len(merged_chains)} chain(s) | "
        f"Risk {campaign_risk.score}/100",
        status="ok",
    )
    ui.print_divider()


@main.command("version")
def version():
    """Show PacketIQ version."""
    from packetiq import __version__
    ui.print_status(f"PacketIQ v{__version__}", status="ok")


# ──────────────────────────────────────────────────────────────────────────────
# alert group  (packetiq alert setup | packetiq alert test)
# ──────────────────────────────────────────────────────────────────────────────

@main.group("alert")
def alert_group():
    """Manage Telegram alert configuration."""


@alert_group.command("setup")
def alert_setup():
    """
    Test Telegram credentials and send a verification message.

    \b
    Reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from .env or shell env.
    Example:
        packetiq alert setup
    """
    from packetiq.alerts import TelegramSender, load_credentials

    ui.print_section("TELEGRAM ALERT SETUP")

    token, chat_id = load_credentials()

    if not token:
        ui.print_status("TELEGRAM_BOT_TOKEN not found in .env or environment.", status="error")
        ui.print_status("Get one from @BotFather on Telegram.", status="info")
        sys.exit(1)

    if not chat_id:
        ui.print_status("TELEGRAM_CHAT_ID not found in .env or environment.", status="error")
        ui.print_status(
            "To find your chat ID: send a message to your bot, then visit "
            "https://api.telegram.org/bot<TOKEN>/getUpdates",
            status="info",
        )
        sys.exit(1)

    ui.print_status(f"Token found: {token[:12]}{'*' * (len(token) - 12)}", status="info")
    ui.print_status(f"Chat ID: {chat_id}", status="info")
    ui.print_status("Testing connection...", status="loading")

    sender = TelegramSender(token, chat_id)
    ok, msg = sender.test_connection()

    if ok:
        ui.print_status(f"Connection OK — {msg}", status="ok")
        ui.print_status("A test message has been sent to your Telegram chat.", status="ok")
    else:
        ui.print_status(f"Connection FAILED — {msg}", status="error")
        sys.exit(1)


@alert_group.command("test")
@click.argument("message", default="PacketIQ test alert fired successfully.")
def alert_test(message: str):
    """Send a custom test message to your Telegram chat."""
    from packetiq.alerts import TelegramSender, load_credentials

    token, chat_id = load_credentials()
    if not token or not chat_id:
        ui.print_status("Telegram credentials not configured. Run 'packetiq alert setup'.", status="error")
        sys.exit(1)

    sender = TelegramSender(token, chat_id)
    ok, err = sender.send(f"🔔 <b>PacketIQ Test Alert</b>\n\n{message}")
    if ok:
        ui.print_status("Test message sent successfully.", status="ok")
    else:
        ui.print_status(f"Send failed: {err}", status="error")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    from packetiq.utils.helpers import is_private_ip
    return is_private_ip(ip)


def _send_telegram_alerts(
    pcap_path,
    result,
    events,
    chains,
    risk,
    threshold: str = "HIGH",
    report_path=None,
):
    """Dispatch Telegram alerts after analysis. Called by analyze and report commands."""
    from packetiq.alerts import TelegramSender, AlertDispatcher, load_credentials
    from packetiq.detection.models import Severity

    ui.print_section("TELEGRAM ALERTS", f"threshold: {threshold}")

    token, chat_id = load_credentials()
    if not token or not chat_id:
        ui.print_status(
            "Telegram credentials not configured. "
            "Add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to .env or run 'packetiq alert setup'.",
            status="warn",
        )
        return

    try:
        sev_threshold = Severity[threshold.upper()]
    except KeyError:
        sev_threshold = Severity.HIGH

    sender     = TelegramSender(token, chat_id)
    dispatcher = AlertDispatcher(sender, threshold=sev_threshold)

    ui.print_status(f"Sending alerts to Telegram (chat: {chat_id})...", status="loading")

    dr = dispatcher.dispatch(
        file_name   = pcap_path.name,
        risk        = risk,
        events      = events,
        chains      = chains,
        result      = result,
        report_path = report_path,
    )

    if dr.ok:
        ui.print_status(
            f"Alerts sent: {dr.sent} message(s) | {dr.skipped} skipped.",
            status="ok",
        )
    else:
        ui.print_status(
            f"Alert dispatch partial: {dr.sent} sent, {dr.failed} failed.",
            status="warn",
        )
        for err in dr.errors[:3]:
            ui.print_status(f"  Error: {err}", status="error")


@main.command("webapp")
@click.option("--port", "-p", default=8080, show_default=True,
              help="Port to serve the web application on.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Host to bind to. Use 0.0.0.0 to expose on all interfaces.")
@click.option("--no-browser", is_flag=True, default=False,
              help="Don't open the browser automatically.")
def webapp(port: int, host: str, no_browser: bool):
    """
    Launch the PacketIQ web application.

    \b
    Upload any PCAP file in your browser and get a full real-time analysis:
    threat detection, attack chains, SIGMA rules, attribution, and more.

    Example:
        packetiq webapp
        packetiq webapp --port 9090
        packetiq webapp --host 0.0.0.0 --port 8080
    """
    import uvicorn
    import webbrowser
    import threading
    from packetiq.webapp import create_app

    url = f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/"
    ui.print_status(f"PacketIQ Web App → {url}", status="info")
    ui.print_status("Upload a PCAP file in your browser to begin analysis.", status="info")
    ui.print_status("Press Ctrl+C to stop.", status="info")

    if not no_browser:
        def _open():
            import time; time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        create_app(), host=host, port=port, log_level="warning",
        limit_max_requests=None,
        timeout_keep_alive=600,   # 10 min — large uploads take time
        h11_max_incomplete_event_size=10 * 1024 * 1024 * 1024,  # 10 GB
    )


if __name__ == "__main__":
    main()
