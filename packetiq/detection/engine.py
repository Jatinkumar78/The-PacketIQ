"""
Detection Engine — orchestrates all detectors and produces a unified
list of DetectionEvents + a RiskReport.

Two-pass design:
  Pass 1 (flow-based): runs on ExtractionResult — brute force, port scan,
                        DNS anomaly, protocol misuse.
  Pass 2 (payload-based): streams packets a second time — credential exposure.

Usage:
    engine = DetectionEngine()
    events, risk, fingerprints = engine.run(extraction_result, pcap_path)
"""

from packetiq.detection import brute_force, port_scan, dns_anomaly, protocol_misuse
from packetiq.detection import credential, beacon, ja3
from packetiq.detection import risk_scorer
from packetiq.detection.fingerprint import Fingerprint, detect as fingerprint_detect
from packetiq.detection.models import DetectionEvent
from packetiq.detection.risk_scorer import RiskReport
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.parser.pcap_parser import PCAPParser


class DetectionEngine:

    def run(
        self,
        result: ExtractionResult,
        pcap_path: str,
        *,
        progress_callback=None,
    ) -> tuple[list[DetectionEvent], RiskReport, list[Fingerprint]]:
        """
        Run all detectors and return (events, risk_report).

        progress_callback: optional callable(step_name: str) for UI updates.
        """
        events: list[DetectionEvent] = []

        def _step(name: str):
            if progress_callback:
                progress_callback(name)

        # ── Pass 1: Flow-based detectors ─────────────────────────────────
        _step("brute_force")
        events.extend(brute_force.detect(result))

        _step("port_scan")
        events.extend(port_scan.detect(result))

        _step("dns_anomaly")
        events.extend(dns_anomaly.detect(result))

        _step("protocol_misuse")
        events.extend(protocol_misuse.detect(result))

        _step("beacon_analysis")
        events.extend(beacon.BeaconDetector().detect(result))

        # ── Pass 2: Payload-based detectors (second PCAP stream) ─────────
        _step("credential_exposure")
        try:
            parser = PCAPParser(pcap_path)
            events.extend(credential.detect_from_stream(parser.stream()))
        except Exception:
            pass

        _step("ja3_fingerprinting")
        try:
            parser2 = PCAPParser(pcap_path)
            events.extend(ja3.JA3Detector().detect_from_stream(parser2.stream()))
        except Exception:
            pass

        # ── Passive OS fingerprinting (informational) ─────────────────────
        _step("os_fingerprinting")
        fingerprints = fingerprint_detect(result)

        # ── Risk scoring ──────────────────────────────────────────────────
        _step("risk_scoring")
        risk = risk_scorer.score(events)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        events.sort(key=lambda e: (severity_order.get(e.severity.value, 9), e.timestamp))

        return events, risk, fingerprints
