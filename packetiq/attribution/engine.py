"""
Threat Actor Attribution Engine.

Scores detected TTPs against known threat actor profiles and returns
ranked attribution matches with confidence percentages.

Scoring algorithm:
  For each actor, sum the weights of TTPs that were detected.
  Divide by the max possible score for that actor → normalized confidence.
  Apply a phase coverage bonus (detected kill chain phases ∩ actor phases).
  Return actors above MIN_CONFIDENCE threshold, ranked by score.
"""

from dataclasses import dataclass

from packetiq.detection.models import DetectionEvent, EventType
from packetiq.correlation.models import AttackChain
from packetiq.attribution.actors import THREAT_ACTORS

MIN_CONFIDENCE = 0.20   # 20% minimum to surface an attribution
PHASE_BONUS    = 0.10   # +10% for each overlapping kill chain phase (max 0.30)


@dataclass
class AttributionMatch:
    actor_name:   str
    aliases:      list[str]
    origin:       str
    motivation:   str
    confidence:   float        # 0.0 – 1.0
    matched_ttps: list[str]    # EventType values that matched
    phases:       set[str]
    description:  str
    icon:         str
    color:        str
    mitre_group:  str
    target_sectors: list[str]


class AttributionEngine:

    def attribute(
        self,
        events: list[DetectionEvent],
        chains: list[AttackChain],
    ) -> list[AttributionMatch]:
        """Score events + chains against all actor profiles, return matches."""
        detected_types: set[EventType] = {e.event_type for e in events}

        # Collect kill chain phases from chains
        detected_phases: set[str] = set()
        for ch in chains:
            detected_phases.update(ch.kill_chain_phases)
        # Also from events directly
        from packetiq.correlation.mitre import EVENT_TYPE_KILL_CHAIN
        for et in detected_types:
            ph = EVENT_TYPE_KILL_CHAIN.get(et, "")
            if ph:
                detected_phases.add(ph)

        matches: list[AttributionMatch] = []

        for actor in THREAT_ACTORS:
            weights   = actor["ttp_weights"]
            max_score = sum(weights.values())
            if max_score == 0:
                continue

            matched: dict[EventType, float] = {}
            for et, weight in weights.items():
                if et in detected_types:
                    matched[et] = weight

            raw_score = sum(matched.values())
            confidence = raw_score / max_score

            # Phase overlap bonus (capped at 3 phases × 10%)
            phase_overlap = detected_phases & actor["phases"]
            bonus = min(len(phase_overlap) * PHASE_BONUS, 0.30)
            confidence = min(confidence + bonus, 1.0)

            if confidence < MIN_CONFIDENCE:
                continue

            matches.append(AttributionMatch(
                actor_name   = actor["name"],
                aliases      = actor["aliases"],
                origin       = actor["origin"],
                motivation   = actor["motivation"],
                confidence   = round(confidence, 3),
                matched_ttps = [et.value for et in matched],
                phases       = actor["phases"],
                description  = actor["description"],
                icon         = actor["icon"],
                color        = actor["color"],
                mitre_group  = actor["mitre_group"],
                target_sectors = actor["target_sectors"],
            ))

        matches.sort(key=lambda m: -m.confidence)
        return matches
