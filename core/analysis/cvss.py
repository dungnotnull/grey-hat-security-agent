"""CVSS v3.1 calculator — FIXED with proper Roundup function.

The CVSS v3.1 specification requires a "Roundup" function that rounds UP
to 1 decimal place (not standard rounding). This is critical for matching
NIST published scores.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional


class CVSS3Metric:
    """CVSS v3.1 metric value mappings."""
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC = {"L": 0.77, "H": 0.44}
    PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI = {"N": 0.85, "R": 0.62}
    S = {"U": 0.0, "C": 1.0}
    CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
    E = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
    RL = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
    RC = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}
    IAR = {"X": 1.0, "N": 0.0, "L": 0.22, "H": 0.56}
    MAV = {"X": None, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    MAC = {"X": None, "L": 0.77, "H": 0.44}
    MPR_UNCHANGED = {"X": None, "N": 0.85, "L": 0.62, "H": 0.27}
    MPR_CHANGED = {"X": None, "N": 0.85, "L": 0.68, "H": 0.50}
    MUI = {"X": None, "N": 0.85, "R": 0.62}
    MS = {"X": None, "U": False, "C": True}
    MCIA = {"X": None, "N": 0.0, "L": 0.22, "H": 0.56}
    SEVERITY_RATING = [
        (0.0, 0.0, "None"),
        (0.1, 3.9, "Low"),
        (4.0, 6.9, "Medium"),
        (7.0, 8.9, "High"),
        (9.0, 10.0, "Critical"),
    ]


def roundup1(x: float) -> float:
    """CVSS v3.1 Roundup: round UP to 1 decimal place.
    
    This is NOT the same as standard rounding. Per the CVSS v3.1 spec,
    'Roundup' returns the smallest number, to one decimal place, 
    that is equal to or higher than the input.
    
    Example: 3.03 → 3.1 (not 3.0)
    Example: 9.8 → 9.8
    Example: 7.5 → 7.5
    """
    return math.ceil(x * 10) / 10


@dataclass
class CVSS3Vector:
    """Parsed CVSS v3.1 vector string."""
    av: str = "N"
    ac: str = "L"
    pr: str = "N"
    ui: str = "N"
    s: str = "U"
    c: str = "N"
    i: str = "N"
    a: str = "N"
    e: str = "X"
    rl: str = "X"
    rc: str = "X"
    cr: str = "X"
    ir: str = "X"
    ar: str = "X"
    mav: str = "X"
    mac: str = "X"
    mpr: str = "X"
    mui: str = "X"
    ms: str = "X"
    mc: str = "X"
    mi: str = "X"
    ma: str = "X"

    def to_vector_string(self) -> str:
        parts = [f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"]
        if self.e != "X" or self.rl != "X" or self.rc != "X":
            parts.append(f"E:{self.e}/RL:{self.rl}/RC:{self.rc}")
        if any(getattr(self, f) != "X" for f in ["cr", "ir", "ar", "mav", "mac", "mpr", "mui", "ms", "mc", "mi", "ma"]):
            parts.append(f"CR:{self.cr}/IR:{self.ir}/AR:{self.ar}/MAV:{self.mav}/MAC:{self.mac}/MPR:{self.mpr}/MUI:{self.mui}/MS:{self.ms}/MC:{self.mc}/MI:{self.mi}/MA:{self.ma}")
        return "/".join(parts)


def parse_vector_string(vector_string: str) -> CVSS3Vector:
    """Parse a CVSS v3.1 vector string into a CVSS3Vector object."""
    if not vector_string.startswith("CVSS:3.1/"):
        raise ValueError(f"Invalid CVSS v3.1 vector string: must start with 'CVSS:3.1/'")
    parts = vector_string.replace("CVSS:3.1/", "").split("/")
    metrics = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    return CVSS3Vector(
        av=metrics.get("AV", "N"), ac=metrics.get("AC", "L"), pr=metrics.get("PR", "N"),
        ui=metrics.get("UI", "N"), s=metrics.get("S", "U"), c=metrics.get("C", "N"),
        i=metrics.get("I", "N"), a=metrics.get("A", "N"), e=metrics.get("E", "X"),
        rl=metrics.get("RL", "X"), rc=metrics.get("RC", "X"), cr=metrics.get("CR", "X"),
        ir=metrics.get("IR", "X"), ar=metrics.get("AR", "X"), mav=metrics.get("MAV", "X"),
        mac=metrics.get("MAC", "X"), mpr=metrics.get("MPR", "X"), mui=metrics.get("MUI", "X"),
        ms=metrics.get("MS", "X"), mc=metrics.get("MC", "X"), mi=metrics.get("MI", "X"),
        ma=metrics.get("MA", "X"),
    )


def calculate_base_score(vector: CVSS3Vector) -> tuple[float, str]:
    """Calculate CVSS v3.1 base score using Roundup function per spec."""
    m = CVSS3Metric
    scope_changed = vector.s == "C"
    iss = 1 - ((1 - m.CIA[vector.c]) * (1 - m.CIA[vector.i]) * (1 - m.CIA[vector.a]))
    
    if scope_changed:
        impact = 7.52 * (iss - 0.012) - 3.25 * (iss - 0.012) ** 15
    else:
        impact = 6.42 * iss

    pr_map = m.PR_CHANGED if scope_changed else m.PR_UNCHANGED
    exploitability = 8.22 * m.AV[vector.av] * m.AC[vector.ac] * pr_map[vector.pr] * m.UI[vector.ui]

    if impact <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = roundup1(min(10.0, 1.08 * (impact + exploitability)))
    else:
        base_score = roundup1(min(10.0, impact + exploitability))

    severity = "None"
    if base_score > 0:
        for low, high, sev in m.SEVERITY_RATING:
            if low <= base_score <= high:
                severity = sev
                break

    return base_score, severity


def calculate_temporal_score(vector: CVSS3Vector) -> tuple[float, str]:
    """Calculate CVSS v3.1 temporal score."""
    m = CVSS3Metric
    base_score, _ = calculate_base_score(vector)
    temporal = roundup1(base_score * m.E[vector.e] * m.RL[vector.rl] * m.RC[vector.rc])
    
    severity = "None"
    if temporal > 0:
        for low, high, sev in m.SEVERITY_RATING:
            if low <= temporal <= high:
                severity = sev
                break
    return temporal, severity


def calculate_environmental_score(vector: CVSS3Vector) -> tuple[float, str]:
    """Calculate CVSS v3.1 environmental score."""
    m = CVSS3Metric
    scope_changed = vector.s == "C"
    av_val = m.MAV[vector.mav] if vector.mav != "X" else m.AV[vector.av]
    ac_val = m.MAC[vector.mac] if vector.mac != "X" else m.AC[vector.ac]
    pr_val = (m.MPR_CHANGED if (vector.ms != "X" and vector.ms == "C") else m.MPR_UNCHANGED)[vector.mpr] if vector.mpr != "X" else (m.PR_CHANGED if scope_changed else m.PR_UNCHANGED)[vector.pr]
    ui_val = m.MUI[vector.mui] if vector.mui != "X" else m.UI[vector.ui]
    ms_changed = (vector.ms == "C") if vector.ms != "X" else scope_changed
    mc_val = m.MCIA[vector.mc] if vector.mc != "X" else m.CIA[vector.c]
    mi_val = m.MCIA[vector.mi] if vector.mi != "X" else m.CIA[vector.i]
    ma_val = m.MCIA[vector.ma] if vector.ma != "X" else m.CIA[vector.a]
    cr_val = m.IAR[vector.cr] if vector.cr != "X" else 1.0
    ir_val = m.IAR[vector.ir] if vector.ir != "X" else 1.0
    ar_val = m.IAR[vector.ar] if vector.ar != "X" else 1.0

    miss = min(1 - (1 - cr_val * mc_val) * (1 - ir_val * mi_val) * (1 - ar_val * ma_val), 0.915)
    if ms_changed:
        modified_impact = 7.52 * (miss - 0.012) - 3.25 * (miss - 0.012) ** 15
    else:
        modified_impact = 6.42 * miss
    modified_exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if modified_impact <= 0:
        env_score = 0.0
    elif ms_changed:
        env_score = roundup1(min(10.0, 1.08 * (modified_impact + modified_exploitability)))
    else:
        env_score = roundup1(min(10.0, modified_impact + modified_exploitability))

    env_score = roundup1(env_score * m.E[vector.e] * m.RL[vector.rl] * m.RC[vector.rc])
    
    severity = "None"
    if env_score > 0:
        for low, high, sev in m.SEVERITY_RATING:
            if low <= env_score <= high:
                severity = sev
                break
    return env_score, severity


def calculate_all_scores(vector_string: str) -> dict:
    """Calculate all CVSS v3.1 scores from a vector string."""
    vector = parse_vector_string(vector_string)
    base_score, base_severity = calculate_base_score(vector)
    temporal_score, temporal_severity = calculate_temporal_score(vector)
    env_score, env_severity = calculate_environmental_score(vector)
    return {
        "vector_string": vector_string,
        "base_score": base_score,
        "base_severity": base_severity,
        "temporal_score": temporal_score,
        "temporal_severity": temporal_severity,
        "environmental_score": env_score,
        "environmental_severity": env_severity,
    }
