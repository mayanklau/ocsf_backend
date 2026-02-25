"""
Universal Log Format Auto-Detector
Identifies 20+ log formats from raw input using pattern matching.
"""
import re
import json
from enum import Enum
from typing import Optional, Tuple
from loguru import logger


class LogFormat(str, Enum):
    CEF = "CEF"
    LEEF = "LEEF"
    SYSLOG_RFC5424 = "SYSLOG_RFC5424"
    SYSLOG_RFC3164 = "SYSLOG_RFC3164"
    WINDOWS_EVENT = "WINDOWS_EVENT"
    WINDOWS_SYSMON = "WINDOWS_SYSMON"
    AWS_CLOUDTRAIL = "AWS_CLOUDTRAIL"
    AWS_VPC_FLOW = "AWS_VPC_FLOW"
    AWS_GUARDDUTY = "AWS_GUARDDUTY"
    AZURE_ACTIVITY = "AZURE_ACTIVITY"
    AZURE_SIGNIN = "AZURE_SIGNIN"
    GCP_AUDIT = "GCP_AUDIT"
    PALO_ALTO = "PALO_ALTO"
    FORTINET = "FORTINET"
    CHECKPOINT = "CHECKPOINT"
    CROWDSTRIKE_EDR = "CROWDSTRIKE_EDR"
    SENTINEL_ONE = "SENTINEL_ONE"
    CARBON_BLACK = "CARBON_BLACK"
    MS_DEFENDER = "MS_DEFENDER"
    SPLUNK_JSON = "SPLUNK_JSON"
    ELASTIC_ECS = "ELASTIC_ECS"
    QRADAR = "QRADAR"
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    OKTA = "OKTA"
    GENERIC_JSON = "GENERIC_JSON"
    CSV = "CSV"
    KEY_VALUE = "KEY_VALUE"
    UNKNOWN = "UNKNOWN"


# ═══════════════════════════════════════════════════════════════════════════════
# Detection Rules (ordered by specificity - most specific first)
# ═══════════════════════════════════════════════════════════════════════════════

DETECTION_RULES = [
    # ── Structured Formats (Header-based) ──
    {
        "format": LogFormat.CEF,
        "pattern": re.compile(r"^CEF:\d\|"),
        "confidence": 0.99,
    },
    {
        "format": LogFormat.LEEF,
        "pattern": re.compile(r"^LEEF:\d\.\d\|"),
        "confidence": 0.99,
    },
    
    # ── Syslog ──
    {
        "format": LogFormat.SYSLOG_RFC5424,
        "pattern": re.compile(r"^<\d{1,3}>\d\s\d{4}-\d{2}-\d{2}T"),
        "confidence": 0.95,
    },
    {
        "format": LogFormat.SYSLOG_RFC3164,
        "pattern": re.compile(
            r"^(?:<\d{1,3}>)?"
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
        ),
        "confidence": 0.90,
    },
    
    # ── Firewall (CSV-based) ──
    {
        "format": LogFormat.PALO_ALTO,
        "pattern": re.compile(r"^(?:TRAFFIC|THREAT|SYSTEM|CONFIG|HIP-MATCH|GLOBALPROTECT|DECRYPTION),"),
        "confidence": 0.95,
    },
    
    # ── VPC Flow (space-delimited) ──
    {
        "format": LogFormat.AWS_VPC_FLOW,
        "pattern": re.compile(r"^\d+\s+\d+\s+eni-[a-f0-9]+"),
        "confidence": 0.98,
    },
    
    # ── Zeek (tab-separated with #fields header or known structure) ──
    {
        "format": LogFormat.ZEEK,
        "pattern": re.compile(r"^#separator|^\d+\.\d+\t"),
        "confidence": 0.90,
    },
]


def _try_json(raw: str) -> Optional[dict]:
    """Attempt to parse raw input as JSON."""
    try:
        return json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _detect_json_format(data: dict) -> Tuple[LogFormat, float]:
    """Detect log format from parsed JSON object."""
    
    # AWS CloudTrail
    if data.get("eventSource", "").endswith("amazonaws.com") or (
        "userIdentity" in data and "awsRegion" in data
    ):
        return LogFormat.AWS_CLOUDTRAIL, 0.97
    
    # AWS GuardDuty
    if data.get("type", "").startswith(("Recon:", "UnauthorizedAccess:", "Trojan:", "CryptoCurrency:")):
        return LogFormat.AWS_GUARDDUTY, 0.95
    
    # Azure Activity Log
    if "callerIpAddress" in data and "operationName" in data and "category" in data:
        return LogFormat.AZURE_ACTIVITY, 0.93
    
    # Azure Sign-in
    if "conditionalAccessStatus" in data or (
        "appDisplayName" in data and "authenticationDetails" in data
    ):
        return LogFormat.AZURE_SIGNIN, 0.93
    
    # GCP Audit Log
    if (data.get("protoPayload", {}).get("@type", "").endswith("AuditLog") or
        "cloudaudit" in data.get("logName", "")):
        return LogFormat.GCP_AUDIT, 0.95
    
    # Windows Sysmon (JSON export)
    if data.get("SourceName") == "Microsoft-Windows-Sysmon" or (
        "RuleName" in data and "UtcTime" in data
    ):
        return LogFormat.WINDOWS_SYSMON, 0.95
    
    # Windows Event Log
    if ("EventID" in data or 
        data.get("System", {}).get("EventID") is not None or
        data.get("Event", {}).get("System") is not None or
        "Microsoft-Windows" in data.get("ProviderName", "")):
        return LogFormat.WINDOWS_EVENT, 0.90
    
    # CrowdStrike Falcon
    if "event_simpleName" in data or (
        "aid" in data and ("ComputerName" in data or "DetectName" in data)
    ):
        return LogFormat.CROWDSTRIKE_EDR, 0.95
    
    # SentinelOne
    if "agentDetectionInfo" in data or "threatInfo" in data or (
        "indicators" in data and "agentRealtimeInfo" in data
    ):
        return LogFormat.SENTINEL_ONE, 0.94
    
    # Carbon Black
    if "device_name" in data and "org_key" in data and (
        "alert_type" in data or "process_name" in data
    ):
        return LogFormat.CARBON_BLACK, 0.93
    
    # Microsoft Defender
    if "AlertId" in data and "DetectionSource" in data and "MitreTechniques" in data:
        return LogFormat.MS_DEFENDER, 0.95
    
    # Suricata EVE
    if "event_type" in data and data.get("event_type") in (
        "alert", "dns", "http", "tls", "flow", "fileinfo", "ssh", "smtp"
    ):
        return LogFormat.SURICATA, 0.94
    
    # Okta
    if "eventType" in data and "actor" in data and "debugContext" in data:
        return LogFormat.OKTA, 0.95
    
    # Fortinet (JSON)
    if "devid" in data and ("logid" in data or "action" in data) and "type" in data:
        return LogFormat.FORTINET, 0.90
    
    # Check Point (JSON)
    if "product" in data and "blade_name" in data:
        return LogFormat.CHECKPOINT, 0.90
    
    # Splunk JSON
    if "_raw" in data or (
        "source" in data and "sourcetype" in data
    ) or "result" in data:
        return LogFormat.SPLUNK_JSON, 0.80
    
    # Elastic ECS
    if "@timestamp" in data and (
        "ecs" in data or data.get("event", {}).get("kind") is not None or
        data.get("agent", {}).get("type") is not None
    ):
        return LogFormat.ELASTIC_ECS, 0.88
    
    # QRadar
    if "QIDNAME" in data or "LOGSOURCENAME" in data or "CATEGORYNAME" in data:
        return LogFormat.QRADAR, 0.92
    
    # Generic JSON fallback
    return LogFormat.GENERIC_JSON, 0.50


def _detect_text_format(raw: str) -> Tuple[LogFormat, float]:
    """Detect format from unstructured text."""
    stripped = raw.strip()
    
    # Pattern-based detection
    for rule in DETECTION_RULES:
        if rule["pattern"].search(stripped):
            return rule["format"], rule["confidence"]
    
    # Check for CSV
    lines = stripped.split("\n")
    if len(lines) >= 2:
        header_commas = lines[0].count(",")
        data_commas = lines[1].count(",")
        if header_commas >= 2 and header_commas == data_commas:
            return LogFormat.CSV, 0.70
    
    # Check for key=value
    kv_matches = re.findall(r'\w+="[^"]*"|\w+=\S+', stripped)
    if len(kv_matches) >= 3:
        # Fortinet KV
        if "devname=" in stripped or "devid=" in stripped:
            return LogFormat.FORTINET, 0.88
        # Check Point KV
        if "product=" in stripped and "blade_name=" in stripped:
            return LogFormat.CHECKPOINT, 0.85
        return LogFormat.KEY_VALUE, 0.60
    
    return LogFormat.UNKNOWN, 0.10


def detect_format(raw: str, hint: Optional[str] = None) -> Tuple[LogFormat, float]:
    """
    Auto-detect log format from raw input.
    
    Returns:
        Tuple of (LogFormat, confidence_score)
    """
    if hint:
        try:
            return LogFormat(hint.upper()), 1.0
        except ValueError:
            pass
    
    raw_stripped = raw.strip()
    if not raw_stripped:
        return LogFormat.UNKNOWN, 0.0
    
    # Try JSON first
    data = _try_json(raw_stripped)
    if data and isinstance(data, dict):
        fmt, conf = _detect_json_format(data)
        logger.debug(f"Detected JSON format: {fmt} (confidence: {conf})")
        return fmt, conf
    
    # Text-based detection
    fmt, conf = _detect_text_format(raw_stripped)
    logger.debug(f"Detected text format: {fmt} (confidence: {conf})")
    return fmt, conf


def detect_bulk_format(raw_lines: list[str]) -> dict[str, int]:
    """Detect formats across multiple log lines."""
    counts = {}
    for line in raw_lines:
        if line.strip():
            fmt, _ = detect_format(line)
            counts[fmt.value] = counts.get(fmt.value, 0) + 1
    return counts
