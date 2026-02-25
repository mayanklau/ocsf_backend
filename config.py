"""
OCSF Processor Configuration
Agentic SOC v3 Integration Settings
"""
import os
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, Dict, List


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Config
# ═══════════════════════════════════════════════════════════════════════════════

class Settings(BaseModel):
    """Global application settings."""
    
    APP_NAME: str = "OCSF Universal Processor"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8900"))
    WORKERS: int = int(os.getenv("WORKERS", "4"))
    
    # Redis (for pipeline queues, caching, Bead Memory)
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_QUEUE_DB: int = int(os.getenv("REDIS_QUEUE_DB", "1"))
    REDIS_BEAD_DB: int = int(os.getenv("REDIS_BEAD_DB", "2"))
    
    # Pipeline
    BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "500"))
    BATCH_TIMEOUT_MS: int = int(os.getenv("BATCH_TIMEOUT_MS", "2000"))
    MAX_QUEUE_SIZE: int = int(os.getenv("MAX_QUEUE_SIZE", "100000"))
    
    # Agent Endpoints (Agentic SOC v3)
    AGENT_DETECTION_URL: str = os.getenv("AGENT_DETECTION_URL", "http://localhost:8001/api/v1/detect")
    AGENT_TRIAGE_URL: str = os.getenv("AGENT_TRIAGE_URL", "http://localhost:8002/api/v1/triage")
    AGENT_THREAT_INTEL_URL: str = os.getenv("AGENT_THREAT_INTEL_URL", "http://localhost:8003/api/v1/enrich")
    AGENT_INVESTIGATION_URL: str = os.getenv("AGENT_INVESTIGATION_URL", "http://localhost:8004/api/v1/investigate")
    AGENT_RESPONSE_URL: str = os.getenv("AGENT_RESPONSE_URL", "http://localhost:8005/api/v1/respond")
    AGENT_HUNTING_URL: str = os.getenv("AGENT_HUNTING_URL", "http://localhost:8006/api/v1/hunt")
    AGENT_FORENSICS_URL: str = os.getenv("AGENT_FORENSICS_URL", "http://localhost:8007/api/v1/forensics")
    AGENT_COMPLIANCE_URL: str = os.getenv("AGENT_COMPLIANCE_URL", "http://localhost:8008/api/v1/compliance")
    
    # Bead Memory
    BEAD_MEMORY_ENABLED: bool = os.getenv("BEAD_MEMORY_ENABLED", "true").lower() == "true"
    BEAD_CORRELATION_WINDOW_SEC: int = int(os.getenv("BEAD_CORRELATION_WINDOW_SEC", "3600"))
    BEAD_CHAIN_MAX_LENGTH: int = int(os.getenv("BEAD_CHAIN_MAX_LENGTH", "50"))
    
    # Syslog Listener
    SYSLOG_UDP_PORT: int = int(os.getenv("SYSLOG_UDP_PORT", "5514"))
    SYSLOG_TCP_PORT: int = int(os.getenv("SYSLOG_TCP_PORT", "5515"))
    SYSLOG_ENABLED: bool = os.getenv("SYSLOG_ENABLED", "false").lower() == "true"
    
    # Webhook Output
    WEBHOOK_URLS: List[str] = []
    WEBHOOK_TIMEOUT: int = int(os.getenv("WEBHOOK_TIMEOUT", "10"))
    
    # Storage / Export
    OUTPUT_ELASTICSEARCH_URL: str = os.getenv("OUTPUT_ES_URL", "")
    OUTPUT_ELASTICSEARCH_INDEX: str = os.getenv("OUTPUT_ES_INDEX", "ocsf-events")
    OUTPUT_FILE_PATH: str = os.getenv("OUTPUT_FILE_PATH", "")
    OUTPUT_KAFKA_BOOTSTRAP: str = os.getenv("OUTPUT_KAFKA_BOOTSTRAP", "")
    OUTPUT_KAFKA_TOPIC: str = os.getenv("OUTPUT_KAFKA_TOPIC", "ocsf-events")


settings = Settings()


# ═══════════════════════════════════════════════════════════════════════════════
# OCSF Schema Constants (v1.1)
# ═══════════════════════════════════════════════════════════════════════════════

class OCSFCategory(int, Enum):
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


OCSF_CLASSES = {
    # System Activity
    1001: "File System Activity",
    1002: "Kernel Extension Activity",
    1003: "Kernel Activity",
    1004: "Memory Activity",
    1005: "Module Activity",
    1006: "Scheduled Job Activity",
    1007: "Process Activity",
    # Findings
    2001: "Security Finding",
    2002: "Vulnerability Finding",
    2003: "Compliance Finding",
    2004: "Detection Finding",
    # IAM
    3001: "Account Change",
    3002: "Authentication",
    3003: "Authorize Session",
    3004: "Entity Management",
    3005: "User Access Management",
    3006: "Group Management",
    # Network
    4001: "Network Activity",
    4002: "HTTP Activity",
    4003: "DNS Activity",
    4004: "DHCP Activity",
    4005: "RDP Activity",
    4006: "SMB Activity",
    4007: "SSH Activity",
    4008: "FTP Activity",
    4009: "Email Activity",
    4010: "Email File Activity",
    4011: "Email URL Activity",
    4012: "NTP Activity",
    4013: "Tunnel Activity",
    # Discovery
    5001: "Device Inventory Info",
    5002: "Device Config State",
    5003: "User Inventory Info",
    5004: "OS Patch State",
    # Application
    6001: "Web Resources Activity",
    6002: "Application Lifecycle",
    6003: "API Activity",
    6004: "Web Resource Access Activity",
}

OCSF_SEVERITY = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
    99: "Other",
}

OCSF_ACTIVITY = {
    0: "Unknown",
    1: "Create",
    2: "Read",
    3: "Update",
    4: "Delete",
    5: "Rename",
    6: "Other",
}

OCSF_STATUS = {
    0: "Unknown",
    1: "Success",
    2: "Failure",
    99: "Other",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Agent Routing Rules
# ═══════════════════════════════════════════════════════════════════════════════

class AgentRoute(BaseModel):
    """Defines when an OCSF event should be routed to a specific agent."""
    agent_name: str
    endpoint: str
    priority: int = 5  # 1=highest
    conditions: Dict = {}


# Default routing rules based on OCSF classification
DEFAULT_AGENT_ROUTES = {
    "detection": AgentRoute(
        agent_name="Detection Agent",
        endpoint=settings.AGENT_DETECTION_URL,
        priority=1,
        conditions={"all_events": True}  # Everything goes through detection
    ),
    "triage": AgentRoute(
        agent_name="Triage Agent",
        endpoint=settings.AGENT_TRIAGE_URL,
        priority=2,
        conditions={"min_severity": 3, "categories": [2]}  # Findings with Medium+
    ),
    "threat_intel": AgentRoute(
        agent_name="Threat Intelligence Agent",
        endpoint=settings.AGENT_THREAT_INTEL_URL,
        priority=2,
        conditions={"has_observables": True, "observable_types": [2, 7, 8]}  # IPs, URLs, Hashes
    ),
    "investigation": AgentRoute(
        agent_name="Investigation Agent",
        endpoint=settings.AGENT_INVESTIGATION_URL,
        priority=3,
        conditions={"min_severity": 4, "categories": [2, 3]}  # High+ Findings & IAM
    ),
    "response": AgentRoute(
        agent_name="Response Agent",
        endpoint=settings.AGENT_RESPONSE_URL,
        priority=4,
        conditions={"min_severity": 5}  # Critical+ auto-response
    ),
    "hunting": AgentRoute(
        agent_name="Hunting Agent",
        endpoint=settings.AGENT_HUNTING_URL,
        priority=3,
        conditions={"categories": [1, 4], "suspicious_patterns": True}
    ),
    "forensics": AgentRoute(
        agent_name="Forensics Agent",
        endpoint=settings.AGENT_FORENSICS_URL,
        priority=4,
        conditions={"min_severity": 4, "has_process": True}
    ),
    "compliance": AgentRoute(
        agent_name="Compliance Agent",
        endpoint=settings.AGENT_COMPLIANCE_URL,
        priority=5,
        conditions={"categories": [3], "class_uids": [2003, 3001, 3005]}
    ),
}
