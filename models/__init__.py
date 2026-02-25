"""
OCSF v1.1 Pydantic Models
Full schema definitions for Agentic SOC pipeline
"""
from __future__ import annotations
import uuid
import time
from enum import IntEnum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator


# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════

class SeverityID(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class StatusID(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class ActivityID(IntEnum):
    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    RENAME = 5
    OTHER = 6


class ObservableTypeID(IntEnum):
    UNKNOWN = 0
    HOSTNAME = 1
    IP_ADDRESS = 2
    MAC_ADDRESS = 3
    USER_NAME = 4
    EMAIL = 5
    URL = 6
    FILE_NAME = 7
    FILE_HASH = 8
    PROCESS_NAME = 9
    RESOURCE_UID = 10
    DOMAIN_NAME = 11
    SUBNET = 12
    USER_AGENT = 13


# ═══════════════════════════════════════════════════════════════════════════════
# Sub-Objects
# ═══════════════════════════════════════════════════════════════════════════════

class HashModel(BaseModel):
    algorithm: str = "SHA-256"
    value: str = ""


class FileModel(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    type_id: Optional[int] = None
    hashes: Optional[List[HashModel]] = None
    uid: Optional[str] = None


class ProcessModel(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    uid: Optional[str] = None
    cmd_line: Optional[str] = None
    file: Optional[FileModel] = None
    parent_process: Optional[ProcessModel] = None
    created_time: Optional[str] = None
    user: Optional[UserModel] = None


class UserModel(BaseModel):
    name: Optional[str] = None
    uid: Optional[str] = None
    type: Optional[str] = None
    type_id: Optional[int] = None
    domain: Optional[str] = None
    email_addr: Optional[str] = None
    groups: Optional[List[Dict[str, Any]]] = None
    credential_uid: Optional[str] = None


class EndpointModel(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    domain: Optional[str] = None
    subnet_uid: Optional[str] = None
    interface_uid: Optional[str] = None
    location: Optional[Dict[str, Any]] = None


class DeviceModel(BaseModel):
    hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    os: Optional[Dict[str, Any]] = None
    type: Optional[str] = None
    type_id: Optional[int] = None
    uid: Optional[str] = None
    domain: Optional[str] = None
    hw_info: Optional[Dict[str, Any]] = None
    agent_list: Optional[List[Dict[str, Any]]] = None


class ActorModel(BaseModel):
    user: Optional[UserModel] = None
    process: Optional[ProcessModel] = None
    session: Optional[Dict[str, Any]] = None
    authorizations: Optional[List[Dict[str, Any]]] = None
    idp: Optional[Dict[str, Any]] = None


class NetworkConnectionInfo(BaseModel):
    protocol_name: Optional[str] = None
    protocol_num: Optional[int] = None
    direction: Optional[str] = None
    direction_id: Optional[int] = None
    uid: Optional[str] = None


class TrafficModel(BaseModel):
    bytes: Optional[int] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    packets: Optional[int] = None
    packets_in: Optional[int] = None
    packets_out: Optional[int] = None


class DNSQueryModel(BaseModel):
    hostname: Optional[str] = None
    type: Optional[str] = None
    class_: Optional[str] = Field(None, alias="class")
    opcode: Optional[str] = None


class DNSAnswerModel(BaseModel):
    type: Optional[str] = None
    rdata: Optional[str] = None
    ttl: Optional[int] = None


class HTTPRequestModel(BaseModel):
    method: Optional[str] = None
    url: Optional[str] = None
    version: Optional[str] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    http_headers: Optional[List[Dict[str, str]]] = None


class HTTPResponseModel(BaseModel):
    code: Optional[int] = None
    message: Optional[str] = None
    content_type: Optional[str] = None
    latency: Optional[int] = None


class ObservableModel(BaseModel):
    name: str
    type: str
    type_id: int
    value: str
    reputation: Optional[Dict[str, Any]] = None


class MITREAttackModel(BaseModel):
    tactic: Optional[Dict[str, Any]] = None
    technique: Optional[Dict[str, Any]] = None
    sub_technique: Optional[Dict[str, Any]] = None
    version: Optional[str] = None


class FindingInfoModel(BaseModel):
    title: Optional[str] = None
    desc: Optional[str] = None
    uid: Optional[str] = None
    types: Optional[List[str]] = None
    src_url: Optional[str] = None
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    first_seen_time: Optional[str] = None
    last_seen_time: Optional[str] = None
    attacks: Optional[List[MITREAttackModel]] = None
    analytic: Optional[Dict[str, Any]] = None
    kill_chain: Optional[List[Dict[str, Any]]] = None
    evidences: Optional[List[Dict[str, Any]]] = None
    data_sources: Optional[List[str]] = None
    related_events: Optional[List[Dict[str, Any]]] = None


class EvidenceModel(BaseModel):
    hash: Optional[HashModel] = None
    file: Optional[FileModel] = None
    process: Optional[ProcessModel] = None
    data: Optional[Dict[str, Any]] = None


class ProductModel(BaseModel):
    name: Optional[str] = None
    vendor_name: Optional[str] = None
    version: Optional[str] = None
    uid: Optional[str] = None
    lang: Optional[str] = None
    feature: Optional[Dict[str, Any]] = None


class MetadataModel(BaseModel):
    version: str = "1.1.0"
    product: Optional[ProductModel] = None
    original_time: Optional[str] = None
    processed_time: Optional[str] = None
    log_name: Optional[str] = None
    log_provider: Optional[str] = None
    log_version: Optional[str] = None
    profiles: List[str] = ["security"]
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_uid: Optional[str] = None
    labels: Optional[List[str]] = None
    logged_time: Optional[str] = None
    sequence: Optional[int] = None


# Forward ref resolution
ProcessModel.model_rebuild()


# ═══════════════════════════════════════════════════════════════════════════════
# Core OCSF Event
# ═══════════════════════════════════════════════════════════════════════════════

class OCSFEvent(BaseModel):
    """
    Universal OCSF v1.1 Base Event.
    All events in the Agentic SOC pipeline use this structure.
    """
    # ── Classification ──
    activity_id: int = 0
    activity_name: Optional[str] = None
    category_uid: int = 0
    category_name: Optional[str] = None
    class_uid: int = 0
    class_name: Optional[str] = None
    type_uid: Optional[int] = None
    type_name: Optional[str] = None
    
    # ── Occurrence ──
    time: int = Field(default_factory=lambda: int(time.time() * 1000))
    start_time: Optional[int] = None
    end_time: Optional[int] = None
    duration: Optional[int] = None
    timezone_offset: Optional[int] = None
    
    # ── Context ──
    severity_id: int = 0
    severity: Optional[str] = None
    status_id: int = 0
    status: Optional[str] = None
    status_detail: Optional[str] = None
    status_code: Optional[str] = None
    message: Optional[str] = None
    count: int = 1
    confidence_id: Optional[int] = None
    confidence: Optional[str] = None
    
    # ── Primary Objects ──
    actor: Optional[ActorModel] = None
    device: Optional[DeviceModel] = None
    src_endpoint: Optional[EndpointModel] = None
    dst_endpoint: Optional[EndpointModel] = None
    connection_info: Optional[NetworkConnectionInfo] = None
    traffic: Optional[TrafficModel] = None
    process: Optional[ProcessModel] = None
    file: Optional[FileModel] = None
    
    # ── Network Specific ──
    http_request: Optional[HTTPRequestModel] = None
    http_response: Optional[HTTPResponseModel] = None
    dns_query: Optional[DNSQueryModel] = None
    dns_answer: Optional[List[DNSAnswerModel]] = None
    tls: Optional[Dict[str, Any]] = None
    
    # ── Findings ──
    finding_info: Optional[FindingInfoModel] = None
    evidences: Optional[List[EvidenceModel]] = None
    
    # ── Enrichment ──
    observables: List[ObservableModel] = Field(default_factory=list)
    enrichments: Optional[List[Dict[str, Any]]] = None
    
    # ── Metadata ──
    metadata: MetadataModel = Field(default_factory=MetadataModel)
    
    # ── Unmapped ──
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    raw_event: Optional[str] = None
    
    # ── Agentic SOC Extensions ──
    bead_id: Optional[str] = None
    agent_routes: List[str] = Field(default_factory=list)
    pipeline_stage: str = "ingested"
    correlation_keys: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
        populate_by_name = True


# ═══════════════════════════════════════════════════════════════════════════════
# API Request/Response Models
# ═══════════════════════════════════════════════════════════════════════════════

class LogInput(BaseModel):
    """Single raw log input."""
    raw: str
    source: Optional[str] = None
    format_hint: Optional[str] = None
    tags: Optional[List[str]] = None
    route_to_agents: bool = True


class BatchLogInput(BaseModel):
    """Batch raw log input."""
    logs: List[LogInput]
    source: Optional[str] = None
    route_to_agents: bool = True
    correlation_id: Optional[str] = None


class StreamConfig(BaseModel):
    """Configuration for streaming ingestion."""
    protocol: str = "syslog"  # syslog, http_stream, webhook
    port: Optional[int] = None
    tls_enabled: bool = False
    filters: Optional[Dict[str, Any]] = None
    agent_routing: bool = True


class ProcessingResult(BaseModel):
    """Result of processing a single log."""
    success: bool
    ocsf_event: Optional[OCSFEvent] = None
    detected_format: Optional[str] = None
    parse_time_ms: float = 0
    map_time_ms: float = 0
    total_time_ms: float = 0
    agent_routes: List[str] = Field(default_factory=list)
    bead_id: Optional[str] = None
    errors: List[str] = Field(default_factory=list)


class BatchResult(BaseModel):
    """Result of batch processing."""
    total: int = 0
    success: int = 0
    failed: int = 0
    results: List[ProcessingResult] = Field(default_factory=list)
    processing_time_ms: float = 0
    format_distribution: Dict[str, int] = Field(default_factory=dict)
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    agent_routing_summary: Dict[str, int] = Field(default_factory=dict)
    correlation_id: Optional[str] = None


class PipelineStats(BaseModel):
    """Pipeline statistics."""
    total_processed: int = 0
    total_errors: int = 0
    events_per_second: float = 0
    avg_processing_time_ms: float = 0
    format_counts: Dict[str, int] = Field(default_factory=dict)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    agent_dispatch_counts: Dict[str, int] = Field(default_factory=dict)
    uptime_seconds: float = 0
    queue_depth: int = 0
    bead_chains_active: int = 0


class AgentDispatchResult(BaseModel):
    """Result of dispatching event to an agent."""
    agent_name: str
    success: bool
    response_time_ms: float = 0
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
