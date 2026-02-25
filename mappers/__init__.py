"""
OCSF Mapper Engine
Maps parsed log fields → OCSF v1.1 schema objects.
Handles classification, severity mapping, observable extraction, and enrichment.
"""
import re
import uuid
import time
from typing import Dict, Any, Optional, List, Tuple
from loguru import logger
from models import (
    OCSFEvent, MetadataModel, ProductModel, ActorModel, UserModel,
    DeviceModel, EndpointModel, ProcessModel, FileModel, HashModel,
    NetworkConnectionInfo, TrafficModel, FindingInfoModel, MITREAttackModel,
    ObservableModel, ObservableTypeID, HTTPRequestModel, DNSQueryModel,
)
from config import OCSF_SEVERITY, OCSF_ACTIVITY, OCSF_STATUS, OCSF_CLASSES


# ═══════════════════════════════════════════════════════════════════════════════
# OCSF Classification Engine
# ═══════════════════════════════════════════════════════════════════════════════

# Pattern → (category_uid, class_uid, category_name, class_name)
CLASSIFICATION_RULES: List[Tuple[re.Pattern, int, int, str, str]] = [
    # Authentication
    (re.compile(r'auth|login|logon|logoff|logout|credential|password|mfa|sso|kerberos|ntlm|4624|4625|4648|4768|4769|4771|4776|sign.?in', re.I),
     3, 3002, "Identity & Access Management", "Authentication"),
    
    # DNS
    (re.compile(r'\bdns\b|nxdomain|query.*type|dns.query|resolve|rrname|rrtype', re.I),
     4, 4003, "Network Activity", "DNS Activity"),
    
    # HTTP
    (re.compile(r'\bhttp\b|url|uri|user.agent|status_code|http_method|GET\s|POST\s|PUT\s|DELETE\s|web.*request', re.I),
     4, 4002, "Network Activity", "HTTP Activity"),
    
    # DHCP
    (re.compile(r'\bdhcp\b|lease|dhcpack|dhcpdiscover|dhcpoffer|dhcprequest', re.I),
     4, 4004, "Network Activity", "DHCP Activity"),
    
    # RDP
    (re.compile(r'\brdp\b|remote.desktop|3389|TermService', re.I),
     4, 4005, "Network Activity", "RDP Activity"),
    
    # SMB
    (re.compile(r'\bsmb\b|445\/tcp|cifs|\\\\.*\\', re.I),
     4, 4006, "Network Activity", "SMB Activity"),
    
    # SSH
    (re.compile(r'\bssh\b|sshd|22\/tcp|authorized_keys|publickey', re.I),
     4, 4007, "Network Activity", "SSH Activity"),
    
    # FTP
    (re.compile(r'\bftp\b|ftpd|21\/tcp|vsftpd', re.I),
     4, 4008, "Network Activity", "FTP Activity"),
    
    # Email
    (re.compile(r'\bemail\b|smtp|imap|pop3|phish|mail|envelope|spf|dkim|dmarc', re.I),
     4, 4009, "Network Activity", "Email Activity"),
    
    # Process Activity
    (re.compile(r'process|exec|spawn|command.*line|cmd\.exe|powershell|bash|1007|CreateProcess|ProcessRollup|sysmon.*event.?id.?1', re.I),
     1, 1007, "System Activity", "Process Activity"),
    
    # File Activity
    (re.compile(r'file.*(?:create|write|read|delete|modify|rename|access)|4663|4656|4660|sysmon.*event.?id.?11', re.I),
     1, 1001, "System Activity", "File System Activity"),
    
    # Module/Driver Activity
    (re.compile(r'module|driver|dll.*load|kernel.*module|sysmon.*event.?id.?7', re.I),
     1, 1005, "System Activity", "Module Activity"),
    
    # Scheduled Job
    (re.compile(r'scheduled|cron|at\.exe|schtasks|task.*scheduler|4698|4699|4700|4702', re.I),
     1, 1006, "System Activity", "Scheduled Job Activity"),
    
    # Vulnerability Finding
    (re.compile(r'vuln|cve-\d|cvss|weakness|exploit|advisory', re.I),
     2, 2002, "Findings", "Vulnerability Finding"),
    
    # Compliance Finding
    (re.compile(r'compliance|policy.*viol|regulation|audit.*fail|hipaa|pci|sox|gdpr|nist|cis.*bench', re.I),
     2, 2003, "Findings", "Compliance Finding"),
    
    # Detection Finding (broad - catches EDR/IDS alerts)
    (re.compile(r'detect|alert|threat|malware|ioc|indicator|suspicious|anomal|attack|intrusion|ransomware|trojan|backdoor', re.I),
     2, 2004, "Findings", "Detection Finding"),
    
    # Security Finding (generic)
    (re.compile(r'finding|security.*event|risk|incident|breach', re.I),
     2, 2001, "Findings", "Security Finding"),
    
    # Account Change
    (re.compile(r'account.*(?:create|change|modify|delete|disable|enable|lock|unlock)|4720|4722|4724|4725|4726|4738|4740|4767', re.I),
     3, 3001, "Identity & Access Management", "Account Change"),
    
    # Group Management
    (re.compile(r'group.*(?:add|remove|create|delete|modify)|4727|4728|4729|4730|4731|4732|4733|4734|4735|4737|4754|4755|4756|4757|4758', re.I),
     3, 3006, "Identity & Access Management", "Group Management"),
    
    # User Access Management
    (re.compile(r'privilege|permission|access.*control|role.*assign|4670|4672|4673|4674', re.I),
     3, 3005, "Identity & Access Management", "User Access Management"),
    
    # API Activity
    (re.compile(r'api|rest.*call|graphql|endpoint.*call|request.*response|cloudtrail|operationName', re.I),
     6, 6003, "Application Activity", "API Activity"),
    
    # Web Activity
    (re.compile(r'web.*resource|waf|cdn|cloudfront|akamai', re.I),
     6, 6001, "Application Activity", "Web Resources Activity"),
    
    # Network Activity (broad - catch-all for network)
    (re.compile(r'traffic|flow|packet|bytes|connection|firewall|vpn|tunnel|nat|src.*dst|network|conn\.log', re.I),
     4, 4001, "Network Activity", "Network Activity"),
    
    # Discovery
    (re.compile(r'inventory|asset|device.*info|discover|scan.*result', re.I),
     5, 5001, "Discovery", "Device Inventory Info"),
]


def classify_event(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Determine OCSF category and class from parsed log content.
    Uses pattern matching against all parsed fields.
    """
    # Build searchable text from all string values
    search_text = " ".join(
        str(v) for v in parsed.values()
        if isinstance(v, (str, int, float)) and not str(v).startswith("{")
    )
    
    for pattern, cat_uid, cls_uid, cat_name, cls_name in CLASSIFICATION_RULES:
        if pattern.search(search_text):
            return {
                "category_uid": cat_uid,
                "class_uid": cls_uid,
                "category_name": cat_name,
                "class_name": cls_name,
            }
    
    # Default: Network Activity
    return {
        "category_uid": 4,
        "class_uid": 4001,
        "category_name": "Network Activity",
        "class_name": "Network Activity",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Severity Mapping
# ═══════════════════════════════════════════════════════════════════════════════

SEVERITY_MAP = {
    "critical": 5, "fatal": 6, "emergency": 6,
    "high": 4, "error": 4, "err": 4, "alert": 5,
    "medium": 3, "warning": 3, "warn": 3,
    "low": 2, "notice": 2, "minor": 2,
    "informational": 1, "info": 1, "debug": 1, "verbose": 1,
}


def map_severity(parsed: Dict[str, Any]) -> Tuple[int, str]:
    """Map parsed severity to OCSF severity_id and label."""
    raw_sev = str(
        parsed.get("severity") or
        parsed.get("Severity") or
        parsed.get("SeverityName") or
        parsed.get("level") or
        parsed.get("Level") or
        parsed.get("alert_severity") or
        parsed.get("syslog_severity") or
        ""
    ).lower().strip()
    
    # Direct name match
    if raw_sev in SEVERITY_MAP:
        sid = SEVERITY_MAP[raw_sev]
        return sid, OCSF_SEVERITY.get(sid, "Unknown")
    
    # Numeric
    try:
        num = int(raw_sev)
        # Syslog severity (0=emergency, 7=debug) → invert
        if parsed.get("_format", "").startswith("SYSLOG"):
            syslog_map = {0: 6, 1: 5, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1, 7: 1}
            sid = syslog_map.get(num, 0)
        elif num <= 1:
            sid = 1
        elif num <= 3:
            sid = 2
        elif num <= 5:
            sid = 3
        elif num <= 7:
            sid = 4
        elif num <= 9:
            sid = 5
        else:
            sid = 6
        return sid, OCSF_SEVERITY.get(sid, "Unknown")
    except (ValueError, TypeError):
        pass
    
    return 0, "Unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# Activity & Status Mapping
# ═══════════════════════════════════════════════════════════════════════════════

def map_activity(parsed: Dict[str, Any]) -> Tuple[int, str]:
    """Infer OCSF activity from parsed fields."""
    action = str(
        parsed.get("action") or
        parsed.get("event_name") or
        parsed.get("event_action") or
        parsed.get("eventName") or
        parsed.get("operation_name") or
        parsed.get("event_type") or
        ""
    ).lower()
    
    if re.search(r'create|add|new|start|open|grant|allow|accept|insert|put|register', action):
        return 1, "Create"
    if re.search(r'read|get|list|describe|query|view|access|lookup|fetch|head|select|retrieve', action):
        return 2, "Read"
    if re.search(r'update|modify|change|set|patch|renew|edit|alter|replace|assign', action):
        return 3, "Update"
    if re.search(r'delete|remove|drop|revoke|deny|block|reject|terminate|kill|close|stop|disable|deregister|purge', action):
        return 4, "Delete"
    if re.search(r'rename|move|relocate|migrate', action):
        return 5, "Rename"
    if action:
        return 6, "Other"
    return 0, "Unknown"


def map_status(parsed: Dict[str, Any]) -> Tuple[int, str]:
    """Infer OCSF status from parsed fields."""
    status = str(
        parsed.get("action") or
        parsed.get("status") or
        parsed.get("log_status") or
        parsed.get("event_outcome") or
        parsed.get("result_type") or
        parsed.get("outcome") or
        ""
    ).lower()
    
    if re.search(r'success|accept|allow|ok|pass|approved|permit|granted|complete', status):
        return 1, "Success"
    if re.search(r'fail|deny|block|reject|error|drop|refused|denied|forbidden|unauthorized|timeout', status):
        return 2, "Failure"
    if status:
        return 99, "Other"
    return 0, "Unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# Field Extractors → OCSF Objects
# ═══════════════════════════════════════════════════════════════════════════════

def extract_timestamp(parsed: Dict[str, Any]) -> Optional[str]:
    """Extract and normalize timestamp."""
    from dateutil.parser import parse as dateparse
    
    ts_fields = [
        "timestamp", "time_created", "event_time", "@timestamp", "receive_time",
        "_time", "TimeCreated", "created", "time", "start_time", "published",
        "eventTime", "createdDateTime",
    ]
    
    for field in ts_fields:
        val = parsed.get(field)
        if val:
            try:
                # Unix epoch
                num = float(val)
                if num > 1e12:
                    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(num / 1000))
                return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(num))
            except (ValueError, TypeError, OverflowError):
                pass
            try:
                dt = dateparse(str(val), fuzzy=True)
                return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            except Exception:
                pass
    
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def extract_actor(parsed: Dict[str, Any]) -> Optional[ActorModel]:
    """Extract actor/user fields."""
    user_name = (
        parsed.get("user_name") or parsed.get("UserName") or
        parsed.get("username") or parsed.get("user") or
        parsed.get("SubjectUserName") or parsed.get("TargetUserName") or
        parsed.get("target_user")
    )
    user_id = (
        parsed.get("user_sid") or parsed.get("user_arn") or
        parsed.get("user_id") or parsed.get("SubjectUserSid")
    )
    user_domain = parsed.get("user_domain")
    
    if not user_name and not user_id:
        return None
    
    return ActorModel(
        user=UserModel(
            name=user_name,
            uid=user_id,
            type=parsed.get("user_type", "User"),
            domain=user_domain,
        )
    )


def extract_device(parsed: Dict[str, Any]) -> Optional[DeviceModel]:
    """Extract device/host fields."""
    hostname = (
        parsed.get("hostname") or parsed.get("computer") or
        parsed.get("ComputerName") or parsed.get("host") or
        parsed.get("host_name") or parsed.get("device_name") or
        parsed.get("agent_name")
    )
    
    if not hostname:
        return None
    
    os_name = parsed.get("device_os") or parsed.get("agent_os") or parsed.get("host_os")
    
    return DeviceModel(
        hostname=hostname,
        ip=parsed.get("src_addr"),
        os={"name": os_name} if os_name else None,
        uid=parsed.get("device_id") or parsed.get("agent_id"),
    )


def extract_network(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Extract network endpoint and traffic fields."""
    result = {}
    
    src_ip = parsed.get("src_addr")
    dst_ip = parsed.get("dst_addr")
    src_port = parsed.get("src_port")
    dst_port = parsed.get("dst_port")
    
    if src_ip:
        result["src_endpoint"] = EndpointModel(
            ip=src_ip,
            port=int(src_port) if src_port else None,
            hostname=parsed.get("src_hostname"),
        )
    
    if dst_ip:
        result["dst_endpoint"] = EndpointModel(
            ip=dst_ip,
            port=int(dst_port) if dst_port else None,
            hostname=parsed.get("dst_hostname"),
        )
    
    proto = parsed.get("protocol")
    if proto:
        result["connection_info"] = NetworkConnectionInfo(
            protocol_name=str(proto).upper(),
            protocol_num=parsed.get("protocol_num"),
            direction=parsed.get("direction"),
        )
    
    bytes_val = parsed.get("bytes") or parsed.get("bytes_sent")
    if bytes_val:
        result["traffic"] = TrafficModel(
            bytes=int(bytes_val) if bytes_val else None,
            bytes_in=int(parsed.get("bytes_recv", 0)) if parsed.get("bytes_recv") else None,
            bytes_out=int(parsed.get("bytes_sent", 0)) if parsed.get("bytes_sent") else None,
            packets=int(parsed.get("packets", 0)) if parsed.get("packets") else None,
        )
    
    return result


def extract_process(parsed: Dict[str, Any]) -> Optional[ProcessModel]:
    """Extract process fields."""
    name = (
        parsed.get("process_name") or parsed.get("ImageFileName") or
        parsed.get("FileName") or parsed.get("program")
    )
    cmd = parsed.get("command_line") or parsed.get("CommandLine")
    pid = parsed.get("pid") or parsed.get("proc_id")
    
    if not name and not cmd:
        return None
    
    parent_name = (
        parsed.get("parent_process") or parsed.get("ParentImageFileName") or
        parsed.get("parent_name")
    )
    
    proc = ProcessModel(
        name=name,
        cmd_line=cmd,
        pid=int(pid) if pid else None,
    )
    
    if parent_name:
        proc.parent_process = ProcessModel(
            name=parent_name,
            cmd_line=parsed.get("parent_command_line"),
            pid=int(parsed.get("parent_pid")) if parsed.get("parent_pid") else None,
        )
    
    # File/hash info
    sha256 = parsed.get("sha256") or parsed.get("SHA256HashData")
    md5 = parsed.get("md5") or parsed.get("MD5HashData")
    if sha256 or md5:
        hashes = []
        if sha256:
            hashes.append(HashModel(algorithm="SHA-256", value=sha256))
        if md5:
            hashes.append(HashModel(algorithm="MD5", value=md5))
        proc.file = FileModel(
            name=name,
            path=parsed.get("process_path") or parsed.get("file_path"),
            hashes=hashes,
        )
    
    return proc


def extract_finding(parsed: Dict[str, Any]) -> Optional[FindingInfoModel]:
    """Extract security finding information."""
    title = (
        parsed.get("name") or parsed.get("threat_name") or
        parsed.get("DetectName") or parsed.get("detect_description") or
        parsed.get("qid_name") or parsed.get("event_name") or
        parsed.get("alert_signature") or parsed.get("finding_type")
    )
    desc = (
        parsed.get("message") or parsed.get("detect_description") or
        parsed.get("reason") or parsed.get("DetectDescription") or
        parsed.get("description")
    )
    
    if not title and not desc:
        return None
    
    finding = FindingInfoModel(
        title=title,
        desc=desc,
        uid=str(uuid.uuid4()),
    )
    
    # MITRE ATT&CK
    tactic = parsed.get("tactic")
    technique = parsed.get("technique")
    if tactic or technique:
        attack = MITREAttackModel()
        if tactic:
            attack.tactic = {"name": tactic}
        if technique:
            attack.technique = {"name": technique, "uid": technique if technique.startswith("T") else None}
        finding.attacks = [attack]
    
    # Kill chain inference
    kill_chain = []
    text = f"{title} {desc}".lower()
    if re.search(r'recon|scan|enumerat', text):
        kill_chain.append({"phase": "Reconnaissance", "phase_id": 1})
    if re.search(r'exploit|weaponiz|deliver', text):
        kill_chain.append({"phase": "Exploitation", "phase_id": 4})
    if re.search(r'install|implant|persist|backdoor', text):
        kill_chain.append({"phase": "Installation", "phase_id": 5})
    if re.search(r'c2|command.*control|beacon|callback', text):
        kill_chain.append({"phase": "Command & Control", "phase_id": 6})
    if re.search(r'exfil|steal|extract|lateral', text):
        kill_chain.append({"phase": "Actions on Objectives", "phase_id": 7})
    if kill_chain:
        finding.kill_chain = kill_chain
    
    return finding


def extract_http(parsed: Dict[str, Any]) -> Optional[HTTPRequestModel]:
    """Extract HTTP request fields."""
    method = parsed.get("http_method") or parsed.get("method")
    url = parsed.get("request_url") or parsed.get("http_url") or parsed.get("url")
    ua = parsed.get("user_agent")
    
    if not method and not url:
        return None
    
    return HTTPRequestModel(
        method=method,
        url=url,
        user_agent=ua,
    )


def extract_dns(parsed: Dict[str, Any]) -> Optional[DNSQueryModel]:
    """Extract DNS query fields."""
    hostname = parsed.get("dns_query") or parsed.get("query_name") or parsed.get("hostname")
    qtype = parsed.get("dns_type") or parsed.get("query_type")
    
    if not hostname:
        return None
    
    return DNSQueryModel(hostname=hostname, type=qtype)


# ═══════════════════════════════════════════════════════════════════════════════
# Observable Builder
# ═══════════════════════════════════════════════════════════════════════════════

def build_observables(parsed: Dict[str, Any], ocsf: OCSFEvent) -> List[ObservableModel]:
    """Extract all observables from event for threat intel enrichment."""
    observables = []
    seen = set()
    
    def _add(name: str, type_name: str, type_id: int, value: Any):
        if value and str(value) not in seen and str(value) != "-" and str(value) != "None":
            seen.add(str(value))
            observables.append(ObservableModel(
                name=name, type=type_name, type_id=type_id, value=str(value)
            ))
    
    # IPs
    if ocsf.src_endpoint and ocsf.src_endpoint.ip:
        _add("src_endpoint.ip", "IP Address", ObservableTypeID.IP_ADDRESS, ocsf.src_endpoint.ip)
    if ocsf.dst_endpoint and ocsf.dst_endpoint.ip:
        _add("dst_endpoint.ip", "IP Address", ObservableTypeID.IP_ADDRESS, ocsf.dst_endpoint.ip)
    
    # Users
    if ocsf.actor and ocsf.actor.user and ocsf.actor.user.name:
        _add("actor.user.name", "User Name", ObservableTypeID.USER_NAME, ocsf.actor.user.name)
    
    # Hostnames
    if ocsf.device and ocsf.device.hostname:
        _add("device.hostname", "Hostname", ObservableTypeID.HOSTNAME, ocsf.device.hostname)
    
    # Process
    if ocsf.process and ocsf.process.name:
        _add("process.name", "Process Name", ObservableTypeID.PROCESS_NAME, ocsf.process.name)
    
    # Hashes
    sha256 = parsed.get("sha256") or parsed.get("SHA256HashData")
    if sha256:
        _add("file.hash.sha256", "File Hash", ObservableTypeID.FILE_HASH, sha256)
    md5 = parsed.get("md5") or parsed.get("MD5HashData")
    if md5:
        _add("file.hash.md5", "File Hash", ObservableTypeID.FILE_HASH, md5)
    
    # URLs
    url = parsed.get("request_url") or parsed.get("http_url") or parsed.get("url")
    if url:
        _add("http_request.url", "URL", ObservableTypeID.URL, url)
    
    # Domains
    domain = parsed.get("dns_query") or parsed.get("query_name") or parsed.get("dst_hostname")
    if domain:
        _add("dns.hostname", "Domain Name", ObservableTypeID.DOMAIN_NAME, domain)
    
    # Email
    email = parsed.get("email") or parsed.get("email_addr") or parsed.get("alternateId")
    if email and "@" in str(email):
        _add("user.email", "Email Address", ObservableTypeID.EMAIL, email)
    
    # User Agent
    ua = parsed.get("user_agent")
    if ua:
        _add("http.user_agent", "User Agent", ObservableTypeID.USER_AGENT, ua)
    
    # File names
    fname = parsed.get("file_name") or parsed.get("TargetFilename")
    if fname:
        _add("file.name", "File Name", ObservableTypeID.FILE_NAME, fname)
    
    return observables


# ═══════════════════════════════════════════════════════════════════════════════
# Correlation Key Builder (for Bead Memory)
# ═══════════════════════════════════════════════════════════════════════════════

def build_correlation_keys(ocsf: OCSFEvent) -> List[str]:
    """Build keys for Bead Memory correlation."""
    keys = []
    
    # IP-based correlation
    if ocsf.src_endpoint and ocsf.src_endpoint.ip:
        keys.append(f"ip:{ocsf.src_endpoint.ip}")
    if ocsf.dst_endpoint and ocsf.dst_endpoint.ip:
        keys.append(f"ip:{ocsf.dst_endpoint.ip}")
    
    # User-based correlation
    if ocsf.actor and ocsf.actor.user and ocsf.actor.user.name:
        keys.append(f"user:{ocsf.actor.user.name}")
    
    # Host-based correlation
    if ocsf.device and ocsf.device.hostname:
        keys.append(f"host:{ocsf.device.hostname}")
    
    # Process-based correlation
    if ocsf.process and ocsf.process.name:
        keys.append(f"proc:{ocsf.process.name}")
    
    # Hash-based correlation
    for obs in ocsf.observables:
        if obs.type_id == ObservableTypeID.FILE_HASH:
            keys.append(f"hash:{obs.value}")
    
    return keys


# ═══════════════════════════════════════════════════════════════════════════════
# Main Mapper
# ═══════════════════════════════════════════════════════════════════════════════

def map_to_ocsf(parsed: Dict[str, Any], format_name: str) -> OCSFEvent:
    """
    Map parsed log fields to a full OCSF v1.1 event.
    This is the core transformation engine.
    """
    # Classification
    classification = classify_event(parsed)
    
    # Severity
    severity_id, severity_name = map_severity(parsed)
    
    # Activity & Status
    activity_id, activity_name = map_activity(parsed)
    status_id, status_name = map_status(parsed)
    
    # Timestamp
    timestamp_str = extract_timestamp(parsed)
    try:
        from dateutil.parser import parse as dateparse
        ts_epoch = int(dateparse(timestamp_str).timestamp() * 1000)
    except Exception:
        ts_epoch = int(time.time() * 1000)
    
    # Build OCSF event
    ocsf = OCSFEvent(
        # Classification
        activity_id=activity_id,
        activity_name=activity_name,
        category_uid=classification["category_uid"],
        category_name=classification["category_name"],
        class_uid=classification["class_uid"],
        class_name=classification["class_name"],
        type_uid=classification["class_uid"] * 100 + activity_id,
        
        # Time
        time=ts_epoch,
        
        # Severity & Status
        severity_id=severity_id,
        severity=severity_name,
        status_id=status_id,
        status=status_name,
        
        # Message
        message=str(
            parsed.get("message") or parsed.get("detect_description") or
            parsed.get("name") or parsed.get("event_name") or
            parsed.get("event_simpleName") or parsed.get("alert_signature") or
            ""
        ),
        
        # Metadata
        metadata=MetadataModel(
            product=ProductModel(
                name=parsed.get("product") or parsed.get("sourcetype") or format_name,
                vendor_name=parsed.get("vendor") or "Unknown",
                version=parsed.get("device_version") or parsed.get("product_version") or parsed.get("agent_version"),
            ),
            original_time=timestamp_str,
            processed_time=time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            log_name=format_name,
            log_provider=parsed.get("logsource") or parsed.get("source") or parsed.get("app_name"),
        ),
        
        # Raw event
        raw_event=parsed.get("_raw"),
    )
    
    # Attach extracted objects
    ocsf.actor = extract_actor(parsed)
    ocsf.device = extract_device(parsed)
    ocsf.process = extract_process(parsed)
    ocsf.finding_info = extract_finding(parsed)
    ocsf.http_request = extract_http(parsed)
    ocsf.dns_query = extract_dns(parsed)
    
    # Network
    net = extract_network(parsed)
    ocsf.src_endpoint = net.get("src_endpoint")
    ocsf.dst_endpoint = net.get("dst_endpoint")
    ocsf.connection_info = net.get("connection_info")
    ocsf.traffic = net.get("traffic")
    
    # Observables
    ocsf.observables = build_observables(parsed, ocsf)
    
    # Correlation keys (Bead Memory)
    ocsf.correlation_keys = build_correlation_keys(ocsf)
    
    # Unmapped fields
    MAPPED_KEYS = {
        "_format", "_raw", "_parse_error", "_extensions", "_event_data",
        "severity", "Severity", "SeverityName", "level", "Level",
        "timestamp", "time_created", "event_time", "@timestamp", "receive_time",
        "_time", "TimeCreated", "src_addr", "dst_addr", "src_port", "dst_port",
        "protocol", "bytes", "bytes_sent", "bytes_recv", "packets",
        "user_name", "UserName", "username", "user", "user_sid", "user_arn",
        "user_type", "user_id", "user_domain",
        "hostname", "computer", "ComputerName", "host", "host_name", "device_name",
        "device_os", "agent_os", "host_os", "device_id", "agent_id",
        "process_name", "ImageFileName", "FileName", "program",
        "command_line", "CommandLine", "pid", "proc_id",
        "parent_process", "ParentImageFileName", "parent_name",
        "parent_command_line", "parent_pid",
        "name", "threat_name", "DetectName", "detect_description",
        "qid_name", "event_name", "event_simpleName", "alert_signature",
        "message", "reason", "description",
        "tactic", "technique", "sha256", "SHA256HashData", "md5", "MD5HashData",
        "action", "log_status", "event_outcome", "status", "result_type",
        "vendor", "product", "sourcetype", "device_version", "product_version",
        "agent_version", "logsource", "source", "app_name",
        "version", "cef_version", "leef_version",
        "src_hostname", "dst_hostname", "dns_query", "query_name",
        "http_method", "request_url", "http_url", "url", "user_agent",
        "direction", "protocol_num", "finding_type",
    }
    
    ocsf.unmapped = {
        k: v for k, v in parsed.items()
        if k not in MAPPED_KEYS and not k.startswith("_") and v is not None and v != ""
    }
    
    return ocsf
