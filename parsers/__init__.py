"""
Universal Log Parsers
Each parser extracts structured fields from its respective log format.
Output is a normalized dict that feeds into the OCSF mapper.
"""
import re
import json
from typing import Dict, Any, List, Optional
from loguru import logger


def _safe_json(raw: str) -> dict:
    try:
        return json.loads(raw.strip())
    except Exception:
        return {}


def _safe_int(val: Any) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# CEF Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_cef(raw: str) -> Dict[str, Any]:
    """Parse Common Event Format (ArcSight, many vendors)."""
    parts = raw.split("|", 7)
    if len(parts) < 8:
        return {"_raw": raw, "_parse_error": "Invalid CEF: insufficient pipe-delimited fields"}
    
    ext_str = parts[7]
    extensions = {}
    # CEF extension parser: key=value with space-separated pairs
    # Handles multi-word values by looking ahead for next key=
    regex = re.compile(r'(\w+)=(.*?)(?=\s\w+=|$)', re.DOTALL)
    for m in regex.finditer(ext_str):
        extensions[m.group(1)] = m.group(2).strip()
    
    return {
        "_format": "CEF",
        "cef_version": parts[0].replace("CEF:", ""),
        "vendor": parts[1],
        "product": parts[2],
        "device_version": parts[3],
        "signature_id": parts[4],
        "name": parts[5],
        "severity": parts[6],
        # Map standard CEF keys
        "src_addr": extensions.get("src"),
        "dst_addr": extensions.get("dst"),
        "src_port": _safe_int(extensions.get("spt")),
        "dst_port": _safe_int(extensions.get("dpt")),
        "protocol": extensions.get("proto"),
        "action": extensions.get("act"),
        "user_name": extensions.get("duser") or extensions.get("suser"),
        "hostname": extensions.get("dhost") or extensions.get("shost"),
        "device_external_id": extensions.get("deviceExternalId"),
        "category": extensions.get("cat"),
        "message": extensions.get("msg"),
        "bytes_in": _safe_int(extensions.get("in")),
        "bytes_out": _safe_int(extensions.get("out")),
        "request_url": extensions.get("request"),
        "file_name": extensions.get("fname"),
        "file_hash": extensions.get("fileHash"),
        "reason": extensions.get("reason"),
        "app": extensions.get("app"),
        "_extensions": extensions,
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# LEEF Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_leef(raw: str) -> Dict[str, Any]:
    """Parse Log Event Extended Format (IBM QRadar native)."""
    header_parts = raw.split("|", 5)
    if len(header_parts) < 6:
        return {"_raw": raw, "_parse_error": "Invalid LEEF header"}
    
    ext_str = header_parts[5]
    delimiter = "\t"  # Default LEEF 1.0
    if header_parts[0].startswith("LEEF:2"):
        # LEEF 2.0 may specify custom delimiter
        delimiter = ext_str[0] if ext_str else "\t"
        ext_str = ext_str[1:]
    
    extensions = {}
    for pair in ext_str.split(delimiter):
        idx = pair.find("=")
        if idx > 0:
            extensions[pair[:idx]] = pair[idx + 1:]
    
    return {
        "_format": "LEEF",
        "leef_version": header_parts[0].replace("LEEF:", ""),
        "vendor": header_parts[1],
        "product": header_parts[2],
        "product_version": header_parts[3],
        "event_id": header_parts[4],
        "src_addr": extensions.get("src"),
        "dst_addr": extensions.get("dst"),
        "src_port": _safe_int(extensions.get("srcPort")),
        "dst_port": _safe_int(extensions.get("dstPort")),
        "protocol": extensions.get("proto"),
        "action": extensions.get("action"),
        "user_name": extensions.get("usrName"),
        "severity": extensions.get("sev"),
        "category": extensions.get("cat"),
        "message": extensions.get("msg"),
        "_extensions": extensions,
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Syslog Parsers
# ═══════════════════════════════════════════════════════════════════════════════

def parse_syslog_rfc5424(raw: str) -> Dict[str, Any]:
    """Parse RFC 5424 syslog."""
    pattern = re.compile(
        r'^<(\d{1,3})>(\d)\s'
        r'(\S+)\s'          # timestamp
        r'(\S+)\s'          # hostname
        r'(\S+)\s'          # app-name
        r'(\S+)\s'          # procid
        r'(\S+)\s?'         # msgid
        r'(?:\[([^\]]*)\]\s?)?' # structured data
        r'(.*)',             # message
        re.DOTALL
    )
    m = pattern.match(raw.strip())
    if not m:
        return {"_raw": raw, "_parse_error": "Failed to match RFC5424 pattern"}
    
    pri = int(m.group(1))
    facility = pri >> 3
    severity = pri & 7
    
    return {
        "_format": "SYSLOG_RFC5424",
        "facility": facility,
        "syslog_severity": severity,
        "version": m.group(2),
        "timestamp": m.group(3),
        "hostname": m.group(4) if m.group(4) != "-" else None,
        "app_name": m.group(5) if m.group(5) != "-" else None,
        "proc_id": m.group(6) if m.group(6) != "-" else None,
        "msg_id": m.group(7) if m.group(7) != "-" else None,
        "structured_data": m.group(8),
        "message": m.group(9) or "",
        "_raw": raw,
    }


def parse_syslog_rfc3164(raw: str) -> Dict[str, Any]:
    """Parse BSD/RFC 3164 syslog."""
    pattern = re.compile(
        r'^(?:<(\d{1,3})>)?'
        r'(\w{3})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s'
        r'(\S+)\s'
        r'(\S+?)(?:\[(\d+)\])?:\s*(.*)',
        re.DOTALL
    )
    m = pattern.match(raw.strip())
    if not m:
        return {"_raw": raw, "_parse_error": "Failed to match RFC3164 pattern", "message": raw}
    
    pri = int(m.group(1)) if m.group(1) else None
    msg = m.group(8) or ""
    
    # Extract IPs from message
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
    
    result = {
        "_format": "SYSLOG_RFC3164",
        "priority": pri,
        "facility": (pri >> 3) if pri else None,
        "syslog_severity": (pri & 7) if pri else None,
        "timestamp": f"{m.group(2)} {m.group(3)} {m.group(4)}",
        "hostname": m.group(5),
        "program": m.group(6),
        "pid": _safe_int(m.group(7)),
        "message": msg,
        "_raw": raw,
    }
    
    # Try to extract firewall fields from message (UFW, iptables)
    fw_match = re.search(
        r'SRC=(\S+)\s+DST=(\S+).*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?',
        msg
    )
    if fw_match:
        result["src_addr"] = fw_match.group(1)
        result["dst_addr"] = fw_match.group(2)
        result["protocol"] = fw_match.group(3)
        result["src_port"] = _safe_int(fw_match.group(4))
        result["dst_port"] = _safe_int(fw_match.group(5))
        if "BLOCK" in msg or "DROP" in msg:
            result["action"] = "block"
        elif "ALLOW" in msg or "ACCEPT" in msg:
            result["action"] = "allow"
    elif ips:
        result["src_addr"] = ips[0] if len(ips) >= 1 else None
        result["dst_addr"] = ips[1] if len(ips) >= 2 else None
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Windows Event Log
# ═══════════════════════════════════════════════════════════════════════════════

def parse_windows_event(raw: str) -> Dict[str, Any]:
    """Parse Windows Event Log (JSON export from SIEM/agent)."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    # Handle multiple JSON structures (evtx, NXLog, Winlogbeat, Sysmon, etc.)
    sys = j.get("System") or j.get("Event", {}).get("System", {})
    evt_data = j.get("EventData") or j.get("Event", {}).get("EventData", {})
    
    event_id = (
        j.get("EventID") or
        sys.get("EventID", {}).get("#text") if isinstance(sys.get("EventID"), dict) else sys.get("EventID")
    )
    
    return {
        "_format": "WINDOWS_EVENT",
        "event_id": _safe_int(event_id),
        "provider": sys.get("Provider", {}).get("Name") or j.get("ProviderName"),
        "channel": sys.get("Channel") or j.get("Channel"),
        "computer": sys.get("Computer") or j.get("Computer"),
        "hostname": sys.get("Computer") or j.get("Computer"),
        "level": sys.get("Level") or j.get("Level"),
        "opcode": sys.get("Opcode"),
        "task": sys.get("Task"),
        "timestamp": sys.get("TimeCreated", {}).get("SystemTime") or j.get("TimeCreated"),
        "user_sid": sys.get("Security", {}).get("UserID") or j.get("SubjectUserSid"),
        "user_name": (
            evt_data.get("SubjectUserName") or
            evt_data.get("TargetUserName") or
            j.get("SubjectUserName") or
            j.get("TargetUserName")
        ),
        "target_user": evt_data.get("TargetUserName") or j.get("TargetUserName"),
        "logon_type": _safe_int(evt_data.get("LogonType") or j.get("LogonType")),
        "src_addr": evt_data.get("IpAddress") or j.get("IpAddress"),
        "src_port": _safe_int(evt_data.get("IpPort") or j.get("IpPort")),
        "status_code": evt_data.get("Status") or j.get("Status"),
        "sub_status": evt_data.get("SubStatus") or j.get("SubStatus"),
        "failure_reason": evt_data.get("FailureReason") or j.get("FailureReason"),
        "process_name": evt_data.get("ProcessName") or evt_data.get("NewProcessName"),
        "command_line": evt_data.get("CommandLine"),
        "parent_process": evt_data.get("ParentProcessName"),
        "object_name": evt_data.get("ObjectName"),
        "object_type": evt_data.get("ObjectType"),
        "access_mask": evt_data.get("AccessMask"),
        "service_name": evt_data.get("ServiceName"),
        "_event_data": evt_data,
        "_raw": raw,
    }


def parse_windows_sysmon(raw: str) -> Dict[str, Any]:
    """Parse Sysmon events."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "WINDOWS_SYSMON",
        "event_id": _safe_int(j.get("EventID")),
        "timestamp": j.get("UtcTime"),
        "rule_name": j.get("RuleName"),
        "process_name": j.get("Image") or j.get("TargetFilename"),
        "command_line": j.get("CommandLine"),
        "parent_process": j.get("ParentImage"),
        "parent_command_line": j.get("ParentCommandLine"),
        "user_name": j.get("User"),
        "hostname": j.get("Computer"),
        "pid": _safe_int(j.get("ProcessId")),
        "parent_pid": _safe_int(j.get("ParentProcessId")),
        "hashes": j.get("Hashes"),
        "sha256": _extract_hash(j.get("Hashes", ""), "SHA256"),
        "md5": _extract_hash(j.get("Hashes", ""), "MD5"),
        "src_addr": j.get("SourceIp"),
        "dst_addr": j.get("DestinationIp"),
        "src_port": _safe_int(j.get("SourcePort")),
        "dst_port": _safe_int(j.get("DestinationPort")),
        "protocol": j.get("Protocol"),
        "dst_hostname": j.get("DestinationHostname"),
        "file_name": j.get("TargetFilename"),
        "file_path": j.get("TargetFilename"),
        "registry_key": j.get("TargetObject"),
        "registry_value": j.get("Details"),
        "query_name": j.get("QueryName"),
        "query_results": j.get("QueryResults"),
        "_raw": raw,
    }


def _extract_hash(hashes_str: str, algo: str) -> Optional[str]:
    """Extract specific hash from Sysmon Hashes field (e.g., 'SHA256=abc,MD5=def')."""
    if not hashes_str:
        return None
    for part in hashes_str.split(","):
        if part.strip().upper().startswith(f"{algo}="):
            return part.split("=", 1)[1]
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Cloud Providers
# ═══════════════════════════════════════════════════════════════════════════════

def parse_cloudtrail(raw: str) -> Dict[str, Any]:
    """Parse AWS CloudTrail."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    identity = j.get("userIdentity", {})
    req = j.get("requestParameters") or {}
    resp = j.get("responseElements") or {}
    
    return {
        "_format": "AWS_CLOUDTRAIL",
        "timestamp": j.get("eventTime"),
        "event_source": j.get("eventSource"),
        "event_name": j.get("eventName"),
        "action": j.get("eventName"),
        "aws_region": j.get("awsRegion"),
        "src_addr": j.get("sourceIPAddress"),
        "user_agent": j.get("userAgent"),
        "user_type": identity.get("type"),
        "user_arn": identity.get("arn"),
        "user_name": identity.get("userName") or identity.get("principalId"),
        "account_id": identity.get("accountId"),
        "mfa_authenticated": identity.get("sessionContext", {}).get("attributes", {}).get("mfaAuthenticated"),
        "event_type": j.get("eventType"),
        "read_only": j.get("readOnly"),
        "error_code": j.get("errorCode"),
        "error_message": j.get("errorMessage"),
        "resources": j.get("resources", []),
        "recipient_account": j.get("recipientAccountId"),
        "request_params": req,
        "response": resp,
        "severity": "High" if j.get("errorCode") else "Informational",
        "_raw": raw,
    }


def parse_vpc_flow(raw: str) -> Dict[str, Any]:
    """Parse AWS VPC Flow Logs."""
    parts = raw.strip().split()
    if len(parts) < 14:
        return {"_raw": raw, "_parse_error": "Insufficient VPC flow fields"}
    
    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    
    return {
        "_format": "AWS_VPC_FLOW",
        "version": parts[0],
        "account_id": parts[1],
        "interface_id": parts[2],
        "src_addr": parts[3],
        "dst_addr": parts[4],
        "src_port": _safe_int(parts[5]),
        "dst_port": _safe_int(parts[6]),
        "protocol": proto_map.get(parts[7], parts[7]),
        "protocol_num": _safe_int(parts[7]),
        "packets": _safe_int(parts[8]),
        "bytes": _safe_int(parts[9]),
        "start_time": parts[10],
        "end_time": parts[11],
        "action": parts[12].lower(),
        "log_status": parts[13],
        "timestamp": parts[10],
        "severity": "Medium" if parts[12] == "REJECT" else "Informational",
        "_raw": raw,
    }


def parse_guardduty(raw: str) -> Dict[str, Any]:
    """Parse AWS GuardDuty findings."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    service = j.get("service", {})
    resource = j.get("resource", {})
    action_info = service.get("action", {})
    
    # Extract network info from action
    net_info = action_info.get("networkConnectionAction", {})
    remote = net_info.get("remoteIpDetails", {})
    local = net_info.get("localIpDetails", {})
    
    return {
        "_format": "AWS_GUARDDUTY",
        "finding_type": j.get("type"),
        "name": j.get("title"),
        "message": j.get("description"),
        "severity": j.get("severity"),
        "confidence": j.get("confidence"),
        "timestamp": j.get("updatedAt") or j.get("createdAt"),
        "account_id": j.get("accountId"),
        "region": j.get("region"),
        "src_addr": remote.get("ipAddressV4"),
        "dst_addr": local.get("ipAddressV4"),
        "src_port": _safe_int(net_info.get("remotePortDetails", {}).get("port")),
        "dst_port": _safe_int(net_info.get("localPortDetails", {}).get("port")),
        "protocol": net_info.get("protocol"),
        "direction": net_info.get("connectionDirection"),
        "resource_type": resource.get("resourceType"),
        "instance_id": resource.get("instanceDetails", {}).get("instanceId"),
        "_raw": raw,
    }


def parse_azure_activity(raw: str) -> Dict[str, Any]:
    """Parse Azure Activity/Audit Log."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "AZURE_ACTIVITY",
        "timestamp": j.get("time") or j.get("timeStamp"),
        "operation_name": j.get("operationName"),
        "category": j.get("category"),
        "result_type": j.get("resultType"),
        "result_signature": j.get("resultSignature"),
        "src_addr": j.get("callerIpAddress"),
        "user_name": j.get("caller") or j.get("identity", {}).get("claims", {}).get("name"),
        "tenant_id": j.get("tenantId"),
        "subscription_id": j.get("subscriptionId"),
        "resource_id": j.get("resourceId"),
        "resource_group": j.get("resourceGroupName"),
        "level": j.get("level"),
        "action": j.get("operationName"),
        "status": "Success" if j.get("resultType") == "Success" else "Failure",
        "correlation_id": j.get("correlationId"),
        "message": j.get("description") or j.get("operationName"),
        "_raw": raw,
    }


def parse_azure_signin(raw: str) -> Dict[str, Any]:
    """Parse Azure AD Sign-in Logs."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "AZURE_SIGNIN",
        "timestamp": j.get("createdDateTime"),
        "user_name": j.get("userDisplayName") or j.get("userPrincipalName"),
        "user_id": j.get("userId"),
        "src_addr": j.get("ipAddress"),
        "app_name": j.get("appDisplayName"),
        "client_app": j.get("clientAppUsed"),
        "action": "Authentication",
        "status": "Success" if j.get("status", {}).get("errorCode") == 0 else "Failure",
        "error_code": j.get("status", {}).get("errorCode"),
        "failure_reason": j.get("status", {}).get("failureReason"),
        "conditional_access": j.get("conditionalAccessStatus"),
        "mfa_detail": j.get("mfaDetail"),
        "risk_level": j.get("riskLevelDuringSignIn"),
        "risk_state": j.get("riskState"),
        "location": j.get("location"),
        "device_detail": j.get("deviceDetail"),
        "_raw": raw,
    }


def parse_gcp_audit(raw: str) -> Dict[str, Any]:
    """Parse GCP Cloud Audit Log."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    proto = j.get("protoPayload", {})
    auth_info = proto.get("authenticationInfo", {})
    req_meta = proto.get("requestMetadata", {})
    
    return {
        "_format": "GCP_AUDIT",
        "timestamp": j.get("timestamp") or j.get("receiveTimestamp"),
        "log_name": j.get("logName"),
        "severity": j.get("severity"),
        "method_name": proto.get("methodName"),
        "service_name": proto.get("serviceName"),
        "resource_name": proto.get("resourceName"),
        "user_name": auth_info.get("principalEmail"),
        "src_addr": req_meta.get("callerIp"),
        "user_agent": req_meta.get("callerSuppliedUserAgent"),
        "action": proto.get("methodName"),
        "status_code": proto.get("status", {}).get("code"),
        "status_message": proto.get("status", {}).get("message"),
        "project_id": j.get("resource", {}).get("labels", {}).get("project_id"),
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall / Network Security
# ═══════════════════════════════════════════════════════════════════════════════

def parse_palo_alto(raw: str) -> Dict[str, Any]:
    """Parse Palo Alto Networks firewall logs (CSV format)."""
    parts = raw.split(",")
    if len(parts) < 15:
        return {"_raw": raw, "_parse_error": "Insufficient PAN fields"}
    
    log_type = parts[0].strip()
    base = {
        "_format": "PALO_ALTO",
        "log_type": log_type,
        "timestamp": parts[1] if len(parts) > 1 else None,
        "serial": parts[2] if len(parts) > 2 else None,
        "type": parts[3] if len(parts) > 3 else None,
        "subtype": parts[4] if len(parts) > 4 else log_type,
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "_raw": raw,
    }
    
    if log_type == "TRAFFIC" and len(parts) > 35:
        base.update({
            "src_addr": parts[7],
            "dst_addr": parts[8],
            "nat_src": parts[9],
            "nat_dst": parts[10],
            "rule": parts[12],
            "app": parts[14],
            "src_zone": parts[16],
            "dst_zone": parts[17],
            "src_port": _safe_int(parts[24]),
            "dst_port": _safe_int(parts[25]),
            "protocol": parts[29] if len(parts) > 29 else None,
            "action": parts[30] if len(parts) > 30 else None,
            "bytes": _safe_int(parts[31]) if len(parts) > 31 else None,
            "bytes_sent": _safe_int(parts[32]) if len(parts) > 32 else None,
            "bytes_recv": _safe_int(parts[33]) if len(parts) > 33 else None,
            "packets": _safe_int(parts[34]) if len(parts) > 34 else None,
            "session_duration": _safe_int(parts[25]) if len(parts) > 25 else None,
            "user_name": parts[13] if len(parts) > 13 and parts[13] else None,
        })
    elif log_type == "THREAT" and len(parts) > 33:
        base.update({
            "src_addr": parts[7],
            "dst_addr": parts[8],
            "rule": parts[12],
            "app": parts[14],
            "threat_name": parts[31] if len(parts) > 31 else None,
            "severity": parts[32] if len(parts) > 32 else None,
            "direction": parts[33] if len(parts) > 33 else None,
            "action": parts[30] if len(parts) > 30 else None,
            "name": parts[31] if len(parts) > 31 else None,
        })
    
    return base


def parse_fortinet(raw: str) -> Dict[str, Any]:
    """Parse FortiGate firewall logs (key=value or JSON)."""
    j = _safe_json(raw)
    if j:
        return {
            "_format": "FORTINET",
            "vendor": "Fortinet",
            "product": "FortiGate",
            "timestamp": j.get("date", "") + "T" + j.get("time", ""),
            "src_addr": j.get("srcip"),
            "dst_addr": j.get("dstip"),
            "src_port": _safe_int(j.get("srcport")),
            "dst_port": _safe_int(j.get("dstport")),
            "protocol": j.get("proto"),
            "action": j.get("action"),
            "severity": j.get("level"),
            "user_name": j.get("user"),
            "app": j.get("app") or j.get("appcat"),
            "policy_id": j.get("policyid"),
            "bytes_sent": _safe_int(j.get("sentbyte")),
            "bytes_recv": _safe_int(j.get("rcvdbyte")),
            "message": j.get("msg"),
            "log_type": j.get("type"),
            "subtype": j.get("subtype"),
            "_raw": raw,
        }
    
    # Key-value format
    fields = {}
    for m in re.finditer(r'(\w+)=("([^"]*)"|(\S+))', raw):
        fields[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(4)
    
    return {
        "_format": "FORTINET",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "timestamp": fields.get("date", "") + "T" + fields.get("time", ""),
        "src_addr": fields.get("srcip"),
        "dst_addr": fields.get("dstip"),
        "src_port": _safe_int(fields.get("srcport")),
        "dst_port": _safe_int(fields.get("dstport")),
        "protocol": fields.get("proto"),
        "action": fields.get("action"),
        "severity": fields.get("level"),
        "user_name": fields.get("user"),
        "bytes_sent": _safe_int(fields.get("sentbyte")),
        "bytes_recv": _safe_int(fields.get("rcvdbyte")),
        "message": fields.get("msg"),
        **fields,
        "_raw": raw,
    }


def parse_checkpoint(raw: str) -> Dict[str, Any]:
    """Parse Check Point firewall logs."""
    j = _safe_json(raw)
    if j:
        return {
            "_format": "CHECKPOINT",
            "vendor": "Check Point",
            "product": j.get("product"),
            "blade_name": j.get("blade_name"),
            "src_addr": j.get("src"),
            "dst_addr": j.get("dst"),
            "src_port": _safe_int(j.get("s_port")),
            "dst_port": _safe_int(j.get("service")),
            "protocol": j.get("proto"),
            "action": j.get("action"),
            "rule": j.get("rule"),
            "user_name": j.get("src_user_name"),
            "severity": j.get("severity"),
            **j,
            "_raw": raw,
        }
    
    # Key-value
    fields = {}
    for m in re.finditer(r'(\w+)=("([^"]*)"|(\S+))', raw):
        fields[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(4)
    
    return {"_format": "CHECKPOINT", "vendor": "Check Point", **fields, "_raw": raw}


# ═══════════════════════════════════════════════════════════════════════════════
# EDR / Endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def parse_crowdstrike(raw: str) -> Dict[str, Any]:
    """Parse CrowdStrike Falcon EDR events."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "CROWDSTRIKE_EDR",
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "event_name": j.get("event_simpleName") or j.get("DetectName") or j.get("ExternalApiType"),
        "timestamp": j.get("timestamp") or j.get("ProcessStartTime") or j.get("DetectTimestamp"),
        "agent_id": j.get("aid"),
        "hostname": j.get("ComputerName"),
        "user_name": j.get("UserName"),
        "process_name": j.get("ImageFileName") or j.get("FileName"),
        "command_line": j.get("CommandLine"),
        "parent_process": j.get("ParentImageFileName"),
        "parent_command_line": j.get("ParentCommandLine"),
        "sha256": j.get("SHA256HashData"),
        "md5": j.get("MD5HashData"),
        "sha1": j.get("SHA1HashData"),
        "pid": _safe_int(j.get("RawProcessId")),
        "parent_pid": _safe_int(j.get("ParentProcessId")),
        "severity": j.get("Severity") or j.get("SeverityName"),
        "tactic": j.get("Tactic"),
        "technique": j.get("Technique"),
        "detect_description": j.get("DetectDescription"),
        "name": j.get("DetectName") or j.get("event_simpleName"),
        "src_addr": j.get("LocalAddressIP4") or j.get("aip"),
        "dst_addr": j.get("RemoteAddressIP4"),
        "src_port": _safe_int(j.get("LocalPort")),
        "dst_port": _safe_int(j.get("RemotePort")),
        "protocol": j.get("Protocol"),
        "ioc_type": j.get("IOCType"),
        "ioc_value": j.get("IOCValue"),
        "action": j.get("PatternDispositionFlags"),
        "_raw": raw,
    }


def parse_sentinel_one(raw: str) -> Dict[str, Any]:
    """Parse SentinelOne EDR alerts."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    threat = j.get("threatInfo", {})
    agent = j.get("agentDetectionInfo", j.get("agentRealtimeInfo", {}))
    indicators = j.get("indicators", [])
    
    return {
        "_format": "SENTINEL_ONE",
        "vendor": "SentinelOne",
        "product": "Singularity",
        "threat_name": threat.get("threatName"),
        "name": threat.get("threatName"),
        "classification": threat.get("classification") or threat.get("classificationSource"),
        "confidence": threat.get("confidenceLevel"),
        "hostname": agent.get("agentComputerName"),
        "agent_os": agent.get("agentOsName"),
        "agent_version": agent.get("agentVersion"),
        "agent_id": agent.get("agentId"),
        "process_name": threat.get("originatorProcess"),
        "file_path": threat.get("filePath"),
        "file_name": threat.get("threatName"),
        "sha256": threat.get("sha256"),
        "sha1": threat.get("sha1"),
        "md5": threat.get("md5"),
        "initiated_by": threat.get("initiatedBy"),
        "status": threat.get("mitigationStatus"),
        "severity": threat.get("confidenceLevel"),
        "action": threat.get("mitigationStatus"),
        "timestamp": threat.get("createdAt") or threat.get("identifiedAt"),
        "indicators": [i.get("description") for i in indicators],
        "_raw": raw,
    }


def parse_carbon_black(raw: str) -> Dict[str, Any]:
    """Parse VMware Carbon Black EDR alerts."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "CARBON_BLACK",
        "vendor": "VMware",
        "product": "Carbon Black",
        "hostname": j.get("device_name"),
        "device_os": j.get("device_os"),
        "device_id": j.get("device_id"),
        "alert_type": j.get("type") or j.get("alert_type"),
        "severity": j.get("severity"),
        "name": j.get("reason") or j.get("watchlist_name"),
        "process_name": j.get("process_name"),
        "process_path": j.get("process_path"),
        "command_line": j.get("process_cmdline"),
        "parent_name": j.get("parent_name"),
        "parent_path": j.get("parent_path"),
        "sha256": j.get("process_sha256"),
        "md5": j.get("process_md5"),
        "user_name": j.get("device_username"),
        "reason": j.get("reason"),
        "org_key": j.get("org_key"),
        "threat_id": j.get("threat_id"),
        "ioc_id": j.get("ioc_id"),
        "action": j.get("sensor_action"),
        "timestamp": j.get("create_time") or j.get("last_update_time"),
        "tactic": j.get("attack_tactic"),
        "technique": j.get("attack_technique"),
        "_raw": raw,
    }


def parse_ms_defender(raw: str) -> Dict[str, Any]:
    """Parse Microsoft Defender for Endpoint alerts."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "MS_DEFENDER",
        "vendor": "Microsoft",
        "product": "Defender for Endpoint",
        "alert_id": j.get("AlertId") or j.get("alertId"),
        "name": j.get("Title") or j.get("title"),
        "severity": j.get("Severity") or j.get("severity"),
        "category": j.get("Category") or j.get("category"),
        "status": j.get("Status") or j.get("status"),
        "hostname": j.get("ComputerDnsName") or j.get("machineName"),
        "user_name": j.get("UserName"),
        "process_name": j.get("FileName"),
        "command_line": j.get("ProcessCommandLine"),
        "sha256": j.get("Sha256") or j.get("sha256"),
        "sha1": j.get("Sha1"),
        "src_addr": j.get("MachineIp"),
        "detection_source": j.get("DetectionSource"),
        "tactic": ",".join(j.get("MitreTechniques", [])) if j.get("MitreTechniques") else None,
        "timestamp": j.get("AlertCreationTime") or j.get("creationTime"),
        "message": j.get("Description") or j.get("description"),
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SIEM / Collectors
# ═══════════════════════════════════════════════════════════════════════════════

def parse_splunk(raw: str) -> Dict[str, Any]:
    """Parse Splunk JSON event exports."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    result = j.get("result", j)
    return {
        "_format": "SPLUNK_JSON",
        "vendor": "Splunk",
        "product": "Splunk Enterprise",
        "source": result.get("source") or j.get("source"),
        "sourcetype": result.get("sourcetype") or j.get("sourcetype"),
        "hostname": result.get("host") or j.get("host"),
        "index": result.get("index") or j.get("index"),
        "timestamp": result.get("_time") or j.get("_time"),
        "raw_event": result.get("_raw") or j.get("_raw"),
        "message": result.get("_raw") or j.get("_raw"),
        **{k: v for k, v in result.items() if not k.startswith("_")},
        "_raw": raw,
    }


def parse_elastic_ecs(raw: str) -> Dict[str, Any]:
    """Parse Elastic Common Schema events."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    event = j.get("event", {})
    source = j.get("source", {})
    dest = j.get("destination", {})
    user = j.get("user", {})
    host = j.get("host", {})
    proc = j.get("process", {})
    
    return {
        "_format": "ELASTIC_ECS",
        "vendor": "Elastic",
        "product": j.get("agent", {}).get("type", "Elasticsearch"),
        "timestamp": j.get("@timestamp"),
        "event_kind": event.get("kind"),
        "event_category": event.get("category"),
        "event_type": event.get("type"),
        "action": event.get("action"),
        "event_outcome": event.get("outcome"),
        "severity": event.get("severity"),
        "risk_score": event.get("risk_score"),
        "src_addr": source.get("ip"),
        "src_port": _safe_int(source.get("port")),
        "dst_addr": dest.get("ip"),
        "dst_port": _safe_int(dest.get("port")),
        "user_name": user.get("name"),
        "user_domain": user.get("domain"),
        "hostname": host.get("name") or host.get("hostname"),
        "host_os": host.get("os", {}).get("name"),
        "process_name": proc.get("name"),
        "command_line": proc.get("command_line"),
        "pid": _safe_int(proc.get("pid")),
        "parent_process": proc.get("parent", {}).get("name"),
        "message": j.get("message"),
        "tags": j.get("tags", []),
        "_raw": raw,
    }


def parse_qradar(raw: str) -> Dict[str, Any]:
    """Parse IBM QRadar events."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    return {
        "_format": "QRADAR",
        "vendor": "IBM",
        "product": "QRadar",
        "qid_name": j.get("QIDNAME"),
        "name": j.get("QIDNAME"),
        "logsource": j.get("LOGSOURCENAME"),
        "category": j.get("CATEGORYNAME"),
        "severity": j.get("severity"),
        "magnitude": j.get("magnitude"),
        "src_addr": j.get("sourceip"),
        "dst_addr": j.get("destinationip"),
        "src_port": _safe_int(j.get("sourceport")),
        "dst_port": _safe_int(j.get("destinationport")),
        "user_name": j.get("username"),
        "protocol": j.get("protocolid"),
        "event_count": _safe_int(j.get("eventCount")),
        "timestamp": j.get("starttime") or j.get("devicetime"),
        "message": j.get("QIDNAME"),
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# IDS / Network Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

def parse_suricata(raw: str) -> Dict[str, Any]:
    """Parse Suricata EVE JSON."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    alert = j.get("alert", {})
    
    return {
        "_format": "SURICATA",
        "vendor": "OISF",
        "product": "Suricata",
        "event_type": j.get("event_type"),
        "timestamp": j.get("timestamp"),
        "src_addr": j.get("src_ip"),
        "dst_addr": j.get("dest_ip"),
        "src_port": _safe_int(j.get("src_port")),
        "dst_port": _safe_int(j.get("dest_port")),
        "protocol": j.get("proto"),
        "app_proto": j.get("app_proto"),
        "alert_signature": alert.get("signature"),
        "alert_signature_id": alert.get("signature_id"),
        "alert_category": alert.get("category"),
        "alert_severity": alert.get("severity"),
        "severity": alert.get("severity"),
        "name": alert.get("signature"),
        "action": alert.get("action") or j.get("event_type"),
        "flow_id": j.get("flow_id"),
        "hostname": j.get("http", {}).get("hostname"),
        "http_url": j.get("http", {}).get("url"),
        "http_method": j.get("http", {}).get("http_method"),
        "user_agent": j.get("http", {}).get("http_user_agent"),
        "dns_query": j.get("dns", {}).get("rrname"),
        "dns_type": j.get("dns", {}).get("rrtype"),
        "_raw": raw,
    }


def parse_zeek(raw: str) -> Dict[str, Any]:
    """Parse Zeek/Bro TSV logs."""
    lines = raw.strip().split("\n")
    fields_line = None
    data_line = None
    
    for line in lines:
        if line.startswith("#fields"):
            fields_line = line.replace("#fields\t", "").split("\t")
        elif not line.startswith("#"):
            data_line = line
            break
    
    if not data_line:
        data_line = lines[-1] if lines else ""
    
    parts = data_line.split("\t")
    
    if fields_line and len(parts) == len(fields_line):
        parsed = dict(zip(fields_line, parts))
    else:
        # Assume conn.log format
        if len(parts) >= 15:
            parsed = {
                "ts": parts[0], "uid": parts[1],
                "id.orig_h": parts[2], "id.orig_p": parts[3],
                "id.resp_h": parts[4], "id.resp_p": parts[5],
                "proto": parts[6], "service": parts[7] if len(parts) > 7 else None,
                "duration": parts[8] if len(parts) > 8 else None,
            }
        else:
            parsed = {f"field_{i}": v for i, v in enumerate(parts)}
    
    return {
        "_format": "ZEEK",
        "vendor": "Zeek",
        "product": "Zeek IDS",
        "timestamp": parsed.get("ts"),
        "src_addr": parsed.get("id.orig_h"),
        "src_port": _safe_int(parsed.get("id.orig_p")),
        "dst_addr": parsed.get("id.resp_h"),
        "dst_port": _safe_int(parsed.get("id.resp_p")),
        "protocol": parsed.get("proto"),
        "service": parsed.get("service"),
        "uid": parsed.get("uid"),
        **parsed,
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Identity / SSO
# ═══════════════════════════════════════════════════════════════════════════════

def parse_okta(raw: str) -> Dict[str, Any]:
    """Parse Okta System Log events."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    
    actor = j.get("actor", {})
    client = j.get("client", {})
    outcome = j.get("outcome", {})
    target = j.get("target", [{}])[0] if j.get("target") else {}
    
    return {
        "_format": "OKTA",
        "vendor": "Okta",
        "product": "Okta SSO",
        "event_type": j.get("eventType"),
        "action": j.get("eventType"),
        "timestamp": j.get("published"),
        "user_name": actor.get("displayName") or actor.get("alternateId"),
        "user_id": actor.get("id"),
        "src_addr": client.get("ipAddress"),
        "user_agent": client.get("userAgent", {}).get("rawUserAgent"),
        "client_os": client.get("userAgent", {}).get("os"),
        "client_browser": client.get("userAgent", {}).get("browser"),
        "target_user": target.get("displayName") or target.get("alternateId"),
        "target_type": target.get("type"),
        "status": outcome.get("result"),
        "reason": outcome.get("reason"),
        "severity": j.get("severity"),
        "message": j.get("displayMessage"),
        "_raw": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Generic Parsers
# ═══════════════════════════════════════════════════════════════════════════════

def parse_generic_json(raw: str) -> Dict[str, Any]:
    """Parse any JSON log."""
    j = _safe_json(raw)
    if not j:
        return {"_raw": raw, "_parse_error": "Not valid JSON"}
    return {"_format": "GENERIC_JSON", **j, "_raw": raw}


def parse_csv(raw: str) -> List[Dict[str, Any]]:
    """Parse CSV log data, returns list of events."""
    lines = raw.strip().split("\n")
    if len(lines) < 2:
        return [{"_raw": raw, "_parse_error": "CSV needs at least header + 1 data row"}]
    
    headers = [h.strip().strip('"') for h in lines[0].split(",")]
    results = []
    
    for line in lines[1:]:
        if not line.strip():
            continue
        vals = [v.strip().strip('"') for v in line.split(",")]
        obj = {"_format": "CSV"}
        for i, h in enumerate(headers):
            obj[h] = vals[i] if i < len(vals) else ""
        # Auto-map common field names
        obj["src_addr"] = obj.get("src_ip") or obj.get("source_ip") or obj.get("SrcAddr")
        obj["dst_addr"] = obj.get("dst_ip") or obj.get("dest_ip") or obj.get("DstAddr")
        obj["src_port"] = _safe_int(obj.get("src_port") or obj.get("source_port"))
        obj["dst_port"] = _safe_int(obj.get("dst_port") or obj.get("dest_port"))
        obj["_raw"] = line
        results.append(obj)
    
    return results


def parse_key_value(raw: str) -> Dict[str, Any]:
    """Parse key=value formatted logs."""
    fields = {"_format": "KEY_VALUE"}
    for m in re.finditer(r'(\w+)=("([^"]*)"|(\S+))', raw):
        key = m.group(1)
        val = m.group(3) if m.group(3) is not None else m.group(4)
        fields[key] = val
    
    # Auto-map
    fields["src_addr"] = fields.get("src") or fields.get("srcip") or fields.get("source_ip")
    fields["dst_addr"] = fields.get("dst") or fields.get("dstip") or fields.get("dest_ip")
    fields["user_name"] = fields.get("user") or fields.get("username") or fields.get("usr")
    fields["action"] = fields.get("action") or fields.get("act")
    fields["_raw"] = raw
    return fields


# ═══════════════════════════════════════════════════════════════════════════════
# Parser Registry
# ═══════════════════════════════════════════════════════════════════════════════

PARSER_REGISTRY = {
    "CEF": parse_cef,
    "LEEF": parse_leef,
    "SYSLOG_RFC5424": parse_syslog_rfc5424,
    "SYSLOG_RFC3164": parse_syslog_rfc3164,
    "WINDOWS_EVENT": parse_windows_event,
    "WINDOWS_SYSMON": parse_windows_sysmon,
    "AWS_CLOUDTRAIL": parse_cloudtrail,
    "AWS_VPC_FLOW": parse_vpc_flow,
    "AWS_GUARDDUTY": parse_guardduty,
    "AZURE_ACTIVITY": parse_azure_activity,
    "AZURE_SIGNIN": parse_azure_signin,
    "GCP_AUDIT": parse_gcp_audit,
    "PALO_ALTO": parse_palo_alto,
    "FORTINET": parse_fortinet,
    "CHECKPOINT": parse_checkpoint,
    "CROWDSTRIKE_EDR": parse_crowdstrike,
    "SENTINEL_ONE": parse_sentinel_one,
    "CARBON_BLACK": parse_carbon_black,
    "MS_DEFENDER": parse_ms_defender,
    "SPLUNK_JSON": parse_splunk,
    "ELASTIC_ECS": parse_elastic_ecs,
    "QRADAR": parse_qradar,
    "SURICATA": parse_suricata,
    "ZEEK": parse_zeek,
    "OKTA": parse_okta,
    "GENERIC_JSON": parse_generic_json,
    "CSV": parse_csv,
    "KEY_VALUE": parse_key_value,
    "UNKNOWN": parse_key_value,
}


def parse(raw: str, format_name: str) -> Dict[str, Any]:
    """Parse raw log using the appropriate parser."""
    parser_fn = PARSER_REGISTRY.get(format_name, parse_key_value)
    try:
        result = parser_fn(raw)
        if isinstance(result, list):
            return result  # CSV multi-event
        return result
    except Exception as e:
        logger.error(f"Parser error for {format_name}: {e}")
        return {"_raw": raw, "_parse_error": str(e), "_format": format_name}
