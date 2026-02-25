"""
OCSF Universal Processor — FastAPI Backend
Agentic SOC v3 Integration Service

Endpoints:
    POST /api/v1/process          — Process single log → OCSF
    POST /api/v1/process/batch    — Process batch logs → OCSF
    POST /api/v1/process/raw      — Process raw text body (newline-separated)
    POST /api/v1/detect           — Detect log format only
    GET  /api/v1/stats            — Pipeline statistics
    GET  /api/v1/formats          — List supported formats
    GET  /api/v1/ocsf/schema      — OCSF schema reference
    GET  /api/v1/bead/{bead_id}   — Get Bead Memory chain
    POST /api/v1/stream/start     — Start streaming listener
    WS   /ws/stream               — WebSocket streaming ingestion
    GET  /health                   — Health check
"""
import sys
import os
import time
import asyncio
import json
import uuid
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from loguru import logger

from config import settings, OCSF_CLASSES, OCSF_SEVERITY, DEFAULT_AGENT_ROUTES
from core import detect_format, LogFormat
from parsers import PARSER_REGISTRY
from models import (
    LogInput, BatchLogInput, ProcessingResult, BatchResult,
    PipelineStats, OCSFEvent,
)
from pipeline import process_single, process_batch, metrics, bead_memory, agent_router


# ═══════════════════════════════════════════════════════════════════════════════
# Application Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown."""
    logger.info(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} starting...")
    logger.info(f"   Supported formats: {len(PARSER_REGISTRY)}")
    logger.info(f"   Agent routes: {len(DEFAULT_AGENT_ROUTES)}")
    logger.info(f"   Bead Memory: {'enabled' if settings.BEAD_MEMORY_ENABLED else 'disabled'}")
    
    # Initialize Bead Memory Redis
    await bead_memory.init_redis()
    
    yield
    
    logger.info("Shutting down OCSF Processor...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Universal log normalization engine → OCSF v1.1 for Agentic SOC",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# Health & Info
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    stats = metrics.get_stats()
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "uptime_seconds": stats.uptime_seconds,
        "total_processed": stats.total_processed,
        "events_per_second": stats.events_per_second,
    }


@app.get("/api/v1/formats", summary="List all supported log formats")
async def list_formats():
    """Returns all supported log formats with metadata."""
    formats = []
    for fmt_name in PARSER_REGISTRY.keys():
        try:
            fmt_enum = LogFormat(fmt_name)
            formats.append({
                "format": fmt_name,
                "parser_available": True,
            })
        except ValueError:
            formats.append({
                "format": fmt_name,
                "parser_available": True,
            })
    
    return {
        "total_formats": len(formats),
        "formats": formats,
        "categories": {
            "structured": ["CEF", "LEEF", "SYSLOG_RFC5424", "SYSLOG_RFC3164"],
            "cloud": ["AWS_CLOUDTRAIL", "AWS_VPC_FLOW", "AWS_GUARDDUTY", "AZURE_ACTIVITY", "AZURE_SIGNIN", "GCP_AUDIT"],
            "edr": ["CROWDSTRIKE_EDR", "SENTINEL_ONE", "CARBON_BLACK", "MS_DEFENDER"],
            "firewall": ["PALO_ALTO", "FORTINET", "CHECKPOINT"],
            "siem": ["SPLUNK_JSON", "ELASTIC_ECS", "QRADAR"],
            "ids": ["SURICATA", "ZEEK"],
            "identity": ["OKTA", "WINDOWS_EVENT", "WINDOWS_SYSMON"],
            "generic": ["GENERIC_JSON", "CSV", "KEY_VALUE"],
        }
    }


@app.get("/api/v1/ocsf/schema", summary="OCSF schema reference")
async def ocsf_schema():
    """Returns OCSF v1.1 schema reference data."""
    return {
        "version": "1.1.0",
        "classes": OCSF_CLASSES,
        "severity_levels": OCSF_SEVERITY,
        "categories": {
            1: "System Activity",
            2: "Findings",
            3: "Identity & Access Management",
            4: "Network Activity",
            5: "Discovery",
            6: "Application Activity",
        }
    }


@app.get("/api/v1/agents", summary="List configured agent routes")
async def list_agents():
    """Returns all configured agent routing rules."""
    return {
        "agents": {
            key: {
                "name": route.agent_name,
                "endpoint": route.endpoint,
                "priority": route.priority,
                "conditions": route.conditions,
            }
            for key, route in DEFAULT_AGENT_ROUTES.items()
        }
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Core Processing Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/process", response_model=ProcessingResult, summary="Process single log event")
async def process_log(log_input: LogInput):
    """
    Process a single raw log event through the full pipeline:
    Detect → Parse → Map to OCSF → Correlate (Bead Memory) → Route to Agents
    """
    result = await process_single(log_input)
    return result


@app.post("/api/v1/process/batch", response_model=BatchResult, summary="Process batch of log events")
async def process_log_batch(batch: BatchLogInput):
    """
    Process a batch of raw log events.
    Each event is independently detected, parsed, and mapped.
    Supports mixed formats in a single batch.
    """
    if len(batch.logs) > 10000:
        raise HTTPException(400, "Batch size limit is 10,000 events. Use streaming for larger volumes.")
    
    result = await process_batch(batch)
    return result


@app.post("/api/v1/process/raw", summary="Process raw text body")
async def process_raw_body(
    request: Request,
    source: Optional[str] = Query(None, description="Log source identifier"),
    route_to_agents: bool = Query(True, description="Route to SOC agents"),
):
    """
    Process raw text body containing one or more log events (newline-separated).
    Useful for direct piping from log collectors.
    
    Example:
        curl -X POST http://localhost:8900/api/v1/process/raw \\
            -H "Content-Type: text/plain" \\
            -d @/var/log/syslog
    """
    body = await request.body()
    raw_text = body.decode("utf-8", errors="replace")
    
    lines = [line for line in raw_text.strip().split("\n") if line.strip()]
    
    if not lines:
        raise HTTPException(400, "Empty body")
    
    if len(lines) == 1:
        result = await process_single(LogInput(
            raw=lines[0],
            source=source,
            route_to_agents=route_to_agents,
        ))
        return result
    
    # Batch processing
    batch = BatchLogInput(
        logs=[LogInput(raw=line, source=source) for line in lines],
        source=source,
        route_to_agents=route_to_agents,
    )
    result = await process_batch(batch)
    return result


@app.post("/api/v1/detect", summary="Detect log format only")
async def detect_log_format(log_input: LogInput):
    """Detect the format of a raw log without full processing."""
    fmt, confidence = detect_format(log_input.raw, log_input.format_hint)
    return {
        "format": fmt.value,
        "confidence": round(confidence, 3),
        "parser_available": fmt.value in PARSER_REGISTRY,
    }


@app.post("/api/v1/process/ndjson", summary="Process NDJSON stream")
async def process_ndjson(request: Request, route_to_agents: bool = Query(True)):
    """
    Process newline-delimited JSON (NDJSON) stream.
    Each line is a separate JSON log event.
    """
    body = await request.body()
    lines = body.decode("utf-8", errors="replace").strip().split("\n")
    
    batch = BatchLogInput(
        logs=[LogInput(raw=line, route_to_agents=route_to_agents) for line in lines if line.strip()],
        route_to_agents=route_to_agents,
    )
    
    return await process_batch(batch)


# ═══════════════════════════════════════════════════════════════════════════════
# Streaming Ingestion (WebSocket)
# ═══════════════════════════════════════════════════════════════════════════════

active_ws_connections: List[WebSocket] = []

@app.websocket("/ws/stream")
async def websocket_stream(ws: WebSocket):
    """
    WebSocket endpoint for real-time log streaming.
    
    Send raw log events as text messages.
    Receive OCSF-normalized events back.
    
    Protocol:
        Client → Server: raw log string or JSON {"raw": "...", "source": "..."}
        Server → Client: OCSF ProcessingResult JSON
    """
    await ws.accept()
    active_ws_connections.append(ws)
    logger.info(f"WebSocket client connected. Active: {len(active_ws_connections)}")
    
    try:
        while True:
            data = await ws.receive_text()
            
            try:
                # Try JSON input
                j = json.loads(data)
                log_input = LogInput(
                    raw=j.get("raw", data),
                    source=j.get("source"),
                    format_hint=j.get("format_hint"),
                    tags=j.get("tags"),
                )
            except (json.JSONDecodeError, ValueError):
                log_input = LogInput(raw=data)
            
            result = await process_single(log_input)
            
            await ws.send_json(result.model_dump(exclude_none=True))
    
    except WebSocketDisconnect:
        active_ws_connections.remove(ws)
        logger.info(f"WebSocket client disconnected. Active: {len(active_ws_connections)}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if ws in active_ws_connections:
            active_ws_connections.remove(ws)


# ═══════════════════════════════════════════════════════════════════════════════
# Bead Memory Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/bead/{bead_id}", summary="Get Bead Memory chain")
async def get_bead_chain(bead_id: str):
    """Retrieve all correlated events in a Bead Memory chain."""
    chain = bead_memory.get_chain(bead_id)
    if not chain or chain.get("event_count", 0) == 0:
        raise HTTPException(404, f"Bead chain '{bead_id}' not found")
    return chain


@app.get("/api/v1/bead", summary="List active Bead Memory chains")
async def list_bead_chains(
    limit: int = Query(50, le=500),
    min_events: int = Query(2, description="Minimum events in chain"),
):
    """List all active Bead Memory chains."""
    chains = []
    for bead_id, meta in bead_memory.bead_metadata.items():
        if meta.get("event_count", 0) >= min_events:
            chains.append({
                "bead_id": bead_id,
                "event_count": meta.get("event_count", 0),
                "severity_max": meta.get("severity_max", 0),
                "categories": list(meta.get("categories", set())),
                "created": meta.get("created"),
            })
    
    # Sort by severity then count
    chains.sort(key=lambda c: (-c["severity_max"], -c["event_count"]))
    
    return {
        "total_chains": len(chains),
        "chains": chains[:limit],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Stats & Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/stats", response_model=PipelineStats, summary="Pipeline statistics")
async def get_stats():
    """Get real-time pipeline performance metrics."""
    stats = metrics.get_stats()
    stats.bead_chains_active = bead_memory.active_chains
    stats.queue_depth = len(active_ws_connections)
    return stats


@app.get("/api/v1/stats/agents", summary="Agent dispatch statistics")
async def get_agent_stats():
    """Get per-agent dispatch statistics."""
    stats = metrics.get_stats()
    agent_details = {}
    
    for key, route in DEFAULT_AGENT_ROUTES.items():
        agent_details[key] = {
            "name": route.agent_name,
            "endpoint": route.endpoint,
            "dispatched_count": stats.agent_dispatch_counts.get(key, 0),
            "priority": route.priority,
        }
    
    return {
        "total_dispatches": sum(stats.agent_dispatch_counts.values()),
        "agents": agent_details,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Bulk Export
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/export/ndjson", summary="Export batch results as NDJSON")
async def export_ndjson(batch: BatchLogInput):
    """Process batch and return results as NDJSON stream."""
    
    async def generate():
        for log in batch.logs:
            result = await process_single(LogInput(
                raw=log.raw,
                source=log.source or batch.source,
                format_hint=log.format_hint,
                route_to_agents=batch.route_to_agents,
            ))
            if result.ocsf_event:
                yield json.dumps(result.ocsf_event.model_dump(exclude_none=True)) + "\n"
    
    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=ocsf_events.ndjson"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Webhook Registration
# ═══════════════════════════════════════════════════════════════════════════════

webhook_registrations: Dict[str, Dict] = {}

@app.post("/api/v1/webhooks", summary="Register output webhook")
async def register_webhook(
    url: str = Body(..., embed=True),
    filters: Optional[Dict] = Body(None, embed=True),
):
    """Register a webhook to receive OCSF events."""
    hook_id = str(uuid.uuid4())[:8]
    webhook_registrations[hook_id] = {
        "url": url,
        "filters": filters or {},
        "created": time.time(),
        "delivered": 0,
    }
    return {"webhook_id": hook_id, "url": url, "status": "registered"}


@app.get("/api/v1/webhooks", summary="List webhooks")
async def list_webhooks():
    return {"webhooks": webhook_registrations}


@app.delete("/api/v1/webhooks/{hook_id}", summary="Remove webhook")
async def remove_webhook(hook_id: str):
    if hook_id in webhook_registrations:
        del webhook_registrations[hook_id]
        return {"status": "removed"}
    raise HTTPException(404, "Webhook not found")


# ═══════════════════════════════════════════════════════════════════════════════
# Custom Agent Route Management
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/agents/routes", summary="Add custom agent route")
async def add_agent_route(
    agent_key: str = Body(..., embed=True),
    agent_name: str = Body(..., embed=True),
    endpoint: str = Body(..., embed=True),
    priority: int = Body(5, embed=True),
    conditions: Dict = Body({}, embed=True),
):
    """Add a custom agent routing rule at runtime."""
    from config import AgentRoute
    
    agent_router.routes[agent_key] = AgentRoute(
        agent_name=agent_name,
        endpoint=endpoint,
        priority=priority,
        conditions=conditions,
    )
    
    return {
        "status": "added",
        "agent_key": agent_key,
        "total_routes": len(agent_router.routes),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"""
╔══════════════════════════════════════════════════════════════╗
║          OCSF Universal Processor — Agentic SOC v3          ║
╠══════════════════════════════════════════════════════════════╣
║  API:        http://{settings.HOST}:{settings.PORT}                         ║
║  Docs:       http://{settings.HOST}:{settings.PORT}/docs                    ║
║  WebSocket:  ws://{settings.HOST}:{settings.PORT}/ws/stream                 ║
║  Formats:    {len(PARSER_REGISTRY):>3} supported                                    ║
║  Agents:     {len(DEFAULT_AGENT_ROUTES):>3} routing rules                               ║
║  Bead Mem:   {'ON ' if settings.BEAD_MEMORY_ENABLED else 'OFF'}                                               ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        reload=settings.DEBUG,
        log_level="info",
    )
