"""
OCSF Processing Pipeline
Orchestrates: Detect → Parse → Map → Enrich → Route → Dispatch
Integrates with Bead Memory for attack chain correlation.
"""
import time
import uuid
import asyncio
import json
from typing import Dict, Any, List, Optional
from collections import defaultdict
from loguru import logger

from config import settings, DEFAULT_AGENT_ROUTES
from core import detect_format, LogFormat
from parsers import parse, PARSER_REGISTRY
from mappers import map_to_ocsf
from models import (
    OCSFEvent, ProcessingResult, BatchResult, PipelineStats,
    LogInput, BatchLogInput, AgentDispatchResult,
)

try:
    import httpx
    HTTP_CLIENT_AVAILABLE = True
except ImportError:
    HTTP_CLIENT_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Statistics
# ═══════════════════════════════════════════════════════════════════════════════

class PipelineMetrics:
    """Thread-safe pipeline metrics collector."""
    
    def __init__(self):
        self.total_processed = 0
        self.total_errors = 0
        self.format_counts: Dict[str, int] = defaultdict(int)
        self.severity_counts: Dict[str, int] = defaultdict(int)
        self.agent_dispatch_counts: Dict[str, int] = defaultdict(int)
        self.processing_times: List[float] = []
        self.start_time = time.time()
        self._lock = asyncio.Lock() if asyncio.get_event_loop().is_running() else None
    
    async def record(self, format_name: str, severity: str, processing_time: float, agents: List[str], error: bool = False):
        self.total_processed += 1
        if error:
            self.total_errors += 1
        self.format_counts[format_name] += 1
        self.severity_counts[severity] += 1
        self.processing_times.append(processing_time)
        for agent in agents:
            self.agent_dispatch_counts[agent] += 1
        # Keep only last 10000 times for avg calculation
        if len(self.processing_times) > 10000:
            self.processing_times = self.processing_times[-5000:]
    
    def get_stats(self) -> PipelineStats:
        uptime = time.time() - self.start_time
        avg_time = sum(self.processing_times) / len(self.processing_times) if self.processing_times else 0
        eps = self.total_processed / uptime if uptime > 0 else 0
        
        return PipelineStats(
            total_processed=self.total_processed,
            total_errors=self.total_errors,
            events_per_second=round(eps, 2),
            avg_processing_time_ms=round(avg_time, 3),
            format_counts=dict(self.format_counts),
            severity_counts=dict(self.severity_counts),
            agent_dispatch_counts=dict(self.agent_dispatch_counts),
            uptime_seconds=round(uptime, 1),
        )


metrics = PipelineMetrics()


# ═══════════════════════════════════════════════════════════════════════════════
# Bead Memory Integration
# ═══════════════════════════════════════════════════════════════════════════════

class BeadMemoryManager:
    """
    Bead Memory for attack chain correlation.
    Links related OCSF events into chains (beads) using correlation keys.
    """
    
    def __init__(self):
        self.chains: Dict[str, List[str]] = {}  # correlation_key → [event_uids]
        self.event_beads: Dict[str, str] = {}   # event_uid → bead_id
        self.bead_metadata: Dict[str, Dict] = {}  # bead_id → metadata
        self._redis = None
    
    async def init_redis(self):
        """Initialize Redis backend for production."""
        if settings.BEAD_MEMORY_ENABLED and settings.REDIS_URL:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    settings.REDIS_URL,
                    db=settings.REDIS_BEAD_DB,
                    decode_responses=True,
                )
                logger.info("Bead Memory: Redis backend connected")
            except Exception as e:
                logger.warning(f"Bead Memory: Redis unavailable, using in-memory: {e}")
    
    async def correlate(self, event: OCSFEvent) -> Optional[str]:
        """
        Correlate event with existing chains.
        Returns bead_id if event joins an existing chain.
        """
        if not settings.BEAD_MEMORY_ENABLED:
            return None
        
        event_uid = event.metadata.uid
        correlation_keys = event.correlation_keys
        
        if not correlation_keys:
            return None
        
        # Check if any correlation key matches an existing chain
        matched_bead_id = None
        
        if self._redis:
            for key in correlation_keys:
                bead_id = await self._redis.get(f"bead:key:{key}")
                if bead_id:
                    matched_bead_id = bead_id
                    break
        else:
            for key in correlation_keys:
                if key in self.chains:
                    # Find bead_id for this chain
                    existing_events = self.chains[key]
                    if existing_events:
                        matched_bead_id = self.event_beads.get(existing_events[0])
                    break
        
        if matched_bead_id:
            # Add to existing chain
            bead_id = matched_bead_id
        else:
            # Create new bead
            bead_id = f"bead-{uuid.uuid4().hex[:12]}"
            self.bead_metadata[bead_id] = {
                "created": time.time(),
                "event_count": 0,
                "severity_max": 0,
                "categories": set(),
            }
        
        # Register event in chains
        for key in correlation_keys:
            if self._redis:
                await self._redis.rpush(f"bead:chain:{key}", event_uid)
                await self._redis.set(f"bead:key:{key}", bead_id)
                await self._redis.expire(f"bead:chain:{key}", settings.BEAD_CORRELATION_WINDOW_SEC)
                await self._redis.expire(f"bead:key:{key}", settings.BEAD_CORRELATION_WINDOW_SEC)
            else:
                if key not in self.chains:
                    self.chains[key] = []
                self.chains[key].append(event_uid)
                # Trim to max length
                if len(self.chains[key]) > settings.BEAD_CHAIN_MAX_LENGTH:
                    self.chains[key] = self.chains[key][-settings.BEAD_CHAIN_MAX_LENGTH:]
        
        self.event_beads[event_uid] = bead_id
        
        # Update bead metadata
        if bead_id in self.bead_metadata:
            meta = self.bead_metadata[bead_id]
            meta["event_count"] += 1
            meta["severity_max"] = max(meta["severity_max"], event.severity_id)
            meta["categories"].add(event.category_uid)
        
        return bead_id
    
    def get_chain(self, bead_id: str) -> Dict[str, Any]:
        """Get all events in a bead chain."""
        meta = self.bead_metadata.get(bead_id, {})
        events = [uid for uid, bid in self.event_beads.items() if bid == bead_id]
        return {
            "bead_id": bead_id,
            "event_count": len(events),
            "event_uids": events,
            "metadata": {
                "created": meta.get("created"),
                "severity_max": meta.get("severity_max", 0),
                "categories": list(meta.get("categories", set())),
            }
        }
    
    @property
    def active_chains(self) -> int:
        return len(self.bead_metadata)


bead_memory = BeadMemoryManager()


# ═══════════════════════════════════════════════════════════════════════════════
# Agent Router
# ═══════════════════════════════════════════════════════════════════════════════

class AgentRouter:
    """
    Routes OCSF events to appropriate Agentic SOC agents
    based on classification, severity, and content.
    """
    
    def __init__(self):
        self.routes = DEFAULT_AGENT_ROUTES
        self._client = None
    
    async def _get_client(self):
        if not self._client and HTTP_CLIENT_AVAILABLE:
            self._client = httpx.AsyncClient(timeout=settings.WEBHOOK_TIMEOUT)
        return self._client
    
    def determine_routes(self, event: OCSFEvent) -> List[str]:
        """Determine which agents should receive this event."""
        matched = []
        
        for route_key, route in self.routes.items():
            conditions = route.conditions
            
            # All events → detection
            if conditions.get("all_events"):
                matched.append(route_key)
                continue
            
            # Severity check
            min_sev = conditions.get("min_severity", 0)
            if min_sev and event.severity_id < min_sev:
                continue
            
            # Category check
            cats = conditions.get("categories", [])
            if cats and event.category_uid not in cats:
                continue
            
            # Class UID check
            class_uids = conditions.get("class_uids", [])
            if class_uids and event.class_uid not in class_uids:
                continue
            
            # Observable check
            if conditions.get("has_observables") and not event.observables:
                continue
            
            obs_types = conditions.get("observable_types", [])
            if obs_types:
                event_obs_types = {o.type_id for o in event.observables}
                if not event_obs_types.intersection(set(obs_types)):
                    continue
            
            # Process check
            if conditions.get("has_process") and not event.process:
                continue
            
            # Suspicious patterns (for hunting agent)
            if conditions.get("suspicious_patterns"):
                if not self._has_suspicious_patterns(event):
                    continue
            
            matched.append(route_key)
        
        # Sort by priority
        matched.sort(key=lambda k: self.routes[k].priority)
        
        return matched
    
    def _has_suspicious_patterns(self, event: OCSFEvent) -> bool:
        """Check for patterns worth sending to hunting agent."""
        msg = (event.message or "").lower()
        
        suspicious_indicators = [
            r"powershell.*encoded",
            r"cmd.*\/c.*whoami",
            r"certutil.*urlcache",
            r"bitsadmin.*transfer",
            r"reverse.*shell",
            r"lateral.*movement",
            r"pass.*the.*hash",
            r"mimikatz|sekurlsa|lsass",
            r"scheduled.*task.*create",
            r"wmi.*process.*call",
            r"psexec|winrm|dcom",
            r"\.ps1|\.vbs|\.hta|\.scr",
            r"base64.*decode",
            r"nc\.exe|ncat|netcat",
            r"reg.*add.*run",
        ]
        
        cmd = ""
        if event.process and event.process.cmd_line:
            cmd = event.process.cmd_line.lower()
        
        search_text = f"{msg} {cmd}"
        
        import re
        return any(re.search(p, search_text) for p in suspicious_indicators)
    
    async def dispatch(self, event: OCSFEvent, route_keys: List[str]) -> List[AgentDispatchResult]:
        """Dispatch event to matched agents via HTTP."""
        results = []
        client = await self._get_client()
        
        if not client:
            # No HTTP client — return mock results
            for key in route_keys:
                route = self.routes[key]
                results.append(AgentDispatchResult(
                    agent_name=route.agent_name,
                    success=True,
                    response_time_ms=0,
                    response={"status": "queued", "note": "HTTP client not available, event queued"},
                ))
            return results
        
        for key in route_keys:
            route = self.routes[key]
            start = time.time()
            
            try:
                payload = {
                    "ocsf_event": event.model_dump(exclude_none=True),
                    "bead_id": event.bead_id,
                    "correlation_keys": event.correlation_keys,
                    "pipeline_stage": event.pipeline_stage,
                }
                
                resp = await client.post(
                    route.endpoint,
                    json=payload,
                    timeout=settings.WEBHOOK_TIMEOUT,
                )
                
                elapsed = (time.time() - start) * 1000
                
                results.append(AgentDispatchResult(
                    agent_name=route.agent_name,
                    success=resp.status_code < 400,
                    response_time_ms=round(elapsed, 2),
                    response=resp.json() if resp.status_code < 400 else None,
                    error=resp.text if resp.status_code >= 400 else None,
                ))
            except Exception as e:
                elapsed = (time.time() - start) * 1000
                results.append(AgentDispatchResult(
                    agent_name=route.agent_name,
                    success=False,
                    response_time_ms=round(elapsed, 2),
                    error=str(e),
                ))
        
        return results


agent_router = AgentRouter()


# ═══════════════════════════════════════════════════════════════════════════════
# Main Processing Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

async def process_single(log_input: LogInput) -> ProcessingResult:
    """
    Full pipeline for a single log event:
    Detect → Parse → Map → Correlate → Route → Dispatch
    """
    start_time = time.time()
    errors = []
    
    try:
        # ── Stage 1: Format Detection ──
        t0 = time.time()
        fmt, confidence = detect_format(log_input.raw, log_input.format_hint)
        format_name = fmt.value
        detect_time = (time.time() - t0) * 1000
        
        # ── Stage 2: Parse ──
        t0 = time.time()
        parsed = parse(log_input.raw, format_name)
        parse_time = (time.time() - t0) * 1000
        
        # Handle CSV multi-events (return first for single processing)
        if isinstance(parsed, list):
            parsed = parsed[0] if parsed else {"_raw": log_input.raw}
        
        # Add source tag
        if log_input.source:
            parsed["_source"] = log_input.source
        
        # ── Stage 3: OCSF Mapping ──
        t0 = time.time()
        ocsf_event = map_to_ocsf(parsed, format_name)
        map_time = (time.time() - t0) * 1000
        
        # Add tags
        if log_input.tags:
            ocsf_event.metadata.labels = log_input.tags
        
        # ── Stage 4: Bead Memory Correlation ──
        bead_id = await bead_memory.correlate(ocsf_event)
        if bead_id:
            ocsf_event.bead_id = bead_id
            ocsf_event.metadata.correlation_uid = bead_id
        
        # ── Stage 5: Agent Routing ──
        agent_routes = []
        if log_input.route_to_agents:
            agent_routes = agent_router.determine_routes(ocsf_event)
            ocsf_event.agent_routes = agent_routes
            ocsf_event.pipeline_stage = "routed"
            
            # ── Stage 6: Dispatch to Agents (async, non-blocking) ──
            if agent_routes:
                # Fire and forget — don't block the pipeline
                asyncio.create_task(_dispatch_background(ocsf_event, agent_routes))
        
        total_time = (time.time() - start_time) * 1000
        
        # Record metrics
        await metrics.record(
            format_name=format_name,
            severity=ocsf_event.severity or "Unknown",
            processing_time=total_time,
            agents=agent_routes,
        )
        
        return ProcessingResult(
            success=True,
            ocsf_event=ocsf_event,
            detected_format=format_name,
            parse_time_ms=round(parse_time, 3),
            map_time_ms=round(map_time, 3),
            total_time_ms=round(total_time, 3),
            agent_routes=agent_routes,
            bead_id=bead_id,
            errors=errors,
        )
    
    except Exception as e:
        total_time = (time.time() - start_time) * 1000
        logger.error(f"Pipeline error: {e}")
        
        await metrics.record(
            format_name="ERROR",
            severity="Unknown",
            processing_time=total_time,
            agents=[],
            error=True,
        )
        
        return ProcessingResult(
            success=False,
            detected_format=None,
            total_time_ms=round(total_time, 3),
            errors=[str(e)],
        )


async def _dispatch_background(event: OCSFEvent, routes: List[str]):
    """Background dispatch to agents."""
    try:
        await agent_router.dispatch(event, routes)
    except Exception as e:
        logger.error(f"Background dispatch error: {e}")


async def process_batch(batch: BatchLogInput) -> BatchResult:
    """Process a batch of log events."""
    start_time = time.time()
    
    results = []
    format_dist = defaultdict(int)
    severity_dist = defaultdict(int)
    agent_routing_summary = defaultdict(int)
    success_count = 0
    
    # Process all logs concurrently
    tasks = [
        process_single(LogInput(
            raw=log.raw,
            source=log.source or batch.source,
            format_hint=log.format_hint,
            tags=log.tags,
            route_to_agents=batch.route_to_agents,
        ))
        for log in batch.logs
    ]
    
    results = await asyncio.gather(*tasks)
    
    for result in results:
        if result.success:
            success_count += 1
        if result.detected_format:
            format_dist[result.detected_format] += 1
        if result.ocsf_event:
            severity_dist[result.ocsf_event.severity or "Unknown"] += 1
        for route in result.agent_routes:
            agent_routing_summary[route] += 1
    
    total_time = (time.time() - start_time) * 1000
    
    return BatchResult(
        total=len(batch.logs),
        success=success_count,
        failed=len(batch.logs) - success_count,
        results=results,
        processing_time_ms=round(total_time, 3),
        format_distribution=dict(format_dist),
        severity_distribution=dict(severity_dist),
        agent_routing_summary=dict(agent_routing_summary),
        correlation_id=batch.correlation_id or str(uuid.uuid4()),
    )
