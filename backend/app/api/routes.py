"""HTTP API. Interactive docs are served at /docs (Swagger UI) by FastAPI."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app import __version__
from app.ai.explainer import ExplainerError
from app.core.ratelimit import client_key
from app.models import (
    CVE,
    ExplainRequest,
    Explanation,
    ScanJob,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    severity_from_cvss,
)
from app.scanner.commands import (
    PORT_PRESETS,
    TECHNIQUES,
    TIMING_TEMPLATES,
    CommandError,
    ScanOptions,
    build_command,
    explain_command,
)
from app.scanner.runner import nmap_available
from app.scanner.validator import TargetError, resolve_and_authorise

router = APIRouter(prefix="/api")

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
FINISHED = {ScanStatus.completed, ScanStatus.failed}


def _state(request: Request):
    return request.app.state


async def _prepare(request: Request, body: ScanRequest) -> tuple[str, str, ScanOptions, list[str]]:
    """Validate the target and options; return (display, ip, options, argv)."""
    state = _state(request)
    settings = state.settings
    try:
        target = await resolve_and_authorise(body.target, state.allowlist)
        options = ScanOptions(
            technique=body.technique,
            timing=body.timing,
            port_preset=body.port_preset,
            custom_ports=body.custom_ports,
            service_detection=body.service_detection,
            cve_detection=body.cve_detection,
            os_detection=body.os_detection,
            skip_host_discovery=body.skip_host_discovery,
        )
        argv = build_command(
            target.ip,
            options,
            nmap_path=settings.nmap_path,
            privileged=settings.nmap_privileged,
            host_timeout_seconds=settings.scan_timeout_seconds,
        )
    except (TargetError, CommandError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return target.display, target.ip, options, argv


# --- meta ------------------------------------------------------------------------------


@router.get("/health")
async def health(request: Request) -> dict:
    s = _state(request).settings
    return {
        "status": "ok",
        "version": __version__,
        "nmap_available": s.demo_mode or nmap_available(s.nmap_path),
        "demo_mode": s.demo_mode,
    }


@router.get("/options")
async def options(request: Request) -> dict:
    """Everything the UI needs to render the scan form."""
    state = _state(request)
    privileged = state.settings.nmap_privileged
    return {
        "techniques": [
            {**asdict(t), "available": privileged or not t.requires_privileges}
            for t in TECHNIQUES.values()
        ],
        "timing_templates": [asdict(t) for t in TIMING_TEMPLATES.values()],
        "port_presets": [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in PORT_PRESETS.items()
        ],
        "privileged": privileged,
        "os_detection_available": privileged,
        "allowed_targets": state.allowlist.describe(),
        "ai_enabled": state.explainer is not None,
        "ai_provider": state.explainer.provider.name if state.explainer else None,
        "demo_mode": state.settings.demo_mode,
    }


# --- scans -----------------------------------------------------------------------------


@router.post("/scans/preview")
async def preview_scan(request: Request, body: ScanRequest) -> dict:
    """Show the exact nmap command a request would run, with every flag explained."""
    display, ip, _, argv = await _prepare(request, body)
    return {
        "target": display,
        "resolved_ip": ip,
        "argv": argv,
        "command": " ".join(argv),
        "explanation": explain_command(argv),
    }


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(request: Request, body: ScanRequest) -> ScanJob:
    state = _state(request)
    if not body.authorized:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Confirm that you own this target or have permission to scan it.",
        )

    # Validate first so rejected requests don't use up the caller's quota.
    display, ip, options, argv = await _prepare(request, body)

    allowed, retry_after = state.scan_limiter.check(
        client_key(request, state.settings.trust_proxy_headers)
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many scans. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    return await state.manager.submit(display, ip, asdict(options), argv)


@router.get("/scans")
async def list_scans(request: Request, limit: int = Query(30, ge=1, le=100)) -> list[ScanSummary]:
    return await _state(request).db.list_scans(limit)


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str) -> ScanJob:
    job = await _state(request).manager.get(scan_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return job


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(request: Request, scan_id: str) -> None:
    state = _state(request)
    if state.manager.is_live(scan_id):
        job = await state.manager.get(scan_id)
        if job and job.status not in FINISHED:
            raise HTTPException(status.HTTP_409_CONFLICT, "Scan is still running")
    state.manager.forget(scan_id)
    if not await state.db.delete_scan(scan_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")


@router.get("/scans/{scan_id}/events")
async def scan_events(request: Request, scan_id: str) -> StreamingResponse:
    """Server-Sent Events stream of scan progress. Closes when the scan finishes."""
    manager = _state(request).manager
    if await manager.get(scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")

    async def stream():
        last_sent = None
        idle = 0.0
        while True:
            if await request.is_disconnected():
                return
            job = await manager.get(scan_id)
            if job is None:
                return
            snapshot = {
                "status": job.status.value,
                "progress": round(job.progress, 1),
                "current_task": job.current_task,
                "error": job.error,
            }
            if snapshot != last_sent:
                yield f"data: {json.dumps(snapshot)}\n\n"
                last_sent = snapshot
                idle = 0.0
            elif idle >= 15:
                yield ": keep-alive\n\n"
                idle = 0.0
            if job.status in FINISHED:
                return
            await asyncio.sleep(0.5)
            idle += 0.5

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --- CVEs ------------------------------------------------------------------------------


def _check_cve_id(cve_id: str) -> str:
    cve_id = cve_id.upper()
    if not CVE_ID.match(cve_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid CVE id (e.g. CVE-2021-41773)")
    return cve_id


@router.get("/cves/{cve_id}")
async def get_cve(request: Request, cve_id: str) -> CVE:
    cve_id = _check_cve_id(cve_id)
    return await _state(request).enricher.enrich_cve(CVE(id=cve_id))


@router.post("/cves/{cve_id}/explain")
async def explain_cve(request: Request, cve_id: str, body: ExplainRequest) -> Explanation:
    state = _state(request)
    cve_id = _check_cve_id(cve_id)
    if state.explainer is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "AI explanations are off. Set GEMINI_API_KEY in .env (see README).",
        )

    allowed, retry_after = state.ai_limiter.check(
        client_key(request, state.settings.trust_proxy_headers)
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many AI requests. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    cve = await state.enricher.enrich_cve(
        CVE(id=cve_id, cvss=body.cvss, severity=severity_from_cvss(body.cvss),
            is_exploit=body.is_exploit)
    )
    try:
        return await state.explainer.explain(cve, body.product, body.version, body.port)
    except ExplainerError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
