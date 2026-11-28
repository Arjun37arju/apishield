from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.core.audit import audit
from app.core.settings import settings
from app.core.url_validation import TargetError, clean_target_url
from app.database.db import add_report, get_scan, init_db, list_scans, save_scan
from app.reports.pdf_report import build_report
from app.scanner.registry import full_registry
from app.services.auth_providers import AuthError, ApiKeyProvider, BasicAuthProvider
from app.services.auth_token_providers import BearerTokenProvider
from app.services.scan_manager import ScanManager

router = APIRouter(tags=["scans"])

init_db()


def _on_finished(scan):
    # Called once when a scan ends: save it to the database.
    try:
        save_scan(scan)
    except Exception as e:
        audit("scan_save_failed", scan_id=scan.id, reason=str(e))


registry = full_registry()
manager = ScanManager(registry, on_finished=_on_finished)


class ScanRequest(BaseModel):
    url: str
    permission_confirmed: bool = False
    check_ids: list[str] | None = None  # None = run all checks
    endpoints: list[str | dict] | None = None
    lab_accounts: bool = False  # use the built-in fake lab test accounts
    auth: dict | None = None  # {"user_a": {...}, "user_b": {...}}, memory only


def _lab_accounts(target):
    """Fake test accounts for the intentionally vulnerable lab only."""
    if not (settings.allow_lab_exception and target["port"] == settings.lab_port):
        raise HTTPException(
            status_code=400,
            detail="lab_accounts only works against the lab on port "
            + str(settings.lab_port)
            + " with ALLOW_LAB_EXCEPTION=true",
        )
    try:
        user_a = BearerTokenProvider("lab-token-user-a")
        user_b = BearerTokenProvider("lab-token-user-b")
        expired = BearerTokenProvider(
            "lab-token-expired", expired_token="lab-token-expired"
        )
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"user_a": user_a, "user_b": user_b, "expired_token": expired}


def _provider_from(spec):
    kind = str(spec.get("type", "")).lower()
    if kind == "bearer":
        return BearerTokenProvider(spec.get("token"))
    if kind == "basic":
        return BasicAuthProvider(spec.get("username"), spec.get("password"))
    if kind == "api_key":
        return ApiKeyProvider(
            spec.get("key"), spec.get("header_name") or "X-API-Key"
        )
    raise AuthError("unknown login type")


def _user_accounts(auth):
    """Accounts sent by the dashboard. Held in memory for this scan only."""
    accounts = {}
    try:
        for name in ("user_a", "user_b"):
            spec = (auth or {}).get(name)
            if isinstance(spec, dict) and spec.get("type"):
                accounts[name] = _provider_from(spec)
        a = (auth or {}).get("user_a") or {}
        if str(a.get("type", "")).lower() == "bearer" and a.get("expired_token"):
            accounts["expired_token"] = BearerTokenProvider(
                a.get("expired_token")
            )
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return accounts or None


@router.get("/checks")
def list_checks():
    return [
        {
            "id": check_id,
            "name": getattr(check, "name", check_id),
            "description": getattr(check, "description", ""),
        }
        for check_id, check in registry.items()
    ]


@router.post("/scans")
async def start_scan(req: ScanRequest):
    if not req.permission_confirmed:
        audit("scan_rejected", reason="permission not confirmed")
        raise HTTPException(
            status_code=400,
            detail="You must confirm you have permission to test this target",
        )
    try:
        target = clean_target_url(req.url)
    except TargetError as e:
        audit("scan_rejected", reason=str(e))
        raise HTTPException(status_code=400, detail=str(e))

    if req.endpoints:
        target["endpoints"] = req.endpoints[:50]

    accounts = (
        _lab_accounts(target) if req.lab_accounts else _user_accounts(req.auth)
    )
    check_ids = req.check_ids if req.check_ids else list(registry.keys())
    try:
        scan = manager.create(
            target, req.permission_confirmed, check_ids, accounts=accounts
        )
        manager.start(scan.id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return scan.to_dict()


@router.get("/scans")
def scan_history(limit: int = 50):
    return list_scans(limit=limit)


def _find_scan(scan_id: str):
    """Running scans live in memory; finished ones may only be in the database."""
    try:
        return manager.get(scan_id).to_dict()
    except KeyError:
        pass
    try:
        return get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/scans/{scan_id}")
def scan_status(scan_id: str):
    return _find_scan(scan_id)


@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: str):
    data = _find_scan(scan_id)
    return {"scan_id": scan_id, "findings": data.get("findings", [])}


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    try:
        return manager.cancel(scan_id).to_dict()
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")


@router.post("/scans/{scan_id}/report")
def make_report(scan_id: str):
    data = _find_scan(scan_id)
    if data.get("state") in ("Running", "Queued"):
        raise HTTPException(status_code=409, detail="Scan is not finished yet")
    path = build_report(data, settings.reports_dir)
    try:
        add_report(scan_id, path.name)
    except Exception as e:
        audit("report_record_failed", scan_id=scan_id, reason=str(e))
    audit("report_created", scan_id=scan_id, file=path.name)
    return {"file_name": path.name, "download": "/reports/" + path.name}


@router.get("/reports/{file_name}")
def download_report(file_name: str, download: bool = False):
    # Only a bare .pdf file name inside the reports folder is allowed.
    if Path(file_name).name != file_name or not file_name.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Invalid file name")
    path = Path(settings.reports_dir) / file_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, media_type="application/pdf", filename=file_name, content_disposition_type="attachment" if download else "inline")