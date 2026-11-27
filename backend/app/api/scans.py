from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.audit import audit
from app.core.url_validation import TargetError, clean_target_url
from app.database.db import get_scan, init_db, list_scans, save_scan
from app.scanner.registry import full_registry
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
    accounts: dict | None = None


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

    check_ids = req.check_ids if req.check_ids else list(registry.keys())
    try:
        scan = manager.create(
            target, req.permission_confirmed, check_ids, accounts=req.accounts
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