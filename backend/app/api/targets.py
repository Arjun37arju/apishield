from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.core.audit import audit
from app.core.settings import settings
from app.core.url_validation import TargetError, clean_target_url
from app.services.openapi_import import OpenAPIError, parse_openapi

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetRequest(BaseModel):
    url: str
    permission_confirmed: bool = False


@router.post("/validate")
def validate_target(req: TargetRequest):
    if not req.permission_confirmed:
        audit("target_rejected", reason="permission not confirmed")
        raise HTTPException(
            status_code=400,
            detail="You must confirm you have permission to test this target",
        )
    try:
        target = clean_target_url(req.url)
    except TargetError as e:
        audit("target_rejected", reason=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    audit("permission_confirmed", scope=target["scope"])
    return {"target": target, "requests_sent": 0}


@router.post("/openapi")
async def import_openapi(file: UploadFile = File(...)):
    content = await file.read(settings.max_upload_bytes + 1)
    try:
        result = parse_openapi(file.filename, content)
    except OpenAPIError as e:
        audit("openapi_rejected", reason=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    audit(
        "openapi_imported",
        endpoint_count=result["endpoint_count"],
        size_bytes=len(content),
    )
    return {**result, "requests_sent": 0}
