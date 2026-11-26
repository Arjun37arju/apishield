import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from app.core.masking import mask_headers


class ScanState(str, Enum):
    QUEUED = "Queued"
    RUNNING = "Running"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"
    FAILED = "Failed"


class Outcome(str, Enum):
    PASSED = "Passed"
    FINDING = "Finding"
    SKIPPED = "Skipped"
    ERROR = "Error"
    MANUAL = "Needs manual check"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    MANUAL = "manual review"
    FALSE_POSITIVE = "false positive"
    FIXED = "fixed"


@dataclass
class Finding:
    title: str
    category: str
    endpoint: str
    severity: Severity
    confidence: Confidence
    impact: str
    fix: str
    status: FindingStatus = FindingStatus.SUSPECTED
    evidence: dict = field(default_factory=dict)
    id: str = ""

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "endpoint": self.endpoint,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "evidence": self.evidence,
            "impact": self.impact,
            "fix": self.fix,
        }


@dataclass
class CheckResult:
    check_id: str
    name: str
    outcome: Outcome
    message: str = ""
    duration_ms: int = 0
    finding_count: int = 0

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "name": self.name,
            "outcome": self.outcome.value,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "finding_count": self.finding_count,
        }


SECRET_JSON = re.compile(
    r'("(?:password|password_hash|passwd|token|access_token|refresh_token|'
    r'secret|client_secret|api_key|apikey)"\s*:\s*)"[^"]*"',
    re.IGNORECASE,
)
AUTH_VALUE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
MAX_BODY_CHARS = 500


def redact_text(text):
    text = SECRET_JSON.sub(r'\1"****"', text)
    return AUTH_VALUE.sub(r"\1 ****", text)


def make_evidence(method, url, request_headers, status_code, response_body):
    """Build evidence that is safe to store, show and put in a PDF."""
    if isinstance(response_body, (bytes, bytearray)):
        body = bytes(response_body).decode("utf-8", errors="replace")
    else:
        body = str(response_body or "")
    return {
        "request": {
            "method": str(method).upper(),
            "url": redact_text(str(url))[:300],
            "headers": mask_headers(request_headers),
        },
        "response": {
            "status": int(status_code),
            "body": redact_text(body)[:MAX_BODY_CHARS],
        },
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
