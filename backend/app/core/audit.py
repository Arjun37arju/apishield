import json
import threading
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG = Path("logs") / "audit.log"
_lock = threading.Lock()


def audit(event, **details):
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    with _lock:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
