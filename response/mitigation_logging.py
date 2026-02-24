"""Database logging helpers for autonomous mitigation actions."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class MitigationDBLogger:
    """Callable logger adapter for ZeroDayMitigationEngine action_logger."""

    def __init__(self, db_session: Any):
        self.db_session = db_session

    def __call__(self, event: Any) -> None:
        try:
            from app.models.database import MitigationActionLog

            row = MitigationActionLog(
                attack_id=event.attack_id,
                attack_type=event.attack_type,
                source_ip=event.source_ip,
                action_taken=event.action_taken,
                timestamp=event.timestamp,
                status=event.status,
                rollback_available=event.rollback_available,
                details=json.dumps(event.details),
            )
            self.db_session.add(row)
            self.db_session.commit()
        except Exception as exc:
            logger.error("Failed to persist mitigation event: %s", exc)
            try:
                self.db_session.rollback()
            except Exception:
                pass
