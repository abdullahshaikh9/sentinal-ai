from sqlalchemy.orm import Session

from app.models import ActivityEvent


def record_event(db: Session, event_type: str, summary: str, scan_id: int | None = None, finding_id: int | None = None, owner_id: int | None = None) -> None:
    db.add(ActivityEvent(event_type=event_type, summary=summary[:1000], scan_id=scan_id, finding_id=finding_id, owner_id=owner_id))
