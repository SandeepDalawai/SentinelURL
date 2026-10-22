from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, JSON, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_created_at", "created_at"), Index("ix_scans_risk_level", "risk_level"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    original_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    registered_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    score_reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
