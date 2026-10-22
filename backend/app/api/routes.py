import csv
import io
import time
from collections import Counter, defaultdict
from datetime import date, datetime, time as datetime_time, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import MAX_BULK_BYTES, MAX_BULK_ROWS, MAX_URL_LENGTH
from app.db.database import get_db
from app.models import Scan
from app.schemas.scan import ScanRequest, ScanPage
from app.services.detection_rules.rules import analyze
from app.services.risk_scoring.scorer import score
from app.services.url_analyzer.parser import parse_url

router = APIRouter(prefix="/api/v1")
_request_hits: dict[str, list[float]] = defaultdict(list)


def enforce_rate_limit(request: Request):
    from app.core.config import MAX_REQUESTS_PER_MINUTE
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    hits = [stamp for stamp in _request_hits[ip] if now - stamp < 60]
    if len(hits) >= MAX_REQUESTS_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit reached. Please wait before submitting another request.")
    hits.append(now)
    if len(_request_hits) > 10_000:
        _request_hits.clear()
    _request_hits[ip] = hits


def serialized(scan: Scan):
    return {"id": scan.id, "original_url": scan.original_url, "normalized_url": scan.normalized_url, "hostname": scan.hostname, "registered_domain": scan.registered_domain, "risk_score": scan.risk_score, "risk_level": scan.risk_level, "score_reasons": scan.score_reasons, "findings": scan.findings, "created_at": scan.created_at}


def create_scan(url: str, db: Session):
    try:
        parsed = parse_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    findings = analyze(parsed)
    risk_score, risk_level, reasons = score(findings)
    record = Scan(original_url=parsed.original, normalized_url=parsed.normalized, hostname=parsed.hostname, registered_domain=parsed.registered_domain, risk_score=risk_score, risk_level=risk_level, findings=findings, score_reasons=reasons)
    db.add(record)
    db.commit()
    db.refresh(record)
    return serialized(record)


@router.get("/health")
def health():
    return {"status": "ok", "service": "SentinelURL API", "analysis": "offline heuristic"}


@router.post("/scans", dependencies=[Depends(enforce_rate_limit)])
def scan_url(payload: ScanRequest, db: Session = Depends(get_db)):
    return create_scan(payload.url, db)


@router.get("/scans")
def list_scans(search: str = "", severity: str = "", start_date: date | None = None, end_date: date | None = None, sort_by: str = "created_at", sort_order: str = "desc", page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    stmt = select(Scan)
    if search:
        like = f"%{search[:200]}%"
        stmt = stmt.where(or_(Scan.original_url.ilike(like), Scan.hostname.ilike(like), Scan.registered_domain.ilike(like)))
    if severity and severity.lower() in {"low", "medium", "high", "critical"}:
        stmt = stmt.where(func.lower(Scan.risk_level) == severity.lower())
    if start_date:
        stmt = stmt.where(Scan.created_at >= datetime.combine(start_date, datetime_time.min))
    if end_date:
        stmt = stmt.where(Scan.created_at <= datetime.combine(end_date, datetime_time.max))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    sort_columns = {"created_at": Scan.created_at, "risk_score": Scan.risk_score, "risk_level": Scan.risk_level, "hostname": Scan.hostname}
    sort_column = sort_columns.get(sort_by, Scan.created_at)
    order_column = sort_column.asc() if sort_order.lower() == "asc" else sort_column.desc()
    rows = db.scalars(stmt.order_by(order_column, desc(Scan.id)).offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [serialized(row) for row in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return serialized(row)


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(row)
    db.commit()
    return {"deleted": True, "id": scan_id}


@router.post("/scans/bulk", dependencies=[Depends(enforce_rate_limit)])
async def bulk_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Upload a .csv file.")
    content = await file.read(MAX_BULK_BYTES + 1)
    if len(content) > MAX_BULK_BYTES:
        raise HTTPException(status_code=413, detail="CSV exceeds the 1 MB limit.")
    try:
        text = content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise HTTPException(status_code=400, detail="CSV must be valid UTF-8.") from exc
    if not rows:
        raise HTTPException(status_code=400, detail="CSV is empty.")
    has_header = any(cell.strip().lower() == "url" for cell in rows[0])
    col = next((i for i, cell in enumerate(rows[0]) if cell.strip().lower() == "url"), 0) if has_header else 0
    candidates = rows[1:] if has_header else rows
    if len(candidates) > MAX_BULK_ROWS:
        raise HTTPException(status_code=413, detail=f"CSV exceeds the {MAX_BULK_ROWS} row limit.")
    out = []
    for index, row in enumerate(candidates, start=2 if has_header else 1):
        if not row or col >= len(row) or not row[col].strip():
            out.append({"row": index, "url": row[col] if col < len(row) else "", "error": "Missing URL value"})
            continue
        try:
            if len(row[col]) > MAX_URL_LENGTH: raise ValueError("URL exceeds the 2,048 character limit.")
            out.append(create_scan(row[col], db))
        except HTTPException as exc:
            out.append({"row": index, "url": row[col][:MAX_URL_LENGTH], "error": exc.detail})
    return {"items": out, "total": len(out), "successful": sum("id" in item for item in out), "failed": sum("error" in item for item in out)}


@router.get("/analytics/summary")
def summary(db: Session = Depends(get_db)):
    rows = db.scalars(select(Scan).order_by(desc(Scan.created_at))).all()
    levels = Counter(row.risk_level for row in rows)
    categories = Counter(item.get("category", "Other") for row in rows for item in row.findings)
    return {"total_scans": len(rows), "high_risk": levels["High"] + levels["Critical"], "critical": levels["Critical"], "distribution": {key: levels[key] for key in ["Low", "Medium", "High", "Critical"]}, "categories": [{"name": k, "count": v} for k, v in categories.most_common(8)], "recent": [serialized(row) for row in rows[:8]]}


@router.get("/analytics/trends")
def trends(db: Session = Depends(get_db)):
    rows = db.scalars(select(Scan).order_by(Scan.created_at)).all()
    grouped = Counter()
    for row in rows:
        created = row.created_at.replace(tzinfo=timezone.utc) if row.created_at.tzinfo is None else row.created_at
        grouped[created.astimezone(timezone.utc).date().isoformat()] += 1
    return {"items": [{"date": key, "scans": grouped[key]} for key in sorted(grouped)]}


def csv_cell(value):
    text = str(value or "")
    return "'" + text if text[:1] in "=+-@\t\r" else text


@router.get("/reports/export.csv")
def export_csv(db: Session = Depends(get_db)):
    rows = db.scalars(select(Scan).order_by(desc(Scan.created_at))).all()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["scan_id", "timestamp_utc", "original_url", "registered_domain", "risk_score", "risk_level", "finding_count", "findings"])
    for row in rows:
        writer.writerow([row.id, row.created_at.isoformat(), csv_cell(row.original_url), csv_cell(row.registered_domain), row.risk_score, row.risk_level, len(row.findings), csv_cell("; ".join(item["name"] for item in row.findings))])
    return StreamingResponse(iter(["\ufeff" + output.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=sentinelurl-scans.csv"})
