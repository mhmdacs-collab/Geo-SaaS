"""
Aronium SaaS - Portal API
==========================
Merchant dashboard endpoints (read-only + settings).
Uses SHA-256 for password hashing (works with any Unicode characters).

Data model reminder: ONE tenant row = one merchant (unique tax_number).
A merchant can have MANY devices (branches), each with its own
application_id. "Branch" in this API always maps to a devices.id row.

Router prefix: /api/portal
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import asyncpg
import jwt
from fastapi import APIRouter, Request, HTTPException
import hashlib

log = logging.getLogger("ingest")

SALES = "2"
REFUND = "4"
PURCHASE = "1"
STOCK_RETURN = "5"

def hash_password(password: str) -> str:
    """Hash password using SHA256 with salt."""
    salt = "aronium_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode('utf-8')).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash."""
    if not hashed:
        return False
    # New SHA256 hashes
    if len(hashed) == 64 and all(c in '0123456789abcdef' for c in hashed):
        return hash_password(password) == hashed
    # Plain text comparison (for phone_number or old plain passwords)
    return password.strip() == hashed.strip()

_LOGIN_HITS: Dict[str, deque] = defaultdict(deque)
_LOGIN_WINDOW = 60.0
_LOGIN_MAX = 5


def _rate_check(ip: str):
    now = time.time()
    q = _LOGIN_HITS[ip]
    while q and now - q[0] > _LOGIN_WINDOW:
        q.popleft()
    if len(q) >= _LOGIN_MAX:
        raise HTTPException(429, "Too many attempts, try again later")
    q.append(now)


def n(v):
    return float(v) if v else 0.0


def to_d(row):
    if row is None:
        return {}
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, (date, datetime)):
            d[k] = v.isoformat()
        elif v is not None and not isinstance(v, (int, float, bool, str, list, dict)):
            d[k] = str(v)
    return d


router = APIRouter(prefix="/api/portal")


def _make_portal_token(tenant_id, tax, store, close_hour=0, onboarded=False, jwt_secret="", jwt_alg="HS256"):
    return jwt.encode({
        "sub": "portal",
        "tenant_id": str(tenant_id),
        "tax": tax,
        "store": store,
        "close_hour": close_hour,
        "onboarded": onboarded,
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
    }, jwt_secret, algorithm=jwt_alg)


async def _require_portal(authorization=None, jwt_secret="", jwt_alg=""):
    if not authorization:
        raise HTTPException(401, "Token missing")
    try:
        tok = authorization.replace("Bearer ", "")
        payload = jwt.decode(tok, jwt_secret, algorithms=[jwt_alg])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if payload.get("sub") != "portal":
        raise HTTPException(401, "Wrong token type")
    return payload


def _scope(auth, branch_id: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Return (tenant_id, device_id_or_None) used to scope every query.

    device_id stays None when no specific branch was requested, meaning
    "all branches of this tenant". Passing a device_id that does not
    belong to this tenant simply yields an empty result set (tenant_id
    is always enforced as well), so there is no cross-tenant leak risk.
    """
    return auth.get("tenant_id"), branch_id


def _period_bounds(close_hour, offset=0):
    now = datetime.now()
    today = now.date()
    current_close = datetime(today.year, today.month, today.day, close_hour, 0, 0)
    if now < current_close:
        current_close -= timedelta(days=1)
    return current_close + timedelta(days=offset), current_close + timedelta(days=offset + 1)


async def _get_auth(request):
    state = request.app.state
    return await _require_portal(
        request.headers.get("Authorization"),
        jwt_secret=state.jwt_secret,
        jwt_alg=state.jwt_alg,
    )


# === LOGIN ===
@router.post("/auth/login")
async def portal_login(body: dict, request: Request):
    state = request.app.state
    _rate_check(request.client.host if request.client else "unknown")
    tax = (body.get("username") or "").strip()
    pwd = (body.get("password") or "").strip()
    if not tax or not pwd:
        raise HTTPException(401, "Invalid credentials")

    pool = state.pool
    async with pool.acquire() as conn:
        tenant = await conn.fetchrow("""
            SELECT id AS tenant_id, store_name, tax_number, phone_number,
                   COALESCE(close_hour, 0) AS close_hour,
                   COALESCE(onboarded, false) AS onboarded,
                   password,
                   COALESCE(status, 'active') AS sub_status
            FROM tenants WHERE tax_number = $1
        """, tax)
        if not tenant:
            raise HTTPException(401, "Tax number not registered")
        if tenant["sub_status"] not in ("active", "", None):
            raise HTTPException(403, "Subscription inactive")
        # Use password column directly (copied from phone_number initially)
        has_custom = bool(tenant["password"] and tenant["password"] != tenant["phone_number"])
        active_password = tenant["password"] or tenant["phone_number"]
        ok = verify_password(pwd, active_password)
        if not ok:
            raise HTTPException(401, "Incorrect password")

        tenant_id = str(tenant["tenant_id"])
        close_hour = int(tenant["close_hour"] or 0)
        onboarded = bool(tenant["onboarded"])

        devices = await conn.fetch("""
            SELECT id AS device_id, branch_name, branch_type, is_active
            FROM devices WHERE tenant_id = $1 ORDER BY registered_at
        """, tenant["tenant_id"])

        start, end = _period_bounds(close_hour, 0)
        sales_rows = await conn.fetch("""
            SELECT device_id, COALESCE(SUM(total), 0) AS total
            FROM document
            WHERE tenant_id = $1
              AND date_created >= $2 AND date_created < $3
              AND document_type_id = $4
            GROUP BY device_id
        """, tenant["tenant_id"], start, end, SALES)
        sales_map = {str(r["device_id"]): float(r["total"]) for r in sales_rows}

    branches = [{
        "device_id": str(d["device_id"]),
        "branch_name": d["branch_name"] or "Branch",
        "branch_type": d["branch_type"],
        "is_active": d["is_active"],
        "today_sales": sales_map.get(str(d["device_id"]), 0.0),
    } for d in devices]

    token = _make_portal_token(
        tenant_id, tax, tenant["store_name"] or "", close_hour, onboarded,
        jwt_secret=state.jwt_secret, jwt_alg=state.jwt_alg,
    )
    return {
        "token": token, "store_name": tenant["store_name"] or "",
        "tax_number": tax, "close_hour": close_hour, "onboarded": onboarded,
        "branches": branches,
        "support_wa": getattr(state, "support_wa", "966558110150"),
        "has_custom_password": has_custom,
    }


# === CHANGE PASSWORD ===
@router.post("/auth/change-password")
async def portal_change_password(body: dict, request: Request):
    if not body or not body.get("new_password"):
        raise HTTPException(400, "Missing new_password")
    state = request.app.state
    auth = await _get_auth(request)
    new_pwd = (body.get("new_password") or "").strip()
    if len(new_pwd) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    hashed = hash_password(new_pwd)
    pool = state.pool
    async with pool.acquire() as conn:
        await conn.execute("UPDATE tenants SET password = $1 WHERE id = $2", hashed, auth.get("tenant_id"))
    return {"success": True}


# === CLOSE HOUR ===
@router.post("/settings/close-hour")
async def portal_set_close_hour(body: dict, request: Request):
    state = request.app.state
    auth = await _get_auth(request)
    hour = int(body.get("close_hour", 0))
    if not 0 <= hour <= 23:
        raise HTTPException(400, "Invalid hour")
    pool = state.pool
    async with pool.acquire() as conn:
        await conn.execute("UPDATE tenants SET close_hour = $1, onboarded = true WHERE id = $2", hour, auth.get("tenant_id"))
    new_token = _make_portal_token(
        auth.get("tenant_id"), auth.get("tax", ""), auth.get("store", ""),
        close_hour=hour, onboarded=True,
        jwt_secret=state.jwt_secret, jwt_alg=state.jwt_alg,
    )
    return {"success": True, "close_hour": hour, "token": new_token}


# === DAY DATA ===
@router.get("/day")
async def portal_day(request: Request, offset: int = 0, tenant_id: Optional[str] = None):
    state = request.app.state
    auth = await _get_auth(request)
    close_hour = int(auth.get("close_hour", 0))
    tid, did = _scope(auth, tenant_id)
    start, end = _period_bounds(close_hour, offset)
    pool = state.pool

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT document_type_id, COALESCE(SUM(total), 0) AS total, COUNT(*) AS cnt
            FROM document
            WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR device_id = $2::uuid)
              AND date_created >= $3 AND date_created < $4
              AND document_type_id = ANY($5::text[])
            GROUP BY document_type_id
        """, tid, did, start, end, [SALES, REFUND, PURCHASE, STOCK_RETURN])

        pay_rows = await conn.fetch("""
            SELECT pt.name AS pay_name, COALESCE(SUM(p.amount), 0) AS total
            FROM payment p
            JOIN document d ON d.id = p.document_id AND d.tenant_id = p.tenant_id AND d.device_id = p.device_id
            JOIN payment_type pt ON pt.id = p.payment_type_id AND pt.tenant_id = p.tenant_id AND pt.device_id = p.device_id
            WHERE p.tenant_id = $1::uuid AND ($2::uuid IS NULL OR p.device_id = $2::uuid)
              AND d.date_created >= $3 AND d.date_created < $4
              AND d.document_type_id = $5
            GROUP BY pt.name
        """, tid, did, start, end, SALES)

    sales = refund = purchases = stock_return = 0.0
    cnt_s = cnt_p = cnt_sr = 0
    for r in rows:
        t = n(r["total"])
        dt = r["document_type_id"]
        if dt == SALES: sales = t; cnt_s = r["cnt"]
        elif dt == REFUND: refund = abs(t)
        elif dt == PURCHASE: purchases = t; cnt_p = r["cnt"]
        elif dt == STOCK_RETURN: stock_return = t; cnt_sr = r["cnt"]

    return {
        "period_start": start.isoformat(), "period_end": end.isoformat(),
        "sales": round(sales, 2), "refund": round(refund, 2),
        "net_sales": round(sales - refund, 2),
        "purchases": round(purchases, 2), "stock_return": round(stock_return, 2),
        "purchases_count": cnt_p, "sales_count": cnt_s,
        "net_income": round(sales - refund - purchases + stock_return, 2),
        "payment_breakdown": {r["pay_name"]: round(n(r["total"]), 2) for r in pay_rows},
    }


# === MONTH / QUARTER ===
async def _period_data(pool, tid, did, period):
    trunc = "month" if period == "month" else "quarter"
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT document_type_id, COALESCE(SUM(total), 0) AS total, COUNT(*) AS cnt
            FROM document
            WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR device_id = $2::uuid)
              AND DATE_TRUNC('{trunc}', doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND document_type_id = ANY($3::text[])
            GROUP BY document_type_id
        """, tid, did, [SALES, REFUND, PURCHASE, STOCK_RETURN])

        tax_rows = await conn.fetch(f"""
            SELECT d.document_type_id, COALESCE(SUM(dt.amount), 0) AS tax_total
            FROM document_item_tax dt
            JOIN document_item di ON di.id = dt.document_item_id AND di.tenant_id = dt.tenant_id AND di.device_id = dt.device_id
            JOIN document d ON d.id = di.document_id AND d.tenant_id = di.tenant_id AND d.device_id = di.device_id
            WHERE dt.tenant_id = $1::uuid AND ($2::uuid IS NULL OR dt.device_id = $2::uuid)
              AND DATE_TRUNC('{trunc}', d.doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND d.document_type_id = ANY($3::text[])
            GROUP BY d.document_type_id
        """, tid, did, [SALES, REFUND, PURCHASE])

        pay_rows = await conn.fetch(f"""
            SELECT pt.name AS pay_name, COALESCE(SUM(p.amount), 0) AS total
            FROM payment p
            JOIN document d ON d.id = p.document_id AND d.tenant_id = p.tenant_id AND d.device_id = p.device_id
            JOIN payment_type pt ON pt.id = p.payment_type_id AND pt.tenant_id = p.tenant_id AND pt.device_id = p.device_id
            WHERE p.tenant_id = $1::uuid AND ($2::uuid IS NULL OR p.device_id = $2::uuid)
              AND DATE_TRUNC('{trunc}', d.doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND d.document_type_id = $3
            GROUP BY pt.name
        """, tid, did, SALES)

        branch_rows = await conn.fetch(f"""
            SELECT d.device_id, dev.branch_name, COALESCE(SUM(d.total), 0) AS total
            FROM document d
            JOIN devices dev ON dev.id = d.device_id
            WHERE d.tenant_id = $1::uuid
              AND DATE_TRUNC('{trunc}', d.doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND d.document_type_id = $2
            GROUP BY d.device_id, dev.branch_name
            ORDER BY total DESC
        """, tid, SALES)

    sales = refund = purchases = 0.0
    tax_s = tax_r = tax_p = 0.0
    for r in rows:
        t = n(r["total"]); dt = r["document_type_id"]
        if dt == SALES: sales = t
        elif dt == REFUND: refund = abs(t)
        elif dt == PURCHASE: purchases = t
    for r in tax_rows:
        t = n(r["tax_total"]); dt = r["document_type_id"]
        if dt == SALES: tax_s = t
        elif dt == REFUND: tax_r = abs(t)
        elif dt == PURCHASE: tax_p = t

    q_label = ""; progress = days_remaining = 0
    if period == "quarter":
        today = date.today()
        qm = ((today.month - 1) // 3) * 3 + 1
        names = {1: "Q1", 4: "Q2", 7: "Q3", 10: "Q4"}
        q_label = f"{names.get(qm, 'Current')} {today.year}"
        q_start = date(today.year, qm, 1)
        qem = qm + 2
        ld = 31 if qem in [1,3,5,7,8,10,12] else 30 if qem in [4,6,9,11] else 28
        total_d = (date(today.year, qem, ld) - q_start).days + 1
        passed = (today - q_start).days + 1
        progress = round(min(passed / max(total_d, 1) * 100, 100))
        dl_m = qem + 1 if qem < 12 else 1
        dl_y = today.year if qem < 12 else today.year + 1
        dl_ld = 31 if dl_m in [1,3,5,7,8,10,12] else 30
        days_remaining = max((date(dl_y, dl_m, dl_ld) - today).days, 0)

    return {
        "sales": round(sales, 2), "refund": round(refund, 2),
        "net_sales": round(sales - refund, 2), "purchases": round(purchases, 2),
        "tax_sales": round(tax_s - tax_r, 2), "tax_refund": round(tax_r, 2),
        "tax_purchases": round(tax_p, 2),
        "vat_due": round((tax_s - tax_r) - tax_p, 2),
        "payment_breakdown": {r["pay_name"]: round(n(r["total"]), 2) for r in pay_rows},
        "branch_breakdown": [{"device_id": str(r["device_id"]), "branch_name": r["branch_name"], "total": round(n(r["total"]), 2)} for r in branch_rows],
        "quarter_progress": progress, "days_remaining": days_remaining,
        "period_label": q_label if q_label else date.today().strftime("%B %Y"),
    }


@router.get("/month")
async def portal_month(request: Request, tenant_id: Optional[str] = None):
    auth = await _get_auth(request)
    tid, did = _scope(auth, tenant_id)
    return await _period_data(request.app.state.pool, tid, did, "month")


@router.get("/quarter")
async def portal_quarter(request: Request, tenant_id: Optional[str] = None):
    auth = await _get_auth(request)
    tid, did = _scope(auth, tenant_id)
    return await _period_data(request.app.state.pool, tid, did, "quarter")


# === QUARTER DETAILS ===
@router.get("/quarter-details")
async def portal_quarter_details(request: Request, tenant_id: Optional[str] = None):
    state = request.app.state
    auth = await _get_auth(request)
    tid, did = _scope(auth, tenant_id)
    pool = state.pool
    today = date.today()
    qm = ((today.month - 1) // 3) * 3 + 1
    q_start = date(today.year, qm, 1)
    qem = qm + 2
    ld = 31 if qem in [1,3,5,7,8,10,12] else 30 if qem in [4,6,9,11] else 28
    q_end = date(today.year, qem, ld)

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DATE_TRUNC('month', doc_date::date) AS month,
                   document_type_id,
                   COALESCE(SUM(total), 0) AS total
            FROM document
            WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR device_id = $2::uuid)
              AND doc_date::date >= $3 AND doc_date::date <= $4
              AND document_type_id = ANY($5::text[])
            GROUP BY month, document_type_id
            ORDER BY month
        """, tid, did, q_start, q_end, [SALES, REFUND, PURCHASE])

        tax_rows = await conn.fetch("""
            SELECT DATE_TRUNC('month', d.doc_date::date) AS month,
                   d.document_type_id,
                   COALESCE(SUM(dt.amount), 0) AS tax_total
            FROM document_item_tax dt
            JOIN document_item di ON di.id = dt.document_item_id AND di.tenant_id = dt.tenant_id AND di.device_id = dt.device_id
            JOIN document d ON d.id = di.document_id AND d.tenant_id = di.tenant_id AND d.device_id = di.device_id
            WHERE dt.tenant_id = $1::uuid AND ($2::uuid IS NULL OR dt.device_id = $2::uuid)
              AND d.doc_date::date >= $3 AND d.doc_date::date <= $4
              AND d.document_type_id = ANY($5::text[])
            GROUP BY month, d.document_type_id
            ORDER BY month
        """, tid, did, q_start, q_end, [SALES, REFUND, PURCHASE])

    monthly = {}
    for r in rows:
        m = r["month"].strftime("%Y-%m") if hasattr(r["month"], 'strftime') else str(r["month"])[:7]
        if m not in monthly:
            monthly[m] = {"sales": 0, "refund": 0, "purchases": 0}
        t = n(r["total"]); dt = r["document_type_id"]
        if dt == SALES: monthly[m]["sales"] = t
        elif dt == REFUND: monthly[m]["refund"] = abs(t)
        elif dt == PURCHASE: monthly[m]["purchases"] = t

    tax_by_month = {}
    for r in tax_rows:
        m = r["month"].strftime("%Y-%m") if hasattr(r["month"], 'strftime') else str(r["month"])[:7]
        if m not in tax_by_month:
            tax_by_month[m] = {"tax_sales": 0, "tax_refund": 0, "tax_purchases": 0}
        t = n(r["tax_total"]); dt = r["document_type_id"]
        if dt == SALES: tax_by_month[m]["tax_sales"] = t
        elif dt == REFUND: tax_by_month[m]["tax_refund"] = abs(t)
        elif dt == PURCHASE: tax_by_month[m]["tax_purchases"] = t

    result = []
    for m in sorted(monthly.keys()):
        d = monthly[m]
        t = tax_by_month.get(m, {})
        vat = round((t.get("tax_sales", 0) - t.get("tax_refund", 0)) - t.get("tax_purchases", 0), 2)
        result.append({
            "month": m,
            "sales": round(d["sales"], 2),
            "refund": round(d["refund"], 2),
            "net_sales": round(d["sales"] - d["refund"], 2),
            "purchases": round(d["purchases"], 2),
            "vat_due": vat,
        })

    return {"months": result, "quarter_start": q_start.isoformat(), "quarter_end": q_end.isoformat()}


# === RECENT ===
@router.get("/recent")
async def portal_recent(request: Request, offset: int = 0, tenant_id: Optional[str] = None):
    state = request.app.state
    auth = await _get_auth(request)
    close_hour = int(auth.get("close_hour", 0))
    tid, did = _scope(auth, tenant_id)
    start, end = _period_bounds(close_hour, offset)
    pool = state.pool

    async with pool.acquire() as conn:
        sales = await conn.fetch("""
            SELECT d.number AS invoice_number, d.date_created AS invoice_date,
                   d.total AS total_with_tax, pt.name AS payment_method
            FROM document d
            LEFT JOIN payment p ON p.document_id = d.id AND p.tenant_id = d.tenant_id AND p.device_id = d.device_id
            LEFT JOIN payment_type pt ON pt.id = p.payment_type_id AND pt.tenant_id = p.tenant_id AND pt.device_id = p.device_id
            WHERE d.tenant_id = $1::uuid AND ($2::uuid IS NULL OR d.device_id = $2::uuid)
              AND d.date_created >= $3 AND d.date_created < $4
              AND d.document_type_id = $5
            ORDER BY d.date_created DESC LIMIT 10
        """, tid, did, start, end, SALES)

        refunds = await conn.fetch("""
            SELECT number AS invoice_number, date_created AS invoice_date, total AS total_with_tax
            FROM document
            WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR device_id = $2::uuid)
              AND date_created >= $3 AND date_created < $4
              AND document_type_id = $5
            ORDER BY date_created DESC LIMIT 5
        """, tid, did, start, end, REFUND)

        purchases = await conn.fetch("""
            SELECT d.number AS invoice_number, d.date_created AS invoice_date,
                   d.total AS total_with_tax, c.name AS supplier_name
            FROM document d
            LEFT JOIN customer c ON c.id = d.customer_id AND c.tenant_id = d.tenant_id AND c.device_id = d.device_id
            WHERE d.tenant_id = $1::uuid AND ($2::uuid IS NULL OR d.device_id = $2::uuid)
              AND d.date_created >= $3 AND d.date_created < $4
              AND d.document_type_id = $5
            ORDER BY d.date_created DESC LIMIT 5
        """, tid, did, start, end, PURCHASE)

        stock_returns = await conn.fetch("""
            SELECT number AS invoice_number, date_created AS invoice_date, total AS total_with_tax
            FROM document
            WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR device_id = $2::uuid)
              AND date_created >= $3 AND date_created < $4
              AND document_type_id = $5
            ORDER BY date_created DESC LIMIT 5
        """, tid, did, start, end, STOCK_RETURN)

    return {
        "sales": [to_d(r) for r in sales],
        "refunds": [to_d(r) for r in refunds],
        "purchases": [to_d(r) for r in purchases],
        "stock_returns": [to_d(r) for r in stock_returns],
    }


# === SYNC STATUS ===
@router.get("/sync-status")
async def portal_sync_status(request: Request, tenant_id: Optional[str] = None):
    state = request.app.state
    auth = await _get_auth(request)
    tid, did = _scope(auth, tenant_id)
    pool = state.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT MAX(date_created) AS last_doc_date, COUNT(*) AS total_invoices
            FROM document WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR device_id = $2::uuid)
        """, tid, did)
        devices = await conn.fetch("""
            SELECT id AS device_id, branch_name, is_active, last_seen
            FROM devices WHERE tenant_id = $1::uuid AND ($2::uuid IS NULL OR id = $2::uuid)
            ORDER BY registered_at
        """, tid, did)
    last = row["last_doc_date"]
    return {
        "last_doc_date": last.isoformat() if last else None,
        "total_invoices": row["total_invoices"] or 0,
        "devices": [{
            "device_id": str(d["device_id"]), "branch_name": d["branch_name"],
            "is_active": d["is_active"],
            "last_seen": d["last_seen"].isoformat() if d["last_seen"] else None,
        } for d in devices],
    }


# === CLIENT INFO ===
@router.get("/client")
async def portal_client(request: Request):
    state = request.app.state
    auth = await _get_auth(request)
    tid = auth.get("tenant_id")
    if not tid:
        return {}
    pool = state.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT t.store_name, t.tax_number, t.phone_number,
                   COALESCE(t.close_hour, 0) AS close_hour,
                   COALESCE(t.onboarded, false) AS onboarded,
                   COALESCE(t.status, 'active') AS sub_status,
                   t.expires_at
            FROM tenants t WHERE t.id = $1
        """, tid)
    if not row:
        return {}
    return {
        "store_name": row["store_name"],
        "tax_number": row["tax_number"],
        "phone_number": row["phone_number"],
        "close_hour": int(row["close_hour"]),
        "onboarded": bool(row["onboarded"]),
        "sub_status": row["sub_status"],
        "sub_expires": row["expires_at"].isoformat() if row["expires_at"] else None,
    }
