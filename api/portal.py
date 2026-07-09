"""
Aronium SaaS - Portal API
==========================
Merchant dashboard endpoints (read-only + settings).
Requires passlib + bcrypt (added in requirements.txt).

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
from passlib.hash import bcrypt

log = logging.getLogger("ingest")

SALES = 2
REFUND = 4
PURCHASE = 1
STOCK_RETURN = 5

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


def _make_portal_token(tenant_ids, tax, store, close_hour=0, onboarded=False, jwt_secret="", jwt_alg="HS256"):
    return jwt.encode({
        "sub": "portal",
        "tenant_ids": tenant_ids,
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


def _get_tids(auth, req_tenant=None):
    all_ids = auth.get("tenant_ids", [])
    if req_tenant and req_tenant in all_ids:
        return [req_tenant]
    return all_ids


def _period_bounds(close_hour, offset=0):
    now = datetime.now()
    today = now.date()
    current_close = datetime(today.year, today.month, today.day, close_hour, 0, 0)
    if now < current_close:
        current_close -= timedelta(days=1)
    return current_close + timedelta(days=offset), current_close + timedelta(days=offset + 1)


async def _verify_password(conn, stored, pwd, tax):
    stored = (stored or "").strip()
    if not stored:
        return False
    if stored.startswith("$"):
        try:
            return bcrypt.verify(pwd, stored)
        except Exception:
            return False
    if stored == pwd:
        try:
            new_hash = bcrypt.hash(pwd)
            await conn.execute("UPDATE tenants SET custom_password=$1 WHERE tax_number=$2", new_hash, tax)
        except Exception:
            pass
        return True
    return False


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
        rows = await conn.fetch("""
            SELECT DISTINCT ON (t.id)
                t.id AS tenant_id, t.store_name, t.tax_number, t.phone_number,
                t.application_id,
                COALESCE(t.close_hour, 0) AS close_hour,
                COALESCE(t.onboarded, false) AS onboarded,
                COALESCE(t.custom_password, t.phone_number) AS active_password,
                COALESCE(t.subscription_status, 'active') AS sub_status
            FROM tenants t
            WHERE t.tax_number = $1
            ORDER BY t.id
        """, tax)
        if not rows:
            raise HTTPException(401, "Tax number not registered")
        first = rows[0]
        if first["sub_status"] not in ("active", "", None):
            raise HTTPException(403, "Subscription inactive")
        ok = await _verify_password(conn, first["active_password"], pwd, tax)
        if not ok:
            raise HTTPException(401, "Incorrect password")

        tenant_ids = [str(r["tenant_id"]) for r in rows]
        close_hour = int(first["close_hour"] or 0)
        onboarded = bool(first["onboarded"])
        start, end = _period_bounds(close_hour, 0)
        sales_rows = await conn.fetch("""
            SELECT tenant_id, COALESCE(SUM(total), 0) AS total
            FROM ar_documents
            WHERE tenant_id = ANY($1::uuid[])
              AND date_created >= $2 AND date_created < $3
              AND document_type_id = $4
            GROUP BY tenant_id
        """, tenant_ids, start, end, SALES)
        sales_map = {str(r["tenant_id"]): float(r["total"]) for r in sales_rows}

    branches = [{
        "tenant_id": str(r["tenant_id"]),
        "store_name": r["store_name"] or "Branch",
        "today_sales": sales_map.get(str(r["tenant_id"]), 0.0),
    } for r in rows]

    token = _make_portal_token(
        tenant_ids, tax, first["store_name"] or "", close_hour, onboarded,
        jwt_secret=state.jwt_secret, jwt_alg=state.jwt_alg,
    )
    return {
        "token": token, "store_name": first["store_name"] or "",
        "tax_number": tax, "close_hour": close_hour, "onboarded": onboarded,
        "branches": branches,
        "support_wa": getattr(state, "support_wa", "966558110150"),
    }


# === CHANGE PASSWORD ===
@router.post("/auth/change-password")
async def portal_change_password(body: dict, request: Request):
    state = request.app.state
    auth = await _get_auth(request)
    new_pwd = (body.get("new_password") or "").strip()
    if len(new_pwd) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    hashed = bcrypt.hash(new_pwd)
    pool = state.pool
    async with pool.acquire() as conn:
        for tid in auth.get("tenant_ids", []):
            await conn.execute("UPDATE tenants SET custom_password = $1 WHERE id = $2", hashed, tid)
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
        for tid in auth.get("tenant_ids", []):
            await conn.execute("UPDATE tenants SET close_hour = $1, onboarded = true WHERE id = $2", hour, tid)
    new_token = _make_portal_token(
        auth.get("tenant_ids", []), auth.get("tax", ""), auth.get("store", ""),
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
    tids = _get_tids(auth, tenant_id)
    start, end = _period_bounds(close_hour, offset)
    pool = state.pool

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT document_type_id, COALESCE(SUM(total), 0) AS total, COUNT(*) AS cnt
            FROM ar_documents
            WHERE tenant_id = ANY($1::uuid[])
              AND date_created >= $2 AND date_created < $3
              AND document_type_id = ANY($4::int[])
            GROUP BY document_type_id
        """, tids, start, end, [SALES, REFUND, PURCHASE, STOCK_RETURN])

        pay_rows = await conn.fetch("""
            SELECT pt.name AS pay_name, COALESCE(SUM(p.amount), 0) AS total
            FROM ar_payments p
            JOIN ar_documents d ON d.aronium_id = p.document_id AND d.tenant_id = p.tenant_id
            JOIN ar_payment_types pt ON pt.aronium_id = p.payment_type_id AND pt.tenant_id = p.tenant_id
            WHERE p.tenant_id = ANY($1::uuid[])
              AND d.date_created >= $2 AND d.date_created < $3
              AND d.document_type_id = $4
            GROUP BY pt.name
        """, tids, start, end, SALES)

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
async def _period_data(pool, tids, period):
    trunc = "month" if period == "month" else "quarter"
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT document_type_id, COALESCE(SUM(total), 0) AS total, COUNT(*) AS cnt
            FROM ar_documents
            WHERE tenant_id = ANY($1::uuid[])
              AND DATE_TRUNC('{trunc}', doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND document_type_id = ANY($2::int[])
            GROUP BY document_type_id
        """, tids, [SALES, REFUND, PURCHASE, STOCK_RETURN])

        tax_rows = await conn.fetch(f"""
            SELECT d.document_type_id, COALESCE(SUM(dt.amount), 0) AS tax_total
            FROM ar_document_item_taxes dt
            JOIN ar_document_items di ON di.aronium_id = dt.document_item_id AND di.tenant_id = dt.tenant_id
            JOIN ar_documents d ON d.aronium_id = di.document_id AND d.tenant_id = di.tenant_id
            WHERE dt.tenant_id = ANY($1::uuid[])
              AND DATE_TRUNC('{trunc}', d.doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND d.document_type_id = ANY($2::int[])
            GROUP BY d.document_type_id
        """, tids, [SALES, REFUND, PURCHASE])

        pay_rows = await conn.fetch(f"""
            SELECT pt.name AS pay_name, COALESCE(SUM(p.amount), 0) AS total
            FROM ar_payments p
            JOIN ar_documents d ON d.aronium_id = p.document_id AND d.tenant_id = p.tenant_id
            JOIN ar_payment_types pt ON pt.aronium_id = p.payment_type_id AND pt.tenant_id = p.tenant_id
            WHERE p.tenant_id = ANY($1::uuid[])
              AND DATE_TRUNC('{trunc}', d.doc_date::date) = DATE_TRUNC('{trunc}', CURRENT_DATE)
              AND d.document_type_id = $2
            GROUP BY pt.name
        """, tids, SALES)

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
        "quarter_progress": progress, "days_remaining": days_remaining,
        "period_label": q_label if q_label else date.today().strftime("%B %Y"),
    }


@router.get("/month")
async def portal_month(request: Request, tenant_id: Optional[str] = None):
    auth = await _get_auth(request)
    return await _period_data(request.app.state.pool, _get_tids(auth, tenant_id), "month")


@router.get("/quarter")
async def portal_quarter(request: Request, tenant_id: Optional[str] = None):
    auth = await _get_auth(request)
    return await _period_data(request.app.state.pool, _get_tids(auth, tenant_id), "quarter")


# === QUARTER DETAILS ===
@router.get("/quarter-details")
async def portal_quarter_details(request: Request, tenant_id: Optional[str] = None):
    state = request.app.state
    auth = await _get_auth(request)
    tids = _get_tids(auth, tenant_id)
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
            FROM ar_documents
            WHERE tenant_id = ANY($1::uuid[])
              AND doc_date::date >= $2 AND doc_date::date <= $3
              AND document_type_id = ANY($4::int[])
            GROUP BY month, document_type_id
            ORDER BY month
        """, tids, q_start, q_end, [SALES, REFUND, PURCHASE])

        tax_rows = await conn.fetch("""
            SELECT DATE_TRUNC('month', d.doc_date::date) AS month,
                   d.document_type_id,
                   COALESCE(SUM(dt.amount), 0) AS tax_total
            FROM ar_document_item_taxes dt
            JOIN ar_document_items di ON di.aronium_id = dt.document_item_id AND di.tenant_id = dt.tenant_id
            JOIN ar_documents d ON d.aronium_id = di.document_id AND d.tenant_id = di.tenant_id
            WHERE dt.tenant_id = ANY($1::uuid[])
              AND d.doc_date::date >= $2 AND d.doc_date::date <= $3
              AND d.document_type_id = ANY($4::int[])
            GROUP BY month, d.document_type_id
            ORDER BY month
        """, tids, q_start, q_end, [SALES, REFUND, PURCHASE])

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
    tids = _get_tids(auth, tenant_id)
    start, end = _period_bounds(close_hour, offset)
    pool = state.pool

    async with pool.acquire() as conn:
        sales = await conn.fetch("""
            SELECT d.number AS invoice_number, d.date_created AS invoice_date,
                   d.total AS total_with_tax, pt.name AS payment_method
            FROM ar_documents d
            LEFT JOIN ar_payments p ON p.document_id = d.aronium_id AND p.tenant_id = d.tenant_id
            LEFT JOIN ar_payment_types pt ON pt.aronium_id = p.payment_type_id AND pt.tenant_id = p.tenant_id
            WHERE d.tenant_id = ANY($1::uuid[])
              AND d.date_created >= $2 AND d.date_created < $3
              AND d.document_type_id = $4
            ORDER BY d.date_created DESC LIMIT 10
        """, tids, start, end, SALES)

        refunds = await conn.fetch("""
            SELECT number AS invoice_number, date_created AS invoice_date, total AS total_with_tax
            FROM ar_documents
            WHERE tenant_id = ANY($1::uuid[])
              AND date_created >= $2 AND date_created < $3
              AND document_type_id = $4
            ORDER BY date_created DESC LIMIT 5
        """, tids, start, end, REFUND)

        purchases = await conn.fetch("""
            SELECT d.number AS invoice_number, d.date_created AS invoice_date,
                   d.total AS total_with_tax, c.name AS supplier_name
            FROM ar_documents d
            LEFT JOIN ar_customers c ON c.aronium_id = d.customer_id AND c.tenant_id = d.tenant_id
            WHERE d.tenant_id = ANY($1::uuid[])
              AND d.date_created >= $2 AND d.date_created < $3
              AND d.document_type_id = $4
            ORDER BY d.date_created DESC LIMIT 5
        """, tids, start, end, PURCHASE)

    return {
        "sales": [to_d(r) for r in sales],
        "refunds": [to_d(r) for r in refunds],
        "purchases": [to_d(r) for r in purchases],
    }


# === SYNC STATUS ===
@router.get("/sync-status")
async def portal_sync_status(request: Request, tenant_id: Optional[str] = None):
    state = request.app.state
    auth = await _get_auth(request)
    tids = _get_tids(auth, tenant_id)
    pool = state.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT MAX(date_created) AS last_doc_date, COUNT(*) AS total_invoices
            FROM ar_documents WHERE tenant_id = ANY($1::uuid[])
        """, tids)
    last = row["last_doc_date"]
    return {"last_doc_date": last.isoformat() if last else None, "total_invoices": row["total_invoices"] or 0}


# === CLIENT INFO ===
@router.get("/client")
async def portal_client(request: Request):
    state = request.app.state
    auth = await _get_auth(request)
    tids = auth.get("tenant_ids", [])
    if not tids:
        return {}
    pool = state.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT t.store_name, t.tax_number, t.phone_number,
                   t.application_id,
                   COALESCE(t.close_hour, 0) AS close_hour,
                   COALESCE(t.onboarded, false) AS onboarded,
                   COALESCE(t.subscription_status, 'active') AS sub_status,
                   t.subscription_expires_at
            FROM tenants t WHERE t.id = $1
        """, tids[0])
    if not row:
        return {}
    return {
        "store_name": row["store_name"],
        "tax_number": row["tax_number"],
        "phone_number": row["phone_number"],
        "close_hour": int(row["close_hour"]),
        "onboarded": bool(row["onboarded"]),
        "sub_status": row["sub_status"],
        "sub_expires": row["subscription_expires_at"].isoformat() if row["subscription_expires_at"] else None,
    }
