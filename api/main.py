"""Aronium SaaS API v12.0
========================
No activation codes. Authentication via Application ID + Tax Number.
Two tables only: tenants, devices.
"""
from __future__ import annotations

import logging
import os
import pathlib
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, date, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import portal
import purchase_qr

# ────────────────────────────────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
# Support rotating secrets: JWT_SECRETS can be a comma-separated list (new,old,...)
_jwt_secrets_env = os.environ.get("JWT_SECRETS", "").strip()
if _jwt_secrets_env:
    JWT_SECRETS = [s for s in (p.strip() for p in _jwt_secrets_env.split(",")) if s]
else:
    _single_jwt = os.environ.get("JWT_SECRET", "").strip()
    JWT_SECRETS = [_single_jwt] if _single_jwt else []
# Primary secret (used for signing new tokens)
JWT_SECRET = JWT_SECRETS[0] if JWT_SECRETS else ""
JWT_ALG = "HS256"
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "aronium-agent")
# Support multiple admin API keys via ADMIN_API_KEYS (comma-separated) falling back to ADMIN_API_KEY
_admin_keys_env = os.environ.get("ADMIN_API_KEYS", "").strip()
if _admin_keys_env:
    ADMIN_API_KEYS = [s for s in (p.strip() for p in _admin_keys_env.split(",")) if s]
else:
    _single_admin = os.environ.get("ADMIN_API_KEY", "").strip()
    ADMIN_API_KEYS = [_single_admin] if _single_admin else []
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")
JWT_TTL_DAYS = int(os.environ.get("JWT_TTL_DAYS", "30"))  # Reduced from 365 to 30 days
SUPPORT_WA = os.environ.get("SUPPORT_WA", "966558110150")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is required")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET env var is required")


def _clean_dsn(dsn: str) -> str:
    if "channel_binding" not in dsn:
        return dsn
    if "?" not in dsn:
        return dsn
    base, _, query = dsn.partition("?")
    parts = [p for p in query.split("&") if not p.startswith("channel_binding")]
    return base + ("?" + "&".join(parts) if parts else "")


# ────────────────────────────────────────────────────────────────────────────
# Logging
# ────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("aronium-api")


# ────────────────────────────────────────────────────────────────────────────
# Rate Limiting
# ────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        self.requests[client_id] = [
            t for t in self.requests[client_id] if t > window_start
        ]
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        self.requests[client_id].append(now)
        return True


# Rate limiters for different endpoints
activate_limiter = RateLimiter(max_requests=10, window_seconds=300)  # 10 requests per 5 min
login_limiter = RateLimiter(max_requests=20, window_seconds=300)     # 20 requests per 5 min
api_limiter = RateLimiter(max_requests=100, window_seconds=60)       # 100 requests per minute
sync_limiter = RateLimiter(max_requests=60, window_seconds=60)       # 60 sync requests per minute


# ────────────────────────────────────────────────────────────────────────────
# DB pool lifecycle
# ────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        dsn=_clean_dsn(DATABASE_URL), min_size=1, max_size=10, command_timeout=60,
    )
    # expose list of accepted JWT secrets and the primary secret used for signing
    app.state.jwt_secrets = JWT_SECRETS
    app.state.jwt_secret = JWT_SECRET
    app.state.jwt_alg = JWT_ALG
    app.state.admin_api_keys = ADMIN_API_KEYS
    app.state.support_wa = SUPPORT_WA
    log.info("DB pool ready")
    try:
        yield
    finally:
        await app.state.pool.close()
        log.info("DB pool closed")


app = FastAPI(title="Aronium Sync API", version="12.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"], allow_headers=["*"],
)
app.include_router(portal.router)
app.include_router(purchase_qr.router)


# ────────────────────────────────────────────────────────────────────────────
# Date / datetime coercion
# ────────────────────────────────────────────────────────────────────────────
TS_COLS = {"date_created", "date_updated", "stock_date"}
DATE_COLS = {"doc_date", "due_date", "pay_date"}
BOOL_COLS = {"is_enabled", "is_customer", "is_supplier", "is_tax_exempt", "is_price_change_allowed", "is_using_default_quantity", "is_service", "is_tax_inclusive_price", "is_fixed", "is_tax_on_total"}
# INT_COLS is scoped per pg_table because "number" is an integer only in
# z_report, while it is a free-form text value (e.g. "26-200-000001") in
# document / pos_order.
INT_COLS_BY_TABLE = {
    "z_report": {"number"},
    "starting_cash": {"starting_cash_type"},
}

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
)


def _to_datetime(v: Any) -> Optional[datetime]:
    if v is None or isinstance(v, datetime):
        return v
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo:
                return dt
            saudi = timezone(timedelta(hours=3))
            return dt.replace(tzinfo=saudi).astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo:
            return dt
        saudi = timezone(timedelta(hours=3))
        return dt.replace(tzinfo=saudi).astimezone(timezone.utc)
    except ValueError:
        return None


def _to_date(v: Any) -> Optional[date]:
    if v is None or isinstance(v, date) and not isinstance(v, datetime):
        return v
    if isinstance(v, datetime):
        return v.date()
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def _to_bool(v: Any) -> Optional[bool]:
    """Convert string '0'/'1' or 'true'/'false' to boolean."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ('1', 'true', 'yes', 'on'):
            return True
        if s in ('0', 'false', 'no', 'off', ''):
            return False
    return None


def _coerce_row(pg_cols: List[str], values: List[Any], pg_table: str = "") -> List[Any]:
    int_cols = INT_COLS_BY_TABLE.get(pg_table, set())
    out: List[Any] = []
    for col, val in zip(pg_cols, values):
        if col in TS_COLS:
            out.append(_to_datetime(val))
        elif col in DATE_COLS:
            out.append(_to_date(val))
        elif col in BOOL_COLS:
            out.append(_to_bool(val))
        elif col in int_cols:
            out.append(int(val) if val is not None and val != "" else None)
        else:
            out.append(val)
    return out


# ────────────────────────────────────────────────────────────────────────────
# JWT helpers + auth
# ────────────────────────────────────────────────────────────────────────────
def _make_token(tenant_id: str, device_id: str, days: int = None) -> str:
    payload = {
        "sub": "agent",
        "tenant_id": str(tenant_id),
        "device_id": str(device_id),
        "aud": JWT_AUDIENCE,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=days or JWT_TTL_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


class AgentCtx(BaseModel):
    tenant_id: str
    device_id: str


async def require_agent(
    authorization: str = Header(None),
    x_application_id: str = Header(None, alias="X-Application-Id"),
) -> AgentCtx:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(None, 1)[1].strip()
    try:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALG],
            audience=JWT_AUDIENCE,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"invalid token: {e}")
    if payload.get("sub") != "agent":
        raise HTTPException(401, "wrong token subject")
    tenant_id = payload.get("tenant_id")
    device_id = payload.get("device_id")
    if not tenant_id or not device_id:
        raise HTTPException(401, "malformed token")
    # Verify device exists and is active
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT d.is_active, d.application_id, t.status, t.expires_at
            FROM devices d
            JOIN tenants t ON t.id = d.tenant_id
            WHERE d.id=$1 AND d.tenant_id=$2
            """,
            device_id, tenant_id,
        )
    if row is None:
        raise HTTPException(403, "device unknown")
    if not row["is_active"]:
        raise HTTPException(403, "device deactivated")
    # Cross-validate the physical Aronium Application ID on every
    # authenticated request (not just at activation time). The JWT alone
    # only proves possession of the token file; if an attacker copies
    # agent.token to a different machine (with a different Aronium
    # Application ID), this check rejects the request even though the
    # token itself is still cryptographically valid.
    stored_app_id = (row["application_id"] or "").strip().upper()
    sent_app_id = (x_application_id or "").strip().upper()
    if not sent_app_id or sent_app_id != stored_app_id:
        raise HTTPException(403, "device identity mismatch - application id does not match")
    # Enforce subscription status/expiry on every authenticated request,
    # not just at activation/heartbeat time. This prevents a bypassed or
    # custom client from continuing to sync data using a still-valid JWT
    # after the tenant's subscription has been suspended or has expired.
    if row["status"] != "active":
        raise HTTPException(403, "subscription not active")
    if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(410, "subscription expired")
    return AgentCtx(tenant_id=tenant_id, device_id=device_id)


# ────────────────────────────────────────────────────────────────────────────
# Schemas
# ────────────────────────────────────────────────────────────────────────────
class ActivateReq(BaseModel):
    application_id: str
    tax_number: str
    hostname: Optional[str] = "unknown"
    agent_version: Optional[str] = None


class ActivateResp(BaseModel):
    token: str
    tenant_id: str
    device_id: str
    store_name: str = ""
    tax_number: str = ""
    expires_at: str = ""
    registered_at: str = ""


class HeartbeatReq(BaseModel):
    agent_version: Optional[str] = None
    ts: Optional[int] = None
    application_id: Optional[str] = None
    last_status: Optional[str] = "ok"


class UpsertReq(BaseModel):
    table: str
    rows: List[Dict[str, Any]]


class ReconcileReq(BaseModel):
    table: str
    local_pks: List[str]


# ────────────────────────────────────────────────────────────────────────────
# Table Map (simplified - maps Aronium tables to Neon tables)
# ────────────────────────────────────────────────────────────────────────────
TABLE_MAP = {
    "Company": {
        "pg_table": "company",
        "columns": {
            "Id": "id", "Name": "name", "TaxNumber": "tax_number",
            "Address": "address", "City": "city", "CountryId": "country_id",
            "Email": "email", "PhoneNumber": "phone_number",
        },
        "conflict": ["id"],
    },
    "Country": {
        "pg_table": "country",
        "columns": {"Id": "id", "Name": "name", "Code": "code"},
        "conflict": ["id"],
    },
    "Currency": {
        "pg_table": "currency",
        "columns": {"Id": "id", "Name": "name", "Code": "code"},
        "conflict": ["id"],
    },
    "Customer": {
        "pg_table": "customer",
        "columns": {
            "Id": "id", "Code": "code", "Name": "name", "TaxNumber": "tax_number",
            "Address": "address", "City": "city", "Email": "email",
            "PhoneNumber": "phone_number", "IsEnabled": "is_enabled",
            "DateCreated": "date_created", "DateUpdated": "date_updated",
        },
        "conflict": ["id"],
    },
    "Product": {
        "pg_table": "product",
        "columns": {
            "Id": "id", "Name": "name", "Code": "code", "PLU": "plu",
            "Price": "price", "Cost": "cost", "IsEnabled": "is_enabled",
            "ProductGroupId": "product_group_id",
            "DateCreated": "date_created", "DateUpdated": "date_updated",
        },
        "conflict": ["id"],
    },
    "Barcode": {
        "pg_table": "barcode",
        "columns": {"Id": "id", "ProductId": "product_id", "Value": "value"},
        "conflict": ["id"],
    },
    "Document": {
        "pg_table": "document",
        "columns": {
            "Id": "id", "Number": "number", "CustomerId": "customer_id",
            "Date": "doc_date", "Total": "total",
            "DocumentTypeId": "document_type_id", "WarehouseId": "warehouse_id",
            "DateCreated": "date_created", "DateUpdated": "date_updated",
        },
        "conflict": ["id"],
    },
    "DocumentItem": {
        "pg_table": "document_item",
        "columns": {
            "Id": "id", "DocumentId": "document_id", "ProductId": "product_id",
            "Quantity": "quantity", "Price": "price", "Total": "total",
        },
        "conflict": ["id"],
    },
    "DocumentItemTax": {
        "pg_table": "document_item_tax",
        "columns": {
            "DocumentItemId": "document_item_id", "TaxId": "tax_id", "Amount": "amount",
        },
        "conflict": ["document_item_id", "tax_id"],
        "pk_text_expr": "document_item_id::text || '|' || tax_id::text",
    },
    "Payment": {
        "pg_table": "payment",
        "columns": {
            "Id": "id", "DocumentId": "document_id",
            "PaymentTypeId": "payment_type_id", "Amount": "amount", "Date": "pay_date",
        },
        "conflict": ["id"],
    },
    "ZReport": {
        "pg_table": "z_report",
        "columns": {
            "Id": "id", "Number": "number",
            "FromDocumentId": "from_document_id", "ToDocumentId": "to_document_id",
            "DateCreated": "date_created",
            "TotalSales": "total_sales", "TotalTax": "total_tax",
            "TotalDiscount": "total_discount",
            "CashAmount": "cash_amount", "CardAmount": "card_amount",
            "TransferAmount": "transfer_amount", "RefundAmount": "refund_amount",
            "DocumentCount": "document_count",
        },
        "conflict": ["id"],
    },
    "ProductGroup": {
        "pg_table": "product_group",
        "columns": {"Id": "id", "Name": "name"},
        "conflict": ["id"],
    },
    "FiscalItem": {
        "pg_table": "fiscal_item",
        "columns": {"PLU": "plu", "Name": "name", "VAT": "vat"},
        "conflict": ["plu"],
    },
    "PaymentType": {
        "pg_table": "payment_type",
        "columns": {"Id": "id", "Name": "name", "Code": "code"},
        "conflict": ["id"],
    },
    "DocumentType": {
        "pg_table": "document_type",
        "columns": {"Id": "id", "Name": "name", "Code": "code"},
        "conflict": ["id"],
    },
    "Warehouse": {
        "pg_table": "warehouse",
        "columns": {"Id": "id", "Name": "name"},
        "conflict": ["id"],
    },
    "Stock": {
        "pg_table": "stock",
        "columns": {"Id": "id", "ProductId": "product_id", "WarehouseId": "warehouse_id", "Quantity": "quantity"},
        "conflict": ["id"],
    },
    "PosOrder": {
        "pg_table": "pos_order",
        "columns": {"Id": "id", "UserId": "user_id", "Number": "number", "Total": "total"},
        "conflict": ["id"],
    },
    "PosOrderItem": {
        "pg_table": "pos_order_item",
        "columns": {"Id": "id", "PosOrderId": "pos_order_id", "ProductId": "product_id", "Quantity": "quantity", "Price": "price"},
        "conflict": ["id"],
    },
    "LoyaltyCard": {
        "pg_table": "loyalty_card",
        "columns": {"Id": "id", "CustomerId": "customer_id", "CardNumber": "card_number"},
        "conflict": ["id"],
    },
    "CustomerDiscount": {
        "pg_table": "customer_discount",
        "columns": {"Id": "id", "CustomerId": "customer_id", "Type": "type", "Value": "value"},
        "conflict": ["id"],
    },
    "Tax": {
        "pg_table": "tax",
        "columns": {
            "Id": "id", "Name": "name", "Rate": "rate", "Code": "code",
            "IsFixed": "is_fixed", "IsTaxOnTotal": "is_tax_on_total", "IsEnabled": "is_enabled",
        },
        "conflict": ["id"],
    },
    "ProductTax": {
        "pg_table": "product_tax",
        "columns": {"ProductId": "product_id", "TaxId": "tax_id"},
        "conflict": ["product_id", "tax_id"],
        "pk_text_expr": "product_id::text || '|' || tax_id::text",
    },
    "DocumentCategory": {
        "pg_table": "document_category",
        "columns": {"Id": "id", "Name": "name", "LanguageKey": "language_key"},
        "conflict": ["id"],
    },
    "StartingCash": {
        "pg_table": "starting_cash",
        "columns": {
            "Id": "id", "UserId": "user_id", "Amount": "amount",
            "Description": "description", "StartingCashType": "starting_cash_type",
            "ZReportNumber": "z_report_number", "DateCreated": "date_created",
        },
        "conflict": ["id"],
    },
}


def validate_table(table_name: str) -> Dict:
    if table_name not in TABLE_MAP:
        raise HTTPException(400, f"Unknown table: {table_name}")
    return TABLE_MAP[table_name]


def project_row(tdef: Dict, raw: Dict[str, Any]) -> List[Any]:
    return [raw.get(k) for k in tdef["columns"].keys()]


# ════════════════════════════════════════════════════════════════════════════
# Agent Routes
# ════════════════════════════════════════════════════════════════════════════

@app.get("/healthz")
async def healthz():
    try:
        async with app.state.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"ok": True, "version": "12.1.0"}
    except Exception as e:
        raise HTTPException(503, f"db unreachable: {e}")


@app.post("/api/v1/agents/activate", response_model=ActivateResp)
async def activate(req: ActivateReq, request: Request):
    """
    Activate device using Application ID + Tax Number.
    No activation codes needed.
    
    Flow:
    1. Find device by application_id
    2. Verify tax_number matches the tenant
    3. Verify subscription is active (expires_at > now)
    4. Return JWT token
    """
    client_ip = request.client.host if request.client else "unknown"
    if not activate_limiter.is_allowed(client_ip):
        raise HTTPException(429, "Too many activation attempts. Try again later.")

    pool: asyncpg.Pool = app.state.pool
    app_id = req.application_id.strip().upper()
    tax_number = req.tax_number.strip()
    hostname = (req.hostname or "unknown")[:255]

    async with pool.acquire() as conn:
        # 1. Find device by application_id
        device = await conn.fetchrow(
            """SELECT d.id, d.tenant_id, d.branch_name, d.is_active,
                      t.store_name, t.tax_number, t.expires_at, t.status, t.created_at
               FROM devices d
               JOIN tenants t ON d.tenant_id = t.id
               WHERE UPPER(d.application_id) = $1""",
            app_id,
        )

        if device is None:
            raise HTTPException(404, "Device not registered - contact admin to register first")

        if not device["is_active"]:
            raise HTTPException(403, "Device deactivated - contact support")

        # 2. Verify tax_number matches
        if device["tax_number"] != tax_number:
            raise HTTPException(401, "Tax number mismatch - this device is registered to a different business")

        # 3. Verify subscription is active
        if device["status"] != "active":
            raise HTTPException(403, "Subscription not active - please renew")

        if device["expires_at"] and device["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(410, "Subscription expired - please renew")

        # 4. Update device last seen
        await conn.execute(
            """UPDATE devices SET hostname = $2, last_seen = now()
               WHERE id = $1""",
            device["id"], hostname,
        )

    # 5. Generate JWT token
    token = _make_token(str(device["tenant_id"]), str(device["id"]))

    expires_at_str = device["expires_at"].isoformat() if device["expires_at"] else ""
    registered_at_str = device["created_at"].isoformat() if device["created_at"] else ""

    log.info(
        "activated device=%s tenant=%s host=%s",
        device["id"], device["tenant_id"], hostname,
    )

    return ActivateResp(
        token=token,
        tenant_id=str(device["tenant_id"]),
        device_id=str(device["id"]),
        store_name=device["store_name"] or "",
        tax_number=device["tax_number"] or "",
        expires_at=expires_at_str,
        registered_at=registered_at_str,
    )




# ────────────────────────────────────────────────────────────────────────────
# VAT declaration reminder logic
# ────────────────────────────────────────────────────────────────────────────
# Saudi ZATCA quarterly deadlines (for businesses < 40M SAR annual revenue):
#   Q1 (Jan-Mar): deadline April 30   → notify April 25
#   Q2 (Apr-Jun): deadline July 31    → notify July 25
#   Q3 (Jul-Sep): deadline October 31 → notify October 25
#   Q4 (Oct-Dec): deadline January 31 → notify January 25
# ────────────────────────────────────────────────────────────────────────────
_VAT_DEADLINES = {
    # (year, deadline_date) → quarter label
    # We generate deadlines dynamically below.
}
_NOTIFY_DAYS_BEFORE = 5  # send notification 5 days before deadline

def _get_current_quarter_deadline_info(now: datetime) -> dict | None:
    """Return quarter deadline info if we're in the notification window."""
    # Quarter deadlines (ZATCA quarterly filing):
    #   Q1 (Jan-Mar) → deadline Apr 30   → notify Apr 25-30
    #   Q2 (Apr-Jun) → deadline Jul 31   → notify Jul 25-31
    #   Q3 (Jul-Sep) → deadline Oct 31   → notify Oct 25-31
    #   Q4 (Oct-Dec) → deadline Jan 31   → notify Jan 25-31
    
    current_year = now.year
    current_month = now.month
    
    # Check each quarter's notification window
    # Q1: notify in April of same year
    if current_month == 4:
        deadline_date = datetime(current_year, 4, 30, tzinfo=timezone.utc)
        if now >= deadline_date - timedelta(days=_NOTIFY_DAYS_BEFORE):
            return {
                "quarter_label": "الربع الأول (يناير - مارس)",
                "deadline_date": deadline_date,
                "q_num": 1,
                "deadline_year": current_year,
            }
    
    # Q2: notify in July of same year
    if current_month == 7:
        deadline_date = datetime(current_year, 7, 31, tzinfo=timezone.utc)
        if now >= deadline_date - timedelta(days=_NOTIFY_DAYS_BEFORE):
            return {
                "quarter_label": "الربع الثاني (أبريل - يونيو)",
                "deadline_date": deadline_date,
                "q_num": 2,
                "deadline_year": current_year,
            }
    
    # Q3: notify in October of same year
    if current_month == 10:
        deadline_date = datetime(current_year, 10, 31, tzinfo=timezone.utc)
        if now >= deadline_date - timedelta(days=_NOTIFY_DAYS_BEFORE):
            return {
                "quarter_label": "الربع الثالث (يوليو - سبتمبر)",
                "deadline_date": deadline_date,
                "q_num": 3,
                "deadline_year": current_year,
            }
    
    # Q4: notify in January of NEXT year
    if current_month == 1:
        deadline_date = datetime(current_year, 1, 31, tzinfo=timezone.utc)
        if now >= deadline_date - timedelta(days=_NOTIFY_DAYS_BEFORE):
            return {
                "quarter_label": "الربع الرابع (أكتوبر - ديسمبر)",
                "deadline_date": deadline_date,
                "q_num": 4,
                "deadline_year": current_year,
            }
    
    return None


@app.post("/api/v1/agents/heartbeat")
async def heartbeat(req: HeartbeatReq, ctx: AgentCtx = Depends(require_agent), request: Request = None):
    client_ip = request.client.host if request and request.client else "unknown"
    if not sync_limiter.is_allowed(f"hb:{client_ip}"):
        raise HTTPException(429, "Rate limited")
    pool: asyncpg.Pool = app.state.pool
    async with pool.acquire() as conn:
        # Check subscription status
        tenant = await conn.fetchrow(
            "SELECT status, expires_at FROM tenants WHERE id=$1",
            ctx.tenant_id,
        )
        if tenant is None:
            raise HTTPException(404, "Tenant not found")
        if tenant["status"] != "active":
            raise HTTPException(403, "Subscription not active")
        if tenant["expires_at"] and tenant["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(410, "Subscription expired")
        
        # Subscription expiry notification (3 days before)
        if tenant["expires_at"]:
            days_left = (tenant["expires_at"] - datetime.now(timezone.utc)).days
            if days_left <= 3 and days_left >= 0:
                # Check if we already sent notification for this expiry
                already_sent = await conn.fetchval(
                    """
                    SELECT 1 FROM notifications
                    WHERE tenant_id = $1
                      AND device_id = $2
                      AND notification_type = 'subscription_expiry'
                      AND created_at >= NOW() - INTERVAL '24 hours'
                    LIMIT 1
                    """,
                    ctx.tenant_id, ctx.device_id,
                )
                if not already_sent:
                    if days_left == 0:
                        msg = "اشتراكك ينتهي اليوم. يرجى التواصل لتجديده."
                    elif days_left == 1:
                        msg = "اشتراكك ينتهي غداً. يرجى التواصل لتجديده."
                    elif days_left == 2:
                        msg = "اشتراكك ينتهي خلال يومين. يرجى التواصل لتجديده."
                    else:
                        msg = f"اشتراكك ينتهي خلال {days_left} أيام. يرجى التواصل لتجديده."
                    await conn.execute(
                        """
                        INSERT INTO notifications (tenant_id, device_id, notification_type, message)
                        VALUES ($1, $2, 'subscription_expiry', $3)
                        """,
                        ctx.tenant_id, ctx.device_id, msg,
                    )

        # Update device last seen
        await conn.execute(
            "UPDATE devices SET last_seen=now() WHERE id=$1 AND tenant_id=$2",
            ctx.device_id, ctx.tenant_id,
        )
        
        # ── VAT declaration reminder ──────────────────────────────────────
        now = datetime.now(timezone.utc)
        qinfo = _get_current_quarter_deadline_info(now)
        if qinfo:
            # Check if we already sent a notification for this quarter this year
            already_sent = await conn.fetchval(
                """
                SELECT 1 FROM notifications
                WHERE tenant_id = $1
                  AND notification_type = 'vat_reminder'
                  AND created_at >= $2
                LIMIT 1
                """,
                ctx.tenant_id,
                datetime(qinfo["deadline_year"], 1, 1, tzinfo=timezone.utc),
            )
            if not already_sent:
                deadline_str = qinfo["deadline_date"].strftime("%Y-%m-%d")
                msg = (
                    f'الإقرار الضريبي ل{qinfo["quarter_label"]} جاهز للرفع. '
                    f'الموعد النهائي: {deadline_str}'
                )
                await conn.execute(
                    """
                    INSERT INTO notifications (tenant_id, device_id, notification_type, message)
                    VALUES ($1, $2, 'vat_reminder', $3)
                    """,
                    ctx.tenant_id, ctx.device_id, msg,
                )
    
    return {"ok": True}


@app.post("/api/v1/sync/upsert")
async def upsert(req: UpsertReq, ctx: AgentCtx = Depends(require_agent), request: Request = None):
    client_ip = request.client.host if request and request.client else "unknown"
    if not sync_limiter.is_allowed(f"up:{client_ip}"):
        raise HTTPException(429, "Rate limited")
    if not req.rows:
        return {"upserted": 0}

    pool: asyncpg.Pool = app.state.pool
    tdef = validate_table(req.table)
    pg_table = tdef["pg_table"]
    pg_cols = list(tdef["columns"].values())
    # tenant_id + device_id must BOTH be part of the conflict target. Each
    # physical Aronium installation (device) generates its own auto-increment
    # local IDs starting from 1, so two branches under the same tenant can
    # easily share the same local "Id". Without device_id in the key, one
    # branch's upsert would silently overwrite another branch's row.
    conflict_cols = ["tenant_id", "device_id"] + tdef["conflict"]
    all_cols = ["tenant_id", "device_id"] + pg_cols
    placeholders = ", ".join(f"${i+1}" for i in range(len(all_cols)))
    col_list = ", ".join(f'"{c}"' for c in all_cols)
    conflict_list = ", ".join(f'"{c}"' for c in conflict_cols)
    update_cols = [c for c in pg_cols if c not in tdef["conflict"]]

    if update_cols:
        update_set = ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in update_cols)
        sql = (
            f'INSERT INTO {pg_table} ({col_list}) VALUES ({placeholders}) '
            f'ON CONFLICT ({conflict_list}) DO UPDATE SET {update_set}'
        )
    else:
        sql = (
            f'INSERT INTO {pg_table} ({col_list}) VALUES ({placeholders}) '
            f'ON CONFLICT ({conflict_list}) DO NOTHING'
        )

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                rows_to_write = []
                for raw in req.rows:
                    values = list(_coerce_row(pg_cols, project_row(tdef, raw), pg_table))
                    rows_to_write.append((ctx.tenant_id, ctx.device_id, *values))

                is_z_report = req.table.lower() == "zreport"
                await conn.executemany(sql, rows_to_write)

                # Any received ZReport is treated as a close event.
                if is_z_report and rows_to_write:
                    dev_row = await conn.fetchrow(
                        """SELECT branch_name, registered_at
                           FROM devices
                           WHERE id=$1::uuid AND tenant_id=$2::uuid""",
                        ctx.device_id, ctx.tenant_id,
                    )
                    branch_name = dev_row["branch_name"] if dev_row else "الفرع"
                    registered_at = dev_row["registered_at"] if dev_row else None
                    saudi = timezone(timedelta(hours=3))
                    now_utc = datetime.now(timezone.utc)
                    now_saudi = now_utc.astimezone(saudi)
                    hour = now_saudi.hour
                    minute = now_saudi.minute
                    period_label = "صباحاً" if hour < 12 else "مساءً"
                    hour12 = hour % 12 or 12
                    time_str = f"{hour12:02d}:{minute:02d} {period_label}"

                    # Baseline guard: ignore historical ZReport rows that are older
                    # than this device registration time, so first activation starts
                    # from "now" without creating historical close events.
                    if registered_at:
                        incoming_z_dates = []
                        for row in rows_to_write:
                            dt = _to_datetime(row[6])
                            if dt:
                                incoming_z_dates.append(dt)
                        if incoming_z_dates and max(incoming_z_dates) < registered_at:
                            return {"upserted": len(rows_to_write), "table": req.table}

                    # Ignore near-duplicate close events caused by rapid retries.
                    recent_close = await conn.fetchval(
                        """SELECT COUNT(*) FROM day_sessions
                           WHERE tenant_id=$1::uuid
                             AND device_id=$2::uuid
                             AND source='z_report'
                             AND period_end >= ($3::timestamptz - interval '120 seconds')
                             AND period_end <= ($3::timestamptz + interval '120 seconds')""",
                        ctx.tenant_id, ctx.device_id, now_utc,
                    )
                    if recent_close and recent_close > 0:
                        return {"upserted": len(rows_to_write), "table": req.table}

                    # Determine period_start: end of the previous day_session
                    prev = await conn.fetchrow(
                        """SELECT period_end FROM day_sessions
                           WHERE tenant_id=$1::uuid AND device_id=$2::uuid
                           ORDER BY period_end DESC LIMIT 1""",
                        ctx.tenant_id, ctx.device_id,
                    )
                    if prev and (now_utc - prev["period_end"]) < timedelta(hours=36):
                        period_start = prev["period_end"]
                    else:
                        # First close or too long ago — use close_hour-based start
                        close_row = await conn.fetchrow(
                            "SELECT COALESCE(close_hour, 0) AS close_hour FROM tenants WHERE id=$1::uuid",
                            ctx.tenant_id,
                        )
                        ch = int(close_row["close_hour"] if close_row else 0)
                        close_saudi = datetime(now_saudi.year, now_saudi.month, now_saudi.day, ch, tzinfo=saudi)
                        if now_saudi < close_saudi:
                            close_saudi -= timedelta(days=1)
                        period_start = close_saudi.astimezone(timezone.utc)

                    await conn.execute(
                        """INSERT INTO day_sessions
                               (tenant_id, device_id, period_start, period_end, source)
                           VALUES ($1::uuid, $2::uuid, $3, $4, 'z_report')""",
                        ctx.tenant_id, ctx.device_id, period_start, now_utc,
                    )
                    await conn.execute(
                        """INSERT INTO notifications (tenant_id, device_id, notification_type, message)
                           VALUES ($1::uuid, $2::uuid, 'daily_close', $3)""",
                        ctx.tenant_id, ctx.device_id,
                        f"تم إنهاء اليوم من {branch_name} - الساعة {time_str}",
                    )

        return {"upserted": len(rows_to_write), "table": req.table}
    except Exception as e:
        log.error(f"Upsert error for {req.table}: {e}")
        raise HTTPException(500, f"Upsert failed: {str(e)[:200]}")


@app.post("/api/v1/sync/reconcile")
async def reconcile(req: ReconcileReq, ctx: AgentCtx = Depends(require_agent), request: Request = None):
    client_ip = request.client.host if request and request.client else "unknown"
    if not sync_limiter.is_allowed(f"re:{client_ip}"):
        raise HTTPException(429, "Rate limited")
    pool: asyncpg.Pool = app.state.pool
    tdef = validate_table(req.table)
    pg_table = tdef["pg_table"]
    pk_text_expr = tdef.get("pk_text_expr", f"{tdef['conflict'][0]}::text")

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Scope deletion to THIS device only. Reconcile must never
                # touch rows synced by another device under the same tenant
                # (e.g. a branch's reconcile must not wipe the main store's
                # documents/products just because they aren't in the
                # branch's own local id list).
                if not req.local_pks:
                    row = await conn.fetch(
                        f"DELETE FROM {pg_table} WHERE tenant_id=$1 AND device_id=$2 "
                        f"RETURNING {pk_text_expr} AS pk",
                        ctx.tenant_id, ctx.device_id,
                    )
                else:
                    row = await conn.fetch(
                        f"DELETE FROM {pg_table} WHERE tenant_id=$1 AND device_id=$2 "
                        f"AND {pk_text_expr} <> ALL($3::text[]) "
                        f"RETURNING {pk_text_expr} AS pk",
                        ctx.tenant_id, ctx.device_id, req.local_pks,
                    )
                deleted = [r["pk"] for r in row]
        
        if deleted:
            log.info("reconcile %s: dropped %d stale rows", req.table, len(deleted))
        
        return {"deleted": deleted, "table": req.table}
    except Exception as e:
        log.error(f"Reconcile error: {e}")
        raise HTTPException(500, f"Reconcile failed: {str(e)[:200]}")


@app.post("/api/v1/agents/notifications")
async def agent_send_notification(req: dict, ctx: AgentCtx = Depends(require_agent)):
    """Agent sends notification to dashboard."""
    pool: asyncpg.Pool = app.state.pool
    notification_type = req.get("type", "info")
    message = req.get("message", "")
    
    if not message:
        raise HTTPException(400, "Message required")
    
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO notifications (tenant_id, device_id, notification_type, message)
               VALUES ($1::uuid, $2::uuid, $3, $4)""",
            ctx.tenant_id, ctx.device_id, notification_type, message
        )
    
    return {"success": True}


@app.post("/api/v1/agents/day-status")
async def agent_day_status(req: dict, ctx: AgentCtx = Depends(require_agent)):
    """Agent polls for auto-close status.

    Server decides based on ACTUAL Saudi time (not agent's current_hour):
      - Determine the current business day window using tenant's close_hour.
      - If we are PAST today's close_hour AND no ZReport was synced within
        the current business day window → trigger auto-close notification.
      - If a ZReport exists (manual close from Aronium) → skip auto-close.

    The message sent matches the portal's notification text exactly.
    """
    pool: asyncpg.Pool = app.state.pool

    async with pool.acquire() as conn:
        tenant = await conn.fetchrow(
            "SELECT close_hour, COALESCE(onboarded, false) AS onboarded FROM tenants WHERE id=$1::uuid",
            ctx.tenant_id,
        )
        if not tenant:
            return {"auto_close": False}
        if not tenant["onboarded"]:
            return {"auto_close": False}

        close_hour = int(tenant["close_hour"] or 0)

        # Compute current business-day window in Saudi time
        saudi = timezone(timedelta(hours=3))
        now_saudi = datetime.now(saudi)
        today_close_saudi = datetime(
            now_saudi.year, now_saudi.month, now_saudi.day,
            close_hour, tzinfo=saudi,
        )
        if now_saudi < today_close_saudi:
            # Business day started yesterday; window = [yesterday_close, today_close)
            window_start_saudi = today_close_saudi - timedelta(days=1)
            window_end_saudi = today_close_saudi
        else:
            # Business day started today; window = [today_close, tomorrow_close)
            window_start_saudi = today_close_saudi
            window_end_saudi = today_close_saudi + timedelta(days=1)

        # Auto-close fires ONLY within the grace window after close_hour (4 hours).
        # Without this, if the agent was offline at close_hour and first connects at
        # 3 PM, it would incorrectly trigger auto-close during business hours.
        MAX_GRACE_HOURS = 4
        grace_end_saudi = window_start_saudi + timedelta(hours=MAX_GRACE_HOURS)
        auto_close_eligible = window_start_saudi <= now_saudi < grace_end_saudi

        if not auto_close_eligible:
            return {"auto_close": False}

        window_start_utc = window_start_saudi.astimezone(timezone.utc)
        window_end_utc = window_end_saudi.astimezone(timezone.utc)
        now_utc = now_saudi.astimezone(timezone.utc)

        # Check for manual ZReport within the current business day window
        z_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM z_report
            WHERE tenant_id=$1::uuid
              AND device_id=$2::uuid
              AND date_created >= $3::timestamptz
              AND date_created <  $4::timestamptz
            """,
            ctx.tenant_id, ctx.device_id, window_start_utc, window_end_utc,
        )

        if z_count and z_count > 0:
            # Manual close already happened for this business day
            return {"auto_close": False}

        # Avoid spamming: at most one close (z_report or auto) per business day
        existing_session = await conn.fetchval(
            """SELECT COUNT(*) FROM day_sessions
               WHERE tenant_id=$1::uuid
                 AND device_id=$2::uuid
                 AND period_end >= $3::timestamptz
                 AND period_end <  $4::timestamptz""",
            ctx.tenant_id, ctx.device_id, window_start_utc, window_end_utc,
        )
        if existing_session and existing_session > 0:
            return {"auto_close": False}

        # Fetch branch name for notification
        dev_row = await conn.fetchrow(
            "SELECT branch_name FROM devices WHERE id=$1::uuid AND tenant_id=$2::uuid",
            ctx.device_id, ctx.tenant_id,
        )
        branch_name = dev_row["branch_name"] if dev_row else "الفرع"

        # Record the closed session and notify
        await conn.execute(
            """INSERT INTO day_sessions
                   (tenant_id, device_id, period_start, period_end, source)
               VALUES ($1::uuid, $2::uuid, $3, $4, 'auto')""",
            ctx.tenant_id, ctx.device_id, window_start_utc, now_utc,
        )
        await conn.execute(
            """INSERT INTO notifications
               (tenant_id, device_id, notification_type, message)
               VALUES ($1::uuid, $2::uuid, 'auto_close', $3)""",
            ctx.tenant_id, ctx.device_id,
            f"تم إنهاء اليوم بشكل أوتوماتيكي من {branch_name}",
        )
        return {"auto_close": True}


# ────────────────────────────────────────────────────────────────────────────
# Static files (dashboard)
# ────────────────────────────────────────────────────────────────────────────
_static_dir = pathlib.Path(__file__).parent / "static"
if _static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
