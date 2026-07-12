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

# ────────────────────────────────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALG = "HS256"
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "aronium-agent")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")
JWT_TTL_DAYS = int(os.environ.get("JWT_TTL_DAYS", "365"))

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


activate_limiter = RateLimiter(max_requests=10, window_seconds=300)


# ────────────────────────────────────────────────────────────────────────────
# DB pool lifecycle
# ────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        dsn=_clean_dsn(DATABASE_URL), min_size=1, max_size=10, command_timeout=60,
    )
    log.info("DB pool ready")
    try:
        yield
    finally:
        await app.state.pool.close()
        log.info("DB pool closed")


app = FastAPI(title="Aronium Sync API", version="12.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"], allow_headers=["*"],
)


# ────────────────────────────────────────────────────────────────────────────
# Date / datetime coercion
# ────────────────────────────────────────────────────────────────────────────
TS_COLS = {"date_created", "date_updated", "stock_date"}
DATE_COLS = {"doc_date", "due_date", "pay_date"}
BOOL_COLS = {"is_enabled", "is_customer", "is_supplier", "is_tax_exempt", "is_price_change_allowed", "is_using_default_quantity", "is_service", "is_tax_inclusive_price"}
# INT_COLS is scoped per pg_table because "number" is an integer only in
# z_report, while it is a free-form text value (e.g. "26-200-000001") in
# document / pos_order.
INT_COLS_BY_TABLE = {
    "z_report": {"number"},
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
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
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


async def require_agent(authorization: str = Header(None)) -> AgentCtx:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(None, 1)[1].strip()
    try:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALG],
            options={"verify_aud": False},
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
            "SELECT is_active FROM devices WHERE id=$1 AND tenant_id=$2",
            device_id, tenant_id,
        )
    if row is None:
        raise HTTPException(403, "device unknown")
    if not row["is_active"]:
        raise HTTPException(403, "device deactivated")
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
        return {"ok": True, "version": "12.0.0"}
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


@app.post("/api/v1/agents/heartbeat")
async def heartbeat(req: HeartbeatReq, ctx: AgentCtx = Depends(require_agent)):
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

        # Update device last seen
        await conn.execute(
            "UPDATE devices SET last_seen=now() WHERE id=$1 AND tenant_id=$2",
            ctx.device_id, ctx.tenant_id,
        )
    return {"ok": True}


@app.post("/api/v1/sync/upsert")
async def upsert(req: UpsertReq, ctx: AgentCtx = Depends(require_agent)):
    if not req.rows:
        return {"upserted": 0}

    pool: asyncpg.Pool = app.state.pool
    tdef = validate_table(req.table)
    pg_table = tdef["pg_table"]
    pg_cols = list(tdef["columns"].values())
    conflict_cols = ["tenant_id"] + tdef["conflict"]  # Always include tenant_id
    all_cols = ["tenant_id"] + pg_cols
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
                    rows_to_write.append((ctx.tenant_id, *values))
                await conn.executemany(sql, rows_to_write)
        return {"upserted": len(rows_to_write), "table": req.table}
    except Exception as e:
        log.error(f"Upsert error for {req.table}: {e}")
        raise HTTPException(500, f"Upsert failed: {str(e)[:200]}")


@app.post("/api/v1/sync/reconcile")
async def reconcile(req: ReconcileReq, ctx: AgentCtx = Depends(require_agent)):
    pool: asyncpg.Pool = app.state.pool
    tdef = validate_table(req.table)
    pg_table = tdef["pg_table"]
    pk_text_expr = tdef.get("pk_text_expr", f"{tdef['conflict'][0]}::text")

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                if not req.local_pks:
                    row = await conn.fetch(
                        f"DELETE FROM {pg_table} WHERE tenant_id=$1 "
                        f"RETURNING {pk_text_expr} AS pk",
                        ctx.tenant_id,
                    )
                else:
                    row = await conn.fetch(
                        f"DELETE FROM {pg_table} WHERE tenant_id=$1 "
                        f"AND {pk_text_expr} <> ALL($2::text[]) "
                        f"RETURNING {pk_text_expr} AS pk",
                        ctx.tenant_id, req.local_pks,
                    )
                deleted = [r["pk"] for r in row]
        if deleted:
            log.info("reconcile %s: dropped %d stale rows", req.table, len(deleted))
        return {"deleted": deleted, "table": req.table}
    except Exception as e:
        log.error(f"Reconcile error: {e}")
        raise HTTPException(500, f"Reconcile failed: {str(e)[:200]}")


# ────────────────────────────────────────────────────────────────────────────
# Static files (dashboard)
# ────────────────────────────────────────────────────────────────────────────
_static_dir = pathlib.Path(__file__).parent / "static"
if _static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
