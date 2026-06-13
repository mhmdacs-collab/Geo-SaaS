"""Aronium SaaS — Main API with Hardening Integration (v11.4.0)
============================================================
Production API with security, monitoring, audit logging,
admin endpoints for n8n integration, and subscription management.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, date, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from table_map import TABLE_MAP, project_row, validate_table
from hardening import (
    log_sync_failure,
    SyncFailureRecord,
    update_device_health,
    audit_log_operation,
)

# ────────────────────────────────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────────────────────────────────
from config import DATABASE_URL, JWT_SECRET, JWT_ALG, JWT_AUDIENCE, ADMIN_API_KEY, CORS_ORIGINS, SUPPORT_WA

# Backward compatibility
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
log = logging.getLogger("ingest")


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


activate_limiter = RateLimiter(max_requests=5, window_seconds=300)


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


app = FastAPI(title="Aronium Ingest API", version="11.4.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"], allow_headers=["*"],
)

# State vars for portal
app.state.jwt_secret = JWT_SECRET
app.state.jwt_alg = JWT_ALG
app.state.support_wa = SUPPORT_WA


# ────────────────────────────────────────────────────────────────────────────
# Admin auth dependency
# ────────────────────────────────────────────────────────────────────────────
async def require_admin(x_admin_key: str = Header(None)) -> bool:
    if not ADMIN_API_KEY:
        raise HTTPException(503, "ADMIN_API_KEY not configured")
    if not x_admin_key or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(403, "invalid admin key")
    return True


# ────────────────────────────────────────────────────────────────────────────
# Date / datetime coercion
# ────────────────────────────────────────────────────────────────────────────
TS_COLS = {"date_created", "date_updated", "stock_date"}
DATE_COLS = {"doc_date", "due_date", "pay_date"}

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


def _coerce_row(pg_cols: List[str], values: List[Any]) -> List[Any]:
    out: List[Any] = []
    for col, val in zip(pg_cols, values):
        if col in TS_COLS:
            out.append(_to_datetime(val))
        elif col in DATE_COLS:
            out.append(_to_date(val))
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
    token_aud = payload.get("aud")
    if token_aud is not None and token_aud != JWT_AUDIENCE:
        raise HTTPException(401, "invalid audience")
    if payload.get("sub") != "agent":
        raise HTTPException(401, "wrong token subject")
    tenant_id = payload.get("tenant_id")
    device_id = payload.get("device_id")
    if not tenant_id or not device_id:
        raise HTTPException(401, "malformed token")
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT revoked_at FROM devices WHERE id=$1 AND tenant_id=$2",
            device_id, tenant_id,
        )
    if row is None:
        raise HTTPException(403, "device unknown")
    if row["revoked_at"] is not None:
        raise HTTPException(403, "device revoked")
    return AgentCtx(tenant_id=tenant_id, device_id=device_id)


# ────────────────────────────────────────────────────────────────────────────
# Schemas
# ────────────────────────────────────────────────────────────────────────────
class DeviceInfo(BaseModel):
    application_id: str
    store_name: Optional[str] = None
    tax_number: Optional[str] = None
    phone_number: Optional[str] = None
    agent_version: Optional[str] = None
    hostname: Optional[str] = None


class ActivateReq(BaseModel):
    activation_code: str = Field(..., min_length=4)
    device: DeviceInfo


class ActivateResp(BaseModel):
    token: str
    tenant_id: str
    device_id: str


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


# Admin schemas
class RegisterClientReq(BaseModel):
    store_name: str
    tax_number: str
    phone_number: str


class RegisterClientResp(BaseModel):
    tenant_id: str
    activation_code: str
    subscription_type: str
    subscription_days: int
    expires_at: str


class RenewReq(BaseModel):
    tax_number: str


class RenewResp(BaseModel):
    tenant_id: str
    new_code: str
    subscription_expires_at: str


class GenerateCodesReq(BaseModel):
    count: int = Field(default=100, ge=1, le=5000)
    subscription_type: str = "monthly"
    subscription_days: int = 30
    validity_days: int = 180


# ────────────────────────────────────────────────────────────────────────────
# Helper: generate code
# ────────────────────────────────────────────────────────────────────────────
def _gen_code() -> str:
    body = secrets.token_urlsafe(12).replace("-", "").replace("_", "").upper()[:12]
    return f"AR-{body[:4]}-{body[4:8]}-{body[8:12]}"


# ════════════════════════════════════════════════════════════════════════════
# Agent Routes
# ════════════════════════════════════════════════════════════════════════════

@app.get("/healthz")
async def healthz():
    try:
        async with app.state.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"ok": True}
    except Exception as e:
        raise HTTPException(503, f"db unreachable: {e}")


@app.post("/api/v1/agents/activate", response_model=ActivateResp)
async def activate(req: ActivateReq, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not activate_limiter.is_allowed(client_ip):
        log.warning(f"Rate limit exceeded for activation from {client_ip}")
        raise HTTPException(429, "Too many activation attempts. Try again later.")

    pool: asyncpg.Pool = app.state.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            code = await conn.fetchrow(
                """SELECT code, tenant_id, used_at, expires_at, subscription_days
                     FROM activation_codes WHERE code = $1 FOR UPDATE""",
                req.activation_code.strip(),
            )
            if code is None:
                raise HTTPException(404, "activation code not found")
            if code["used_at"] is not None:
                raise HTTPException(409, "activation code already used")
            if code["expires_at"] < datetime.now(timezone.utc):
                raise HTTPException(410, "activation code expired")

            tenant_id = code["tenant_id"]
            sub_days = code["subscription_days"] or 30

            if tenant_id is None:
                # Pre-generated code: create tenant now
                row = await conn.fetchrow(
                    """INSERT INTO tenants
                         (application_id, store_name, tax_number, phone_number,
                          subscription, subscription_status, subscription_expires_at)
                       VALUES ($1, $2, $3, $4, 'monthly', 'active',
                               now() + make_interval(days => $5))
                       RETURNING id""",
                    "pending-" + secrets.token_hex(6),
                    "", "", "", sub_days,
                )
                tenant_id = row["id"]
                await conn.execute(
                    "UPDATE activation_codes SET tenant_id = $1 WHERE code = $2",
                    tenant_id, code["code"],
                )
            else:
                # Existing tenant: extend subscription (بدون updated_at)
                await conn.execute(
                    """UPDATE tenants SET
                         subscription_status = 'active',
                         subscription_expires_at = now() + make_interval(days => $2)
                       WHERE id = $1""",
                    tenant_id, sub_days,
                )

            # Update tenant identity from device info (بدون updated_at)
            try:
                await conn.execute(
                    """UPDATE tenants SET
                          application_id = COALESCE(NULLIF($2,''), application_id),
                          store_name     = COALESCE(NULLIF($3,''), store_name),
                          tax_number     = COALESCE(NULLIF($4,''), tax_number),
                          phone_number   = COALESCE(NULLIF($5,''), phone_number)
                        WHERE id = $1
                          AND (application_id LIKE 'pending-%' OR application_id IS NULL)""",
                    tenant_id, req.device.application_id,
                    req.device.store_name or "",
                    req.device.tax_number or "",
                    req.device.phone_number or "",
                )
            except asyncpg.UniqueViolationError:
                log.warning("application_id %s already exists", req.device.application_id)

            hostname = (req.device.hostname or "unknown")[:255]
            device_row = await conn.fetchrow(
                """INSERT INTO devices (tenant_id, hostname, agent_version,
                                        first_seen_at, last_seen_at)
                        VALUES ($1, $2, $3, now(), now())
                   ON CONFLICT (tenant_id, hostname)
                   DO UPDATE SET agent_version = EXCLUDED.agent_version,
                                 last_seen_at  = now(), revoked_at = NULL
                   RETURNING id""",
                tenant_id, hostname, req.device.agent_version or "",
            )
            device_id = device_row["id"]

            await conn.execute(
                """INSERT INTO agent_health (device_id, tenant_id, last_sync_at,
                                             last_status, agent_version)
                        VALUES ($1, $2, now(), 'activated', $3)
                   ON CONFLICT (device_id)
                   DO UPDATE SET tenant_id = EXCLUDED.tenant_id,
                                 last_sync_at = now(), last_status = 'activated',
                                 agent_version = EXCLUDED.agent_version""",
                device_id, tenant_id, req.device.agent_version or "",
            )

            await conn.execute(
                "UPDATE activation_codes SET used_at = now() WHERE code = $1",
                code["code"],
            )

    token = _make_token(str(tenant_id), str(device_id), sub_days)
    log.info("activated tenant=%s device=%s host=%s", tenant_id, device_id, hostname)
    return ActivateResp(token=token, tenant_id=str(tenant_id), device_id=str(device_id))


@app.post("/api/v1/agents/heartbeat")
async def heartbeat(req: HeartbeatReq, ctx: AgentCtx = Depends(require_agent)):
    pool: asyncpg.Pool = app.state.pool
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE devices SET last_seen_at=now(), agent_version=COALESCE($3,agent_version) "
            "WHERE id=$1 AND tenant_id=$2",
            ctx.device_id, ctx.tenant_id, req.agent_version,
        )
        await conn.execute(
            """INSERT INTO agent_health (device_id,tenant_id,last_sync_at,last_status,agent_version)
                    VALUES ($1,$2,now(),$3,$4)
               ON CONFLICT (device_id) DO UPDATE SET
                    tenant_id=EXCLUDED.tenant_id, last_sync_at=now(),
                    last_status=EXCLUDED.last_status,
                    agent_version=COALESCE(EXCLUDED.agent_version,agent_health.agent_version)""",
            ctx.device_id, ctx.tenant_id, req.last_status or "ok", req.agent_version,
        )
    try:
        await update_device_health(pool, str(ctx.device_id), str(ctx.tenant_id), "ok")
    except Exception as e:
        log.warning(f"Failed to update device health: {e}")
    return {"ok": True}


@app.post("/api/v1/sync/upsert")
async def upsert(req: UpsertReq, ctx: AgentCtx = Depends(require_agent)):
    if not req.rows:
        return {"upserted": 0}
    pool: asyncpg.Pool = app.state.pool
    try:
        tdef = validate_table(req.table)
    except HTTPException as e:
        await log_sync_failure(pool, SyncFailureRecord(
            tenant_id=str(ctx.tenant_id), device_id=str(ctx.device_id),
            table_name=req.table, error_message=str(e.detail)[:500],
            pending_rows=len(req.rows), severity="critical",
        ))
        raise

    pg_table = tdef["pg_table"]
    pg_cols = list(tdef["columns"].values())
    conflict_cols = tdef["conflict"]
    all_cols = ["tenant_id"] + pg_cols
    placeholders = ", ".join(f"${i+1}" for i in range(len(all_cols)))
    col_list = ", ".join(f'"{ c}"' for c in all_cols)
    conflict_list = ", ".join(f'"{ c}"' for c in conflict_cols)
    update_cols = [c for c in pg_cols if c not in conflict_cols]

    if update_cols:
        update_set = ", ".join(
            f'"{ c}" = EXCLUDED."{ c}"' for c in update_cols
        ) + ', "synced_at" = now()'
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
                bool_cols_records = await conn.fetch(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name=$1 AND data_type='boolean'",
                    pg_table,
                )
                bool_cols = {r["column_name"] for r in bool_cols_records}
                rows_to_write = []
                for raw in req.rows:
                    values = list(_coerce_row(pg_cols, project_row(tdef, raw)))
                    for i, cn in enumerate(pg_cols):
                        if cn in bool_cols and isinstance(values[i], int):
                            values[i] = bool(values[i])
                    rows_to_write.append((ctx.tenant_id, *values))
                await conn.executemany(sql, rows_to_write)
        try:
            await audit_log_operation(
                pool, str(ctx.tenant_id), str(ctx.device_id),
                req.table, "upsert", len(rows_to_write),
            )
        except Exception as e:
            log.warning(f"Failed to log audit: {e}")
        try:
            await update_device_health(
                pool, str(ctx.device_id), str(ctx.tenant_id), "ok",
            )
        except Exception as e:
            log.warning(f"Failed to update device health: {e}")
        return {"upserted": len(rows_to_write), "table": req.table}
    except Exception as e:
        error_msg = str(e)[:500]
        try:
            await log_sync_failure(pool, SyncFailureRecord(
                tenant_id=str(ctx.tenant_id), device_id=str(ctx.device_id),
                table_name=req.table, error_message=error_msg,
                pending_rows=len(req.rows),
                severity="critical" if "integrity" in error_msg.lower() else "warning",
            ))
        except Exception as log_err:
            log.error(f"Failed to log sync failure: {log_err}")
        log.error(f"Upsert error for {req.table}: {error_msg}")
        raise HTTPException(500, f"Upsert failed: {error_msg[:200]}")


@app.post("/api/v1/sync/reconcile")
async def reconcile(req: ReconcileReq, ctx: AgentCtx = Depends(require_agent)):
    pool: asyncpg.Pool = app.state.pool
    try:
        tdef = validate_table(req.table)
    except HTTPException as e:
        await log_sync_failure(pool, SyncFailureRecord(
            tenant_id=str(ctx.tenant_id), device_id=str(ctx.device_id),
            table_name=req.table, error_message=str(e.detail)[:500],
            pending_rows=0, severity="critical",
        ))
        raise
    pg_table = tdef["pg_table"]
    pk_text_expr = tdef["pk_text_expr"]
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
            await conn.execute(
                "UPDATE devices SET last_seen_at=now() WHERE id=$1",
                ctx.device_id,
            )
        try:
            await audit_log_operation(
                pool, str(ctx.tenant_id), str(ctx.device_id),
                req.table, "reconcile", len(deleted),
            )
        except Exception as e:
            log.warning(f"Failed to log reconcile: {e}")
        if deleted:
            log.info(
                "reconcile %s: dropped %d stale rows for tenant %s",
                req.table, len(deleted), ctx.tenant_id,
            )
        return {"deleted": deleted, "table": req.table}
    except Exception as e:
        error_msg = str(e)[:500]
        await log_sync_failure(pool, SyncFailureRecord(
            tenant_id=str(ctx.tenant_id), device_id=str(ctx.device_id),
            table_name=req.table, error_message=error_msg,
            pending_rows=0, severity="warning",
        ))
        raise HTTPException(500, f"Reconcile failed: {error_msg[:200]}")


# ════════════════════════════════════════════════════════════════════════════
# Admin Endpoints (for n8n / dashboard)
# ════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/admin/clients/register", response_model=RegisterClientResp)
async def admin_register_client(req: RegisterClientReq, _=Depends(require_admin)):
    """Register a new client: create tenant + assign a random available code."""
    pool: asyncpg.Pool = app.state.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Pick a random available code
            code_row = await conn.fetchrow(
                """SELECT code, subscription_type, subscription_days, expires_at
                   FROM activation_codes
                   WHERE tenant_id IS NULL AND used_at IS NULL
                     AND expires_at > now()
                   ORDER BY random() LIMIT 1
                   FOR UPDATE SKIP LOCKED"""
            )
            if code_row is None:
                raise HTTPException(409, "No available activation codes. Generate more.")

            sub_days = code_row["subscription_days"] or 30

            # Create tenant
            tenant = await conn.fetchrow(
                """INSERT INTO tenants
                     (application_id, store_name, tax_number, phone_number,
                      subscription, subscription_status, subscription_expires_at)
                   VALUES ($1, $2, $3, $4, $5, 'active',
                           now() + make_interval(days => $6))
                   RETURNING id""",
                "pending-" + secrets.token_hex(6),
                req.store_name, req.tax_number, req.phone_number,
                code_row["subscription_type"] or "monthly", sub_days,
            )
            tenant_id = tenant["id"]

            # Assign code to tenant
            await conn.execute(
                "UPDATE activation_codes SET tenant_id=$1 WHERE code=$2",
                tenant_id, code_row["code"],
            )

    log.info(
        "Admin registered client: tenant=%s store=%s code=%s",
        tenant_id, req.store_name, code_row["code"],
    )

    return RegisterClientResp(
        tenant_id=str(tenant_id),
        activation_code=code_row["code"],
        subscription_type=code_row["subscription_type"] or "monthly",
        subscription_days=sub_days,
        expires_at=code_row["expires_at"].isoformat(),
    )


@app.post("/api/v1/admin/clients/renew", response_model=RenewResp)
async def admin_renew_client(req: RenewReq, _=Depends(require_admin)):
    """Renew subscription: find tenant by tax_number, assign new code, extend expiry."""
    pool: asyncpg.Pool = app.state.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            tenant = await conn.fetchrow(
                "SELECT id FROM tenants WHERE tax_number=$1", req.tax_number
            )
            if tenant is None:
                raise HTTPException(404, "Tenant not found with this tax number")

            # Pick available code
            code_row = await conn.fetchrow(
                """SELECT code, subscription_days
                   FROM activation_codes
                   WHERE tenant_id IS NULL AND used_at IS NULL AND expires_at > now()
                   ORDER BY random() LIMIT 1
                   FOR UPDATE SKIP LOCKED"""
            )
            if code_row is None:
                raise HTTPException(409, "No available activation codes. Generate more.")

            sub_days = code_row["subscription_days"] or 30
            new_expiry = datetime.now(timezone.utc) + timedelta(days=sub_days)

            # Assign code and extend subscription
            await conn.execute(
                "UPDATE activation_codes SET tenant_id=$1 WHERE code=$2",
                tenant["id"], code_row["code"],
            )
            await conn.execute(
                """UPDATE tenants SET
                     subscription_status = 'active',
                     subscription_expires_at = $2,
                     updated_at = now()
                   WHERE id = $1""",
                tenant["id"], new_expiry,
            )

    log.info(
        "Admin renewed: tenant=%s tax=%s until=%s",
        tenant["id"], req.tax_number, new_expiry.isoformat(),
    )

    return RenewResp(
        tenant_id=str(tenant["id"]),
        new_code=code_row["code"],
        subscription_expires_at=new_expiry.isoformat(),
    )


@app.post("/api/v1/admin/codes/generate")
async def admin_generate_codes(req: GenerateCodesReq, _=Depends(require_admin)):
    """Generate a batch of activation codes."""
    pool: asyncpg.Pool = app.state.pool
    codes = set()
    while len(codes) < req.count:
        codes.add(_gen_code())

    async with pool.acquire() as conn:
        # Check for collisions
        existing = await conn.fetch("SELECT code FROM activation_codes")
        existing_set = {r["code"] for r in existing}
        codes = codes - existing_set
        while len(codes) < req.count:
            c = _gen_code()
            if c not in existing_set:
                codes.add(c)

        expires = datetime.now(timezone.utc) + timedelta(days=req.validity_days)
        await conn.executemany(
            """INSERT INTO activation_codes
               (code, tenant_id, expires_at, subscription_type, subscription_days, issued_for)
               VALUES ($1, NULL, $2, $3, $4, 'api-generated')""",
            [(c, expires, req.subscription_type, req.subscription_days) for c in codes],
        )

    return {
        "generated": len(codes),
        "subscription_type": req.subscription_type,
        "subscription_days": req.subscription_days,
        "validity_days": req.validity_days,
    }


@app.get("/api/v1/admin/codes/stats")
async def admin_codes_stats(_=Depends(require_admin)):
    """Get activation codes statistics."""
    pool: asyncpg.Pool = app.state.pool
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM activation_codes")
        available = await conn.fetchval(
            "SELECT COUNT(*) FROM activation_codes "
            "WHERE tenant_id IS NULL AND used_at IS NULL AND expires_at > now()"
        )
        used = await conn.fetchval(
            "SELECT COUNT(*) FROM activation_codes WHERE used_at IS NOT NULL"
        )
        expired = await conn.fetchval(
            "SELECT COUNT(*) FROM activation_codes "
            "WHERE expires_at <= now() AND used_at IS NULL"
        )
        assigned_unused = await conn.fetchval(
            "SELECT COUNT(*) FROM activation_codes "
            "WHERE tenant_id IS NOT NULL AND used_at IS NULL"
        )
    return {
        "total": total,
        "available": available,
        "used": used,
        "expired": expired,
        "assigned_unused": assigned_unused,
    }


# ════════════════════════════════════════════════════════════════════════════
# Monitoring Endpoints
# ════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/health/check")
async def health_check():
    pool: asyncpg.Pool = app.state.pool
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
            unhealthy = await conn.fetchval(
                """SELECT COUNT(*) FROM devices
                   WHERE revoked_at IS NULL
                     AND last_seen_at < now() - INTERVAL '24 hours'"""
            )
            unresolved = await conn.fetchval(
                "SELECT COUNT(*) FROM sync_failures WHERE resolved_at IS NULL"
            )
        status = (
            "unhealthy" if (unhealthy or 0) > 5
            else "degraded" if (unhealthy or 0) > 0
            else "healthy"
        )
        return {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unhealthy_devices": unhealthy or 0,
            "unresolved_failures": unresolved or 0,
        }
    except Exception as e:
        log.error(f"Health check failed: {e}")
        raise HTTPException(503, f"Health check failed: {str(e)[:200]}")


@app.get("/api/v1/sync/failures/{tenant_id}")
async def get_sync_failures(tenant_id: str):
    pool: asyncpg.Pool = app.state.pool
    try:
        async with pool.acquire() as conn:
            failures = await conn.fetch(
                """SELECT id, table_name, error_message, severity, failed_at
                   FROM sync_failures WHERE tenant_id=$1 AND resolved_at IS NULL
                   ORDER BY failed_at DESC LIMIT 50""",
                tenant_id,
            )
        return {
            "tenant_id": tenant_id,
            "count": len(failures),
            "failures": [dict(f) for f in failures],
        }
    except Exception as e:
        raise HTTPException(500, f"Failed: {str(e)[:200]}")


@app.get("/api/v1/devices/health/{tenant_id}")
async def get_devices_health(tenant_id: str):
    pool: asyncpg.Pool = app.state.pool
    try:
        async with pool.acquire() as conn:
            devices = await conn.fetch(
                """SELECT d.id, d.hostname, d.agent_version, d.last_seen_at,
                          EXTRACT(EPOCH FROM (now()-d.last_seen_at))/3600
                              AS hours_since_seen
                   FROM devices d
                   WHERE d.tenant_id=$1 AND d.revoked_at IS NULL
                   ORDER BY d.last_seen_at DESC""",
                tenant_id,
            )
        return {
            "tenant_id": tenant_id,
            "device_count": len(devices),
            "devices": [dict(d) for d in devices],
        }
    except Exception as e:
        raise HTTPException(500, f"Failed: {str(e)[:200]}")


# ════════════════════════════════════════════════════════════════════════════
# Merchant Portal
# ════════════════════════════════════════════════════════════════════════════
try:
    from portal import router as portal_router
    app.include_router(portal_router)
    log.info("Portal endpoints loaded")
except Exception as e:
    log.warning("Portal endpoints not loaded: %s", e)


# ── Serve dashboard (static files) ──────────────────────────────────────────
import pathlib
_static_dir = pathlib.Path(__file__).parent / "static"
if _static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
    log.info("Static dashboard served from %s", _static_dir)
