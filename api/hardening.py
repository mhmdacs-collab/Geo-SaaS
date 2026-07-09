# -*- coding: utf-8 -*-
"""
Aronium SaaS Hardening Module (v11.4.0)
========================================
Production-grade enhancements:
  - Sync failure tracking & alerting
  - Device health monitoring
  - Audit logging for all operations
  - Data validation helpers
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
from pydantic import BaseModel

log = logging.getLogger("aronium-hardening")


# ============================================================================
# Models
# ============================================================================

class SyncFailureRecord(BaseModel):
    tenant_id: str
    device_id: Optional[str] = None
    table_name: str
    error_message: str
    pending_rows: int = 0
    severity: str = "warning"  # info | warning | critical


# ============================================================================
# 1. Sync Failure Tracking
# ============================================================================

async def log_sync_failure(
    pool: asyncpg.Pool,
    failure: SyncFailureRecord,
) -> int:
    """Log a sync failure for monitoring & alerting."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO sync_failures 
               (tenant_id, device_id, table_name, error_message, pending_rows, severity)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id""",
            failure.tenant_id,
            failure.device_id,
            failure.table_name,
            failure.error_message,
            failure.pending_rows,
            failure.severity,
        )
    log.warning(
        f"Sync failure logged: {failure.table_name} (tenant={failure.tenant_id}, "
        f"severity={failure.severity})"
    )
    return row["id"] if row else 0


async def resolve_sync_failure(
    pool: asyncpg.Pool,
    failure_id: int,
) -> bool:
    """Mark a sync failure as resolved."""
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE sync_failures SET resolved_at = now() WHERE id = $1",
            failure_id,
        )
    return result == "UPDATE 1"


async def get_unresolved_failures(
    pool: asyncpg.Pool,
    tenant_id: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Retrieve unresolved failures for a tenant."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, device_id, table_name, error_message, severity, failed_at
               FROM sync_failures
               WHERE tenant_id = $1 AND resolved_at IS NULL
               ORDER BY failed_at DESC
               LIMIT $2""",
            tenant_id,
            limit,
        )
    return [dict(r) for r in rows]


# ============================================================================
# 2. Device Health Monitoring
# ============================================================================

async def update_device_health(
    pool: asyncpg.Pool,
    device_id: str,
    tenant_id: str,
    status: str = "ok",
) -> bool:
    """Update device health status."""
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO device_health_extended 
               (device_id, tenant_id, last_heartbeat_at, last_status)
               VALUES ($1, $2, now(), $3)
               ON CONFLICT (device_id) DO UPDATE SET
                   last_heartbeat_at = now(),
                   last_status = $3,
                   consecutive_failures = 
                       CASE WHEN $3 = 'ok' THEN 0 
                            ELSE device_health_extended.consecutive_failures + 1 
                       END,
                   consecutive_failures_since = 
                       CASE WHEN $3 = 'ok' THEN NULL 
                            ELSE COALESCE(device_health_extended.consecutive_failures_since, now())
                       END""",
            device_id,
            tenant_id,
            status,
        )
    return True


async def check_unhealthy_devices(
    pool: asyncpg.Pool,
    hours_threshold: int = 24,
) -> List[Dict[str, Any]]:
    """Find devices that haven't synced in N hours."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM v_unhealthy_devices 
               WHERE hours_without_sync > $1
               ORDER BY hours_without_sync DESC""",
            hours_threshold,
        )
    return [dict(r) for r in rows]


# ============================================================================
# 3. Audit Logging
# ============================================================================

async def audit_log_operation(
    pool: asyncpg.Pool,
    tenant_id: str,
    device_id: Optional[str],
    table_name: str,
    operation: str,
    rows_affected: int,
    changes: Dict[str, Any] = None,
    source_ip: Optional[str] = None,
) -> int:
    """Log an operation to the audit trail."""
    checksum = hashlib.sha256(
        json.dumps(changes, sort_keys=True, default=str).encode()
    ).hexdigest() if changes else None
    
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO audit_log 
               (tenant_id, device_id, table_name, operation, rows_affected, 
                checksum_after, changes_json, source_ip)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id""",
            tenant_id,
            device_id,
            table_name,
            operation,
            rows_affected,
            checksum,
            json.dumps(changes or {}),
            source_ip,
        )
    return row["id"] if row else 0


async def get_audit_trail(
    pool: asyncpg.Pool,
    tenant_id: str,
    table_name: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Retrieve audit trail for a tenant."""
    query = """SELECT id, table_name, operation, rows_affected, created_at
               FROM audit_log
               WHERE tenant_id = $1"""
    params = [tenant_id]
    
    if table_name:
        query += " AND table_name = $2"
        params.append(table_name)
    
    query += f" ORDER BY created_at DESC LIMIT {limit}"
    
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return [dict(r) for r in rows]


# ============================================================================
# 4. Data Validation Helpers
# ============================================================================

async def validate_document_integrity(
    pool: asyncpg.Pool,
    tenant_id: str,
    document_id: int,
    doc_total: float,
) -> Tuple[bool, Optional[str]]:
    """Validate that document total matches line items."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT SUM(total_after_document_discount) as items_total
               FROM ar_document_items
               WHERE tenant_id = $1 AND document_id = $2""",
            tenant_id,
            document_id,
        )
    
    items_total = float(row["items_total"] or 0)
    discrepancy = abs(doc_total - items_total)
    
    if discrepancy > 0.01:
        return False, f"Total mismatch: doc={doc_total}, items={items_total}"
    
    return True, None


async def validate_temporal_consistency(
    pool: asyncpg.Pool,
    tenant_id: str,
) -> Tuple[int, List[str]]:
    """Check for temporal anomalies (future dates, reversed timelines)."""
    issues = []
    count = 0
    
    async with pool.acquire() as conn:
        future_rows = await conn.fetch(
            """SELECT aronium_id, doc_date FROM ar_documents
               WHERE tenant_id = $1 AND doc_date > CURRENT_DATE
               LIMIT 10""",
            tenant_id,
        )
        
        if future_rows:
            count += len(future_rows)
            issues.append(f"Found {len(future_rows)} documents with future dates")
    
    return count, issues
