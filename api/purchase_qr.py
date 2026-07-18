"""
Aronium SaaS - Purchase QR Invoice API
=======================================
Scan ZATCA QR from purchase invoices, decode TLV, store in dashboard_purchase_invoice.
Merged with Aronium purchases in all reports (quarter, month, day, recent, VAT).
"""
from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

log = logging.getLogger("aronium.purchase_qr")

router = APIRouter(prefix="/api/portal")


# ────────────────────────────────────────────────────────────────────────────
# ZATCA QR TLV Decoder
# ────────────────────────────────────────────────────────────────────────────
def decode_zatca_qr(qr_payload: str) -> Dict[str, Any]:
    """
    Decode ZATCA Phase 1 QR (Base64 → TLV).
    Tags: 1=Seller, 2=TaxNumber, 3=Timestamp, 4=Total, 5=VAT
    """
    try:
        raw = base64.b64decode(qr_payload)
    except Exception:
        raise ValueError("QR غير صالح - ترميز Base64 خاطئ")

    result: Dict[int, str] = {}
    i = 0
    while i < len(raw):
        if i + 2 > len(raw):
            break
        tag = raw[i]
        length = raw[i + 1]
        i += 2
        if i + length > len(raw):
            break
        value = raw[i:i + length].decode("utf-8", errors="replace")
        result[tag] = value
        i += length

    required = {1, 2, 3, 4, 5}
    missing = required - set(result.keys())
    if missing:
        raise ValueError(f"QR ناقص - الحقول المفقودة: {missing}")

    try:
        total = float(result[4])
        vat = float(result[5])
    except ValueError:
        raise ValueError("QR غير صالح - المبالغ غير رقمية")

    try:
        issued_at = datetime.fromisoformat(result[3])
        # ZATCA QR timestamps without an offset are Saudi time.
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone(timedelta(hours=3)))
        issued_at = issued_at.astimezone(timezone.utc)
    except ValueError:
        raise ValueError("QR غير صالح - التاريخ غير صحيح")

    return {
        "seller_name": result[1].strip(),
        "seller_tax_number": result[2].strip(),
        "issued_at": issued_at,
        "total_amount": total,
        "vat_amount": vat,
    }


# ────────────────────────────────────────────────────────────────────────────
# Schemas
# ────────────────────────────────────────────────────────────────────────────
class QrDecodeReq(BaseModel):
    qr_payload: str


class QrConfirmReq(BaseModel):
    qr_payload: str
    device_id: str


# ────────────────────────────────────────────────────────────────────────────
# Auth helper (same as portal)
# ────────────────────────────────────────────────────────────────────────────
async def _get_portal_auth(request: Request):
    # Import at runtime to avoid circular import
    import portal
    return await portal._get_auth(request)


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────
@router.post("/purchase-qr/decode")
async def decode_qr(body: QrDecodeReq, request: Request):
    """Decode ZATCA QR and return parsed data (no DB write)."""
    auth = await _get_portal_auth(request)
    try:
        data = decode_zatca_qr(body.qr_payload.strip())
    except ValueError as e:
        raise HTTPException(400, str(e))

    return {
        "seller_name": data["seller_name"],
        "seller_tax_number": data["seller_tax_number"],
        "issued_at": data["issued_at"].isoformat(),
        "total_amount": data["total_amount"],
        "vat_amount": data["vat_amount"],
    }


@router.post("/purchase-qr/confirm")
async def confirm_qr_invoice(body: QrConfirmReq, request: Request):
    """Confirm and store the QR invoice after user accepts responsibility."""
    auth = await _get_portal_auth(request)
    tenant_id = auth.get("tenant_id")
    state = request.app.state
    pool: asyncpg.Pool = state.pool

    try:
        data = decode_zatca_qr(body.qr_payload.strip())
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Validate device belongs to tenant
    device_id = body.device_id.strip()
    async with pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id FROM devices WHERE id=$1::uuid AND tenant_id=$2::uuid",
            device_id, tenant_id,
        )
        if not dev:
            raise HTTPException(400, "الفرع غير صحيح")

    qr_hash = hashlib.sha256(body.qr_payload.strip().encode("utf-8")).hexdigest()

    # Duplicate check: same QR payload hash (exact match)
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("""
            SELECT id, created_at FROM dashboard_purchase_invoice
            WHERE tenant_id = $1::uuid
              AND device_id = $2::uuid
              AND qr_payload_hash = $3
            LIMIT 1
        """, tenant_id, device_id, qr_hash)

        if existing:
            return {
                "duplicate": True,
                "existing_id": str(existing["id"]),
                "message": "هذه الفاتورة مسجلة مسبقاً لهذا الفرع. هل تريد تسجيلها مرة أخرى؟",
            }

        # Insert
        new_id = await conn.fetchval("""
            INSERT INTO dashboard_purchase_invoice
              (tenant_id, device_id, seller_name, seller_tax_number,
               issued_at, total_amount, vat_amount, qr_payload, qr_payload_hash)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        """, tenant_id, device_id, data["seller_name"], data["seller_tax_number"],
             data["issued_at"], data["total_amount"], data["vat_amount"],
             body.qr_payload.strip(), qr_hash)

    log.info("QR invoice stored: tenant=%s device=%s seller=%s total=%s",
             tenant_id, device_id, data["seller_name"], data["total_amount"])

    return {
        "duplicate": False,
        "id": str(new_id),
        "seller_name": data["seller_name"],
        "seller_tax_number": data["seller_tax_number"],
        "issued_at": data["issued_at"].isoformat(),
        "total_amount": data["total_amount"],
        "vat_amount": data["vat_amount"],
    }


@router.post("/purchase-qr/force-save")
async def force_save_qr_invoice(body: QrConfirmReq, request: Request):
    """Force save even if duplicate (user accepted responsibility)."""
    auth = await _get_portal_auth(request)
    tenant_id = auth.get("tenant_id")
    state = request.app.state
    pool: asyncpg.Pool = state.pool

    try:
        data = decode_zatca_qr(body.qr_payload.strip())
    except ValueError as e:
        raise HTTPException(400, str(e))

    device_id = body.device_id.strip()
    async with pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id FROM devices WHERE id=$1::uuid AND tenant_id=$2::uuid",
            device_id, tenant_id,
        )
        if not dev:
            raise HTTPException(400, "الفرع غير صحيح")

    qr_hash = hashlib.sha256(body.qr_payload.strip().encode("utf-8")).hexdigest()

    async with pool.acquire() as conn:
        new_id = await conn.fetchval("""
            INSERT INTO dashboard_purchase_invoice
              (tenant_id, device_id, seller_name, seller_tax_number,
               issued_at, total_amount, vat_amount, qr_payload, qr_payload_hash)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        """, tenant_id, device_id, data["seller_name"], data["seller_tax_number"],
             data["issued_at"], data["total_amount"], data["vat_amount"],
             body.qr_payload.strip(), qr_hash)

    return {"id": str(new_id), "saved": True}
