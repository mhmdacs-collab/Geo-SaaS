# -*- coding: utf-8 -*-
"""
Aronium Sync Agent v12.0
========================
No activation codes. Authentication via Application ID + Tax Number.

Flow:
1. Read Application ID + Tax Number from local Aronium DB
2. Send to server: POST /api/v1/agents/activate {application_id, tax_number, hostname}
3. Server verifies: device registered? tax matches? subscription active?
4. Server returns JWT token
5. Agent syncs data using token

Config (config.json):
{
  "api_base_url": "https://aronium-sync.onrender.com",
  "sync_interval_sec": 60,
  "aronium_db_path": "C:\\Users\\...\\Aronium\\Data\\pos.db"
}
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

# ─── Paths ───────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
STATE_DB = os.path.join(BASE_DIR, "agent_state.db")
TOKEN_FILE = os.path.join(BASE_DIR, "agent.token")
LOG_FILE = os.path.join(BASE_DIR, "agent.log")

VERSION = "12.2.0"

# ─── Logging ─────────────────────────────────────────────────────────────────
logger = logging.getLogger("aronium-agent")
logger.setLevel(logging.INFO)
_fmt = logging.Formatter("[%(asctime)s] %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
_fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
_fh.setFormatter(_fmt)
logger.addHandler(_fh)

# ─── Log Messages ────────────────────────────────────────────────────────────
LOG = {
    "start":          "Aronium Agent v12.2 started | server={url}",
    "shutdown":       "Agent stopped by user",
    "activating":     "Activating device...",
    "activated":      "Activation successful | store={store} tax={tax}",
    "activate_fail":  "Activation failed: {reason}",
    "device_not_found": "Device not registered - contact admin to register first",
    "tax_mismatch":   "TAX MISMATCH! Local={local} Server={server} - blocked",
    "sub_expired":    "Subscription expired! Please renew via support",
    "sub_suspended":  "Subscription suspended - contact support",
    "sub_ok":         "Subscription active",
    "sync_start":     "--- Sync cycle started ---",
    "sync_done":      "--- Sync completed: {total} rows synced ---",
    "sync_nothing":   "No new data to sync",
    "table_hash":     "  {table}: {changed}/{total} rows changed",
    "table_inc":      "  {table}: {count} new rows",
    "table_child":    "  {table}: {count} linked rows",
    "table_empty":    "  {table}: no changes",
    "table_reconcile":"  {table}: {count} deleted remotely",
    "err_server":     "Server error ({code}) - will retry next cycle",
    "err_no_internet":"No internet connection - retrying in {sec}s",
    "err_timeout":    "Connection timed out - server may be restarting",
    "err_rate_limit": "Too many requests - waiting before retry",
    "err_cycle":      "Sync cycle failed: {reason}",
    "tax_ok":         "Tax number verified: {tax}",
    "db_found":       "Aronium DB found: {path}",
    "db_missing":     "Aronium DB not found - searching...",
    "heartbeat_ok":   "Heartbeat sent",
    "heartbeat_fail": "Heartbeat failed: {reason}",
    "token_valid":    "Token valid - continuing sync",
    "token_expired":  "Token expired - reactivating...",
}

HTTP_ERROR_MAP = {
    401: LOG["sub_expired"],
    403: LOG["sub_suspended"],
    404: LOG["device_not_found"],
    410: LOG["sub_expired"],
    429: LOG["err_rate_limit"],
}


# ─── Config ──────────────────────────────────────────────────────────────────
@dataclass
class AgentConfig:
    api_base_url: str
    sync_interval_sec: int = 60
    reconcile_interval_sec: int = 3600
    batch_size: int = 500
    aronium_db_path: Optional[str] = None
    verify_tls: bool = True

    @classmethod
    def load(cls) -> "AgentConfig":
        if not os.path.exists(CONFIG_PATH):
            default = {
                "api_base_url": "https://aronium-sync.onrender.com",
                "sync_interval_sec": 60,
                "aronium_db_path": os.path.join(
                    os.environ.get("LOCALAPPDATA", ""), "Aronium", "Data", "pos.db"
                ),
            }
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=2)
            return cls(**default)
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return cls(
            api_base_url=raw["api_base_url"].rstrip("/"),
            sync_interval_sec=int(raw.get("sync_interval_sec", 60)),
            reconcile_interval_sec=int(raw.get("reconcile_interval_sec", 3600)),
            batch_size=int(raw.get("batch_size", 500)),
            aronium_db_path=raw.get("aronium_db_path"),
            verify_tls=bool(raw.get("verify_tls", True)),
        )


# ─── Token Storage ───────────────────────────────────────────────────────────
def _save_token(token: str) -> None:
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(token)
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass


def _load_token() -> Optional[str]:
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        token = f.read().strip()
    return token if token else None


def _clear_token() -> None:
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)


# ─── State DB ────────────────────────────────────────────────────────────────
def _init_state_db() -> None:
    conn = sqlite3.connect(STATE_DB)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sync_cursor (
            table_name TEXT PRIMARY KEY,
            last_updated_at TEXT,
            last_full_reconcile_at TEXT
        );
        CREATE TABLE IF NOT EXISTS row_hash (
            table_name TEXT,
            pk TEXT,
            hash TEXT,
            PRIMARY KEY (table_name, pk)
        );
        CREATE TABLE IF NOT EXISTS kv (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()
    conn.close()


def _kv_get(key: str, default: Optional[str] = None) -> Optional[str]:
    conn = sqlite3.connect(STATE_DB)
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def _kv_set(key: str, value: str) -> None:
    conn = sqlite3.connect(STATE_DB)
    conn.execute("INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)", (key, value))
    conn.commit()
    conn.close()


def _cursor_get(table: str) -> Optional[str]:
    conn = sqlite3.connect(STATE_DB)
    row = conn.execute(
        "SELECT last_updated_at FROM sync_cursor WHERE table_name=?", (table,)
    ).fetchone()
    conn.close()
    val = row[0] if row else None
    if val:
        # Convert ISO 8601 (2026-07-12T09:21:08.001439+00:00) to SQLite format (2026-07-12 09:21:08.001439)
        val = val.replace("T", " ").split("+")[0].split("Z")[0]
    return val


def _cursor_set(table: str, last_updated_at: str) -> None:
    conn = sqlite3.connect(STATE_DB)
    conn.execute(
        "INSERT INTO sync_cursor(table_name,last_updated_at) VALUES(?,?) "
        "ON CONFLICT(table_name) DO UPDATE SET last_updated_at=excluded.last_updated_at",
        (table, last_updated_at),
    )
    conn.commit()
    conn.close()


def _hash_lookup(table: str) -> Dict[str, str]:
    conn = sqlite3.connect(STATE_DB)
    rows = conn.execute(
        "SELECT pk, hash FROM row_hash WHERE table_name=?", (table,)
    ).fetchall()
    conn.close()
    return {pk: h for pk, h in rows}


def _hash_upsert_many(table: str, items: Iterable[Tuple[str, str]]) -> None:
    conn = sqlite3.connect(STATE_DB)
    conn.executemany(
        "INSERT INTO row_hash(table_name,pk,hash) VALUES(?,?,?) "
        "ON CONFLICT(table_name,pk) DO UPDATE SET hash=excluded.hash",
        [(table, pk, h) for pk, h in items],
    )
    conn.commit()
    conn.close()


def _hash_delete_many(table: str, pks: Iterable[str]) -> None:
    pks = list(pks)
    if not pks:
        return
    conn = sqlite3.connect(STATE_DB)
    conn.executemany(
        "DELETE FROM row_hash WHERE table_name=? AND pk=?",
        [(table, pk) for pk in pks],
    )
    conn.commit()
    conn.close()


# ─── Aronium DB ──────────────────────────────────────────────────────────────
DEFAULT_ARONIUM_PATHS = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Aronium", "Data", "pos.db"),
    os.path.join(os.environ.get("PROGRAMDATA", ""), "Aronium", "Data", "pos.db"),
]


def find_aronium_db(cfg: AgentConfig) -> Optional[str]:
    if cfg.aronium_db_path and os.path.exists(cfg.aronium_db_path):
        return cfg.aronium_db_path
    for p in DEFAULT_ARONIUM_PATHS:
        if p and os.path.exists(p):
            return p
    return None


def snapshot_db(src_path: str) -> Optional[str]:
    dst_path = os.path.join(tempfile.gettempdir(), "aronium_snap.db")
    try:
        src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
        dst = sqlite3.connect(dst_path)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        return dst_path
    except Exception as e:
        logger.error(f"DB snapshot failed: {e}")
        return None


def read_device_info(snap_path: str) -> Dict[str, Any]:
    """Read Application ID and Tax Number from Aronium DB."""
    conn = sqlite3.connect(snap_path)
    try:
        props = {
            n: v
            for n, v in conn.execute(
                "SELECT Name, Value FROM ApplicationProperty WHERE Name IN ('Application.Id','Application.Uid')"
            ).fetchall()
        }
        app_id = props.get("Application.Id") or props.get("Application.Uid")
        comp = conn.execute("SELECT Name, TaxNumber FROM Company LIMIT 1").fetchone()
        return {
            "application_id": app_id,
            "store_name": comp[0] if comp else "",
            "tax_number": comp[1] if comp else "",
        }
    finally:
        conn.close()


# ─── Sync Map ────────────────────────────────────────────────────────────────
SyncTable = Dict[str, Any]

SYNC_MAP: List[SyncTable] = [
    # ─── Reference Data (full sync - hash_diff) ─────────────────────────────
    {"name": "Company", "strategy": "hash_diff", "pk": "Id",
     "cols": ["Id","Name","Address","PostalCode","City","CountryId","TaxNumber","Email","PhoneNumber","BankAccountNumber","BankDetails","StreetName","AdditionalStreetName","BuildingNumber","PlotIdentification","CitySubdivisionName","CountrySubentity"]},
    {"name": "Warehouse", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","Name"]},
    {"name": "ProductGroup", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","Name","ParentGroupId","Color","Rank"]},
    {"name": "DocumentType", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","Name","Code","DocumentCategoryId","WarehouseId","StockDirection","EditorType","PriceType","LanguageKey"]},
    {"name": "PaymentType", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","Name","Code","IsCustomerRequired","IsFiscal","IsSlipRequired","IsChangeAllowed","Ordinal","IsEnabled","IsQuickPayment","OpenCashDrawer","ShortcutKey","MarkAsPaid"]},
    {"name": "FiscalItem", "strategy": "hash_diff", "pk": "PLU", "cols": ["PLU","Name","VAT"]},
    {"name": "Customer", "strategy": "hash_diff", "pk": "Id",
     "cols": ["Id","Code","Name","TaxNumber","Address","PostalCode","City","CountryId","DateCreated","DateUpdated","Email","PhoneNumber","IsEnabled","IsCustomer","IsSupplier","DueDatePeriod","StreetName","AdditionalStreetName","BuildingNumber","PlotIdentification","CitySubdivisionName","CountrySubentity","IsTaxExempt"]},
    {"name": "Product", "strategy": "hash_diff", "pk": "Id",
     "cols": ["Id","ProductGroupId","Name","Code","PLU","MeasurementUnit","Price","IsTaxInclusivePrice","CurrencyId","IsPriceChangeAllowed","IsService","IsUsingDefaultQuantity","IsEnabled","Description","DateCreated","DateUpdated","Cost","Markup","Color","AgeRestriction","LastPurchasePrice","Rank"]},
    {"name": "Barcode", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","ProductId","Value"]},
    {"name": "Stock", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","ProductId","WarehouseId","Quantity"]},
    
    # ─── Transaction Data (from registration date - incremental/child_of) ───
    {"name": "Document", "strategy": "incremental_updated", "pk": "Id", "updated_col": "DateUpdated",
     "cols": ["Id","Number","UserId","CustomerId","OrderNumber","Date","StockDate","Total","IsClockedOut","DocumentTypeId","WarehouseId","ReferenceDocumentNumber","DateCreated","DateUpdated","InternalNote","Note","DueDate","Discount","DiscountType","PaidStatus","DiscountApplyRule","ServiceType"]},
    {"name": "DocumentItem", "strategy": "child_of", "pk": "Id", "parent_table": "Document", "parent_fk": "DocumentId",
     "cols": ["Id","DocumentId","ProductId","Quantity","ExpectedQuantity","PriceBeforeTax","Price","Discount","DiscountType","ProductCost","PriceBeforeTaxAfterDiscount","PriceAfterDiscount","Total","TotalAfterDocumentDiscount","DiscountApplyRule"]},
    {"name": "DocumentItemTax", "strategy": "child_of", "pk_composite": ["DocumentItemId","TaxId"], "parent_table": "DocumentItem", "parent_fk": "DocumentItemId", "cols": ["DocumentItemId","TaxId","Amount"]},
    {"name": "Payment", "strategy": "child_of", "pk": "Id", "parent_table": "Document", "parent_fk": "DocumentId",
     "cols": ["Id","DocumentId","PaymentTypeId","Amount","Date","UserId","ZReportId","DateCreated"]},
    {"name": "ZReport", "strategy": "z_report_with_summary", "pk": "Id", "updated_col": "DateCreated",
     "cols": ["Id","Number","FromDocumentId","ToDocumentId","DateCreated","TotalSales","TotalTax","TotalDiscount","CashAmount","CardAmount","TransferAmount","RefundAmount","DocumentCount"]},
    {"name": "PosOrder", "strategy": "incremental_updated", "pk": "Id", "updated_col": "DateCreated",
     "cols": ["Id","UserId","Number","Discount","DiscountType","Total","CustomerId","ServiceType","DateCreated"]},
    {"name": "PosOrderItem", "strategy": "child_of", "pk": "Id", "parent_table": "PosOrder", "parent_fk": "PosOrderId",
     "cols": ["Id","PosOrderId","ProductId","RoundNumber","Quantity","Price","IsLocked","Discount","DiscountType","IsFeatured","VoidedBy","Comment","DateCreated","Bundle","DiscountAppliedType"]},
    {"name": "LoyaltyCard", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","CustomerId","CardNumber"]},
    {"name": "CustomerDiscount", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","CustomerId","Type","Uid","Value"]},

    # ─── Reference/Transaction Data (added: tax rates, product-tax link,
    #     document categories, cash drawer starting/withdrawal amounts) ────
    {"name": "Tax", "strategy": "hash_diff", "pk": "Id",
     "cols": ["Id","Name","Rate","Code","IsFixed","IsTaxOnTotal","IsEnabled"]},
    {"name": "ProductTax", "strategy": "hash_diff", "pk_composite": ["ProductId","TaxId"],
     "cols": ["ProductId","TaxId"]},
    {"name": "DocumentCategory", "strategy": "hash_diff", "pk": "Id", "cols": ["Id","Name","LanguageKey"]},
    {"name": "StartingCash", "strategy": "incremental_updated", "pk": "Id", "updated_col": "DateCreated",
     "cols": ["Id","UserId","Amount","Description","StartingCashType","ZReportNumber","DateCreated"]},
]


# ─── Row Helpers ─────────────────────────────────────────────────────────────
def _row_to_dict(row: sqlite3.Row, cols: Sequence[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for c in cols:
        v = row[c]
        if isinstance(v, bytes):
            continue
        # Keep booleans as booleans, convert everything else to string
        if isinstance(v, bool):
            out[c] = v
        elif v is not None:
            out[c] = str(v)
        else:
            out[c] = None
    return out


def _row_hash(d: Dict[str, Any]) -> str:
    s = json.dumps(d, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _pk_value(d: Dict[str, Any], table: Dict[str, Any]) -> str:
    composite_key = table.get("pk_composite")
    if composite_key:
        parts = [str(d.get(c, d.get(c.lower(), ""))) for c in composite_key]
        return "|".join(parts)
    pk = table.get("pk", "Id")
    return str(d.get(pk, d.get(pk.lower(), "")))


# ─── API Client ──────────────────────────────────────────────────────────────
class ApiClient:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.token = _load_token()

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "User-Agent": f"aronium-agent/{VERSION}"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        app_id = _kv_get("application_id")
        if app_id:
            h["X-Application-Id"] = app_id
        return h

    def activate(self, application_id: str, tax_number: str, hostname: str) -> Dict[str, Any]:
        """Activate using Application ID + Tax Number (no activation code)."""
        url = f"{self.cfg.api_base_url}/api/v1/agents/activate"
        payload = {
            "application_id": application_id,
            "tax_number": tax_number,
            "hostname": hostname,
            "agent_version": VERSION,
        }
        r = self.session.post(
            url, json=payload, headers=self._headers(),
            timeout=30, verify=self.cfg.verify_tls,
        )
        r.raise_for_status()
        data = r.json()
        self.token = data["token"]
        _save_token(self.token)
        return data

    def heartbeat(self, payload: Dict[str, Any]) -> None:
        url = f"{self.cfg.api_base_url}/api/v1/agents/heartbeat"
        r = self.session.post(
            url, json=payload, headers=self._headers(),
            timeout=15, verify=self.cfg.verify_tls,
        )
        r.raise_for_status()

    def upsert(self, table: str, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        url = f"{self.cfg.api_base_url}/api/v1/sync/upsert"
        r = self.session.post(
            url, json={"table": table, "rows": rows},
            headers=self._headers(), timeout=60, verify=self.cfg.verify_tls,
        )
        r.raise_for_status()

    def reconcile(self, table: str, pks: List[str]) -> List[str]:
        url = f"{self.cfg.api_base_url}/api/v1/sync/reconcile"
        r = self.session.post(
            url, json={"table": table, "local_pks": pks},
            headers=self._headers(), timeout=60, verify=self.cfg.verify_tls,
        )
        r.raise_for_status()
        return r.json().get("deleted", [])

    def send_notification(self, notification_type: str, message: str) -> None:
        """Send notification to dashboard."""
        try:
            url = f"{self.cfg.api_base_url}/api/v1/agents/notifications"
            payload = {
                "type": notification_type,
                "message": message,
            }
            r = self.session.post(
                url, json=payload, headers=self._headers(),
                timeout=15, verify=self.cfg.verify_tls,
            )
            r.raise_for_status()
            logger.debug(f"Notification sent: {notification_type}")
        except Exception as e:
            logger.warning(f"Failed to send notification: {e}")

    def report_day_status(self, closed_today: bool, current_hour: int) -> Dict[str, Any]:
        """Report day status to server for auto-close logic."""
        try:
            url = f"{self.cfg.api_base_url}/api/v1/agents/day-status"
            payload = {
                "closed_today": closed_today,
                "current_hour": current_hour,
            }
            r = self.session.post(
                url, json=payload, headers=self._headers(),
                timeout=15, verify=self.cfg.verify_tls,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"Failed to report day status: {e}")
            return {"auto_close": False}


# ─── Subscription Error ──────────────────────────────────────────────────────
class SubscriptionError(Exception):
    pass


def _friendly_http_error(e: requests.HTTPError) -> str:
    code = e.response.status_code if e.response is not None else None
    detail = None
    if e.response is not None:
        try:
            detail = e.response.json().get("detail")
        except Exception:
            detail = None
    if detail:
        return f"{detail} ({code})"
    if code in HTTP_ERROR_MAP:
        return HTTP_ERROR_MAP[code]
    return LOG["err_server"].format(code=code)


# ─── Sync Strategies ────────────────────────────────────────────────────────
def _sync_incremental_updated(snap, api, table, batch_size):
    name = table["name"]
    cols = table["cols"]
    updated_col = table["updated_col"]
    cursor = _cursor_get(name) or "1970-01-01 00:00:00"
    col_list = ", ".join(f'"{c}"' for c in cols)
    rows = snap.execute(
        f'SELECT {col_list} FROM "{name}" WHERE "{updated_col}" > ? ORDER BY "{updated_col}" ASC LIMIT ?',
        (cursor, batch_size),
    ).fetchall()
    if not rows:
        return 0
    payload = [_row_to_dict(r, cols) for r in rows]
    api.upsert(name, payload)
    new_cursor = max(str(r[updated_col]) for r in rows if r[updated_col] is not None)
    if new_cursor:
        _cursor_set(name, new_cursor)
    logger.info(LOG["table_inc"].format(count=len(payload), table=name))
    return len(payload)


def _sync_z_report_with_summary(snap, api, table, batch_size):
    """Sync ZReport with calculated summaries from Document/Payment tables."""
    name = table["name"]
    updated_col = table["updated_col"]
    cursor = _cursor_get(name) or "1970-01-01 00:00:00"
    
    # Get new ZReports
    z_reports = snap.execute(
        f'SELECT Id, Number, FromDocumentId, ToDocumentId, DateCreated FROM "{name}" WHERE "{updated_col}" > ? ORDER BY "{updated_col}" ASC LIMIT ?',
        (cursor, batch_size),
    ).fetchall()
    
    if not z_reports:
        return 0
    
    payload = []
    for z in z_reports:
        z_id, z_number, from_doc, to_doc, date_created = z
        
        # Calculate summaries for this ZReport range
        if from_doc and to_doc and from_doc > 0:
            # Total sales (ONLY Sales - DocumentTypeId=2)
            total_sales = snap.execute(
                'SELECT COALESCE(SUM(Total), 0) FROM Document WHERE Id >= ? AND Id <= ? AND DocumentTypeId = 2',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            # Total tax (ONLY from Sales documents)
            total_tax = snap.execute(
                'SELECT COALESCE(SUM(Amount), 0) FROM DocumentItemTax WHERE DocumentItemId IN (SELECT Id FROM DocumentItem WHERE DocumentId >= ? AND DocumentId <= ? AND DocumentId IN (SELECT Id FROM Document WHERE DocumentTypeId = 2))',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            # Total discount (ONLY from Sales documents)
            total_discount = snap.execute(
                'SELECT COALESCE(SUM(Discount), 0) FROM Document WHERE Id >= ? AND Id <= ? AND DocumentTypeId = 2',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            # Payment amounts by type (ONLY from Sales documents)
            cash_amount = snap.execute(
                'SELECT COALESCE(SUM(Amount), 0) FROM Payment WHERE DocumentId >= ? AND DocumentId <= ? AND PaymentTypeId = 1 AND DocumentId IN (SELECT Id FROM Document WHERE DocumentTypeId = 2)',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            card_amount = snap.execute(
                'SELECT COALESCE(SUM(Amount), 0) FROM Payment WHERE DocumentId >= ? AND DocumentId <= ? AND PaymentTypeId = 2 AND DocumentId IN (SELECT Id FROM Document WHERE DocumentTypeId = 2)',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            transfer_amount = snap.execute(
                'SELECT COALESCE(SUM(Amount), 0) FROM Payment WHERE DocumentId >= ? AND DocumentId <= ? AND PaymentTypeId = 3 AND DocumentId IN (SELECT Id FROM Document WHERE DocumentTypeId = 2)',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            # Refund amount (payments for refund documents - DocumentTypeId=4)
            refund_amount = snap.execute(
                'SELECT COALESCE(SUM(Amount), 0) FROM Payment WHERE DocumentId >= ? AND DocumentId <= ? AND DocumentId IN (SELECT Id FROM Document WHERE DocumentTypeId = 4)',
                (from_doc, to_doc)
            ).fetchone()[0]
            
            # Document count (ONLY Sales documents)
            document_count = snap.execute(
                'SELECT COUNT(*) FROM Document WHERE Id >= ? AND Id <= ? AND DocumentTypeId = 2',
                (from_doc, to_doc)
            ).fetchone()[0]
        else:
            total_sales = total_tax = total_discount = 0
            cash_amount = card_amount = transfer_amount = refund_amount = 0
            document_count = 0
        
        payload.append({
            "Id": str(z_id),
            "Number": z_number,
            "FromDocumentId": str(from_doc) if from_doc else "0",
            "ToDocumentId": str(to_doc) if to_doc else "0",
            "DateCreated": date_created,
            "TotalSales": float(total_sales),
            "TotalTax": float(total_tax),
            "TotalDiscount": float(total_discount),
            "CashAmount": float(cash_amount),
            "CardAmount": float(card_amount),
            "TransferAmount": float(transfer_amount),
            "RefundAmount": float(refund_amount),
            "DocumentCount": document_count
        })
    
    api.upsert(name, payload)
    new_cursor = max(str(z[4]) for z in z_reports if z[4] is not None)
    if new_cursor:
        _cursor_set(name, new_cursor)
    logger.info(LOG["table_inc"].format(count=len(payload), table=name))
    return len(payload)


def _sync_hash_diff(snap, api, table):
    name = table["name"]
    cols = table["cols"]
    col_list = ", ".join(f'"{c}"' for c in cols)
    rows = snap.execute(f'SELECT {col_list} FROM "{name}"').fetchall()
    known = _hash_lookup(name)
    changed = []
    new_hashes = []
    for r in rows:
        d = _row_to_dict(r, cols)
        pk = _pk_value(d, table)
        h = _row_hash(d)
        if known.get(pk) != h:
            changed.append(d)
            new_hashes.append((pk, h))
    if changed:
        for i in range(0, len(changed), 500):
            api.upsert(name, changed[i : i + 500])
        _hash_upsert_many(name, new_hashes)
        logger.info(LOG["table_hash"].format(changed=len(changed), total=len(rows), table=name))
    else:
        logger.info(LOG["table_empty"].format(table=name))
    return len(changed), len(rows)


def _sync_child_of(snap, api, table, parent_changed_ids):
    if not parent_changed_ids:
        logger.info(LOG["table_empty"].format(table=table["name"]))
        return 0
    name = table["name"]
    cols = table["cols"]
    fk = table["parent_fk"]
    col_list = ", ".join(f'"{c}"' for c in cols)
    total = 0
    for i in range(0, len(parent_changed_ids), 800):
        chunk = parent_changed_ids[i : i + 800]
        placeholders = ",".join("?" for _ in chunk)
        rows = snap.execute(
            f'SELECT {col_list} FROM "{name}" WHERE "{fk}" IN ({placeholders})', tuple(chunk)
        ).fetchall()
        if rows:
            payload = [_row_to_dict(r, cols) for r in rows]
            api.upsert(name, payload)
            total += len(payload)
    logger.info(LOG["table_child"].format(count=total, table=name))
    return total


def _collect_parent_ids_since(snap, parent_table, cursor_value):
    rows = snap.execute(
        f'SELECT "Id" FROM "{parent_table}" WHERE "DateUpdated" > ?', (cursor_value,)
    ).fetchall()
    return [r[0] for r in rows]


def _reconcile_table(snap, api, table):
    name = table["name"]
    if "pk_composite" in table:
        col_list = ",".join(f'"{c}"' for c in table["pk_composite"])
        pks = [
            "|".join(str(v) for v in r)
            for r in snap.execute(f'SELECT {col_list} FROM "{name}"').fetchall()
        ]
    else:
        pks = [str(r[0]) for r in snap.execute(f'SELECT "{table["pk"]}" FROM "{name}"').fetchall()]
    deleted = api.reconcile(name, pks)
    if deleted:
        _hash_delete_many(name, deleted)
        logger.info(LOG["table_reconcile"].format(count=len(deleted), table=name))
    return len(deleted)


# ─── Company Change Detection ────────────────────────────────────────────────
def check_company_changes(snap_path: str) -> bool:
    """Check if tax number or store name changed in local Aronium DB.
    Returns True if changes detected (sync should be blocked).
    """
    saved_tax = _kv_get("tax_number")
    saved_store = _kv_get("store_name")
    
    if not saved_tax:
        return False  # First activation, no comparison possible
    
    info = read_device_info(snap_path)
    current_tax = info.get("tax_number", "")
    current_store = info.get("store_name", "")
    
    changed = False
    
    if current_tax and current_tax != saved_tax:
        logger.error(f"CRITICAL: Tax number changed! Saved={saved_tax}, Current={current_tax}")
        logger.error("This may indicate data tampering. Contact support.")
        changed = True
    
    if current_store and current_store != saved_store:
        logger.warning(f"Store name changed: '{saved_store}' → '{current_store}'")
        # Update saved store name (this is allowed)
        _kv_set("store_name", current_store)
    
    return changed


# ─── Activation (v12: no activation code) ────────────────────────────────────
def ensure_activated(cfg: AgentConfig, api: ApiClient, snap_path: str) -> None:
    """Activate using Application ID + Tax Number from Aronium DB."""
    if api.token:
        # Verify token is still valid via heartbeat
        try:
            api.heartbeat({
                "agent_version": VERSION,
                "ts": int(time.time()),
                "application_id": _kv_get("application_id"),
            })
            logger.info(LOG["token_valid"])
            return
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else None
            if code == 401:
                logger.info(LOG["token_expired"])
                _clear_token()
                api.token = None
            elif code in (403, 410):
                # Subscription/device issue - keep the token (it will start
                # working again automatically once resolved) and stop this
                # cycle before any sync call is made. Logged once by the
                # outer SubscriptionError handler with the real reason.
                raise SubscriptionError(_friendly_http_error(e)) from e
            else:
                raise

    # No token - activate
    logger.info(LOG["activating"])

    device_info = read_device_info(snap_path)
    app_id = device_info.get("application_id")
    tax_number = device_info.get("tax_number")
    hostname = socket.gethostname()

    if not app_id:
        raise RuntimeError("Could not read Application ID from Aronium DB")
    if not tax_number:
        raise RuntimeError("Could not read Tax Number from Aronium DB")

    logger.info(f"App ID: {app_id}")
    logger.info(f"Tax Number: {tax_number}")
    logger.info(f"Hostname: {hostname}")

    try:
        resp = api.activate(app_id, tax_number, hostname)
    except requests.HTTPError as e:
        msg = _friendly_http_error(e)
        logger.error(LOG["activate_fail"].format(reason=msg))
        raise

    # Post-activation verification
    local_tax = tax_number
    server_tax = resp.get("tax_number", "")

    if local_tax and server_tax and local_tax != server_tax:
        _clear_token()
        logger.error(LOG["tax_mismatch"].format(local=local_tax, server=server_tax))
        raise RuntimeError("Tax number mismatch - activation blocked")

    logger.info(LOG["tax_ok"].format(tax=server_tax or local_tax))
    logger.info(LOG["activated"].format(
        store=resp.get("store_name", ""),
        tax=resp.get("tax_number", ""),
    ))

    # Save device info
    _kv_set("application_id", app_id)
    _kv_set("store_name", resp.get("store_name", ""))
    _kv_set("tax_number", resp.get("tax_number", ""))
    _kv_set("hostname", hostname)
    
    # Save registered_at as initial cursor for incremental sync
    registered_at = resp.get("registered_at", "")
    if registered_at:
        _kv_set("registered_at", registered_at)
        # Set initial cursors for incremental tables
        for table in SYNC_MAP:
            if table["strategy"] == "incremental_updated":
                if not _cursor_get(table["name"]):
                    _cursor_set(table["name"], registered_at)


# ─── Sync Cycle ──────────────────────────────────────────────────────────────
def run_sync_cycle(cfg: AgentConfig, api: ApiClient, snap_path: str) -> None:
    logger.info(LOG["sync_start"])
    conn = sqlite3.connect(snap_path)
    conn.row_factory = sqlite3.Row
    all_synced = 0
    
    # Track if ZReport was synced this cycle (for day status)
    z_report_synced = False
    
    try:
        parent_cursor_before_doc = _cursor_get("Document") or "1970-01-01 00:00:00"

        for table in SYNC_MAP:
            strategy = table["strategy"]
            try:
                if strategy == "incremental_updated":
                    n = _sync_incremental_updated(conn, api, table, cfg.batch_size)
                    all_synced += n
                elif strategy == "z_report_with_summary":
                    n = _sync_z_report_with_summary(conn, api, table, cfg.batch_size)
                    all_synced += n
                    if n > 0:
                        z_report_synced = True
                elif strategy == "hash_diff":
                    changed, total = _sync_hash_diff(conn, api, table)
                    all_synced += changed
                elif strategy == "child_of":
                    parent_table = table["parent_table"]
                    parent_fk = table.get("parent_fk", f"{parent_table}Id")
                    if parent_table == "Document":
                        parent_ids = _collect_parent_ids_since(conn, "Document", parent_cursor_before_doc)
                    elif parent_table == "DocumentItem":
                        doc_ids = _collect_parent_ids_since(conn, "Document", parent_cursor_before_doc)
                        if not doc_ids:
                            parent_ids = []
                        else:
                            ch = doc_ids[:800]
                            placeholders = ",".join("?" for _ in ch)
                            parent_ids = [
                                r[0]
                                for r in conn.execute(
                                    f'SELECT Id FROM DocumentItem WHERE DocumentId IN ({placeholders})', tuple(ch)
                                ).fetchall()
                            ]
                    elif parent_table == "PosOrder":
                        pos_cursor = _cursor_get("PosOrder") or "1970-01-01 00:00:00"
                        parent_ids = _collect_parent_ids_since(conn, "PosOrder", pos_cursor)
                    else:
                        parent_ids = []
                    n = _sync_child_of(conn, api, table, parent_ids)
                    all_synced += n
            except requests.HTTPError as he:
                if he.response is not None and he.response.status_code == 401:
                    raise SubscriptionError(_friendly_http_error(he)) from he
                logger.error(_friendly_http_error(he))
            except SubscriptionError:
                raise
            except Exception as e:
                logger.error(LOG["err_cycle"].format(reason=str(e)))
    finally:
        conn.close()
    
    # Reconcile: detect local deletions and sync them to server
    # IMPORTANT: Reconcile child tables FIRST (DocumentItem, Payment) before parents (Document)
    # to avoid foreign key constraint violations
    try:
        snap = sqlite3.connect(snap_path)
        snap.row_factory = sqlite3.Row
        
        # Reverse order for reconcile: children before parents
        reconcile_order = list(reversed(SYNC_MAP))
        
        for table in reconcile_order:
            strategy = table["strategy"]
            if strategy in ("incremental_updated", "hash_diff", "z_report_with_summary", "child_of"):
                name = table["name"]
                logger.info(f"Reconciling {name}...")
                try:
                    deleted_count = _reconcile_table(snap, api, table)
                    if deleted_count > 0:
                        logger.info(LOG["table_reconcile"].format(count=deleted_count, table=name))
                except Exception as e:
                    logger.error(f"Reconcile {name} failed: {e}")
        
        snap.close()
    except Exception as e:
        logger.error(f"Reconcile cycle failed: {e}")
    
    # Check day status for auto-close logic
    # Check Aronium DB directly: was a ZReport created today?
    try:
        today_str = datetime.now().strftime("%Y-%m-%d")
        db_conn = sqlite3.connect(db_path)
        last_z = db_conn.execute(
            '''SELECT DateCreated FROM ZReport 
               WHERE DateCreated >= ? 
               ORDER BY DateCreated DESC LIMIT 1''',
            (today_str,)
        ).fetchone()
        db_conn.close()
        closed_today = last_z is not None
        current_hour = datetime.now().hour
        result = api.report_day_status(closed_today, current_hour)
        if result.get("auto_close"):
            logger.info("Day auto-closed by server (no ZReport synced)")
    except Exception as e:
        logger.warning(f"Day status check failed: {e}")
    
    logger.info(LOG["sync_done"].format(total=all_synced))


def run_reconcile_cycle(cfg: AgentConfig, api: ApiClient, snap_path: str) -> None:
    conn = sqlite3.connect(snap_path)
    conn.row_factory = sqlite3.Row
    try:
        for table in SYNC_MAP:
            try:
                _reconcile_table(conn, api, table)
            except requests.HTTPError as he:
                if he.response is not None and he.response.status_code == 401:
                    raise SubscriptionError(_friendly_http_error(he)) from he
                logger.error(_friendly_http_error(he))
            except Exception as e:
                logger.error(LOG["err_cycle"].format(reason=str(e)))
    finally:
        conn.close()


# ─── Main ────────────────────────────────────────────────────────────────────
def main() -> None:
    cfg = AgentConfig.load()
    _init_state_db()
    api = ApiClient(cfg)
    logger.info(LOG["start"].format(url=cfg.api_base_url))

    last_reconcile = 0.0
    while True:
        db_path = find_aronium_db(cfg)
        if not db_path:
            logger.warning(LOG["db_missing"])
            time.sleep(cfg.sync_interval_sec)
            continue

        logger.info(LOG["db_found"].format(path=db_path))

        snap = snapshot_db(db_path)
        if not snap:
            time.sleep(cfg.sync_interval_sec)
            continue

        # Always refresh the cached application_id from the local Aronium DB
        # before any authenticated request. This prevents a false-positive
        # 403 "identity mismatch" if agent_state.db was ever recreated/lost
        # while agent.token (which skips re-activation) still exists.
        try:
            fresh_app_id = read_device_info(snap).get("application_id")
            if fresh_app_id:
                _kv_set("application_id", fresh_app_id)
        except Exception:
            pass

        try:
            ensure_activated(cfg, api, snap)
            
            # Check for company data changes (tax number, store name)
            if check_company_changes(snap):
                logger.error("Sync blocked due to company data changes")
                time.sleep(300)  # Wait 5 minutes before retrying
                continue
            
            run_sync_cycle(cfg, api, snap)

            now = time.time()
            if now - last_reconcile > cfg.reconcile_interval_sec:
                run_reconcile_cycle(cfg, api, snap)
                last_reconcile = now

            try:
                api.heartbeat({
                    "agent_version": VERSION,
                    "ts": int(time.time()),
                    "application_id": _kv_get("application_id"),
                })
            except Exception as e:
                logger.warning(LOG["heartbeat_fail"].format(reason=str(e)))

        except SubscriptionError as e:
            logger.error(str(e) or LOG["sub_expired"])
            time.sleep(300)
        except Exception as e:
            logger.error(LOG["err_cycle"].format(reason=str(e)))
            
            # Retry mechanism: 3 attempts with increasing delay
            retry_count = 0
            while retry_count < 3:
                retry_count += 1
                retry_delay = 5 * (2 ** (retry_count - 1))  # 5s, 10s, 20s
                logger.info(f"Retrying sync in {retry_delay}s (attempt {retry_count}/3)...")
                time.sleep(retry_delay)
                
                try:
                    snap = snapshot_db(db_path)
                    if snap:
                        ensure_activated(cfg, api, snap)
                        run_sync_cycle(cfg, api, snap)
                        logger.info("Retry successful")
                        break
                except Exception as retry_e:
                    logger.error(f"Retry {retry_count} failed: {retry_e}")
        finally:
            try:
                os.remove(snap)
            except Exception:
                pass

        time.sleep(cfg.sync_interval_sec)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info(LOG["shutdown"])
