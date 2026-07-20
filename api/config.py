"""Shared config for Aronium SaaS"""
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
# Support rotating JWT secrets via JWT_SECRETS env or fallback to JWT_SECRET
_jwt_secrets_env = os.environ.get("JWT_SECRETS", "").strip()
if _jwt_secrets_env:
    JWT_SECRETS = [s for s in (p.strip() for p in _jwt_secrets_env.split(",")) if s]
else:
    _single_jwt = os.environ.get("JWT_SECRET", "").strip()
    JWT_SECRETS = [_single_jwt] if _single_jwt else []
JWT_SECRET = JWT_SECRETS[0] if JWT_SECRETS else ""
JWT_ALG      = "HS256"
JWT_AUDIENCE = "aronium-agent"
JWT_TTL_DAYS = int(os.environ.get("JWT_TTL_DAYS", "365"))
# ADMIN_API_KEYS (comma-separated) fallback
_admin_keys_env = os.environ.get("ADMIN_API_KEYS", "").strip()
if _admin_keys_env:
    ADMIN_API_KEYS = [s for s in (p.strip() for p in _admin_keys_env.split(",")) if s]
else:
    _single_admin = os.environ.get("ADMIN_API_KEY", "").strip()
    ADMIN_API_KEYS = [_single_admin] if _single_admin else []
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",")]
SUPPORT_WA   = os.environ.get("SUPPORT_WA", "966558110150")
