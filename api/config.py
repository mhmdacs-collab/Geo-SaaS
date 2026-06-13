"""Shared config for Aronium SaaS"""
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET   = os.environ.get("JWT_SECRET", "")
JWT_ALG      = "HS256"
JWT_AUDIENCE = "aronium-agent"
JWT_TTL_DAYS = int(os.environ.get("JWT_TTL_DAYS", "365"))
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",")]
SUPPORT_WA   = os.environ.get("SUPPORT_WA", "966558110150")
