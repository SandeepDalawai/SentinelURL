import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinelurl.db'}")
CORS_ORIGINS = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if item.strip()]
MAX_REQUESTS_PER_MINUTE = max(10, int(os.getenv("MAX_REQUESTS_PER_MINUTE", "60")))
MAX_URL_LENGTH = 2048
MAX_BULK_BYTES = 1_000_000
MAX_BULK_ROWS = 500
BRANDS = {item.strip().lower() for item in os.getenv("SENTINELURL_BRANDS", "paypal,microsoft,google,apple,amazon,netflix,facebook,instagram,adobe,dropbox").split(",") if item.strip()}
