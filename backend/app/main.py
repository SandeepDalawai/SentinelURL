import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import CORS_ORIGINS
from app.db.database import Base, engine
from app import models  # noqa: F401

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("sentinelurl")


@asynccontextmanager
async def lifespan(application: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="SentinelURL API", version="1.0.0", description="Offline, explainable suspicious URL analysis. Submitted URLs are not fetched.", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type"])
app.include_router(router)


@app.exception_handler(Exception)
async def generic_error_handler(request, exc):
    logger.exception("Unhandled server error on %s", request.url.path)
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": "An internal error occurred. No submitted URL was included in server logs."})
