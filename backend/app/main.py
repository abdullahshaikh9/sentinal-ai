import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.api.routes import router
from app.config import get_settings
from app.db import database_error_category

settings = get_settings()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
app = FastAPI(title=settings.app_name, version="0.1.0", description="Evidence-based website security assessment platform")


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    original = getattr(exc, "orig", None)
    original_code = None
    if original is not None and getattr(original, "args", None) and isinstance(original.args[0], int):
        original_code = original.args[0]
    logging.getLogger("sentinel.database").error(
        "Database operation failed method=%s path=%s error_class=%s driver_class=%s category=%s driver_code=%s",
        request.method,
        request.url.path,
        type(exc).__name__,
        type(original).__name__ if original is not None else "none",
        database_error_category(exc),
        original_code if original_code is not None else "none",
    )
    return JSONResponse(
        status_code=503,
        content={"detail": "The configured database is unavailable. Check DATABASE_URL and ensure the database server is running."},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)
app.include_router(router, prefix=settings.api_v1_prefix)


class _HSTSMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("scheme") != "https":
            await self.app(scope, receive, send)
            return

        async def add_hsts(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, add_hsts)


if settings.app_env.lower() == "production":
    # ProxyHeaders must be outermost so the redirect and HSTS policy see the
    # original scheme only when the connection came from a trusted proxy.
    app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(_HSTSMiddleware)
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=settings.proxy_hosts)

