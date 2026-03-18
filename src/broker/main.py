from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from broker.api import router
from broker.config import AppConfig, load_config
from broker.dao.sqlite import SqliteSessionDAO, SqliteTemplateDAO
from broker.templates import BUILTIN_TEMPLATES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("linkauth")

_cleanup_task: asyncio.Task | None = None


async def _cleanup_loop(dao: SqliteSessionDAO, interval: int) -> None:
    while True:
        try:
            deleted = await dao.cleanup_expired()
            if deleted:
                logger.info("Cleaned up %d expired sessions", deleted)
        except Exception:
            logger.exception("Error during session cleanup")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    config: AppConfig = app.state.config

    # Initialize DAOs
    session_dao = SqliteSessionDAO(config.storage.sqlite.path)
    template_dao = SqliteTemplateDAO(config.storage.sqlite.path)
    await session_dao.init()
    await template_dao.init()

    # Seed built-in templates
    for tpl in BUILTIN_TEMPLATES.values():
        await template_dao.register(tpl)

    app.state.session_dao = session_dao
    app.state.template_dao = template_dao

    # Start cleanup task
    global _cleanup_task
    _cleanup_task = asyncio.create_task(
        _cleanup_loop(session_dao, config.sessions.cleanup_interval)
    )

    logger.info("LinkAuth broker started on %s:%d", config.server.host, config.server.port)
    yield

    # Shutdown
    if _cleanup_task:
        _cleanup_task.cancel()
    await session_dao.close()
    await template_dao.close()
    logger.info("LinkAuth broker stopped")


def create_app(config: AppConfig | None = None) -> FastAPI:
    if config is None:
        config = load_config()

    app = FastAPI(
        title="LinkAuth",
        description="Zero-knowledge credential broker for AI agents",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.config = config

    # CORS — allow frontend on same origin
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routes
    app.include_router(router)

    # Serve frontend static files
    frontend_dir = Path(__file__).parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

        # Serve index.html for /connect/{code} — the frontend SPA handles routing
        @app.get("/connect/{code}")
        async def serve_connect_page(code: str):
            return FileResponse(str(frontend_dir / "index.html"))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    config = load_config()
    uvicorn.run(
        "broker.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=True,
    )
