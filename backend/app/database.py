from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from .config import settings


def make_engine(*, worker: bool = False):
    """The API keeps a pool; workers use NullPool.

    A Celery task runs on a fresh event loop each time, and a pooled asyncpg
    connection is bound to the loop that opened it — reusing one from a dead
    loop deadlocks. NullPool opens and closes per session instead.
    """
    url = settings.DATABASE_URL
    if url.startswith("sqlite"):
        return create_async_engine(url, poolclass=NullPool if worker else None)
    if worker:
        return create_async_engine(url, poolclass=NullPool, pool_pre_ping=True)
    return create_async_engine(
        url,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
    )


engine = make_engine()
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db():
    async with SessionLocal() as session:
        yield session
