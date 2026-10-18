"""Object storage (MinIO / any S3): raw evidence, crawled HTML, dossiers.

One bucket per tenant, so the tenant-deletion saga can drop a bucket instead
of filtering objects. The SDK is synchronous; calls run in a thread.
"""

import asyncio
import io
import logging

from ..config import settings
from .breaker import minio_breaker

logger = logging.getLogger("secyourscan.storage")

_client = None


def client():
    global _client
    if _client is None and settings.minio_enabled:
        from minio import Minio

        endpoint = settings.MINIO_ENDPOINT.replace("http://", "").replace("https://", "")
        _client = Minio(
            endpoint,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE,
        )
    return _client


def bucket_for(tenant_id: str) -> str:
    return f"tenant-{tenant_id}"


async def put_bytes(tenant_id: str, name: str, data: bytes, content_type: str) -> str | None:
    c = client()
    if c is None:
        return None
    bucket = bucket_for(tenant_id)

    def _put():
        if not c.bucket_exists(bucket):
            c.make_bucket(bucket)
        c.put_object(bucket, name, io.BytesIO(data), len(data), content_type=content_type)
        return f"s3://{bucket}/{name}"

    async def _run():
        return await asyncio.to_thread(_put)

    return await minio_breaker.call(_run)


async def put_stream(tenant_id: str, name: str, fileobj, content_type: str) -> str | None:
    """Upload a file object without reading it into memory (multipart)."""
    c = client()
    if c is None:
        return None
    bucket = bucket_for(tenant_id)

    def _put():
        if not c.bucket_exists(bucket):
            c.make_bucket(bucket)
        c.put_object(bucket, name, fileobj, length=-1, part_size=16 * 1024 * 1024, content_type=content_type)
        return f"s3://{bucket}/{name}"

    return await asyncio.to_thread(_put)


async def get_bytes(path: str) -> bytes | None:
    c = client()
    if c is None or not path or not path.startswith("s3://"):
        return None
    bucket, _, name = path[5:].partition("/")

    def _get():
        resp = c.get_object(bucket, name)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()

    return await asyncio.to_thread(_get)


def stream_lines(path: str):
    """Yield decoded lines from an object without loading it whole."""
    c = client()
    bucket, _, name = path[5:].partition("/")
    resp = c.get_object(bucket, name)
    try:
        buf = b""
        for chunk in resp.stream(1024 * 1024):
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for line in lines:
                yield line.decode("utf-8", "replace")
        if buf:
            yield buf.decode("utf-8", "replace")
    finally:
        resp.close()
        resp.release_conn()


async def delete_bucket(tenant_id: str) -> int:
    c = client()
    if c is None:
        return 0
    bucket = bucket_for(tenant_id)

    def _delete():
        if not c.bucket_exists(bucket):
            return 0
        from minio.deleteobjects import DeleteObject

        objects = [DeleteObject(o.object_name) for o in c.list_objects(bucket, recursive=True)]
        errors = list(c.remove_objects(bucket, objects))
        if errors:
            raise RuntimeError(f"{len(errors)} objects could not be deleted")
        c.remove_bucket(bucket)
        return len(objects)

    return await asyncio.to_thread(_delete)


async def ping() -> bool:
    c = client()
    if c is None:
        return False
    await asyncio.to_thread(c.list_buckets)
    return True
