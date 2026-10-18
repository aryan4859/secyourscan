"""Hand work from the API to the workers.

The API publishes a Celery protocol-2 message straight onto RabbitMQ with
aio_pika (body serialised by orjson) and returns 202 — it never waits for
analysis. One robust connection is shared per API process; each publish uses
a short-lived channel.

With no broker configured the task runs in-process instead, so a laptop or
the test suite needs nothing but a database.
"""

import asyncio
import logging
import uuid

import orjson

from ..config import settings

logger = logging.getLogger("secyourscan.broker")

_connection = None
_lock = asyncio.Lock()

TASK_PROCESS = "app.worker.tasks.process_leak_task"
TASK_MASSIVE = "app.worker.tasks.massive_ingest_task"
TASK_RECON = "app.worker.tasks.run_source_task"
TASK_AHMIA = "app.worker.tasks.ahmia_probe_task"
TASK_DELETE_TENANT = "app.worker.tasks.delete_tenant_saga"
TASK_INTEL = "app.worker.tasks.intel_scan_task"

QUEUES = {TASK_MASSIVE: "massive", TASK_RECON: "osint", TASK_AHMIA: "osint", TASK_INTEL: "osint"}


async def _get_connection():
    global _connection
    async with _lock:
        if _connection is None or _connection.is_closed:
            import aio_pika

            _connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
    return _connection


async def publish(task: str, args: list, kwargs: dict | None = None) -> str:
    import aio_pika

    task_id = str(uuid.uuid4())
    queue = QUEUES.get(task, "default")
    body = orjson.dumps([args, kwargs or {}, {"callbacks": None, "errbacks": None, "chain": None, "chord": None}])
    message = aio_pika.Message(
        body=body,
        content_type="application/json",
        content_encoding="utf-8",
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        correlation_id=task_id,
        headers={
            "lang": "py",
            "task": task,
            "id": task_id,
            "root_id": task_id,
            "parent_id": None,
            "group": None,
            "retries": 0,
            "eta": None,
            "expires": None,
            "argsrepr": f"<{len(args)} args>",
            "kwargsrepr": "{}",
            "origin": "secyourscan-api",
        },
    )
    conn = await _get_connection()
    channel = await conn.channel()
    try:
        # Celery declares a direct exchange named after each queue.
        exchange = await channel.declare_exchange(queue, aio_pika.ExchangeType.DIRECT, durable=True)
        # Declare and bind the queue too (same arguments as the worker), so a
        # message published before any worker has started is kept, not dropped.
        q = await channel.declare_queue(queue, durable=True)
        await q.bind(exchange, routing_key=queue)
        await exchange.publish(message, routing_key=queue)
    finally:
        await channel.close()
    return task_id


async def close() -> None:
    global _connection
    if _connection is not None and not _connection.is_closed:
        await _connection.close()
    _connection = None


async def ping() -> bool:
    conn = await _get_connection()
    return not conn.is_closed
