from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

from ..config import settings

celery_app = Celery("secyourscan", broker=settings.RABBITMQ_URL or "memory://", include=["app.worker.tasks"])

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_ignore_result=True,
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,  # one task at a time per process
    task_acks_late=True,  # ack after completion, so a crash re-delivers
    task_reject_on_worker_lost=True,
    task_time_limit=900,
    task_soft_time_limit=840,
    task_default_queue="default",
    task_queues=[
        Queue("default", Exchange("default", type="direct"), routing_key="default"),
        Queue("osint", Exchange("osint", type="direct"), routing_key="osint"),
        Queue("massive", Exchange("massive", type="direct"), routing_key="massive"),
    ],
    task_routes={
        "app.worker.tasks.massive_ingest_task": {"queue": "massive"},
        "app.worker.tasks.run_source_task": {"queue": "osint"},
        "app.worker.tasks.ahmia_probe_task": {"queue": "osint"},
        "app.worker.tasks.intel_scan_task": {"queue": "osint"},
        "app.worker.tasks.intel_sweep": {"queue": "osint"},
        "app.worker.tasks.ioc_refresh": {"queue": "osint"},
    },
    beat_schedule={
        "dispatch-due-sources": {"task": "app.worker.tasks.dispatch_due_sources", "schedule": crontab(minute="*/5")},
        "purge-revoked-tokens": {"task": "app.worker.tasks.purge_revoked_tokens", "schedule": crontab(minute=7)},
        "intel-sweep": {"task": "app.worker.tasks.intel_sweep",
                        "schedule": crontab(minute=17, hour=f"*/{max(1, min(settings.INTEL_SWEEP_HOURS, 24))}")},
        "ioc-refresh": {"task": "app.worker.tasks.ioc_refresh", "schedule": crontab(minute=43, hour=3)},
        "vuln-intel-refresh": {"task": "app.worker.tasks.vuln_intel_refresh", "schedule": crontab(minute=29, hour="*/6")},
    },
)
