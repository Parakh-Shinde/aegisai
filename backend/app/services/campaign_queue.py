from dataclasses import dataclass

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue
from rq.exceptions import NoSuchJobError
from rq.job import Job

from app.core.config import get_settings

QUEUE_NAME = "aegisai-campaigns"


class CampaignQueueUnavailableError(RuntimeError):
    pass


class CampaignJobNotFoundError(RuntimeError):
    pass


@dataclass(frozen=True)
class CampaignJobStatus:
    job_id: str
    campaign_id: str
    model: str
    status: str


def enqueue_basic_suite(payload: dict) -> CampaignJobStatus:
    queue = _queue()
    settings = get_settings()
    try:
        job = queue.enqueue(
            "app.services.campaign_worker.run_basic_suite_job",
            payload,
            job_timeout=settings.model_timeout_seconds * 20,
            result_ttl=3600,
            failure_ttl=86400,
            meta={
                "organization_id": payload["actor"]["organization_id"],
                "campaign_id": payload["campaign_id"],
                "model": payload["model"],
            },
        )
    except RedisError as exc:
        raise CampaignQueueUnavailableError("Campaign queue is unavailable.") from exc
    return CampaignJobStatus(
        job_id=job.id,
        campaign_id=payload["campaign_id"],
        model=payload["model"],
        status=job.get_status(),
    )


def get_campaign_job(job_id: str, organization_id: str) -> CampaignJobStatus:
    connection = _connection()
    try:
        job = Job.fetch(job_id, connection=connection)
    except NoSuchJobError as exc:
        raise CampaignJobNotFoundError("Campaign job was not found.") from exc
    except RedisError as exc:
        raise CampaignQueueUnavailableError("Campaign job is unavailable.") from exc

    if job.meta.get("organization_id") != organization_id:
        raise PermissionError("Campaign job does not belong to this organization.")

    return CampaignJobStatus(
        job_id=job.id,
        campaign_id=job.meta["campaign_id"],
        model=job.meta["model"],
        status=job.get_status(),
    )


def _connection() -> Redis:
    redis_url = get_settings().redis_url
    if not redis_url:
        raise CampaignQueueUnavailableError("Campaign queue is not configured.")
    return Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)


def _queue() -> Queue:
    connection = _connection()
    try:
        connection.ping()
    except RedisError as exc:
        raise CampaignQueueUnavailableError("Campaign queue is unavailable.") from exc
    return Queue(QUEUE_NAME, connection=connection)
