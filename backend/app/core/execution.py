from threading import BoundedSemaphore

from app.core.config import get_settings


class ModelCapacityError(RuntimeError):
    pass


class ModelExecutionGate:
    def __init__(self, max_concurrency: int) -> None:
        self._semaphore = BoundedSemaphore(value=max_concurrency)

    def acquire(self) -> None:
        if not self._semaphore.acquire(blocking=False):
            raise ModelCapacityError("Model execution capacity is currently exhausted.")

    def release(self) -> None:
        self._semaphore.release()


model_execution_gate = ModelExecutionGate(get_settings().model_max_concurrency)
