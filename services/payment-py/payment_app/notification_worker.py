"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Asynchronous Notification Worker & Dead-Letter Queue

Manages asynchronous delivery of merchant notifications, SMS alerts,
and email confirmations with exponential backoff and circuit isolation.
"""

import time
import math
from typing import Dict, Any, List, Optional
from collections import deque


class NotificationTask:
    """Represents a single queued notification job."""

    def __init__(
        self,
        task_id: str,
        recipient_url: str,
        payload: Dict[str, Any],
        max_attempts: int = 5,
    ):
        self.task_id = task_id
        self.recipient_url = recipient_url
        self.payload = payload
        self.max_attempts = max_attempts
        self.attempts_made = 0
        self.created_at = time.time()
        self.next_attempt_at = self.created_at
        self.status = "PENDING"
        self.last_error: Optional[str] = None


class NotificationWorker:
    """
    Background queue processor executing HTTP webhook delivery with exponential backoff.
    """

    def __init__(self, base_retry_delay_seconds: float = 2.0):
        self._base_delay = base_retry_delay_seconds
        self._pending_queue: deque = deque()
        self._dead_letter_queue: List[NotificationTask] = []
        self._delivered_tasks: List[NotificationTask] = []
        self._total_deliveries = 0
        self._total_failures = 0

    def enqueue_notification(
        self, task_id: str, recipient_url: str, payload: Dict[str, Any]
    ) -> NotificationTask:
        """
        Submits a new notification to the active queue.
        """
        task = NotificationTask(task_id, recipient_url, payload)
        self._pending_queue.append(task)
        return task

    def process_queue_batch(self, max_batch_size: int = 50) -> int:
        """
        Processes up to max_batch_size tasks currently ready for delivery.
        """
        now = time.time()
        processed = 0

        # Rotate tasks
        for _ in range(min(len(self._pending_queue), max_batch_size)):
            task = self._pending_queue.popleft()

            if task.next_attempt_at > now:
                # Not ready yet, re-enqueue
                self._pending_queue.append(task)
                continue

            task.attempts_made += 1
            success, err = self._simulate_delivery(task)

            if success:
                task.status = "DELIVERED"
                self._delivered_tasks.append(task)
                self._total_deliveries += 1
                processed += 1
            else:
                self._total_failures += 1
                task.last_error = err

                if task.attempts_made >= task.max_attempts:
                    task.status = "DEAD_LETTER"
                    self._dead_letter_queue.append(task)
                else:
                    # Exponential backoff calculation
                    delay = self._base_delay * math.pow(2, task.attempts_made - 1)
                    task.next_attempt_at = now + delay
                    self._pending_queue.append(task)

                processed += 1

        return processed

    def _simulate_delivery(self, task: NotificationTask) -> (bool, Optional[str]):
        """
        Simulates HTTP POST delivery to merchant webhook endpoint.
        """
        if "invalid" in task.recipient_url:
            return False, "Connection refused (simulated)"
        return True, None

    def replay_dead_letter(self, task_id: str) -> bool:
        """
        Resurrects a dead-lettered notification task back into the active queue.
        """
        for i, task in enumerate(self._dead_letter_queue):
            if task.task_id == task_id:
                task.attempts_made = 0
                task.status = "PENDING"
                task.next_attempt_at = time.time()
                self._pending_queue.append(task)
                self._dead_letter_queue.pop(i)
                return True
        return False

    def clear_delivered_history(self, keep_last: int = 1000) -> None:
        """
        Prunes completed task memory history.
        """
        if len(self._delivered_tasks) > keep_last:
            self._delivered_tasks = self._delivered_tasks[-keep_last:]

    def get_queue_statistics(self) -> Dict[str, Any]:
        """
        Returns telemetry metrics on queue depth and delivery rates.
        """
        return {
            "pending_count": len(self._pending_queue),
            "dead_letter_count": len(self._dead_letter_queue),
            "delivered_count": self._total_deliveries,
            "failed_attempts": self._total_failures,
        }
