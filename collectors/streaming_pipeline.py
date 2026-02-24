"""Streaming ingestion pipeline utilities for real-time traffic processing."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BufferedFlow:
    """Flow wrapper used inside rate-limited buffers."""

    flow: Dict[str, Any]
    received_at: datetime = field(default_factory=datetime.utcnow)


class FlowBufferRateLimiter:
    """Bounded queue + token bucket limiter for bursty traffic spikes."""

    def __init__(self, max_queue_size: int = 10000, max_flows_per_second: int = 2000):
        self.max_flows_per_second = max(1, max_flows_per_second)
        self._tokens = float(self.max_flows_per_second)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._queue: "queue.Queue[BufferedFlow]" = queue.Queue(maxsize=max_queue_size)
        self.dropped_flows = 0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now
        self._tokens = min(
            float(self.max_flows_per_second),
            self._tokens + (elapsed * self.max_flows_per_second),
        )

    def enqueue(self, flow: Dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(BufferedFlow(flow=flow))
            return True
        except queue.Full:
            self.dropped_flows += 1
            logger.warning("Flow buffer full; dropping flow")
            return False

    def dequeue(self, timeout: float = 0.1) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._refill()
            if self._tokens < 1:
                return None
            self._tokens -= 1

        try:
            buffered = self._queue.get(timeout=timeout)
            return buffered.flow
        except queue.Empty:
            return None

    @property
    def size(self) -> int:
        return self._queue.qsize()


class KafkaFlowPublisher:
    """Publishes normalized flow dictionaries to Kafka."""

    def __init__(self, brokers: str, topic: str):
        self.brokers = brokers
        self.topic = topic
        self._client = None
        self._producer = None

    def _connect(self) -> None:
        if self._producer is not None:
            return

        try:
            from pykafka import KafkaClient
        except ImportError as exc:
            raise ImportError("PyKafka is required for Kafka streaming support") from exc

        self._client = KafkaClient(hosts=self.brokers)
        kafka_topic = self._client.topics[self.topic.encode("utf-8")]
        self._producer = kafka_topic.get_producer(sync=False)

    def publish(self, flow: Dict[str, Any]) -> None:
        self._connect()
        payload = json.dumps(flow, default=str).encode("utf-8")
        self._producer.produce(payload)


class KafkaFlowConsumer:
    """Consumes flows from Kafka and forwards to a callback."""

    def __init__(self, brokers: str, topic: str, group_id: str = "ai-nids-stream"):
        self.brokers = brokers
        self.topic = topic
        self.group_id = group_id
        self._client = None
        self._consumer = None

    def _connect(self) -> None:
        if self._consumer is not None:
            return

        try:
            from pykafka import KafkaClient
        except ImportError as exc:
            raise ImportError("PyKafka is required for Kafka streaming support") from exc

        self._client = KafkaClient(hosts=self.brokers)
        kafka_topic = self._client.topics[self.topic.encode("utf-8")]
        self._consumer = kafka_topic.get_simple_consumer(
            consumer_group=self.group_id.encode("utf-8"),
            auto_offset_reset="latest",
            reset_offset_on_start=False,
        )

    def consume_forever(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self._connect()
        for message in self._consumer:
            if message is None:
                continue
            try:
                callback(json.loads(message.value.decode("utf-8")))
            except Exception as exc:
                logger.error("Failed to process consumed flow: %s", exc)


class LiveCaptureKafkaBridge:
    """Callback adapter for collectors.live_capture.PacketCallback."""

    def __init__(
        self,
        publisher: KafkaFlowPublisher,
        buffer: Optional[FlowBufferRateLimiter] = None,
    ):
        self.publisher = publisher
        self.buffer = buffer or FlowBufferRateLimiter()
        self._running = False
        self._worker: Optional[threading.Thread] = None

    def on_start(self) -> None:
        self._running = True
        self._worker = threading.Thread(target=self._flush_loop, daemon=True)
        self._worker.start()

    def on_packet(self, packet: Any) -> None:
        # Packet is intentionally typed as Any to avoid hard coupling to live_capture module.
        flow = {
            "timestamp": packet.timestamp.isoformat(),
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "protocol": packet.protocol,
            "length": packet.length,
            "flags": packet.flags,
            "interface": packet.interface,
        }
        self.buffer.enqueue(flow)

    def on_stop(self) -> None:
        self._running = False
        if self._worker is not None:
            self._worker.join(timeout=2)

    def _flush_loop(self) -> None:
        while self._running:
            flow = self.buffer.dequeue(timeout=0.2)
            if flow is None:
                continue
            try:
                self.publisher.publish(flow)
            except Exception as exc:
                logger.error("Failed to publish flow to Kafka: %s", exc)
