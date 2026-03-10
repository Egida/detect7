"""Log Writer Worker -- consumes domain_logs from RabbitMQ and batch-inserts into TimescaleDB.

Run:
    python -m app.workers.log_writer
"""

import json
import logging
import os
import signal
import time
from datetime import datetime

import pika
from sqlalchemy import text

from ..database import engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("log_writer")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
EXCHANGE = os.getenv("RABBITMQ_DOMAIN_LOGS_EXCHANGE", "detect7.domain_logs")
QUEUE = os.getenv("RABBITMQ_DOMAIN_LOGS_QUEUE", "domain_logs")
ROUTING_KEY = os.getenv("RABBITMQ_DOMAIN_LOGS_ROUTING_KEY", "domain_logs")

BATCH_SIZE = int(os.getenv("LOG_WRITER_BATCH_SIZE", "500"))
FLUSH_INTERVAL_SEC = float(os.getenv("LOG_WRITER_FLUSH_INTERVAL", "2.0"))

INSERT_SQL = text("""
    INSERT INTO domain_logs
        (timestamp, domain_id, source_ip, method, path, status_code, bytes_sent, request_time, country, city)
    VALUES
        (:timestamp, :domain_id, :source_ip, :method, :path, :status_code, :bytes_sent, :request_time, :country, :city)
""")

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Shutdown signal received")
    _shutdown = True


def _flush(buffer: list[dict]) -> None:
    if not buffer:
        return
    try:
        with engine.begin() as conn:
            conn.execute(INSERT_SQL, buffer)
        logger.info("Flushed %d domain_log rows", len(buffer))
    except Exception:
        logger.exception("Failed to flush %d rows", len(buffer))


def main() -> None:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    params = pika.URLParameters(RABBITMQ_URL)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=QUEUE, routing_key=ROUTING_KEY)
    channel.basic_qos(prefetch_count=BATCH_SIZE * 2)

    buffer: list[dict] = []
    last_flush = time.monotonic()

    def on_message(ch, method, properties, body):
        nonlocal last_flush
        try:
            msg = json.loads(body)
            buffer.append({
                "timestamp": datetime.fromisoformat(msg["timestamp"]),
                "domain_id": msg["domain_id"],
                "source_ip": msg.get("source_ip", ""),
                "method": msg.get("method", "")[:10],
                "path": msg.get("path", "")[:2048],
                "status_code": int(msg.get("status_code", 0)),
                "bytes_sent": int(msg.get("bytes_sent", 0)),
                "request_time": float(msg.get("request_time", 0)),
                "country": (msg.get("country") or "")[:2] or None,
                "city": (msg.get("city") or "")[:100] or None,
            })
        except Exception:
            logger.exception("Bad message, skipping")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        now = time.monotonic()
        if len(buffer) >= BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL_SEC:
            _flush(buffer)
            for _ in range(len(buffer)):
                pass
            ch.basic_ack(delivery_tag=method.delivery_tag, multiple=True)
            buffer.clear()
            last_flush = now
        else:
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=QUEUE, on_message_callback=on_message, auto_ack=False)

    logger.info("Log Writer Worker started (batch=%d, interval=%.1fs)", BATCH_SIZE, FLUSH_INTERVAL_SEC)

    while not _shutdown:
        try:
            connection.process_data_events(time_limit=FLUSH_INTERVAL_SEC)
        except pika.exceptions.ConnectionClosedByBroker:
            logger.error("Connection closed by broker, reconnecting...")
            break
        except Exception:
            logger.exception("Error in event loop")
            break

        if buffer and (time.monotonic() - last_flush) >= FLUSH_INTERVAL_SEC:
            _flush(buffer)
            buffer.clear()
            last_flush = time.monotonic()

    _flush(buffer)
    buffer.clear()

    try:
        connection.close()
    except Exception:
        pass
    logger.info("Log Writer Worker stopped")


if __name__ == "__main__":
    main()
