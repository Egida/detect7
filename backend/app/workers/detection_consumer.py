"""Detection Consumer -- consumes ML detections from RabbitMQ and writes to detection_events hypertable.

Run:
    python -m app.workers.detection_consumer
"""

import json
import logging
import os
import signal
from datetime import datetime, timezone

import pika
from sqlalchemy import text

from ..database import engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("detection_consumer")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
EXCHANGE = os.getenv("RABBITMQ_DETECTIONS_EXCHANGE", "detect7.detections")
QUEUE = os.getenv("RABBITMQ_DETECTIONS_QUEUE", "detections")
ROUTING_KEY = os.getenv("RABBITMQ_DETECTIONS_ROUTING_KEY", "detections")

INSERT_SQL = text("""
    INSERT INTO detection_events
        (started_at, domain_id, detected_ip, threat_score,
         country, city, ptr, request_count, peak_rps,
         request_rate, error_rate, ip_data_preview, last_feature)
    VALUES
        (:started_at, :domain_id, :detected_ip, :threat_score,
         :country, :city, :ptr, :request_count, :peak_rps,
         :request_rate, :error_rate, :ip_data_preview, :last_feature)
""")

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Shutdown signal received")
    _shutdown = True


def _write_event(msg: dict) -> None:
    try:
        ts_raw = msg.get("timestamp")
        if isinstance(ts_raw, (int, float)):
            started_at = datetime.fromtimestamp(ts_raw, tz=timezone.utc).replace(tzinfo=None)
        elif isinstance(ts_raw, str):
            started_at = datetime.fromisoformat(ts_raw)
        else:
            started_at = datetime.now(timezone.utc).replace(tzinfo=None)

        row = {
            "started_at": started_at,
            "domain_id": msg["domain_id"],
            "detected_ip": msg.get("ip", ""),
            "threat_score": float(msg.get("problem", 0)) / 100.0,
            "country": (msg.get("country") or "")[:2] or None,
            "city": (msg.get("city") or "")[:100] or None,
            "ptr": (msg.get("ptr") or "")[:255] or None,
            "request_count": int(msg.get("req_count", 0)),
            "peak_rps": float(msg.get("rps", 0)),
            "request_rate": float(msg.get("req_rate", 0)),
            "error_rate": float(msg.get("err_rate", 0)),
            "ip_data_preview": json.dumps(msg.get("ip_data")) if msg.get("ip_data") else None,
            "last_feature": json.dumps(msg.get("last_feature")) if msg.get("last_feature") else None,
        }

        with engine.begin() as conn:
            conn.execute(INSERT_SQL, row)

        logger.info(
            "Detection saved: domain=%s ip=%s score=%.2f",
            row["domain_id"], row["detected_ip"], row["threat_score"],
        )
    except Exception:
        logger.exception("Failed to write detection event")


def main() -> None:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    params = pika.URLParameters(RABBITMQ_URL)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=QUEUE, routing_key=ROUTING_KEY)
    channel.basic_qos(prefetch_count=10)

    def on_message(ch, method, properties, body):
        try:
            msg = json.loads(body)
            _write_event(msg)
        except Exception:
            logger.exception("Bad detection message, skipping")
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=QUEUE, on_message_callback=on_message, auto_ack=False)

    logger.info("Detection Consumer started")

    while not _shutdown:
        try:
            connection.process_data_events(time_limit=1.0)
        except pika.exceptions.ConnectionClosedByBroker:
            logger.error("Connection closed by broker, reconnecting...")
            break
        except Exception:
            logger.exception("Error in event loop")
            break

    try:
        connection.close()
    except Exception:
        pass
    logger.info("Detection Consumer stopped")


if __name__ == "__main__":
    main()
