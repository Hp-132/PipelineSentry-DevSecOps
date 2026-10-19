import json
import logging

import pika

from shared import config

log = logging.getLogger(__name__)


def dead_letter_exchange(queue: str) -> str:
    return f"{queue}.dlx"


def dead_letter_queue(queue: str) -> str:
    return f"{queue}.dlq"


def connect() -> pika.BlockingConnection:
    params = pika.URLParameters(config.RABBITMQ_URL)
    params.heartbeat = 60
    params.blocked_connection_timeout = 30
    params.connection_attempts = 3
    params.retry_delay = 2
    return pika.BlockingConnection(params)


def declare_topology(channel, queue: str | None = None) -> None:
    queue = queue or config.EVENT_QUEUE
    dlx, dlq = dead_letter_exchange(queue), dead_letter_queue(queue)
    channel.exchange_declare(dlx, exchange_type="direct", durable=True)
    channel.queue_declare(dlq, durable=True)
    channel.queue_bind(dlq, dlx, routing_key=queue)
    channel.queue_declare(
        queue,
        durable=True,
        arguments={"x-dead-letter-exchange": dlx, "x-dead-letter-routing-key": queue},
    )


def _properties(message: dict, attempt: int) -> pika.BasicProperties:
    return pika.BasicProperties(
        content_type="application/json",
        delivery_mode=pika.DeliveryMode.Persistent,
        message_id=message.get("event_id"),
        headers={"x-attempt": attempt},
    )


def publish(message: dict, attempt: int = 0, channel=None, queue: str | None = None) -> None:
    """Publish a persistent message. Raises if the broker does not confirm it."""
    queue = queue or config.EVENT_QUEUE
    body = json.dumps(message, default=str).encode()
    if channel is not None:
        channel.basic_publish("", queue, body, _properties(message, attempt), mandatory=True)
    else:
        connection = connect()
        try:
            ch = connection.channel()
            ch.confirm_delivery()
            declare_topology(ch, queue)
            ch.basic_publish("", queue, body, _properties(message, attempt), mandatory=True)
        finally:
            connection.close()
    log.info("published event %s to %s (attempt %d)", message.get("event_id"), queue, attempt)


def queue_depths(queue: str | None = None) -> dict[str, int]:
    queue = queue or config.EVENT_QUEUE
    connection = connect()
    try:
        ch = connection.channel()
        declare_topology(ch, queue)
        return {
            name: ch.queue_declare(name, passive=True).method.message_count
            for name in (queue, dead_letter_queue(queue))
        }
    finally:
        connection.close()
