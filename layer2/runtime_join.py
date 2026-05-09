"""
Layer 2 — Runtime-to-Code Join Job (Apache Flink / PyFlink).

Consumes the `runtime_calls` Kafka topic. For each event, finds the matching
Function node in Neo4j (by source_file + source_line) and writes/updates a
RUNTIME_CALLS relationship with rolling call counts.

Also tombstones (removes RUNTIME_CALLS edges for) functions not seen in 30 days.

Run:
    flink run -py layer2/runtime_join.py \
        --kafka-brokers kafka:9092 \
        --neo4j-uri bolt://neo4j:7687

Or as a standalone process (for dev / Kind cluster testing):
    python -m layer2.runtime_join --standalone
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Iterator

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)

# ─── Lazy imports (only required in Flink mode) ───────────────────────────────

def _flink_available() -> bool:
    try:
        import pyflink  # noqa: F401
        return True
    except ImportError:
        return False


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class Config:
    kafka_brokers: str   = os.environ.get("KAFKA_BROKERS", "localhost:9092")
    kafka_topic: str     = os.environ.get("KAFKA_TOPIC", "runtime_calls")
    kafka_group: str     = "lsig-runtime-join"
    neo4j_uri: str       = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str      = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password: str  = os.environ.get("NEO4J_PASSWORD", "lsig_dev")
    # How often to flush accumulated counts to Neo4j
    flush_interval_s: int = 30
    # Functions not seen after this many days lose their RUNTIME_CALLS edge
    tombstone_days: int   = 30
    # Checkpoint interval for Flink state backend
    checkpoint_interval_ms: int = 60_000


# ─── Neo4j state writer ───────────────────────────────────────────────────────

class RuntimeGraphWriter:
    """Writes and updates RUNTIME_CALLS edges in Neo4j."""

    def __init__(self, cfg: Config):
        from neo4j import GraphDatabase
        self._driver = GraphDatabase.driver(
            cfg.neo4j_uri, auth=(cfg.neo4j_user, cfg.neo4j_password)
        )
        self._tombstone_days = cfg.tombstone_days

    def close(self):
        self._driver.close()

    def upsert_runtime_calls(self, events: list[RuntimeEdgeUpdate]) -> None:
        """
        Upsert RUNTIME_CALLS relationships in a single batched transaction.

        For each event we:
          1. Find the Function node by (source_file, source_line, service).
          2. MERGE a RUNTIME_CALLS self-loop (Function)-[:RUNTIME_CALLS]->(Function)
             using the function as both ends — the edge semantics here represent
             "this function was observed running", mirroring the Layer 1 CALLS edges.
          3. Increment call counts and update last_seen.
        """
        if not events:
            return

        cypher = """
        UNWIND $batch AS ev
        MATCH (f:Function {service: ev.service})
        WHERE f.file = ev.source_file
          AND f.line = ev.source_line
          AND f.deprecated_at IS NULL
        WITH f, ev
        MERGE (f)-[r:RUNTIME_CALLS]->(f)
        ON CREATE SET
            r.last_seen        = datetime(ev.timestamp),
            r.call_count_24h   = ev.count_60s,
            r.call_count_7d    = ev.count_60s
        ON MATCH SET
            r.last_seen        = datetime(ev.timestamp),
            r.call_count_24h   = r.call_count_24h + ev.count_60s,
            r.call_count_7d    = r.call_count_7d  + ev.count_60s
        """

        batch = [
            {
                "service":     e.service,
                "source_file": e.source_file,
                "source_line": e.source_line,
                "timestamp":   e.timestamp.isoformat(),
                "count_60s":   e.call_count_60s,
            }
            for e in events
        ]

        with self._driver.session() as session:
            session.run(cypher, {"batch": batch})

        logger.info("Upserted %d RUNTIME_CALLS edges", len(events))

    def decay_daily_counts(self) -> None:
        """
        Rolls the 24h window: subtract yesterday's contribution.
        Run once per day via a separate scheduled task or Flink timer.
        This is a simplification — production would use a time-series store
        (VictoriaMetrics) for precise windowing and read the rolled-up value here.
        """
        cypher = """
        MATCH ()-[r:RUNTIME_CALLS]->()
        WHERE r.last_seen < datetime() - duration({hours: 24})
        SET r.call_count_24h = 0
        """
        with self._driver.session() as session:
            session.run(cypher)

    def tombstone_dead_edges(self) -> int:
        """Remove RUNTIME_CALLS edges not seen in tombstone_days. Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._tombstone_days)
        cypher = """
        MATCH (f)-[r:RUNTIME_CALLS]->(f)
        WHERE r.last_seen < datetime($cutoff)
        DELETE r
        RETURN count(r) AS removed
        """
        with self._driver.session() as session:
            result = session.run(cypher, {"cutoff": cutoff.isoformat()})
            row = result.single()
            count = row["removed"] if row else 0
        logger.info("Tombstoned %d stale RUNTIME_CALLS edges (cutoff=%s)", count, cutoff.date())
        return count

    def lookup_function(self, service: str, source_file: str, source_line: int) -> str | None:
        """Return Function node ID for a given location, or None if not in graph."""
        cypher = """
        MATCH (f:Function {service: $service})
        WHERE f.file = $file AND f.line = $line AND f.deprecated_at IS NULL
        RETURN f.id AS id LIMIT 1
        """
        with self._driver.session() as session:
            result = session.run(cypher, {
                "service": service, "file": source_file, "line": source_line,
            })
            row = result.single()
            return row["id"] if row else None


@dataclass
class RuntimeEdgeUpdate:
    service: str
    function_symbol: str
    source_file: str
    source_line: int
    caller_symbol: str
    call_count_60s: int
    timestamp: datetime


# ─── Accumulator (in-memory buffer between Kafka polls and Neo4j flushes) ─────

class CallAccumulator:
    """
    Accumulates RuntimeCallEvents between flush intervals.
    Thread-safe via a lock — the consumer thread writes; the flush thread reads.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # key: (service, source_file, source_line) → RuntimeEdgeUpdate
        self._buckets: dict[tuple, RuntimeEdgeUpdate] = {}

    def record(self, ev: dict) -> None:
        key = (ev["service"], ev["source_file"], ev["source_line"])
        ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))

        with self._lock:
            if key in self._buckets:
                self._buckets[key].call_count_60s += ev["call_count_last_60s"]
                self._buckets[key].timestamp = max(self._buckets[key].timestamp, ts)
            else:
                self._buckets[key] = RuntimeEdgeUpdate(
                    service=ev["service"],
                    function_symbol=ev.get("function_symbol", ""),
                    source_file=ev["source_file"],
                    source_line=ev["source_line"],
                    caller_symbol=ev.get("caller_symbol", ""),
                    call_count_60s=ev["call_count_last_60s"],
                    timestamp=ts,
                )

    def drain(self) -> list[RuntimeEdgeUpdate]:
        with self._lock:
            result = list(self._buckets.values())
            self._buckets.clear()
        return result


# ─── Standalone consumer (dev / Kind mode) ───────────────────────────────────

class StandaloneConsumer:
    """
    Kafka consumer that runs in a single process without Flink.
    Suitable for development, CI, and Kind cluster testing.
    """

    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._writer = RuntimeGraphWriter(cfg)
        self._acc = CallAccumulator()
        self._stop = threading.Event()

    def run(self) -> None:
        import kafka as kafka_lib  # kafka-python

        consumer = kafka_lib.KafkaConsumer(
            self._cfg.kafka_topic,
            bootstrap_servers=self._cfg.kafka_brokers,
            group_id=self._cfg.kafka_group,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            consumer_timeout_ms=1000,
        )

        # Flush thread
        flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        flush_thread.start()

        # Tombstone thread — runs once per day
        tombstone_thread = threading.Thread(target=self._tombstone_loop, daemon=True)
        tombstone_thread.start()

        logger.info(
            "StandaloneConsumer started — brokers=%s topic=%s",
            self._cfg.kafka_brokers, self._cfg.kafka_topic,
        )

        try:
            while not self._stop.is_set():
                for msg in consumer:
                    if self._stop.is_set():
                        break
                    try:
                        self._acc.record(msg.value)
                    except Exception as e:
                        logger.warning("Bad message: %s — %s", msg.value, e)
        finally:
            consumer.close()
            self._stop.set()
            self._writer.close()

    def stop(self) -> None:
        self._stop.set()

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._cfg.flush_interval_s)
            events = self._acc.drain()
            if events:
                try:
                    self._writer.upsert_runtime_calls(events)
                except Exception as e:
                    logger.error("Neo4j flush error: %s", e)

    def _tombstone_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(24 * 3600)
            try:
                self._writer.tombstone_dead_edges()
                self._writer.decay_daily_counts()
            except Exception as e:
                logger.error("Tombstone error: %s", e)


# ─── Flink job (production mode) ─────────────────────────────────────────────

def run_flink_job(cfg: Config) -> None:
    """
    PyFlink streaming job. Requires Apache Flink 1.18+ with the Kafka connector.

    Topology:
        KafkaSource → map(parse+validate) → KeyBy(service) →
        ProcessFunction(accumulate 60s) → SinkFunction(Neo4j upsert)
    """
    from pyflink.datastream import StreamExecutionEnvironment, CheckpointingMode
    from pyflink.datastream.connectors.kafka import (
        KafkaSource, KafkaOffsetsInitializer,
    )
    from pyflink.common.serialization import SimpleStringSchema
    from pyflink.common.watermark_strategy import WatermarkStrategy
    from pyflink.datastream.functions import MapFunction, ProcessFunction
    from pyflink.datastream.state import ValueStateDescriptor
    from pyflink.common.typeinfo import Types

    env = StreamExecutionEnvironment.get_execution_environment()
    env.enable_checkpointing(cfg.checkpoint_interval_ms, CheckpointingMode.EXACTLY_ONCE)
    env.set_parallelism(4)

    source = (
        KafkaSource.builder()
        .set_bootstrap_servers(cfg.kafka_brokers)
        .set_topics(cfg.kafka_topic)
        .set_group_id(cfg.kafka_group)
        .set_starting_offsets(KafkaOffsetsInitializer.committed_offsets())
        .set_value_only_deserializer(SimpleStringSchema())
        .build()
    )

    stream = env.from_source(
        source,
        WatermarkStrategy.for_monotonous_timestamps(),
        "KafkaRuntimeCalls",
    )

    class ParseEvent(MapFunction):
        def map(self, value: str):
            ev = json.loads(value)
            # key for KeyBy: (service, source_file, source_line)
            return (
                f"{ev['service']}|{ev['source_file']}|{ev['source_line']}",
                ev,
            )

    class RuntimeCallProcessFunction(ProcessFunction):
        """Accumulates call counts in Flink keyed state; flushes to Neo4j on timer."""

        def open(self, runtime_context):
            from pyflink.datastream.state import ValueStateDescriptor
            from pyflink.common.typeinfo import Types
            self._count_state = runtime_context.get_state(
                ValueStateDescriptor("call_count", Types.LONG())
            )
            self._last_event = runtime_context.get_state(
                ValueStateDescriptor("last_event", Types.STRING())
            )
            self._writer = RuntimeGraphWriter(cfg)

        def process_element(self, value, ctx):
            key, ev = value
            current = self._count_state.value() or 0
            self._count_state.update(current + ev["call_count_last_60s"])
            self._last_event.update(json.dumps(ev))

            # Register a processing-time timer for the flush boundary
            ctx.timer_service().register_processing_time_timer(
                ctx.timer_service().current_processing_time() + cfg.flush_interval_s * 1000
            )
            return []

        def on_timer(self, timestamp, ctx):
            count = self._count_state.value() or 0
            last_raw = self._last_event.value()
            if not last_raw or count == 0:
                return []

            ev = json.loads(last_raw)
            update = RuntimeEdgeUpdate(
                service=ev["service"],
                function_symbol=ev.get("function_symbol", ""),
                source_file=ev["source_file"],
                source_line=ev["source_line"],
                caller_symbol=ev.get("caller_symbol", ""),
                call_count_60s=count,
                timestamp=datetime.now(timezone.utc),
            )
            try:
                self._writer.upsert_runtime_calls([update])
            except Exception as e:
                logger.error("Flink Neo4j flush: %s", e)

            self._count_state.update(0)
            return []

    (
        stream
        .map(ParseEvent(), output_type=Types.TUPLE([Types.STRING(), Types.MAP(Types.STRING(), Types.STRING())]))
        .key_by(lambda x: x[0])
        .process(RuntimeCallProcessFunction())
    )

    env.execute("LSIG RuntimeCodeJoinJob")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LSIG Layer 2 — Runtime Join Job")
    parser.add_argument("--standalone", action="store_true",
                        help="Run without Flink (dev/CI mode)")
    parser.add_argument("--kafka-brokers", default=None)
    parser.add_argument("--kafka-topic", default=None)
    parser.add_argument("--neo4j-uri", default=None)
    parser.add_argument("--flush-interval", type=int, default=None)
    args = parser.parse_args()

    cfg = Config()
    if args.kafka_brokers:
        cfg.kafka_brokers = args.kafka_brokers
    if args.kafka_topic:
        cfg.kafka_topic = args.kafka_topic
    if args.neo4j_uri:
        cfg.neo4j_uri = args.neo4j_uri
    if args.flush_interval:
        cfg.flush_interval_s = args.flush_interval

    if args.standalone or not _flink_available():
        logger.info("Running in standalone consumer mode")
        consumer = StandaloneConsumer(cfg)

        def _signal_handler(sig, frame):
            logger.info("Shutdown requested")
            consumer.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
        consumer.run()
    else:
        logger.info("Running as Flink job")
        run_flink_job(cfg)


if __name__ == "__main__":
    main()
