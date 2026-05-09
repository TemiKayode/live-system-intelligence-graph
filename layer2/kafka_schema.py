"""
Layer 2 — Kafka topic schema for `runtime_calls`.

Provides a Pydantic model (validation on the consumer side) and a
JSON Schema dict (for topic schema registry registration).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class RuntimeCallEvent(BaseModel):
    """
    Canonical message published to the `runtime_calls` Kafka topic
    by the Go eBPF agent's CallAggregator.

    One message per unique (service, function_symbol, source_file, source_line)
    tuple per 60-second aggregation window.
    """

    timestamp: datetime = Field(..., description="Window close time (ISO 8601 UTC)")
    service: str = Field(..., min_length=1, description="Logical service name")
    function_symbol: str = Field(..., min_length=1, description="Demangled symbol name")
    source_file: str = Field(..., description="Repo-relative source file path")
    source_line: int = Field(..., ge=0, description="Source line number")
    caller_symbol: str = Field("", description="Immediate caller's demangled symbol")
    call_count_last_60s: int = Field(..., ge=0, description="Calls observed in the 60s window")
    pid: int = Field(..., ge=0, description="PID of observed process (representative)")
    binary: str = Field("", description="Absolute path to the ELF binary")

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v

    @field_validator("source_file")
    @classmethod
    def strip_leading_slash(cls, v: str) -> str:
        # Ensure repo-relative (agent may emit absolute on symbolizer miss)
        return v.lstrip("/")


# JSON Schema for Confluent Schema Registry / Apicurio
RUNTIME_CALL_EVENT_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "RuntimeCallEvent",
    "type": "object",
    "required": [
        "timestamp", "service", "function_symbol",
        "source_file", "source_line", "call_count_last_60s",
    ],
    "properties": {
        "timestamp":            {"type": "string", "format": "date-time"},
        "service":              {"type": "string", "minLength": 1},
        "function_symbol":      {"type": "string", "minLength": 1},
        "source_file":          {"type": "string"},
        "source_line":          {"type": "integer", "minimum": 0},
        "caller_symbol":        {"type": "string"},
        "call_count_last_60s":  {"type": "integer", "minimum": 0},
        "pid":                  {"type": "integer", "minimum": 0},
        "binary":               {"type": "string"},
    },
    "additionalProperties": False,
}

KAFKA_TOPIC = "runtime_calls"
KAFKA_PARTITIONS = 12        # one per service shard; override in values.yaml
KAFKA_REPLICATION = 3
KAFKA_RETENTION_MS = 7 * 24 * 60 * 60 * 1000   # 7 days
