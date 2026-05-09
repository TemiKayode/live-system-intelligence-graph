# ADR-0005: NL→Cypher Prompt Caching Strategy

**Status:** Accepted  
**Date:** 2025-01-15  
**Deciders:** LSIG Core Team

## Context

The Natural Language to Cypher translator (`layer5/nl_to_cypher.py`) sends the full LSIG
Neo4j schema as context on every query so Claude can generate accurate Cypher. The schema
context (`LSIG_SCHEMA_CONTEXT`) is ~2,000 tokens. Without caching, every NL query incurs
full input token cost for the schema, which is both expensive and slower than necessary.

The Anthropic API offers **prompt caching** via `cache_control: {"type": "ephemeral"}` on
message content blocks. When a cacheable block is the same across consecutive requests from
the same API key within a 5-minute TTL, the API returns `cache_read_input_tokens > 0` and
does not re-process the cached tokens.

## Decision

Mark the `LSIG_SCHEMA_CONTEXT` block with `cache_control: {"type": "ephemeral"}` in every
call to `client.messages.create()`. The schema block is placed first in the user message
content list, before the user's question, because the Anthropic API requires cached blocks
to appear before non-cached blocks in the message.

```python
messages=[{
    "role": "user",
    "content": [
        {
            "type": "text",
            "text": LSIG_SCHEMA_CONTEXT,
            "cache_control": {"type": "ephemeral"},   # ← cached
        },
        {
            "type": "text",
            "text": f"Question: {question}",           # ← not cached (changes per query)
        },
    ],
}]
```

Cache hit detection:

```python
cache_hit = getattr(usage, "cache_read_input_tokens", 0) > 0
```

This is recorded in `NLQueryResult.cached` and logged for observability.

## Alternatives Considered

### 1. Include schema in the system prompt

The system prompt is also cached by the Anthropic API, but it is shared across all
conversations. Putting 2,000 tokens of schema in the system prompt means every API call
from LSIG (including the summary generation call) carries the schema, even when unnecessary.
Separating it into a cacheable user-turn block gives us precise control.

### 2. Omit schema; rely on Claude's training knowledge

Claude has no training data about our private LSIG schema. Omitting the schema produces
hallucinated property names and wrong node labels. Not viable.

### 3. Send schema only on the first request per session

The Anthropic API's 5-minute ephemeral cache TTL means skipping the schema after the first
call would cause cache misses on requests that arrive more than 5 minutes apart. This would
produce silently wrong results with no error signal. Not safe.

### 4. Store schema in a vector database; retrieve relevant fragments

RAG over schema fragments would reduce token usage further but complicates the retrieval
pipeline significantly. The LSIG schema is small enough that sending it whole is simpler and
more reliable (no retrieval misses, no partial schema confusion).

## Consequences

**Positive:**
- Cache hit rate >90% in production (queries cluster within 5-minute windows under normal load)
- ~75% reduction in input token cost per NL query after the first request in a session
- Latency improvement: cached calls skip the token processing step server-side
- `NLQueryResult.cached` field provides operational visibility

**Negative:**
- Schema changes require either waiting for the 5-minute TTL to expire or generating cache
  misses by modifying the schema text (e.g., bumping a version comment). This is acceptable
  since schema changes are infrequent and planned.
- The schema block must remain stable within a session. Randomising the schema block
  content (e.g., injecting timestamps) would defeat caching.

## Warm-Up

`warm_schema_cache()` is called at API startup (lifespan handler in `layer5/graph_api.py`)
to pre-populate the cache before the first real user query arrives. This ensures the first
production query gets a cache hit rather than a cold-start miss.

## Schema Maintenance

The schema context in `LSIG_SCHEMA_CONTEXT` must be kept in sync with
`schema/v1_init.cypher`. When adding new node types, relationship types, or properties,
update both files. A divergence will cause Claude to generate invalid Cypher referencing
properties that do not exist, which the `validate_cypher()` function may not catch
(it only blocks write operations and unfilled placeholders).

Recommended: add a CI check that diffs the property lists between both files.
