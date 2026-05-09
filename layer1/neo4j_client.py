"""Thin Neo4j driver wrapper used by all Layer 1 components."""
import os
import logging
from neo4j import GraphDatabase, Driver
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)

_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "lsig_dev")
        _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


def run_query(cypher: str, params: dict | None = None) -> list[dict]:
    """Execute a Cypher query and return all records as plain dicts."""
    driver = get_driver()

    def _execute():
        with driver.session() as session:
            result = session.run(cypher, params or {})
            return [dict(record) for record in result]

    return with_retry(_execute, label=f"neo4j:{cypher[:40]}")


def upsert_node(label: str, id_props: dict, extra_props: dict | None = None) -> None:
    """MERGE on id_props, SET remaining props. Never deletes nodes (Rule 3)."""
    all_props = {**(extra_props or {})}
    prop_set = ", ".join(f"n.{k} = ${k}" for k in all_props) if all_props else ""
    id_match = " AND ".join(f"n.{k} = ${k}" for k in id_props)

    cypher = f"""
        MERGE (n:{label} {{{', '.join(f'{k}: ${k}' for k in id_props)}}})
        {f'SET {prop_set}' if prop_set else ''}
    """
    run_query(cypher, {**id_props, **all_props})


def upsert_relationship(
    src_label: str, src_id: dict,
    rel_type: str, rel_props: dict,
    dst_label: str, dst_id: dict,
) -> None:
    src_match = " AND ".join(f"a.{k} = $src_{k}" for k in src_id)
    dst_match = " AND ".join(f"b.{k} = $dst_{k}" for k in dst_id)
    rel_set = ", ".join(f"r.{k} = $rel_{k}" for k in rel_props) if rel_props else ""

    params = (
        {f"src_{k}": v for k, v in src_id.items()} |
        {f"dst_{k}": v for k, v in dst_id.items()} |
        {f"rel_{k}": v for k, v in rel_props.items()}
    )

    cypher = f"""
        MATCH (a:{src_label}) WHERE {src_match}
        MATCH (b:{dst_label}) WHERE {dst_match}
        MERGE (a)-[r:{rel_type}]->(b)
        {f'SET {rel_set}' if rel_set else ''}
    """
    run_query(cypher, params)
