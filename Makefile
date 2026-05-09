## LSIG — Live System Intelligence Graph
## Usage: make <target>

HELM_RELEASE   := lsig
HELM_CHART     := ./helm/lsig
KIND_CLUSTER   := lsig-dev
KUBECONFIG     ?= ~/.kube/config

.PHONY: install ingest test teardown lint type-check dev-neo4j dev-up

## ─── Development ─────────────────────────────────────────────────────────────

dev-neo4j:
	@echo "Starting Neo4j via Docker..."
	docker run -d --name lsig-neo4j \
	  -p 7474:7474 -p 7687:7687 \
	  -e NEO4J_AUTH=neo4j/lsig_dev \
	  -e NEO4JLABS_PLUGINS='["apoc"]' \
	  neo4j:5
	@echo "Neo4j browser: http://localhost:7474"

dev-schema:
	@echo "Applying schema..."
	cypher-shell -u neo4j -p lsig_dev -f schema/v1_init.cypher

dev-up: dev-neo4j
	@sleep 10
	$(MAKE) dev-schema

## ─── Kind cluster ────────────────────────────────────────────────────────────

kind-create:
	kind create cluster --name $(KIND_CLUSTER)

kind-delete:
	kind delete cluster --name $(KIND_CLUSTER)

## ─── Helm ────────────────────────────────────────────────────────────────────

install:
	helm dependency update $(HELM_CHART)
	helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) \
	  -f $(HELM_CHART)/values.yaml \
	  --wait --timeout 15m

teardown:
	helm uninstall $(HELM_RELEASE) || true
	kubectl delete pvc -l app.kubernetes.io/instance=$(HELM_RELEASE) || true

## ─── Ingestion ───────────────────────────────────────────────────────────────

ingest:
ifndef repo
	$(error Usage: make ingest repo=https://github.com/org/repo)
endif
	python -m layer1.code_ingester --repo $(repo) --service $(notdir $(repo))

## ─── Testing ─────────────────────────────────────────────────────────────────

test:
	pytest tests/ -v --tb=short -m "not slow"

test-full:
	pytest tests/ -v --tb=short

type-check:
	mypy layer1/ --ignore-missing-imports --strict

lint:
	ruff check layer1/ tests/
	ruff format --check layer1/ tests/
