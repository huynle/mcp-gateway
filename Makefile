.PHONY: install test render-k8s compile docker-build clean

IMAGE ?= mcp-gateway:local

install:
	python -m pip install -e '.[dev]'

test:
	pytest -q

compile:
	python -m compileall -q src migrations

render-k8s:
	kubectl kustomize k8s/base >/tmp/mcp-gateway-base.yaml
	kubectl kustomize k8s/overlays/local >/tmp/mcp-gateway-local.yaml
	kubectl kustomize k8s/overlays/production >/tmp/mcp-gateway-production.yaml

docker-build:
	docker build -t $(IMAGE) .

clean:
	rm -rf .pytest_cache src/mcp_gateway.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
