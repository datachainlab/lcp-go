DOCKER         ?= docker
DOCKER_COMPOSE ?= docker compose
DOCKER_REPO    ?= ""
DOCKER_TAG     ?= latest
DOCKER_BUILD   ?= $(DOCKER) build --rm --no-cache --pull

RLY_BIN ?= ../../../../bin/yrly

.PHONY: network
network:
	TAG=${DOCKER_TAG} $(DOCKER_COMPOSE) \
		-f ../docker-compose-test.yaml \
		up -d \
		tendermint-chain0 tendermint-chain1

.PHONY: network-down
network-down:
	TAG=${DOCKER_TAG} $(DOCKER_COMPOSE) \
		-f ../docker-compose-test.yaml \
		down --volumes --remove-orphans

.PHONY: setup
setup:
	./scripts/fixture
	RLY_BIN=$(RLY_BIN) ./scripts/init-rly

.PHONY: handshake
handshake:
	RLY_BIN=$(RLY_BIN) ./scripts/handshake

.PHONY: test-relay
test-relay:
	RLY_BIN=$(RLY_BIN) ./scripts/test-relay

.PHONY: restore
restore:
	RLY_BIN=$(RLY_BIN) ./scripts/restore

.PHONY: test-elc-update
test-elc-update:
	RLY_BIN=$(RLY_BIN) ./scripts/test-elc-update
