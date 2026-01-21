.PHONY: help
help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: test-up
test-up: ## Start test infrastructure
	docker compose up -d
	./scripts/create-bastion-account.sh

.PHONY: test-down
test-down: ## Stop and remove test infrastructure
	docker compose down --volumes

.PHONY: test
test: ## Run all tests
	go test -v -timeout 15m ./...

.DEFAULT_GOAL := help
