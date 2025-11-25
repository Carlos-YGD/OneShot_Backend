PY      := python
PIP     := $(PY) -m pip
MANAGE  := $(PY) manage.py
# Default port; override like: make run PORT=9000
PORT    ?= 8000
.PHONY: help
help:
	@echo "Common commands:"
	@echo "  make install        Install dependencies from requirements.txt"
	@echo "  make run            Run Django dev server (PORT=$(PORT))"
	@echo "  make migrate        Apply migrations"
	@echo "  make makemigrations Create migrations"
	@echo "  make test           Run test suite (pytest)"
	@echo "  make lint           Lint with ruff"
	@echo "  make format         Format with black"
	@echo "  make shell          Open Django shell"
	@echo "  make superuser      Create superuser"
	@echo "  make check          Lint + Tests (quality gate)"
.PHONY: install
install:
	$(PIP) install -r requirements.txt
.PHONY: run
run:
	$(MANAGE) runserver 0.0.0.0:$(PORT)
.PHONY: migrate
migrate:
	$(MANAGE) migrate
.PHONY: makemigrations
makemigrations:
	$(MANAGE) makemigrations
.PHONY: test
test:
	pytest
.PHONY: lint
lint:
	ruff check .
.PHONY: format
format:
	black .
.PHONY: shell
shell:
	$(MANAGE) shell
.PHONY: superuser
superuser:
	$(MANAGE) createsuperuser
.PHONY: check
check: lint test