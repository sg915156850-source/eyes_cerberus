# Eyes Cerberus.
#
#   make lint       shellcheck + bash -n over the supported tree
#   make test       bats suite (no root, does not touch the host)
#   make check      lint + test -- what CI runs
#   make install    install/upgrade on this host (needs root)
#   make uninstall  remove code and units, keep config and evidence
#   make deb        build dist/eyes-cerberus_<version>_all.deb
#   make clean      remove build output

SHELL := /bin/bash

# ir/experimental is deliberately excluded: unsupported, unpackaged, and not
# held to the lint gate.
SCRIPTS := cerberus.sh master.sh install.sh uninstall.sh \
           $(wildcard lib/*.sh) \
           ir/quick_response.sh ir/emergency_remediation.sh \
           $(wildcard ir/docker/*.sh) \
           packaging/build-deb.sh tests/helper.bash

VERSION := $(shell sed -n 's/^VERSION="\([0-9.]*\)"/\1/p' cerberus.sh | head -1)

.PHONY: help lint test check install uninstall deb clean version

help:
	@sed -n '3,10p' $(MAKEFILE_LIST) | sed 's/^# \{0,1\}//'

version:
	@echo $(VERSION)

lint:
	@command -v shellcheck >/dev/null || { echo "shellcheck not installed"; exit 1; }
	bash -n $(SCRIPTS)
	shellcheck -x -S warning $(SCRIPTS)
	@echo "lint: clean"

test:
	@command -v bats >/dev/null || { echo "bats not installed"; exit 1; }
	bats tests

check: lint test

install:
	./install.sh

uninstall:
	./uninstall.sh

deb:
	@./packaging/build-deb.sh dist

clean:
	rm -rf dist
