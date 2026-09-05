REPO=malice-plugins/diec
ORG=malice
NAME=diec
CATEGORY=exe
VERSION=$(shell cat VERSION)

MALWARE=tests/malware
NOT_MALWARE=tests/not.malware


all: build size tag test_all

.PHONY: build
build:
	docker build --build-context pkgs=../malice-plugins -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: ssh
ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

.PHONY: tar
tar:
	docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

.PHONY: malware
malware:
ifeq (,$(wildcard $(MALWARE)))
	cd tests; echo "TEST" > not.malware
endif

.PHONY: test
test: malware
	@echo "===> ${NAME} --help"
	docker run --init --rm $(ORG)/$(NAME):$(VERSION) --help
	@echo "===> ${NAME} scan (JSON to stdout)"
	docker run --init --rm -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V $(MALWARE) | jq . > docs/results.json
	cat docs/results.json | jq .

.PHONY: test_table
test_table: malware
	@echo "===> ${NAME} scan (markdown table)"
	docker run --init --rm -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -t $(MALWARE)

.PHONY: clean
clean:
	docker image rm $(ORG)/$(NAME):$(VERSION) || true
	docker image rm $(ORG)/$(NAME):latest || true
	rm $(MALWARE) || true
	rm $(NOT_MALWARE) || true

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "} {printf "\033[36m%-30s \033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
