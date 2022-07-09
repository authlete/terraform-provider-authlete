
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=registry.terraform.io
NAMESPACE=authlete
NAME=authlete
BINARY=terraform-provider-${NAME}
VERSION=1.1.0
OS_ARCH=darwin_arm64

default: install

build:
	go build -o ${BINARY}

release:
	goreleaser release --rm-dist --snapshot --skip-publish  --skip-sign

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

# Run acceptance tests
.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m
