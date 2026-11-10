HOSTNAME=registry.terraform.io
NAMESPACE=encryption-consulting-llc
NAME=certsecure
VERSION?=1.0.0
BINARY=terraform-provider-${NAME}
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
INSTALLDIR := ${HOME}/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

default: fmtcheck lint build generate

build: fmtcheck
	go build -v ./...

install: build
	go install -v ./...

# Install into Terraform's implicit local mirror, so `terraform init` uses this build
# for `source = "encryption-consulting-llc/certsecure"`, `version = "$(VERSION)"`.
install-local: fmtcheck
	mkdir -p ${INSTALLDIR}
	go build -ldflags "-X main.version=${VERSION}" -o ${INSTALLDIR}/${BINARY}_v${VERSION}$(shell go env GOEXE) .

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

docs-validate:
	cd tools; go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs validate --provider-dir .. --provider-name ${NAME}

fmt:
	gofmt -s -w -e .

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

test:
	go test -v -cover -timeout=300s -parallel=10 ./...

# Issues real certificates. Requires CERTSECURE_URL, CERTSECURE_TOKEN,
# CERTSECURE_TEST_CA and CERTSECURE_TEST_TEMPLATE.
testacc:
	TF_ACC=1 go test -v -cover -timeout 120m -run '^TestAcc' ./internal/provider/

.PHONY: default build install install-local lint generate docs-validate fmt fmtcheck test testacc
