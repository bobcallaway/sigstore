#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all pkg test test-e2e clean lint fuzz help

all: pkg fuzz

SRCS = $(shell find pkg -name "*.go") $(GENSRC)

TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
FUZZ_DIR := ./test/fuzz
INTEGRATION_TEST_DIR := ./test/e2e
GO-FUZZ-BUILD := $(TOOLS_BIN_DIR)/go-fuzz-build

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

LDFLAGS ?=

GO_MOD_DIRS = . ./pkg/signature/kms/aws ./pkg/signature/kms/azure ./pkg/signature/kms/gcp ./pkg/signature/kms/hashivault

PLUGINDIR:= $(abspath pkg/signature/kms/plugin)
PROTODIR:= $(PLUGINDIR)/proto
GENSRCDIR:= $(PLUGINDIR)/generated
GENSRC = $(GENSRCDIR)/%.go
GEN_GO_MODULE=$(shell head -1 $(PLUGINDIR)/go.mod | cut -f2 -d ' ')
PROTOBUF_DEPS = $(abspath $(shell find . -iname "*.proto" | grep -v "protobuf-specs" | grep -v "googleapis"))

PROTOC-GEN-GO := $(TOOLS_BIN_DIR)/protoc-gen-go
PROTOC-GEN-GO-GRPC := $(TOOLS_BIN_DIR)/protoc-gen-go-grpc
PROTOC-API-LINTER := $(TOOLS_BIN_DIR)/api-linter

$(GENSRC): $(PROTOC-GEN-GO) $(PROTOC-GEN-GO-GRPC) $(PROTOC-API-LINTER)
	mkdir -p $(GENSRCDIR)
	# $(PROTOC-API-LINTER) -I $(PROTODIR) -I $(PROTODIR)/protobuf-specs -I $(PROTODIR)/googleapis $(PROTOBUF_DEPS) #--set-exit-status # TODO: add strict checking
	protoc -I $(PROTODIR) -I $(PROTODIR)/googleapis/ -I $(PROTODIR)/protobuf-specs/protos/ \
	       --plugin=protoc-gen-go=$(PROTOC-GEN-GO) \
	       --go_opt=module=$(GEN_GO_MODULE) --go_out=$(PLUGINDIR) \
	       --plugin=protoc-gen-go-grpc=$(PROTOC-GEN-GO-GRPC) \
	       --go-grpc_opt=module=$(GEN_GO_MODULE) --go-grpc_out=$(PLUGINDIR) $(PROTOBUF_DEPS)

gen: $(GENSRC)

golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.2 ;\

lint: golangci-lint ## Run golangci-lint
	$(GOLANGCI_LINT_BIN) run -v --new-from-rev=HEAD~ ./...

pkg: $(SRCS) ## Build pkg
	set -o xtrace; \
	for dir in $(GO_MOD_DIRS) ; do \
	    cd $$dir && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" ./... && cd - >/dev/null; \
	done

test: ## Run Tests for all Go modules.
	set -o xtrace; \
	for dir in $(GO_MOD_DIRS) ; do \
	    cd $$dir && go test ./... && cd - >/dev/null; \
	done

tidy: ## Run go mod tidy all Go modules.
	set -o xtrace; \
	for dir in $(GO_MOD_DIRS) ; do \
	    cd $$dir && go mod tidy && cd - >/dev/null; \
	done

test-e2e: ## Run E2E Tests
	cd $(INTEGRATION_TEST_DIR); ./e2e-test.sh

fuzz: $(GO-FUZZ-BUILD) ## Run Fuzz tests
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o pem-fuzz.zip ./pem
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o signature-fuzz.zip ./signature
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o fuzz-fuzz.zip .
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o dsse-fuzz.zip ./dsse

clean: ## Clean workspace
	rm -rf sigstore
	rm -f $(FUZZ_DIR)/*fuzz.zip
	rm -rf $(TOOLS_BIN_DIR)

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(GO-FUZZ-BUILD): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/go-fuzz-build github.com/dvyukov/go-fuzz/go-fuzz-build

$(PROTOC-GEN-GO): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go

$(PROTOC-GEN-GO-GRPC): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc

$(PROTOC-API-LINTER): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/api-linter github.com/googleapis/api-linter/cmd/api-linter 

##################
# help
##################

help:  ## Display this help
	@awk \
		-v "col=${COLOR}" -v "nocol=${NOCOLOR}" \
		' \
			BEGIN { \
				FS = ":.*##" ; \
				printf "\nUsage:\n  make %s<target>%s\n", col, nocol \
			} \
			/^[a-zA-Z_-]+:.*?##/ { \
				printf "  %s%-15s%s %s\n", col, $$1, nocol, $$2 \
			} \
			/^##@/ { \
				printf "\n%s%s%s\n", col, substr($$0, 5), nocol \
			} \
		' $(MAKEFILE_LIST)
