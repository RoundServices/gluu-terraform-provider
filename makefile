GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)

MAKEFLAGS += --silent

build:
	go build -o terraform-provider-gluu

build-example: build
	mkdir -p example/.terraform/plugins/terraform.local/RoundServices/gluu/1.0.0/darwin_amd64
	mkdir -p example/terraform.d/plugins/terraform.local/RoundServices/gluu/1.0.0/darwin_amd64
	cp terraform-provider-gluu example/.terraform/plugins/terraform.local/RoundServices/gluu/1.0.0/darwin_amd64/
	cp terraform-provider-gluu example/terraform.d/plugins/terraform.local/RoundServices/gluu/1.0.0/darwin_amd64/

local: deps
	./scripts/create-terraform-client.sh

deps:
	./scripts/check-deps.sh

fmt:
	gofmt -w -s $(GOFMT_FILES)

test: fmtcheck vet
	go test $(TEST)

testacc: fmtcheck vet
	go test -v ./gluu
	TF_ACC=1 CHECKPOINT_DISABLE=1 go test -v -timeout 60m -parallel 4 ./provider $(TESTARGS)

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

vet:
	go vet ./...
