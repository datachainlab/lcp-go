protoVer=0.13.1
protoImageName=ghcr.io/cosmos/proto-builder:$(protoVer)
protoImage=docker run --user 0 --rm -v $(CURDIR):/workspace --workdir /workspace $(protoImageName)

.PHONY: yrly
yrly:
	go build -o ./bin/yrly -tags customcert ./relay/bin

.PHONY: lcp
lcp:
	$(MAKE) -C ./lcp -B && mv ./lcp/bin/* ./bin/

.PHONY: e2e-test
e2e-test: yrly lcp
	./scripts/run_e2e_test.sh

.PHONY: proto-gen proto-update-deps
proto-gen:
	@echo "Generating Protobuf files"
	@$(protoImage) sh ./scripts/protocgen.sh

proto-update-deps:
	@echo "Updating Protobuf dependencies"
	$(DOCKER) run --user 0 --rm -v $(CURDIR)/proto:/workspace --workdir /workspace $(protoImageName) buf mod update
