TESTS= $(shell go list ./... | grep -v gowasm_test)

.PHONY: test
test:
	go test $(TESTS)

.PHONY: install
install:
	go mod download
