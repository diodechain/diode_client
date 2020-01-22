TESTS= $(shell go list ./... | grep -v gowasm_test)

.PHONY: all
all: diode_go_client

.PHONY: test
test:
	go test $(TESTS)

.PHONY: install
install:
	go install

gateway: diode_go_client
	strip -s diode_go_client
	scp -C diode_go_client root@diode.ws:
	ssh root@diode.ws 'svc -k .'
	touch gateway

.PHONY: diode_go_client
diode_go_client:
	go build
	go build -ldflags "-X main.version=`git rev-list -1 HEAD`"

.PHONY: static
static:
	go get -a -tags openssl_static github.com/diodechain/openssl
	go build -tags netgo,openssl_static -ldflags '-extldflags "-static"'
