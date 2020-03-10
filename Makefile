TESTS= $(shell go list ./... | grep -v gowasm_test)

.PHONY: all
all: diode

.PHONY: test
test:
	go test $(TESTS)

.PHONY: install
install:
	go build -ldflags "-X main.version=`git describe --tags --dirty`" -o diode
	mv diode /usr/local/bin/diode

.PHONY: uninstall
uninstall:
	rm -rf /usr/local/bin/diode

gateway: diode_go_client
	strip -s diode_go_client
	scp -C diode_go_client root@diode.ws:
	ssh root@diode.ws 'svc -k .'
	touch gateway

.PHONY: diode_go_client
diode:
	go build -ldflags "-X main.version=`git describe --tags --dirty`" -o diode

.PHONY: static
static:
	go get -a -tags openssl_static github.com/diodechain/openssl
	go build -tags netgo,openssl_static -ldflags '-extldflags "-static"' -o diode
