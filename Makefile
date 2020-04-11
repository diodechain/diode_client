TESTS= $(shell go list ./... | grep -v gowasm_test)

.PHONY: all
all: diode

.PHONY: test
test:
	go test $(TESTS)

.PHONY: install
install:
	go build -ldflags "-X main.version=`git describe --tags --dirty`" -o diode cmd/diode.go
	mv diode /usr/local/bin/diode

.PHONY: uninstall
uninstall:
	rm -rf /usr/local/bin/diode

gateway: diode
	strip -s diode
	upx diode
	scp -C diode root@diode.ws:diode_go_client
	ssh root@diode.ws 'svc -k .'
	touch gateway

.PHONY: diode
diode:
	go build -ldflags "-X main.version=`git describe --tags --dirty`" -o diode cmd/diode.go

.PHONY: static
static:
	go get -a -tags openssl_static github.com/diodechain/openssl
	go build -tags netgo,openssl_static -ldflags '-extldflags "-static"' -o diode cmd/diode.go

