TESTS= $(shell go list ./... | grep -v -e gowasm_test -e cmd)
GOPATH= $(shell go env GOPATH)
GOBUILD=go build -ldflags "-X main.version=`git describe --tags --dirty`"
BINS=diode diode_static config_server client_debug

.PHONY: default
default: diode

.PHONY: all
all: $(BINS)

.PHONY: test
test:
	go test $(TESTS)

.PHONY: lint
lint:
	go vet ./...
	GO111MODULE=on go get honnef.co/go/tools/cmd/staticcheck@2020.1.3
	$(GOPATH)/bin/staticcheck -go 1.14 ./...

.PHONY: clean
clean:
	-rm $(BINS)
	go clean -cache ./...

.PHONY: install
install:
	$(MAKE) diode
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
	$(GOBUILD) -o diode cmd/diode/diode.go

.PHONY: diode_static
diode_static:
	go get -a -tags openssl_static github.com/diodechain/openssl
	$(GOBUILD) -tags netgo,openssl_static -ldflags '-extldflags "-static"' -o diode_static cmd/diode/diode.go

.PHONY: config_server
config_server:
	GODEBUG=netdns=go CGO_ENABLED=0 $(GOBUILD) -ldflags "-X main.serverAddress=localhost:1081 -X main.configPath=./.diode.yml" -o config_server cmd/config_server/config_server.go

.PHONY: client_debug
client_debug:
	$(GOBUILD) -o client_debug cmd/client_debug/*.go
