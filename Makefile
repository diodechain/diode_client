TESTS= $(shell go list ./... | grep -v -e gowasm_test -e cmd)
GOPATH= $(shell go env GOPATH)
COMMIT= $(shell git describe --tags --dirty)
BUILDTIME= $(shell date +"%d %b %Y")
GOBUILD=go build -ldflags '-s -r ./ -X "main.version=${COMMIT}" -X "main.buildTime=${BUILDTIME}"'
ARCHIVE= $(shell ./deployment/zipname.sh)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	STRIP = echo nostrip
else
	STRIP = strip --strip-all
endif

EXE = 
ifdef OS
	EXE = .exe
endif

BINS=diode$(EXE) config_server$(EXE)

.PHONY: default
default: diode$(EXE)

.PHONY: all
all: $(BINS)

.PHONY: test
test:
	go test -race $(TESTS)

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

dist: diode_static
	mkdir -p dist
	cp diode$(EXE) dist/
	$(STRIP) dist/diode$(EXE)
	upx --force dist/diode$(EXE)

.PHONY: archive
archive: $(ARCHIVE)
$(ARCHIVE): dist
	zip -1 -j $(ARCHIVE) dist/*

.PHONY: gateway
gateway: diode
	strip -s diode
	upx diode
	scp -C diode root@diode.ws:diode_go_client
	ssh root@diode.ws 'svc -k .'

.PHONY: diode$(EXE)
diode$(EXE):
	$(GOBUILD) -o diode$(EXE) cmd/diode/*.go

.PHONY: diode_static
diode_static:
	go get -a -tags openssl_static github.com/diodechain/openssl
	$(GOBUILD) -tags openssl_static -o diode$(EXE) cmd/diode/*.go

.PHONY: config_server$(EXE)
config_server$(EXE):
	GODEBUG=netdns=go CGO_ENABLED=0 $(GOBUILD) -ldflags "-X main.serverAddress=localhost:1081 -X main.configPath=./.diode.yml" -o config_server$(EXE) cmd/config_server/config_server.go

.PHONY: client_debug$(EXE)
client_debug$(EXE):
	$(GOBUILD) -o client_debug$(EXE) cmd/client_debug/*.go

.PHONY: diode_race_test
diode_race_test:
	$(GOBUILD) -race -o diode_race_test cmd/diode/*.go

.PHONY: ci_test
ci_test:
	$(MAKE) test
	$(MAKE) diode_race_test
	chmod +x ./diode_race_test 
	./diode_race_test config -list
	./diode_race_test time
	rm ./diode_race_test
