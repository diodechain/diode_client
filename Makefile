TESTS= $(shell go list ./... | grep -v -e gowasm_test -e cmd)
GOPATH= $(shell go env GOPATH)
GOBUILD=go build -ldflags "-s -r ./ -X main.version=`git describe --tags --dirty`"
ARCHIVE= $(shell ./deployment/zipname.sh)


UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	COPY_DEPS = otool -L diode | awk '/libssl|libcrypto/ {system("cp " $$1 " dist/")}'
	STRIP = ./deployment/darwin_rpath.sh
else
	COPY_DEPS = ldd diode | awk '/libssl|libcrypto/ {system("cp " $$3 " dist/")}'
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

dist: $(BINS)
	mkdir -p dist
	cp $(BINS) dist/
	$(COPY_DEPS)
	for d in $(addprefix dist/,$(BINS)); do \
		$(STRIP) $$d ; \
	done
	upx $(addprefix dist/,$(BINS))

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

.PHONY: diode_static$(EXE)
diode_static$(EXE):
	go get -a -tags openssl_static github.com/diodechain/openssl
	$(GOBUILD) -tags netgo,openssl_static -ldflags '-extldflags "-static"' -o diode_static$(EXE) cmd/diode/*.go

.PHONY: config_server$(EXE)
config_server$(EXE):
	GODEBUG=netdns=go CGO_ENABLED=0 $(GOBUILD) -ldflags "-X main.serverAddress=localhost:1081 -X main.configPath=./.diode.yml" -o config_server$(EXE) cmd/config_server/config_server.go

.PHONY: client_debug$(EXE)
client_debug$(EXE):
	$(GOBUILD) -o client_debug$(EXE) cmd/client_debug/*.go
