TESTS= $(shell go list ./... | grep -v -e gowasm_test -e cmd)
GOPATH= $(shell go env GOPATH)
GOMODCACHE= $(shell go env GOMODCACHE)
# go 1.14 patch
ifeq ($(GOMODCACHE),)
GOMODCACHE := $(shell go env GOPATH)/pkg/mod
endif
COMMIT= $(shell git describe --tags --dirty)
BUILDTIME= $(shell date +"%d %b %Y")
GOBUILD=go build -ldflags '-s -r ./ -X "main.version=${COMMIT}${VARIANT}" -X "main.buildTime=${BUILDTIME}"' -tags patch_runtime
ARCHIVE= $(shell ./deployment/zipname.sh)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	UPX = upx
else
	UPX = echo noupx
endif
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

.PHONY: runtime
runtime:
	@./patch_runtime.sh

.PHONY: all
all: $(BINS)

.PHONY: openssl
openssl:
	go mod download
	bash "$(GOMODCACHE)/github.com/diodechain/openssl@v1.0.20/install_openssl.sh"

.PHONY: test
test: runtime
	go test -race $(TESTS)

.PHONY: windows_test
windows_test: runtime
	go test $(TESTS)

.PHONY: ci_test
ci_test: runtime
	$(MAKE) test
	$(MAKE) diode_race_test
	chmod +x ./diode_race_test
	./ci_test.sh

.PHONY: lint
lint: runtime
	go vet ./...
	cd tools && go install honnef.co/go/tools/cmd/staticcheck@latest
	$(GOPATH)/bin/staticcheck -go 1.14 ./...

# Exclude rules from security check:
# G104 (CWE-703): Errors unhandled.
# G108 (CWE-200): Profiling endpoint is automatically exposed on /debug/pprof
# G110 (CWE-409): Potential DoS vulnerability via decompression bomb.
# G112: Potential slowloris attack
# G114: Use of net/http serve function that has no support for setting timeouts
# G204 (CWE-78): Subprocess launched with variable.
# G304 (CWE-22): Potential file inclusion via variable.
# G402 (CWE-295): TLS InsecureSkipVerify set true.
# G404 (CWE-338): Use of weak random number generator (math/rand instead of crypto/rand).
.PHONY: seccheck
seccheck: runtime
	cd tools && go install github.com/securego/gosec/v2/cmd/gosec@latest
	$(GOPATH)/bin/gosec -exclude=G104,G108,G110,G112,G114,G204,G304,G402,G404 -exclude-dir .history ./...

.PHONY: clean
clean:
	-rm $(BINS)
	go clean -cache

.PHONY: install
install:
	$(MAKE) diode
	mv diode /usr/local/bin/diode

.PHONY: uninstall
uninstall:
	rm -rf /usr/local/bin/diode

dist: diode$(EXE)
	mkdir -p dist
	cp diode$(EXE) dist/
	$(STRIP) dist/diode$(EXE)
	$(UPX) --force dist/diode$(EXE)

.PHONY: archive
archive: $(ARCHIVE)
$(ARCHIVE): dist
	zip -1 -j $(ARCHIVE) dist/*

.PHONY: gateway
gateway: diode_debug
	scp -C diode_debug root@diode.link:diode_go_client
	ssh root@diode.link 'svc -k .'

.PHONY: diode$(EXE)
diode$(EXE): runtime
	$(GOBUILD) -o diode$(EXE) cmd/diode/*.go

.PHONY: config_server$(EXE)
config_server$(EXE): runtime
	GODEBUG=netdns=go CGO_ENABLED=0 $(GOBUILD) -ldflags "-X main.serverAddress=localhost:1081 -X main.configPath=./.diode.yml" -o config_server$(EXE) cmd/config_server/config_server.go

.PHONY: gauge$(EXE)
gauge$(EXE): runtime
	$(GOBUILD) -o gauge$(EXE) cmd/gauge/*.go

.PHONY: diode_race_test
diode_race_test: runtime
	$(GOBUILD) -race -o diode_race_test cmd/diode/*.go

.PHONY: debug
diode_debug: VARIANT=-debug
diode_debug: runtime
	$(GOBUILD) -gcflags="-N -l" -o diode_debug cmd/diode/*.go
