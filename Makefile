TESTS= $(shell go list ./... | grep -v -e gowasm_test -e cmd)
GOPATH= $(shell go env GOPATH)
GOBIN= $(or $(shell go env GOBIN), $(GOPATH)/bin)
GOMODCACHE= $(or $(shell go env GOMODCACHE), $(GOPATH)/pkg/mod)
COMMIT= $(shell git describe --tags --dirty)
BUILDTIME= $(shell date +"%d %b %Y")
TAGS := $(strip patch_runtime $(EXTRA_TAGS))
GOBUILD=go build -ldflags '-s -r ./ -X "main.version=${COMMIT}${VARIANT}" -X "main.buildTime=${BUILDTIME}"' -tags "$(TAGS)"
# Variant without RPATH for CGO GUI/tray builds to avoid odd loader paths
GOBUILD_NORPATH=go build -ldflags '-s -X "main.version=${COMMIT}${VARIANT}" -X "main.buildTime=${BUILDTIME}"' -tags "$(TAGS)"
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
	bash "$(GOMODCACHE)/github.com/diodechain/openssl@v1.0.21/install_openssl.sh"

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

.PHONY: format
format: runtime
	go fmt ./...

.PHONY: lint
lint: runtime
	go vet ./...
	cd tools && go install honnef.co/go/tools/cmd/staticcheck@latest
	$(GOBIN)/staticcheck -go 1.25 ./...

# Exclude rules from security check:
# G104 (CWE-703): Errors unhandled.
# G108 (CWE-200): Profiling endpoint is automatically exposed on /debug/pprof
# G110 (CWE-409): Potential DoS vulnerability via decompression bomb.
# G112: Potential slowloris attack
# G107 (CWE-88): HTTP request made with variable url (expected in RPC calls)
# G114: Use of net/http serve function that has no support for setting timeouts
# G204 (CWE-78): Subprocess launched with variable.
# G304 (CWE-22): Potential file inclusion via variable.
# G402 (CWE-295): TLS InsecureSkipVerify set true.
# G404 (CWE-338): Use of weak random number generator (math/rand instead of crypto/rand).
.PHONY: seccheck
seccheck: runtime
	if [ ! -f ./gosec ]; \
	then \
		curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b ./ v2.22.10; \
	fi;
	./gosec -exclude=G104,G107,G108,G110,G112,G114,G115,G204,G304,G402,G404,G407,G602 -exclude-dir .history ./...

.PHONY: clean
clean:
	-rm $(BINS)
	-rm -f diode_tray$(EXE)
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
	CGO_ENABLED=1 $(GOBUILD_NORPATH) -o diode$(EXE) ./cmd/diode

.PHONY: traybin
# Backwards-compatible alias now that tray is integrated.
traybin: diode

.PHONY: diode_tray
# Deprecated: tray is now integrated into the main diode binary
diode_tray: diode

.PHONY: tray
tray: diode

.PHONY: run_tray
# Run diode with tray UI enabled
run_tray: diode
	./diode -tray=true $(ARGS)

.PHONY: tray_legacy
tray_legacy: diode_tray_legacy

.PHONY: diode_tray_legacy
# Build single diode binary with legacy appindicator support
diode_tray_legacy: VARIANT=
diode_tray_legacy: runtime
	EXTRA_TAGS=legacy_appindicator CGO_ENABLED=1 $(GOBUILD_NORPATH) -o diode$(EXE) ./cmd/diode

.PHONY: run_tray_legacy
run_tray_legacy: diode_tray_legacy
	./diode -tray=true $(ARGS)

.PHONY: config_server$(EXE)
config_server$(EXE): runtime
	GODEBUG=netdns=go CGO_ENABLED=0 $(GOBUILD) -ldflags "-X main.serverAddress=localhost:1081 -X main.configPath=./.diode.yml" -o config_server$(EXE) cmd/config_server/config_server.go

.PHONY: gauge$(EXE)
gauge$(EXE): runtime
	$(GOBUILD) -o gauge$(EXE) cmd/gauge/*.go

.PHONY: diode_race_test
diode_race_test: runtime
	CGO_ENABLED=1 $(GOBUILD_NORPATH) -race -o diode_race_test ./cmd/diode

.PHONY: debug
diode_debug: VARIANT=-debug
diode_debug: runtime
	CGO_ENABLED=1 $(GOBUILD_NORPATH) -gcflags="-N -l" -o diode_debug ./cmd/diode
