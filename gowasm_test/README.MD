# GO WASM TEST

It's a test directory to explore the possibility for diode_go_client webassembly.

# TODO

Split openssl and other libraries from diode_go_client, and compile diode_go_client.

# Compile main.go to wasm

```BASH
$ GOOS=js GOARCH=wasm go build
```

# Run code in nodejs (After compile main.go to main.wasm)

* copy wasm_exec.js from $GOROOT/misc/wasm/wasm_exec.js

```BASH
$ cp /path/to/GOROOT/misc/wasm/wasm_exec.js ./wasm_exec.js
```

* install fetch library in nodejs

```BASH
$ npm i
```

* start

```BASH
$ node index.js
```