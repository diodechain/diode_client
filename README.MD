# Diode go client
This is Go client for connecting device through diodechain. You can found more detail about how diodechain/client works in our previous presentations https://github.com/diodechain/presentations.

# Development
## Prerequisite
* go > 1.10
* enable go module (see: https://blog.golang.org/using-go-modules)
  ```BASH
  export GO111MODULE=on
  ```
* optional: run dev diodechain locally (see: https://github.com/diodechain/diode_server_ex)

## Setup go environment
### Mac
Before install golang, please ensure your device meets the requirements (https://golang.org/doc/install#requirements).

You can download the latest binary distribution https://golang.org/dl/ or install from the source code https://golang.org/doc/install/source. Here we are going to install golang with [Homebrew](https://brew.sh/).

#### Install Homebrew
```BASH
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

#### Install Go
```BASH
$ brew install golang
```

Then you can check go version meets the requirement (>1.10).
```BASH
$ go version
```

## Install dependencies

```BASH
$ go mod download
```

## Run test

```BASH
$ go test `go list ./... | grep -v gowasm_test` // ignore gowasm_test folder
```

## Build

```BASH
$ go build
```

# Examples
## Command line options

```BASH
Usage of:
  -blockquicklimit int
    	total number limit to run blockquick algorithm, only useful in debug mode (default 100)
  -dbpath string
    	file path to db file (default "./db/private.db")
  -debug
    	turn on debug mode
  -enablekeepalive
    	enable tcp keepalive (default true)
  -fleet string
    	fleet contract address (default "0x6000000000000000000000000000000000000000")
  -registry string
    	registry contract address (default "0x5000000000000000000000000000000000000000")
  -remoterpcaddr string
    	remote rpc address (default "127.0.0.1:41043")
  -remoterpctimeout int
    	timeout seconds to connect to the remote rpc server (default 1)
  -retrytimes int
    	retry times to connect the remote rpc server (default 3)
  -retrywait int
    	wait seconds before next retry (default 1)
  -runsocks
    	run socks server
  -runsocksws
    	run socks with websocket server
  -skiphostvalidation
    	skip host validation
  -socksaddr string
    	socks server address which listen to (default "127.0.0.1:8080")
  -wsaddr string
    	websocket server address which socks server connect to (default "127.0.0.1:8081")

```

## Tunnel to ssh using socat2

```BASH
$ ./socat TCP-LISTEN:2222,fork,reuseaddr "SOCKS5:<DIODE ADDRESS>.diode:22|tcp:localhost:8080"

# In a different terminal window
$ ssh pi@127.0.0.2 -p 2222
```

## Streaming video through websocket

* Start socks with websocket server

```BASH
$ go run main.go
```

* Start raspivid or any other stream service

```BASH
// profile must be baseline
$ raspivid -n -w 320 -h 180 -t 0 -l -o tcp://0.0.0.0:3030 -fps 12 -pf baseline
```

Then you can see streaming video through web/mplayer.

* Through mplayer
  ```BASH
  $ curl --socks5-hostname localhost:8080 <DIODE ADDRESS>.diode:9090 -o- | mplayer - -cache 1000
  ```

* Through examples/web

  ```BASH
  $ npm run dev
  ```

* Enable proxy settings in browser

  Firefox
  1. Open Preferences in menu or type `about:preferences` in search bar.
  2. Goto Network Settings and click `Settings` button.
  3. Setup `Automatic proxy configuration URL` to the porxy.pac, eg: `file:///Users/Guest/diode_go_client/proxy.pac`
  4. Click `reload` then you can proxy request from `*.diode` `*diode.ws` to the go client.

* Type the website URL and see `<MODE>.<DIODE ADDRESS>.diode:8082`.

  MODE:
  1. r: read
  2. w: write
  3. s: share