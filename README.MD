# Diode go client

This is Go client for connecting device through diodechain. You can found more detail about how diodechain/client works in our previous presentations https://github.com/diodechain/presentations.

[![Build Status](https://travis-ci.com/diodechain/diode_go_client.svg?branch=master)](https://travis-ci.com/diodechain/diode_go_client)

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

or

```BASH
$ make test
```

## Build

```BASH
$ go build
```

or

```BASH
$ make build
```

# Examples

## Command line options

```BASH
Name
  diode - Diode network command line interfaces
SYNOPSIS
  diode [OPTIONS] COMMAND [ARG...]
OPTIONS
  -blacklists string
    	addresses are not allowed to connect to published resource (worked when whitelists is empty)
  -dbpath string
    	file path to db file (default "./db/private.db")
  -debug
    	turn on debug mode
  -diodeaddrs string
    	addresses of Diode node server (default "asia.testnet.diode.io:41045,europe.testnet.diode.io:41045,usa.testnet.diode.io:41045")
  -fleet string
    	fleet contract address (default "0x6000000000000000000000000000000000000000")
  -keepalive
    	enable tcp keepalive (only Linux >= 2.4, DragonFly, FreeBSD, NetBSD and OS X >= 10.8 are supported) (default true)
  -keepalivecount int
    	the maximum number of keepalive probes TCP should send before dropping the connection (default 4)
  -keepaliveidle int
    	the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes (default 30)
  -keepaliveinterval int
    	the time (in seconds) between individual keepalive probes (default 5)
  -metrics
    	enable metrics stats
  -registry string
    	registry contract address (default "0x5000000000000000000000000000000000000000")
  -retrytimes int
    	retry times to connect the remote rpc server (default 3)
  -retrywait int
    	wait seconds before next retry (default 1)
  -rlimit_nofile int
    	specify the file descriptor numbers that can be opened by this process
  -skiphostvalidation
    	skip host validation
  -timeout int
    	timeout seconds to connect to the remote rpc server (default 5)
  -whitelists string
    	addresses are allowed to connect to published resource (worked when whitelists is empty)
COMMANDS
  config
    This command manages variables in the local config store.
    ARG
      -delete value
    	deletes the given variable from the config
      -list
    	list all stored config keys
      -set value
    	sets the given variable in the config
    EXAMPLE
      diode config -delete lvbn2 -delete lvbn
  publish
    This command publishes ports of the local device to the Diode Network.
    ARG
      -private value
    	expose ports to private users, so that user could connect to
      -protected value
    	expose ports to protected users (in fleet contract), so that user could connect to
      -public value
    	expose ports to public users, so that user could connect to
    EXAMPLE
      diode publish -public 80:80 -public 8080:8080 -protected 3000:3000 -protected 3001:3001 -private 22:22,0x......,0x...... -private 33:33,0x......,0x......
  socksd
    This command enables a socks proxy on the local host for use with Browsers (Firefox), SSH, Java and other applications to communicate via the Diode Network.
    ARG
      -socksd_host string
    	host of socks server listening to (default "127.0.0.1")
      -socksd_port int
    	port of socks server listening to (default 1080)
    EXAMPLE
      diode socksd -socksd_port 8082 -socksd_host 127.0.0.1
  httpd
    This command enables a public http server as is used by the "diode.link" website
    ARG
      -allow_redirect
    	allow redirect all http transmission to httpsd
      -certpath string
    	Pem format of certificate file path of httpsd secure server (default "./priv/cert.pem")
      -httpd_host string
    	host of httpd server listening to (default "127.0.0.1")
      -httpd_port int
    	port of httpd server listening to (default 80)
      -httpsd_host string
    	host of httpsd server listening to (default "127.0.0.1")
      -httpsd_port int
    	port of httpsd server listening to (default 443)
      -privpath string
    	Pem format of private key file path of httpsd secure server (default "./priv/priv.pem")
      -proxy_host string
    	host of socksd proxy server (default "127.0.0.1")
      -proxy_port int
    	port of socksd proxy server (default 1080)
      -secure
    	enable httpsd server
      -socksd
    	enable socksd proxy server
    EXAMPLE
      diode httpd -httpd_port 8080 -httpsd_port 443 -secure -certpath ./cert.pem -privpath ./priv.pem
```

## Tunnel to ssh using your diode socks proxy

```BASH
$ diode_go_client socksd
$ ssh pi@<ADDRESS>.diode -o 'ProxyCommand=nc -X 5 -x localhost:1080 %h %p'
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
  $ curl --socks5-hostname localhost:1080 <DIODE ADDRESS>.diode:3030 -o- | mplayer - -cache 1000
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

* Type the website URL and see, url could be `<MODE>-<DIODE ADDRESS>.diode<:PORT>` or `<MODE>-<DIODE ADDRESS>-<:PORT>.diode`.

  MODE:
  1. r: read
  2. w: write
  3. s: share
