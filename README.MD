# Diode go client

This is Go client for connecting device through the diodechain mesh network. You can find more details about how diode and its client works in our previous presentations https://github.com/diodechain/presentations and on https://diode.io

[![Build Status](https://travis-ci.com/diodechain/diode_go_client.svg?branch=master)](https://travis-ci.com/diodechain/diode_go_client)
![CI](https://github.com/diodechain/diode_go_client/workflows/CI/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/diodechain/diode_go_client)](https://goreportcard.com/report/github.com/diodechain/diode_go_client)

# Usage

## Command line options

```BASH
Name
  diode - Diode network command line interface

SYNOPSYS
  diode [-allowlists=] [-api=false] [-apiaddr=localho...]
        [-bind=] [-blocklists=] [-configpath=] [-cpuprofile=]
        [-dbpath=/Users/...] [-debug=false] [-diodeaddrs=] [-fleet=]
        [-keepalive=true] [-keepalivecount=4] [-keepaliveidle=30] [-keepaliveinterval=5]
        [-logfilepath=] [-memprofile=] [-metrics=false] [-retrytimes=3]
        [-retrywait=1] [-rlimit_nofile=0] [-timeout=5] COMMAND <args>

COMMANDS
  bns          Register/Update name service on diode blockchain.
  config       Manage variables in the local config store.
  httpd        Enable a public http server as is used by the "diode.link" website
  publish      Publish ports of the local device to the Diode Network.
  reset        Initialize a new account and a new fleet contract in the network. WARNING deletes current credentials!
  socksd       Enable a socks proxy for use with browsers and other apps.
  time         Lookup the current time from the blockchain consensus.

Run 'diode COMMAND --help' for more information on a command.
```

## Tunnel ssh using your diode socks proxy

On the client:

```BASH
$ diode socksd
$ ssh pi@<ADDRESS>.diode -o 'ProxyCommand=nc -X 5 -x localhost:1080 %h %p'
```

On the destination:
```BASH
$ diode publish -public 22:22
```

## Enable Proxy Server in Browser

1. Start the socks server

```BASH
$ diode socksd
```

2. Configure Firefox

   1. Open Preferences in menu or type `about:preferences` in search bar.
   2. Goto Network Settings and click `Settings` button.
   3. Setup `Automatic proxy configuration URL` to the porxy.pac, eg: `file:///Users/Guest/diode_go_client/proxy.pac`
   4. Click `reload` then you can proxy request from `*.diode` `*diode.ws` to the go client.

3. Type the website URL and see. You can try `http://pi-taipei.diode` or `http://0xc206e1255cbace8ba904daa259d7a5b7f90e2d50.diode` and more general:

```http://(<MODE>-)<DIODE ADDRESS>.diode<:PORT>```

  MODES:
  * "r" read-only
  * "w" write-only
  * "rw" read-write (default)
  * "rs" read-only shared
  * "ws" write-only shared
  * "rws" read-write shared


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
$ make test
```

## Build

```BASH
$ make build
```
