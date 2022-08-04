# Diode go client
[![Build Status](https://travis-ci.com/diodechain/diode_client.svg?branch=master)](https://travis-ci.com/diodechain/diode_client)
![CI](https://github.com/diodechain/diode_client/workflows/CI/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/diodechain/diode_client)](https://goreportcard.com/report/github.com/diodechain/diode_client)

This is Go client for connecting device through the diodechain mesh network. You can bridge your local resource to the internet with diodechain mesh network. The whole data will be encrypted with ecdh (secp256k1). You can find more details about how diode and its client works in our previous presentations https://github.com/diodechain/presentations and on https://diode.io

![Conceptual diagram](docs/diode.png)

*Conceptual diagram for diode*



# Usage

## Command line options

```BASH
Name
  diode - Diode network command line interface

SYNOPSYS
  diode [-allowlists=] [-api=false] [-apiaddr=localho...]
        [-bind=] [-blocklists=] [-blockprofile=] [-blockprofilerate=1]
        [-configpath=] [-cpuprofile=] [-dbpath=/Users/...] [-debug=false]
        [-diodeaddrs=] [-e2etimeout=5s] [-fleet=]
        [-keepalive=true] [-keepaliveinterval=5s] [-logdatetime=false] [-logfilepath=]
        [-memprofile=] [-metrics=false] [-mutexprofile=] [-mutexprofilerate=1]
        [-pprofport=0] [-retrytimes=3] [-retrywait=1s] [-rlimit_nofile=0]
        [-timeout=5s] [-update=true] COMMAND <args>

COMMANDS
  bns          Register/Update name service on diode blockchain.
  config       Manage variables in the local config store.
  gateway      Enable a public gateway server as is used by the "diode.link" website
  publish      Publish ports of the local device to the Diode Network.
  reset        Initialize a new account and a new fleet contract in the network. WARNING deletes current credentials!
  socksd       Enable a socks proxy for use with browsers and other apps.
  time         Lookup the current time from the blockchain consensus.
  token        Transfer DIODEs to the given address on diode blockchain.
  update       Force updating the diode client version.
  version      Print the diode client version.

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

## Use cases

### Publish a Local Webserver [Article link](https://support.diode.io/article/ss32engxlq-publish-your-local-webserver)

  Diode is the Swiss army knife of Web3 capabilities! One of the neat things it allows you to do is to publish a local website / webserver to the Internet where anyone can view it. A common reason for doing this is to allow others to see a website that is under development - the development is done locally and can be viewed by collaborators remotely without setting up a staging server and without any IT tools / configuration. 


### Develop LINE chatbots [Article link](https://diode.io/diode/How-Diode-Allows-Engineers-to-Develop-LINE-Chatbots-in-a-Decentralized-Way-20252/)

  Diode is the best tool in connecting LINE’s webhook - it allows you to connect LINE’s message API through Diode’s peer-to-peer network and establish your LINE’s webhook within minutes of time. We're giving everyone a better, more secure, fully decentralized option when developing LINE chatbots. 


## Enable Proxy Server in Browser

1. Start the socks server

```BASH
$ diode socksd
```

2. Configure Firefox

   1. Open Preferences in menu or type `about:preferences` in search bar.
   2. Goto Network Settings and click `Settings` button.
   3. Setup `Automatic proxy configuration URL` to the porxy.pac, eg: `file:///Users/Guest/diode_client/proxy.pac`
   4. Click `reload` then you can proxy request from `*.diode` `*diode.ws` to the go client.

3. Type the website URL and see. You can try `http://betahaus-berlin.diode` or `http://0xc206e1255cbace8ba904daa259d7a5b7f90e2d50.diode` and more general:

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

* go >= 1.14
* enable go module (see: https://blog.golang.org/using-go-modules)

  ```BASH
  export GO111MODULE=on
  ```

* optional: run dev diodechain locally (see: https://github.com/diodechain/diode_server_ex)

## Setup go environment

### macOS

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

Then you can check go version meets the requirement (>=1.14).

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
$ make
```

## Notes on debugging with pprof

To enable pprof on port 6060 run with `diode -pprofport 6060`
