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
        [-bind=] [-blockdomains=] [-blocklists=]
        [-blockprofile=] [-blockprofilerate=1]
        [-bnscachetime=10m0s] [-configpath=] [-cpuprofile=]
        [-dbpath=<path>] [-debug=false] [-diodeaddrs=]
        [-e2etimeout=15s] [-fleet=] [-logdatetime=false]
        [-logfilepath=] [-memprofile=] [-metrics=false]
        [-mutexprofile=] [-mutexprofilerate=1] [-pprofport=0]
        [-resolvecachetime=10m0s] [-retrytimes=3] [-retrywait=1s]
        [-rlimit_nofile=0] [-timeout=5s] [-tray=false] [-update=true] COMMAND <args>

COMMANDS
  bns         Register/Update name service on diode blockchain.
  config      Manage variables in the local config store.
  fetch       HTTP client over the Diode Network.
  gateway     Public gateway server as used by "diode.link".
  join        Join the Diode Network; watch on-chain properties and optionally manage WireGuard.
  publish     Publish local ports to the Diode Network.
  query       Query device/account information from the network.
  reset       Initialize a new account and fleet contract (DESTRUCTIVE).
  socksd      Start a local SOCKS5 proxy for browsers/apps.
  ssh         SSH via Diode network (beta; not on Windows).
  time        Lookup the current time from blockchain consensus.
  token       Transfer DIODE tokens to an address.
  update      Force update the diode client.
  version     Print the diode client version.

Run 'diode COMMAND --help' for command-specific flags and examples.
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

* go <= 1.22

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

### System Tray UI

- Enable the tray UI by passing `-tray=true` to any command that keeps the client running, e.g. `diode -tray=true publish ...`.
- Windows, macOS, and most Linux desktop environments are supported out of the box.
- Linux legacy AppIndicator: for older environments that require AppIndicator, build the legacy variant:
  - `make diode_tray_legacy` (uses `-tags legacy_appindicator`)

Notes:
- CGO must be enabled for tray builds (the default in our Makefile). The `diode` binary already includes tray support; no separate tray binary is needed.

## Notes on debugging with pprof

To enable pprof on port 6060 run with `diode -pprofport 6060`

## WireGuard Integration (Join Command)

Overview
- The `diode join` command can read a WireGuard configuration from the device’s on-chain `wireguard` property and configure a local WireGuard interface for the selected Diode network.
- The on-chain WireGuard config must NOT include a `PrivateKey`. The client generates and stores a private key locally and injects it into the final config file.
- One interface per Diode network: interface name and config path derive from the network, e.g. `wg-diode-prod` for mainnet and `wg-diode-dev` for testnet.

First Run Key Generation
- Generate your local WireGuard keypair and print the public key. You can run this with or without a contract address:
  - With address (normal): `diode join -wireguard <contract_address>`
  - Without address (key-only mode): `diode join -wireguard`
- Optional: specify a custom suffix for interface/config names:
  - `diode join -wireguard -suffix staging <contract_address>`
  - Works in key-only mode too: `diode join -wireguard -suffix staging`
- This creates `<iface>.key` in the platform WireGuard directory and prints the public key so you can add it to your on-chain config later. In key-only mode the command exits after printing the key.

Interface Names and Paths
- Default mapping:
  - Mainnet: interface `wg-diode-prod`
  - Testnet: interface `wg-diode-dev`
  - Local: interface `wg-diode-local`
- Custom suffix: use `-suffix <name>` to override the default (allowed: letters, digits, `.`, `_`, `-`). Example: `-suffix staging` -> `wg-diode-staging`.

Config file locations by OS
- Linux: `/etc/wireguard/wg-diode-<net>.conf`
- macOS: `/usr/local/etc/wireguard/wg-diode-<net>.conf`
- Windows: `C:\\Program Files\\WireGuard\\Data\\Configurations\\wg-diode-<net>.conf` (or user-local fallback)

Private Key Handling
- The client creates a private key on first use and stores it next to the config as `/etc/wireguard/wg-diode-<net>.key` (or the platform’s directory) with `0600` permissions.
- The client derives the public key and logs it for your reference. Keep the private key file secure.
  - If key creation fails due to permissions (e.g., Linux system path), run with elevated privileges (e.g., `sudo`).

On-Chain WireGuard Property
- Property key: `wireguard`
- Value: the WireGuard config content WITHOUT `PrivateKey`. Example:

```
[Interface]
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <remote-public-key>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = example.org:51820
PersistentKeepalive = 25
```

Notes
- Omit `PrivateKey` from the on-chain configuration. The client injects a locally generated key automatically.
- You may include additional fields in `[Interface]` (e.g., `Address`, `DNS`) and in `[Peer]` typically `PublicKey`, `AllowedIPs`, `Endpoint`, and `PersistentKeepalive`.

Bringing the Interface Up
- Linux/macOS: the client tries to enable the interface using `wg-quick up` automatically. If it fails due to permissions, run with administrative permissions or run manually:
  - `sudo wg-quick up /etc/wireguard/wg-diode-<net>.conf`
- Windows: import and activate the generated config in WireGuard for Windows (GUI), or install it as a service (admin shell):
  - `"C:\\Program Files\\WireGuard\\wireguard.exe" /installtunnelservice C:\\Program Files\\WireGuard\\Data\\Configurations\\wg-diode-<net>.conf`

Updating
- When the on-chain `wireguard` property changes, the client rewrites the config and attempts to re-enable the interface. Any manual edits will be overwritten; change the config on-chain instead.

Security
- The private key is never stored on-chain.
- The generated local key is stored with restrictive permissions. Ensure your system backups and access controls protect this file.
