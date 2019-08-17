DLT client

# Development
prerequisite
* go > 1.10
* GO111MODULE=on


1. Create Certificate

```BASH
	openssl ecparam -name secp256k1 -out secp256k1_params.pem
	openssl req -newkey ec:./secp256k1_params.pem -nodes -keyout device_key.pem -x509 -days 365 -out device_certificate.pem -subj "/CN=device"
```

2. Install dependencies

```BASH
$ go mod download
```

3. Run go test(not support yet)

```BASH
$ go test
```

4. Command line options

```BASH
Usage of:
  -debug
    	turn on debug mode
  -key2path string
    	another ssl client key (default "device2_key.pem")
  -keypath string
    	ssl client key (default "device_key.pem")
  -pempath string
    	ssl client certificate (default "device_certificate.pem")
  -remoterpcaddr string
    	remote rpc address (default "127.0.0.1:41043")
  -retrytimes int
    	retry times to connect the ssl server (default 3)
  -retrywait int
    	wait seconds before next retry (default 1)
  -runrpc
    	run rpc server
  -runsocks
    	run socks server
  -runsocksws
    	run socks with websocket server
  -skiphostvalidation
    	skip host validation
  -socksaddr string
    	socks server address which listen to (default "127.0.0.1:8080")
  -sockswsaddr string
    	socks with websocket server address which listen to (default "127.0.0.1:8079")
  -wsaddr string
    	websocket server address which socks server connect to (default "127.0.0.1:8081")
```

4. Run test

* Start a vlc server on localhost:9090

** For mac

```BASH
$ ./vlc-osx-static screen:// ":sout=#transcode{width=300,vcodec=mjpg,fps=15}:http{mux=ts,dst=localhost:9090/}" :no-sout-all
# Alternative: NetCat debug Server
$ nc -l 9090
```

** For linux

```BASH
$ TO DO
```

* Start a poc-server-ex

```BASH
$ ./run
```

* Start socks5 server and RPC server

```BASH
$ go run main.go -runrpc -runsocks -debug
```

* Start another RPC server

```BASH
$ go run main.go -runrpc -debug
```

* Try to connect with socks5 server

```BASH
$ curl --socks5-hostname localhost:8080 <PUBLIC KEY OF RPC SERVER2>.diode:9090 -o- | mplayer - -cache 1000
# Alternative: NetCat debug Client
$ nc -X 5 -x localhost:8080 GNRF2MU66CDUBPEVTLJCSOLX.diode 9090
```


* Example of tunneling to ssh using socat2

```BASH
$ ./socat TCP-LISTEN:2222,fork,reuseaddr "SOCKS5:3MGWKQNXHDB7OGZ2GYFVXWXV.diode:22|tcp:localhost:8080"
# In a different window
$ ssh pi@127.0.0.2 -p 2222
```

# Examples

1. Streaming video through websocket

* Start socks with websocket server
```BASH
$go run main.go -runsocks -runrpc -remoterpcaddr seed-alpha.diodechain.io:41043 -debug -runsocksws
```

* Start raspivid or any other stream service

```BASH
// profile must be baseline
$raspivid -n -w 320 -h 180 -t 0 -l -o tcp://0.0.0.0:3030 -fps 12 -pf baseline
```

* Start examples/web

```BASH
$npm run dev
```

Then open browser!
