# Diode go client test

This is test program for connecting the target through diodechain concurrently.

# Run

```BASH
$ go run flag.go main.go -conn 10
```

# Command line options

```BASH
Usage:
  -conn int
    	total connection concurrently (default 100)
  -socksd_host string
    	host of socks server (default "127.0.0.1")
  -socksd_port int
    	port of socks server (default 1080)
  -target string
    	test target (default "http://pi-taipei.diode")
  -transport
    	enable http transport (default true)
```