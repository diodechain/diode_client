# Diode go client test

This is test program for connecting the target through diodechain concurrently.

# Run

1. Normal connection
```BASH
$ go run flag.go client_debug.go -conn 10
```

2. Transport with socks5 server
```BASH
$ go run flag.go client_debug.go -conn 10 -transport -socks5
```

3. Transport with http proxy server
```BASH
$ go run flag.go client_debug.go -conn 10 -transport -socks5=false -proxy
```

4. Transport with https proxy serve
> Note: make sure you host the tls server if the target is https protocol (in this condition, proxy will establish a https tunnel and send CONNECT request).
```BASH
$ go run flag.go client_debug.go -conn 10 -transport -socks5=false -proxy
```

# Command line options

```BASH
Usage:
  -conn int
    	total connection concurrently (default 100)
  -proxy
    	enable proxy transport
  -proxy_host string
    	host of proxy server (default "127.0.0.1")
  -proxy_port int
    	port of proxy server (default 80)
  -socks5
    	enable socks5 transport (default true)
  -socksd_host string
    	host of socks server (default "127.0.0.1")
  -socksd_port int
    	port of socks server (default 1080)
  -sproxy
    	enable secure proxy transport
  -sproxy_host string
    	host of secure proxy server (default "127.0.0.1")
  -sproxy_port int
    	port of secure proxy server (default 443)
  -target string
    	test target (default "http://pi-taipei.diode")
  -transport
    	enable http transport (default true)
```