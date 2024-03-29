# Diode go client test

This is a client program to send multiple requests through diode network concurrently.

![gauge demo](/docs/gauge.gif)

# Run

1. Normal connection
```BASH
$ gauge -conn 10
```

2. Transport with socks5 server
```BASH
$ gauge -conn 10 -transport -socks5
```

3. Transport with http proxy server
```BASH
$ gauge --conn 10 --transport --socks5=false --proxy
```

4. Transport with https proxy serve
> Note: make sure you host the tls server if the target is https protocol (in this condition, proxy will establish a https tunnel and send CONNECT request).
```BASH
$ go run gauge.go --conn 10 --transport --socks5=false --proxy
```

# Command line options

```BASH
This is a client program to send multiple requests through diode network concurrently.

Usage:
  gauge [flags]

Flags:
  -c, --conn int             total connection concurrently (default 100)
  -h, --help                 help for gauge
  -g, --proxy                enable proxy transport
  -i, --proxy_host string    host of proxy server (default "127.0.0.1")
  -j, --proxy_port int       port of proxy server (default 80)
  -r, --rlimit_nofile int    specify the file descriptor numbers that can be opened by this process
  -d, --socks5               enable socks5 transport (default true)
  -e, --socksd_host string   host of socks server (default "127.0.0.1")
  -f, --socksd_port int      port of socks server (default 1080)
  -k, --sproxy               enable secure proxy transport
  -l, --sproxy_host string   host of secure proxy server (default "127.0.0.1")
  -m, --sproxy_port int      port of secure proxy server (default 443)
  -a, --target string        test target (default "http://betahaus-berlin.diode")
  -b, --transport            enable http transport (default true)
  -v, --verbose              enable verbose to show the response body
```
