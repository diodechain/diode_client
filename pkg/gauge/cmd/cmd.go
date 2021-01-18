// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"crypto/tls"
	"fmt"
	"github.com/diodechain/diode_go_client/config"
	"github.com/gdamore/tcell/v2"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
	// "github.com/gdamore/tcell/v2/views"
	"github.com/spf13/cobra"
)

var (
	gaugeCmd = &cobra.Command{
		Use:   "gauge",
		Short: "A client application to send request through diode network.",
		Long:  `This is a client program to send multiple requests through diode network concurrently.`,
		RunE:  clientDebugHandler,
	}
	cfg                      = &Config{}
	ErrUnsupportTransport    = fmt.Errorf("unsupported transport, make sure you use these options (proxy, sproxy, socks5)")
	ErrFailedSetRlimitNofile = fmt.Errorf("cannot set rlimit nofile")
	headerTemplate           = `                |    DNS Lookup   |  TCP Connection    |  Server Process    | Content Transfer |    Total     
`
	rowTemplate = `    Fetch #%-3d  |    %-10s   |    %-12s    |    %-12s    |   %-12s   | %-12s 
`
	errorRowTemplate = `    Fetch #%-3d  |    %-10s
`
	a *App
)

// App represents command line application for gauge
type App struct {
	screen tcell.Screen
	style  tcell.Style
	mx     sync.Mutex
	conns  map[net.Conn]net.Conn
}

// Init initialize the command line application
func (app *App) Init() (err error) {
	app.conns = make(map[net.Conn]net.Conn, cfg.Conn)
	app.style = tcell.StyleDefault.Background(tcell.ColorReset).Foreground(tcell.ColorReset)
	app.screen, err = tcell.NewScreen()
	if err != nil {
		return
	}
	if err = app.screen.Init(); err != nil {
		return
	}
	app.screen.SetStyle(app.style)
	return
}

// LoopEvent keep consuming the event from command line
func (app *App) LoopEvent() {
	for {
		ev := app.screen.PollEvent()

		switch ev := ev.(type) {
		case *tcell.EventResize:
			app.screen.Sync()
		case *tcell.EventKey:
			if ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyCtrlC {
				app.Stop()
				return
			}
		}
	}
}

// Println print the text at col x1, row y1
func (app *App) Println(x1, y1 int, text string) {
	col := x1
	row := y1
	for _, c := range text {
		app.screen.SetContent(col, row, c, nil, app.style)
		col++
	}
	app.screen.Show()
}

// Stop the application
func (app *App) Stop() {
	// clean connections
	for _, c := range app.conns {
		c.Close()
	}
	app.screen.Fini()
}

// addConn add new http connection
func (app *App) addConn(c net.Conn) {
	app.mx.Lock()
	app.conns[c] = c
	app.mx.Unlock()
}

// delConn delete existing http connection
func (app *App) delConn(c net.Conn) {
	app.mx.Lock()
	if _, ok := app.conns[c]; ok {
		c.Close()
		delete(app.conns, c)
	}
	app.mx.Unlock()
}

func clientDebugHandler(cmd *cobra.Command, args []string) (err error) {
	// initialize app
	a = new(App)
	if e := a.Init(); e != nil {
		return err
	}
	var proxyTransport *http.Transport = &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "socks5:",
			Host:   "localhost:33",
		}),
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	var tlsTransport *http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	var wg sync.WaitGroup
	var transport *http.Transport
	if cfg.EnableTransport {
		var prox *url.URL
		if cfg.EnableSocks5Transport {
			prox, _ = url.Parse(fmt.Sprintf("socks5://%s", cfg.SocksServerAddr()))
		} else if cfg.EnableProxyTransport {
			prox, _ = url.Parse(fmt.Sprintf("http://%s", cfg.ProxyServerAddr()))
		} else if cfg.EnableSProxyTransport {
			prox, _ = url.Parse(fmt.Sprintf("https://%s", cfg.SProxyServerAddr()))
			proxyTransport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			err = ErrUnsupportTransport
			return
		}
		proxyTransport.Proxy = http.ProxyURL(prox)
		transport = proxyTransport
	} else {
		transport = tlsTransport
	}
	if cfg.RlimitNofile > 0 {
		if err = config.SetRlimitNofile(cfg.RlimitNofile); err != nil {
			return
		}
	}
	col := 0
	row := 0
	a.Println(col, row, fmt.Sprintf("    Start to connect to %s for %d times", cfg.Target, cfg.Conn))
	row++
	a.Println(col, row, headerTemplate)
	row++
	wg.Add(cfg.Conn)
	for i := 0; i < cfg.Conn; i++ {
		a.Println(col, row, fmt.Sprintf(rowTemplate, i, "", "", "", "", ""))
		go func(j, row int, app *App) {
			var c net.Conn
			var t0, t1, t2, t3, t4 time.Time
			req, _ := http.NewRequest("GET", cfg.Target, nil)
			trace := &httptrace.ClientTrace{
				DNSStart: func(ds httptrace.DNSStartInfo) {
					t0 = time.Now()
				},
				DNSDone: func(ds httptrace.DNSDoneInfo) {
					t1 = time.Now()
				},
				ConnectStart: func(network, addr string) {
					if t0.IsZero() {
						t0 = time.Now()
					}
					if t1.IsZero() {
						t1 = time.Now()
					}
					a.Println(col, row, fmt.Sprintf(rowTemplate, j, t1.Sub(t0), "", "", "", ""))
				},
				ConnectDone: func(network, addr string, err error) {
					if err == nil {
						t2 = time.Now()
					}
					a.Println(col, row, fmt.Sprintf(rowTemplate, j, t1.Sub(t0), t2.Sub(t1), "", "", ""))
				},
				GotConn: func(cn httptrace.GotConnInfo) {
					t3 = time.Now()
					c = cn.Conn
				},
				GotFirstResponseByte: func() {
					t4 = time.Now()
					a.Println(col, row, fmt.Sprintf(rowTemplate, j, t1.Sub(t0), t2.Sub(t1), t4.Sub(t3), "", ""))
				},
			}
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
			resp, err := transport.RoundTrip(req)
			if err != nil {
				a.Println(col, row, fmt.Sprintf(errorRowTemplate, j, err.Error()))
				wg.Done()
				return
			}
			app.addConn(c)
			defer app.delConn(c)
			defer resp.Body.Close()
			_, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				a.Println(col, row, fmt.Sprintf(errorRowTemplate, j, err.Error()))
				wg.Done()
				return
			}
			t5 := time.Now()
			a.Println(col, row, fmt.Sprintf(rowTemplate, j, t1.Sub(t0), t2.Sub(t1), t4.Sub(t3), t5.Sub(t4), t5.Sub(t0)))
			wg.Done()
		}(i+1, row, a)
		row++
	}
	wg.Wait()
	a.Println(col, row, "Press ctrl + c or ESC to exit")
	a.LoopEvent()
	return
}

func init() {
	gaugeCmd.PersistentFlags().StringVarP(&cfg.Target, "target", "a", "http://pi-taipei.diode", "test target")
	gaugeCmd.PersistentFlags().BoolVarP(&cfg.EnableTransport, "transport", "b", true, "enable http transport")
	gaugeCmd.PersistentFlags().IntVarP(&cfg.Conn, "conn", "c", 100, "total connection concurrently")
	gaugeCmd.PersistentFlags().BoolVarP(&cfg.EnableSocks5Transport, "socks5", "d", true, "enable socks5 transport")
	gaugeCmd.PersistentFlags().StringVarP(&cfg.SocksServerHost, "socksd_host", "e", "127.0.0.1", "host of socks server")
	gaugeCmd.PersistentFlags().IntVarP(&cfg.SocksServerPort, "socksd_port", "f", 1080, "port of socks server")
	gaugeCmd.PersistentFlags().BoolVarP(&cfg.EnableProxyTransport, "proxy", "g", false, "enable proxy transport")
	gaugeCmd.PersistentFlags().StringVarP(&cfg.ProxyServerHost, "proxy_host", "i", "127.0.0.1", "host of proxy server")
	gaugeCmd.PersistentFlags().IntVarP(&cfg.ProxyServerPort, "proxy_port", "j", 80, "port of proxy server")
	gaugeCmd.PersistentFlags().BoolVarP(&cfg.EnableSProxyTransport, "sproxy", "k", false, "enable secure proxy transport")
	gaugeCmd.PersistentFlags().StringVarP(&cfg.SProxyServerHost, "sproxy_host", "l", "127.0.0.1", "host of secure proxy server")
	gaugeCmd.PersistentFlags().IntVarP(&cfg.SProxyServerPort, "sproxy_port", "m", 443, "port of secure proxy server")
	gaugeCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "enable verbose to show the response body")
	gaugeCmd.PersistentFlags().IntVarP(&cfg.RlimitNofile, "rlimit_nofile", "r", 0, "specify the file descriptor numbers that can be opened by this process")
}

// Execute the diode command
func Execute() error {
	return gaugeCmd.Execute()
}
