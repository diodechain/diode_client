package main

import (
	"syscall/js"
	"io/ioutil"
	"fmt"
	"net/http"
	"net"
	// "sync"
)

var global =  js.Global()
var diodeRoot js.Value
// var wg sync.WaitGroup

func callRpc(this js.Value, args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		fmt.Println(err)
		return nil, fmt.Errorf("Please enter url")
	}
	url := args[0].String()
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("js.fetch:mode", "no-cors")
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	return body, nil
}

func listen(this js.Value, args []js.Value) (interface{}, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	fmt.Println("Start listener", ln)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		fmt.Println("New socks client:", conn.RemoteAddr(), " close connection...")
		conn.Close()
	}
	return nil, nil
}

func add(this js.Value, args []js.Value) (interface{}, error) {
	var ret float64

	for _, item := range args {
		if item.Type() == js.TypeNumber {
			val := item.Float()
			ret += val
		}
	}

	return ret, nil
}

func registrationWrapper(fn func(this js.Value, args []js.Value) (interface{}, error)) func(this js.Value, args []js.Value) interface{} {
	return func(this js.Value, args []js.Value) interface{} {
		cb := args[len(args)-1]

		ret, err := fn(this, args[:len(args)-1])

		if err != nil {
			cb.Invoke(err.Error(), js.Null())
		} else {
			cb.Invoke(js.Null(), ret)
		}

		return ret
	}
}

func err(this js.Value, args []js.Value) (interface{}, error) {
	return nil, fmt.Errorf("This is an error")
}

func init () {
	diodeRoot = global.Get("diode")
}

func main() {
	done := make(chan struct{}, 0)
	println("Web Assembly is ready")
	// wg.Add(1)

	diodeRoot.Set("add", js.FuncOf(registrationWrapper(add)))
	diodeRoot.Set("raiseError", js.FuncOf(registrationWrapper(err)))
	diodeRoot.Set("hhh", "Hello World")
	diodeRoot.Set("callRpc", js.FuncOf(registrationWrapper(callRpc)))
	diodeRoot.Set("listen", js.FuncOf(registrationWrapper(listen)))
	// wg.Wait()

	<-done
}
