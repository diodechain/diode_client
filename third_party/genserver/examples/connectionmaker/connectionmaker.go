// +build example

package main

import (
	"fmt"

	"github.com/dominicletz/genserver"
)

// ConnectionMaker example actor
type ConnectionMaker struct {
	gen *genserver.GenServer
}

// StartConnectionMaker runs the new actor
func StartConnectionMaker() *ConnectionMaker {
	return &ConnectionMaker{gen: genserver.New("ConnectionMaker")}
}

// Add runs with a callback
func (cm *ConnectionMaker) Add(address string) {
	cm.gen.Call(func() {
		cm.addConnection(address)
	})
}

// String is an action with a return value
func (cm *ConnectionMaker) String() (ret string) {
	cm.gen.Call(func() {
		ret = cm.status()
	})
	return
}

func (cm *ConnectionMaker) addConnection(address string) {
	fmt.Printf("addConnection(%s)\n", address)
}

func (cm *ConnectionMaker) status() string {
	return "ok"
}

func main() {
	cm := StartConnectionMaker()
	cm.Add("some_address")
	fmt.Printf("string() => %s\n", cm.String())
}
