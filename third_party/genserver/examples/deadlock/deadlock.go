// +build example

package main

import (
	"fmt"
	"time"

	"github.com/dominicletz/genserver"
)

// Connection example Deadlock
type Connection struct {
	gen  *genserver.GenServer
	peer *Peer
}

// Peer example Deadlock
type Peer struct {
	gen  *genserver.GenServer
	conn *Connection
}

// StartConnection runs the new Connection
func StartConnection() *Connection {
	gen := genserver.New("Connection")
	// default is 30 seconds but for this example we want to see the message quicker
	gen.DeadlockTimeout = 10 * time.Second
	conn := &Connection{gen: gen}
	conn.peer = StartPeer(conn)
	return conn
}

func (conn *Connection) SendGossipMessage() {
	conn.gen.Call(func() {
		conn.queryLoop()
	})
}

func (conn *Connection) queryLoop() {
	conn.handleSetEstablished()
}

func (conn *Connection) handleSetEstablished() {
	conn.peer.ConnEstablished()
}

// StartPeer runs the new Peer
func StartPeer(conn *Connection) *Peer {
	gen := genserver.New("localPeer")
	// default is 30 seconds but for this example we want to see the message quicker
	gen.DeadlockTimeout = 10 * time.Second
	return &Peer{gen: gen, conn: conn}
}

// ConnEstablished from Bryans presentation
func (peer *Peer) ConnEstablished() {
	peer.gen.Call(func() {
		peer.queryLoop()
	})
}

func (peer *Peer) queryLoop() {
	peer.handleAddConnection()
}

func (peer *Peer) handleAddConnection() {
	peer.conn.SendGossipMessage()
}

func main() {
	go func() {
		for i := 1; ; i++ {
			time.Sleep(time.Second)
			if i%10 == 0 {
				fmt.Printf("%d seconds have elapsed\n", i)
			}
		}
	}()

	conn := StartConnection()
	conn.SendGossipMessage()
}
