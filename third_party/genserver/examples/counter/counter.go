// +build example

package main

import (
	"fmt"
	"time"

	"github.com/dominicletz/genserver"
)

// Counter example Counter
type Counter struct {
	gen    *genserver.GenServer
	number int64
}

// StartCounter runs the new Counter
func StartCounter() *Counter {
	gen := genserver.New("Counter")
	return &Counter{gen: gen, number: 0}
}

// Incr increments the counter
func (counter *Counter) Incr() {
	counter.gen.Call(func() {
		fmt.Printf("Called Incr(): %d\n", counter.number)
		counter.number++
	})
}

// GetIncr is an example of composition of gen.Call()
// self-calls to the actor are recognized and resolved so this
// is not deadlocking
func (counter *Counter) GetIncr() (ret int64) {
	counter.gen.Call(func() {
		fmt.Printf("Called GetIncr(): %d\n", counter.number)
		counter.Incr()
		ret = counter.number
	})
	return ret
}

// Await uses the genserver.Terminate callback to block
// until the counter goroutine has finished
func (counter *Counter) Await() {
	wait := make(chan bool)
	counter.gen.Call(func() {
		counter.gen.Terminate = func() {
			fmt.Println("Exiting goroutine")
			wait <- true
		}
	})

	// Shutodwn(linger) will keep the counter running
	// for linger (5 seconds here) during which
	// all calls and casts are still being worked on
	fmt.Printf("Lingering for 5 seconds")
	counter.gen.Shutdown(5 * time.Second)
	<-wait
}

func main() {
	counter := StartCounter()
	for i := 0; i < 5; i++ {
		counter.Incr()
	}
	for i := 0; i < 5; i++ {
		counter.GetIncr()
	}

	counter.Await()
}
