// Copyright 2021 Dominic Letz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.

package genserver

import (
	"sync"
)

type closeableChannel struct {
	head *channelItem
	tail *channelItem

	open   bool
	lock   *sync.Mutex
	signal *sync.Cond
}

type channelItem struct {
	item func()
	next *channelItem
}

func newChannel() *closeableChannel {
	lock := &sync.Mutex{}
	return &closeableChannel{
		open:   true,
		signal: sync.NewCond(lock),
		lock:   lock,
	}
}

func (cc *closeableChannel) send(fun func()) bool {
	if fun == nil {
		return false
	}

	cc.lock.Lock()
	defer cc.lock.Unlock()

	if !cc.open {
		return false
	}
	if cc.head == nil {
		cc.tail = &channelItem{item: fun}
		cc.head = cc.tail
	} else {
		cc.tail.next = &channelItem{item: fun}
		cc.tail = cc.tail.next
	}
	cc.signal.Signal()
	return true
}

func (cc *closeableChannel) recv() (fun func()) {
	cc.lock.Lock()
	defer cc.lock.Unlock()

	for {
		// Case 1 item is readily waiting
		if cc.head != nil {
			fun = cc.head.item
			cc.head = cc.head.next
			return
		}

		// Case 2 no item and the channel is closed
		if !cc.open {
			return
		}

		// Case 3 item not closed but nothing available yet
		cc.signal.Wait()
	}
}

func (cc *closeableChannel) close() {
	cc.lock.Lock()
	defer cc.lock.Unlock()

	if cc.open {
		cc.open = false
		cc.signal.Signal()
	}
}
