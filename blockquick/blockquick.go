// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package blockquick

import (
	"fmt"
	"sync"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/util"
)

// Address represents an Ethereum address of a miner
type Address = util.Address

// Sha3 is a Sha3 hash
type Sha3 = crypto.Sha3

// Window is a state
type Window struct {
	mx          sync.RWMutex
	lastValid   *BlockScore
	finals      []*BlockScore
	pending     map[Sha3]*BlockScore
	minerCounts map[Address]int
	windowSize  int
}

// BlockScore keeps track of scores
type BlockScore struct {
	parent  *BlockScore
	bh      BlockHeader
	hash    Sha3
	miner   Address
	isFinal bool
}

// New creates a new BlockQuick window
func New(bhs []BlockHeader, windowSize int) (*Window, error) {
	if len(bhs) != windowSize {
		return nil, fmt.Errorf("provided block header count != window size (%v/%v)", len(bhs), windowSize)
	}

	win := &Window{
		pending:    make(map[Sha3]*BlockScore, windowSize),
		windowSize: windowSize,
	}

	bss := make([]*BlockScore, 0, windowSize)

	for i, bh := range bhs {
		if !bh.ValidateSig() {
			return nil, fmt.Errorf("block has an invalid signature %v", bhs)
		}
		bs := &BlockScore{
			bh:      bh,
			hash:    bh.Hash(),
			miner:   bh.Miner(),
			isFinal: true,
		}
		if i > 0 {
			if bs.bh.Parent() != bss[i-1].hash {
				return nil, fmt.Errorf("received non-follower block %v is not a parent of %v", bss[i-1], bh)
			}
			bs.parent = bss[i-1]
		}
		bss = append(bss, bs)
	}

	win.initialize(bss)
	return win, nil
}

// GetBlockHeader returns valid BlockHeaders from the window
// this only allows storing 'window_size' block headers
func (win *Window) GetBlockHeader(num uint64) (bh BlockHeader) {
	win.mx.Lock()
	defer win.mx.Unlock()

	if num == win.lastValid.bh.number {
		bh = win.lastValid.bh
		return
	}

	base := win.finals[0].bh.number
	offset := num - base
	if offset >= uint64(len(win.finals)) {
		return
	}
	bh = win.finals[offset].bh
	return
}

// Last is the peak of the finalized blocks and can be behind lastValid
// if a new lastValid has been validated using a couple of gapped blocks
func (win *Window) Last() (uint64, Sha3) {
	win.mx.Lock()
	defer win.mx.Unlock()

	return win.lastFinal().bh.number, win.lastFinal().hash
}

// lastFinal is the peak of the finalized blocks and can be behind lastValid
// if a new lastValid has been validated using a couple of gapped blocks
func (win *Window) lastFinal() *BlockScore {
	return win.finals[len(win.finals)-1]
}

// NeedsUpdate informs whether the window needs to be reinitialized
func (win *Window) NeedsUpdate() bool {
	win.mx.Lock()
	defer win.mx.Unlock()

	return win.lastValid.bh.number != win.lastFinal().bh.number
}

// Initialize creates a new window
func (win *Window) initialize(finals []*BlockScore) {
	win.finals = finals
	win.lastValid = win.lastFinal()
	win.minerCounts = make(map[Address]int, win.windowSize)
	for _, bs := range finals {
		win.minerCounts[bs.miner]++
	}
}

// collectGarbage deletes all pending blocks that are older than the last
// valid block
func (win *Window) collectGarbage() {
	lv := win.lastValid
	min := lv.bh.number
	for hash, bs := range win.pending {
		if bs.bh.number <= min {
			delete(win.pending, hash)
		}
	}

	if lv.bh.number > uint64(win.windowSize) {
		lowest_to_keep := lv.bh.number - uint64(win.windowSize)
		for p := lv; p != nil; p = p.parent {
			if p.bh.number < lowest_to_keep {
				p.parent = nil
				break
			}
		}
	}
}

// AddBlock adds a new block to the window
func (win *Window) AddBlock(bh BlockHeader, allowGap bool) error {
	win.mx.Lock()
	defer win.mx.Unlock()

	if !bh.ValidateSig() {
		return fmt.Errorf("invalid block header %v", bh)
	}

	if bh.number <= win.lastValid.bh.number {
		// Too old block
		return nil
	}

	hash := bh.Hash()
	if win.pending[hash] != nil {
		// Block exists already in pending
		return nil
	}

	bs := &BlockScore{
		bh:    bh,
		hash:  hash,
		miner: bh.Miner(),
	}

	// Linking the parent if possible
	if bh.Parent() == win.lastValid.hash {
		bs.parent = win.lastValid
	} else if bh.Parent() == win.lastFinal().hash {
		bs.parent = win.lastFinal()
	} else {
		bs.parent = win.pending[bh.Parent()]
	}

	// Gap check
	if bs.parent != nil {
		if bh.number != bs.parent.bh.number+1 {
			return fmt.Errorf("child number is wrong %v, %v", bh.number, bs.parent.bh.number)
		}
	} else if !allowGap {
		lfnum, lfhash := win.Last()
		return fmt.Errorf("last final is: %v %v, and don't know direct parent of this block %v", lfnum, util.EncodeToString(lfhash[:]), bh.number)
	}

	// Adding block
	win.pending[hash] = bs

	// Checking for children
	win.validate(bs)
	return nil
}

func (win *Window) threshold() int {
	return win.windowSize / 2
}

func (win *Window) validate(bs *BlockScore) {
	// This recursively checks whether there are any children (plural) of the
	// current block known, and if so validates them instead.
	skip := false
	for _, pending := range win.pending {
		if pending.bh.Parent() == bs.hash {
			pending.parent = bs
			win.validate(pending)
			skip = true
		}
	}
	if skip {
		return
	}

	var length int
	for p := bs; p != nil; p = p.parent {
		length++
	}
	if length < win.windowSize {
		// This could be validated, but not finalized as we can't rebuild the window
		// without at least windowSize blocks
		// so we just return and wait for more blocks to be validated
		return
	}

	visited := make(map[Address]bool)
	var score int

	for p := bs; p != nil && !p.isFinal; p = p.parent {
		if !visited[p.miner] {
			visited[p.miner] = true
			score += win.minerCounts[p.miner]
		}
		if score > win.threshold() {
			// Yay this block is confirmed by >50% of all mining power
			win.finalize(p)
			return
		}
	}
}

func (win *Window) finalize(bs *BlockScore) {
	if win.lastValid.bh.number >= bs.bh.number {
		fmt.Printf("Validated old block %+v\n", bs)
		return
	}

	// Checking whether there is a gap between the new last valid block and the old last valid
	gap := true

	// Collecting new final block headers
	// unfortunately they are newest -> oldest, so we need to reverse them next
	slanif := make([]*BlockScore, 0, win.windowSize)
	for p := bs; p != nil; p = p.parent {
		if win.lastValid == p {
			gap = false
			break
		}
		p.isFinal = true
		slanif = append(slanif, p)
	}

	// Reversing
	finals := make([]*BlockScore, 0, len(slanif))
	for i := range slanif {
		finals = append(finals, slanif[len(slanif)-(i+1)])
	}

	if gap {
		// Need to rebuild the window
		if len(finals) < win.windowSize {
			// Can't rebuild because there is not enough data
			return
		}
		win.initialize(finals)
	} else {
		// This should be the normal case when connected and listening
		// to block updates
		for _, bs := range finals {
			win.add(bs)
		}
	}

	win.collectGarbage()
}

func (win *Window) add(new *BlockScore) {
	win.minerCounts[new.miner]++
	win.finals = append(win.finals, new)
	// must be true
	// if len(win.finals) > win.windowSize {
	win.minerCounts[win.finals[0].miner]--
	win.finals = win.finals[1:]
	win.lastValid = new
	// }
}
