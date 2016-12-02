// Copyright (c) 2016, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pose

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
)

type Chain struct {
	db *leveldb.DB // Database holding all the blocks

	chainLock   *sync.Mutex
	size        int
	confirmTime int
	main        *Block            // Last block in the "main" (i.e., longest) chain
	others      map[string]*Block // Other blocks that came in to the network in a chain
}

// TODO: Chain's file probably should be protected using CloudProxy..
func NewChain(dbFile string, confirmTime int) (*Chain, error) {
	db, err := leveldb.OpenFile(dbFile, nil)
	if err != nil {
		return nil, err
	}

	sb, err := db.Get([]byte("Size"), nil)
	if err == leveldb.ErrNotFound {
		sb = []byte{0, 0, 0, 0, 0, 0, 0, 0}
		err = db.Put([]byte("Size"), sb, nil)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint64(sb)

	mb, err := db.Get(sb, nil)
	if err == leveldb.ErrNotFound {
		mb, _ = proto.Marshal(GENESIS)
	} else if err != nil {
		return nil, err
	}
	main := &Block{}
	err = proto.Unmarshal(mb, main)
	if err != nil {
		return nil, err
	}

	chain := &Chain{
		db: db,

		size:        int(size),
		confirmTime: confirmTime,
		main:        main,

		chainLock: new(sync.Mutex),
		others:    make(map[string]*Block),
	}

	return chain, nil
}

func (c *Chain) SetConfirmTime(confirmTime int) {
	c.chainLock.Lock()
	defer c.chainLock.Unlock()
	c.confirmTime = confirmTime
}

func (c *Chain) MainBlock() *Block {
	c.chainLock.Lock()
	defer c.chainLock.Unlock()
	return c.main
}

// If the block is less than the index that's already written out,
// just ignore the block.
// Else, add the block to "others". If this makes the chain sufficiently large,
// then permanently write it out to the chain.
func (c *Chain) AddBlock(block *Block) error {
	// TODO: Current implementation just overwrites the whole chain every
	// time something longer comes around.. Should find a better way..
	c.chainLock.Lock()
	defer c.chainLock.Unlock()

	bb, err := proto.Marshal(block)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(bb)
	c.others[string(hash[:])] = block

	// Longest chain..
	if *block.Index > *c.main.Index {
		c.main = block
	}

	chainLen := 1
	key := block.PrevBlock
	idx := *block.Index - 1
	for {
		b, ok := c.others[string(key)]
		if !ok {
			b, err = c.Block(int(idx))
			if err == leveldb.ErrNotFound {
				break
			}
		}

		chainLen++
		idx--
		// Confirm blocks longer than certain length
		if chainLen > c.confirmTime {
			if err := c.StoreBlock(b); err != nil {
				return err
			}
			//delete(c.others, string(key))
		}
		key = b.PrevBlock
	}
	return nil
}

func (c *Chain) Block(idx int) (*Block, error) {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, uint64(idx))
	bb, err := c.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	block := &Block{}
	err = proto.Unmarshal(bb, block)
	return block, err
}

// Commit a block into our chain
func (c *Chain) StoreBlock(block *Block) error {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, uint64(*block.Index))
	value, err := proto.Marshal(block)
	if err != nil {
		return err
	}
	err = c.db.Put(key, value, nil)
	if int(*block.Index) > c.size {
		c.size = int(*block.Index)
	}
	return err
}

func (c *Chain) Close() error {
	return c.db.Close()
}
