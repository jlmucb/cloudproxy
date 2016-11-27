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

package time_client

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"sync"
	"testing"

	"github.com/golang/protobuf/proto"
)

var dbPath string = "/tmp/chain"

func addRandomBlocks(chain *Chain, num int) ([]*Block, error) {
	gb, err := proto.Marshal(GENESIS)
	if err != nil {
		return nil, err
	}

	blocks := make([]*Block, num+1)
	hash := sha256.Sum256(gb)
	for i := 1; i <= 2*CONFIRM_TIME; i++ {
		idx := int64(i)
		data := make([]byte, 64)
		rand.Read(data)
		prev := make([]byte, sha256.Size)
		copy(prev, hash[:])
		blocks[i] = &Block{
			PrevBlock:  prev,
			Index:      &idx,
			Difficulty: nil,
			Creator:    nil,
			Data:       data,
		}
		chain.AddBlock(blocks[i])

		bb, err := proto.Marshal(blocks[i])
		if err != nil {
			return nil, err
		}
		hash = sha256.Sum256(bb)
	}
	return blocks, nil
}

func TestAddChain(t *testing.T) {
	chain, err := NewChain(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer chain.Close()

	blocks, err := addRandomBlocks(chain, 2*CONFIRM_TIME)
	if err != nil {
		log.Fatal(err)
	}

	if chain.size != CONFIRM_TIME {
		log.Fatal(errors.New("Did not confirm the right number of blocks"), chain.size, CONFIRM_TIME)
	}

	for i := 1; i < CONFIRM_TIME; i++ {
		block, err := chain.Block(i)
		if err != nil {
			log.Fatal(err)
		}
		if len(block.Data) != len(blocks[i].Data) {
			log.Fatal(errors.New("Chain did not store blocks correctly"))
		}
		for d := range block.Data {
			if block.Data[d] != blocks[i].Data[d] {
				log.Fatal(errors.New("Chain did not store blocks correctly"))
			}
		}
	}
}

func TestFork(t *testing.T) {
	chain, err := NewChain(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	wg := new(sync.WaitGroup)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := addRandomBlocks(chain, 2*CONFIRM_TIME)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
	wg.Wait()

	if chain.size != CONFIRM_TIME {
		log.Fatal(errors.New("Did not confirm the right number of blocks"), chain.size, CONFIRM_TIME)
	}

	block, err := chain.Block(CONFIRM_TIME)
	if err != nil {
		log.Fatal(err)
	}
	hash := block.PrevBlock

	for i := CONFIRM_TIME - 1; i > 0; i-- {
		cur, err := chain.Block(i)
		if err != nil {
			log.Fatal(err)
		}
		cb, err := proto.Marshal(cur)
		if err != nil {
			log.Fatal(err)
		}
		curHash := sha256.Sum256(cb)
		for h := range curHash {
			if curHash[h] != hash[h] {
				log.Fatal(errors.New("Incorrect chain"))
			}
		}
		hash = cur.PrevBlock
	}
}
