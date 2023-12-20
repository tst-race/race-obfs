//
// Copyright 2023 Two Six Technologies
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
//

// Library to facilitate generation of necessary obfsX server info (nodeid, keypair, drbg-seed, iat-mode) during config-gen
// IAT: Inter-arrival Time = [0, 1, 2] - https://tor.stackexchange.com/questions/17981/what-is-iat-mode-at-the-end-of-obfs4s-bridge-lines

package main

import "C"

import (
	"github.com/RACECAR-GU/obfsX/common/ntor"
	"github.com/RACECAR-GU/obfsX/common/drbg"
	"github.com/google/uuid"
	"strings"
	"encoding/hex"
	golog "log"
	"unsafe"
	// "fmt" // main test
)

type IatMode int
const (
	IatMode_0 IatMode = 0
	IatMode_1 IatMode = 1
	IatMode_2 IatMode = 2
)

func (mode IatMode) String() string {
	switch mode {
	case IatMode_0:
		return "0"
	case IatMode_1:
		return "1"
	case IatMode_2:
		return "2"
	}
	return "-1"
}

// generate server config
// out, outSize used to allow buffer from another language
// out is returned to avoid having to manage go heap allocations

//export createServerConfig
func createServerConfig(iatMode IatMode, out *byte, outSize int64) (*byte) {
	golog.Printf("generating new server config")	

	uuidWithHyphens := uuid.New().String()
	uuidStr := strings.Replace(uuidWithHyphens, "-", "", -1)
	nodeId := hex.EncodeToString([]byte("race")) + uuidStr
	
	keyPair, err := ntor.NewKeypair(false)
	if err != nil {
		golog.Printf("error generating new key pair: %s", err.Error())
		return out
	}

	seedBytes, err := drbg.NewSeed()
	if err != nil {
		golog.Printf("error generating new DRBG seed: %s", err.Error())
		return out
	}

	publicKey := keyPair.Public().Hex()
	privateKey := keyPair.Private().Hex()
	drbgSeed := seedBytes.Hex()

	// format: {"node-id":"id","private-key":"key","public-key":"key","drbg-seed":"seed","iat-mode":mode}
	var sb strings.Builder
	sb.WriteString("{\"node-id\":\"")
	sb.WriteString(nodeId)
	sb.WriteString("\",\"private-key\":\"")
	sb.WriteString(privateKey)
	sb.WriteString("\",\"public-key\":\"")
	sb.WriteString(publicKey)
	sb.WriteString("\",\"drbg-seed\":\"")
	sb.WriteString(drbgSeed)
	sb.WriteString("\",\"iat-mode\":")
	sb.WriteString(iatMode.String())
	sb.WriteString("}")
	config := sb.String()

	// copy input into out (*byte)
	if outSize > int64(len(config)) { // not >= for null termination
		outPtr := (*[0x7fffffff]byte)(unsafe.Pointer(out))[:outSize:outSize]
		ix := 0
		for ; ix < len(config); ix++ {
			outPtr[ix] = config[ix]
		}
		outPtr[ix] = 0 // ensure null termination
	} else {
		golog.Printf("input buffer too small (%d <= %d)", outSize, len(config))
		return out
	}

	// golog.Printf("\nconfig %s\n", config)
	return out
}

func main() {
	// // test
	// var maxSize int64
	// maxSize = 512
	// var config = []byte{0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,

	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,

	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,

	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
	// 					0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,}

	// createServerConfig(0, &config[0], maxSize)
	// fmt.Printf("result (in underlying array): %s\n", string(config[:]))
}
