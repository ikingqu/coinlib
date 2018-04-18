package rpc

import (
	"encoding/json"
	"fmt"
	"testing"
)

const (
	url = "http://111:111@127.0.0.1:8332/"
)

func TestClient(t *testing.T) {
	fmt.Println(json.Marshal(nil))
	fmt.Println(json.Marshal([]byte{}))
	fmt.Println(json.Marshal([0]string{}))
	client, err := DialHTTP(url)
	var result float32
	fmt.Println("client.Call", client.Call("getbalance", nil, &result))
	var bestBlockHash string
	fmt.Println("client.Call", client.Call("getbestblockhash", nil, &bestBlockHash))
	fmt.Println("result", result, err, bestBlockHash, result)
	var blockhash []byte //= make([]byte, 1)
	var req = 1000
	client.Call("getblockhash", &req, &blockhash)
	fmt.Println("result2", result, err, blockhash, result)
	// client.Do()
}
