package rpc

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestClient(t *testing.T) {
	fmt.Println(json.Marshal(nil))
	fmt.Println(json.Marshal([]byte{}))
	fmt.Println(json.Marshal([0]string{}))
	client, err := DialHTTP("http://111:222@192.168.8.80:8332")
	var result float32
	fmt.Println("client.Call", client.Call("getbalance", nil, &result))
	var bestBlockHash string
	fmt.Println("client.Call", client.Call("getbestblockhash", nil, &bestBlockHash))
	fmt.Println("result", result, err, bestBlockHash, result)
	var blockhash string
	var req = 1000
	client.Call("getblockhash", &req, &blockhash)
	fmt.Println("result2", result, err, blockhash, result)
	// client.Do()
}
