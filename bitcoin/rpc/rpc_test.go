package rpc

import (
	"fmt"
	"testing"
)

const (
	url = "http://111:111@127.0.0.1:8332"
)

func TestClient(t *testing.T) {
	client := DialHTTP(url)
	fmt.Println(client.GetBlockHash(4))

	fmt.Println(client.GetBlockByHash("3fec8d9e2a415fe14f5d94afc7e7688f57ce7b14df72c6dfe3e43877bc0e5277"))
	fmt.Println(client.GetRawTransaction("cf9aed205810e71907cffdcc9f4afd52def2b3f65c0c04cbf73723e2ab5f7082"))
	// client.Do()
}
