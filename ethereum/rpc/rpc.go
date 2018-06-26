package rpc

import (
	"context"
	"math/big"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/maiiz/coinlib/ethereum/ethclient"
	"github.com/maiiz/coinlib/ethereum/types"
	log "github.com/maiiz/coinlib/log"
)

// Client definies a wrapper of ethclient.
type Client struct {
	*ethclient.Client
}

// NewRPCClient returns a ethclient wrapper.
func NewRPCClient(client *ethclient.Client) *Client {
	return &Client{
		client,
	}
}

// GetBlock gets block by blockNumber.
func (c *Client) GetBlock(n *big.Int) *types.Block {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	block, err := c.BlockByNumber(ctx, n)
	if err != nil {
		log.Errorf("getBlock error %v - %+v", err, block)
		return nil
	}

	return block
}

// GetTransactionByHash gets transaction info by hash.
func (c *Client) GetTransactionByHash(h string) (*types.Transaction, *big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.TransactionByHash(ctx, common.HexToHash(h))
}

// GetTransactionReceipt detecting token transfer.
func (c *Client) GetTransactionReceipt(hash common.Hash) *types.Receipt {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	receipt, err := c.TransactionReceipt(ctx, hash)
	if err != nil {
		log.Errorf("getTransactionReceipt error %v - %+v", err, receipt)
		return nil
	}

	return receipt
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (c *Client) SuggestGasPrice() *big.Int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gasPrice, err := c.Client.SuggestGasPrice(ctx)
	if err != nil {
		return big.NewInt(5000000000)
	}

	return gasPrice
}

// SendRawTransaction sends tx to node.
func (c *Client) SendRawTransaction(tx *types.Transaction) error {
	ctx := context.Background()
	return c.SendTransaction(ctx, tx)
}

// EstimateGas tries to estimate the gas needed to execute a specific transaction.
func (c *Client) EstimateGas(msg ethereum.CallMsg) (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gas, err := c.Client.EstimateGas(ctx, msg)
	if err != nil {
		return big.NewInt(21000), nil
	}
	return gas, err
}
