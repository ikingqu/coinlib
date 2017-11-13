package types

import "crypto"

// BlockHeader represents a BlockHeader.
type BlockHeader struct {
	Version       uint32
	PrevBlockHash crypto.Hash
	MerkleRoot    crypto.Hash
	Timestamp     int64
	Bits          uint32
	Nonce         uint32
}

// Block represents a block including all transactions in it.
type Block struct {
	Header BlockHeader

	Transactions []*Transaction
}
