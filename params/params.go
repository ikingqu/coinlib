package params

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/maiiz/coinlib/crypto"
	"github.com/maiiz/coinlib/encoding/base58"
)

// ChainParams defines the chain parameters.
type ChainParams struct {
	PubkeyAddressPrefix byte
	IsCompressed        bool
	ScriptAddressPrefix byte
	PrivateKeyPrefix    byte

	// Segwit
	WitnessPubkeyPrefix     byte
	WitnessScriptAddrPrefix byte

	HDPrivateKeyPrefix [4]byte
	HDPublicKeyPrefix  [4]byte

	// DNSSeeds                []string
	// GenesisBlock            Block
	DefaultPort uint32
	RPCPort     uint32

	CoinbaseMaturity uint8
	Coin             *big.Int
	Currency         string

	AddressHashFunc func([]byte) []byte
	ToAddress       func([]byte) string

	TxGas   *big.Int
	ChainID *big.Int
}

const (
	BTC = "btc"
	LTC = "ltc"
	BCC = "bcc"
	ETH = "eth"
	ETC = "etc"
	XRP = "xrp"
)

var (
	// Params represents the coin parameters you select.
	Params *ChainParams

	btcMainnetParams = &ChainParams{
		PubkeyAddressPrefix: 0,
		IsCompressed:        true,
		ScriptAddressPrefix: 5,
		PrivateKeyPrefix:    128,

		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 8333,
		RPCPort:     8332,

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{0}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.StdEncoding.Encode(a)
		},

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),
		Currency:         BTC,
	}

	ltcMainnetParams = &ChainParams{
		PubkeyAddressPrefix: 48,
		IsCompressed:        true,
		ScriptAddressPrefix: 5,
		PrivateKeyPrefix:    176,

		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 9333,
		RPCPort:     9332,

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),
		Currency:         LTC,

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{48}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.StdEncoding.Encode(a)
		},
	}

	bccMainnetParams = &ChainParams{
		PubkeyAddressPrefix:     0,
		IsCompressed:            true,
		ScriptAddressPrefix:     5,
		PrivateKeyPrefix:        128,
		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 8333,
		RPCPort:     8332,

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{0}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.StdEncoding.Encode(a)
		},

		Currency: BCC,
	}

	ethMainnetParams = &ChainParams{
		// PubkeyAddressPrefix:     0,
		IsCompressed: false,
		// ScriptAddressPrefix:     0,
		// PrivateKeyPrefix:        0,
		// WitnessPubkeyPrefix:     0,
		// WitnessScriptAddrPrefix: 0,

		// HDPrivateKeyPrefix: [4]byte{0x00, 0x, 0xad, 0xe4},
		// HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		Currency:         ETH,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(1),
	}
	etcMainnetParams = &ChainParams{
		// PubkeyAddressPrefix:     0,
		IsCompressed: false,
		// ScriptAddressPrefix:     0,
		// PrivateKeyPrefix:        0,
		// WitnessPubkeyPrefix:     0,
		// WitnessScriptAddrPrefix: 0,

		// HDPrivateKeyPrefix: [4]byte{0x00, 0x, 0xad, 0xe4},
		// HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		Currency:         ETC,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(61),
	}

	rippleMainnetParams = &ChainParams{
		PubkeyAddressPrefix: 0,
		IsCompressed:        true,
		ScriptAddressPrefix: 5,
		PrivateKeyPrefix:    128,

		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 8333,
		RPCPort:     8332,

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{0}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.RippleEncoding.Encode(a)
		},

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),
		Currency:         BTC,
	}
)

// SelectChain selects the chain parameters to use
// coinType is one of 'bitcoin', 'litecoin'
// name is one of 'mainnet', 'testnet', or 'regtest'
// Default chain is 'mainnet'
func SelectChain(ct string) *ChainParams {
	switch strings.ToLower(ct) {
	case BTC:
		Params = btcMainnetParams
	case LTC:
		Params = ltcMainnetParams
	case BCC:
		Params = bccMainnetParams
	case ETH:
		Params = ethMainnetParams
	case ETC:
		Params = etcMainnetParams
	case XRP:
		Params = rippleMainnetParams
	}
	return Params
}
