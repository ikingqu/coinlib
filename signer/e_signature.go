package signer

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/maiiz/coinlib/log"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/maiiz/coinlib/keystore"
	"github.com/maiiz/coinlib/utils"
)

// ESignTxWithPassphrase signs eth transaction.
func ESignTxWithPassphrase(
	addresses []utils.Address,
	txHex string,
	auth string,
	ks *keystore.KeyStore,
	chainID *big.Int) (string, error) {

	var (
		rawTx    *types.Transaction
		signedTx *types.Transaction
		err      error
		priv     *ecdsa.PrivateKey
	)
	log.Println("args", addresses, "txhex", txHex, "txbytes", utils.HexToBytes(txHex), chainID)
	if err = rlp.DecodeBytes(utils.HexToBytes(txHex), &rawTx); err != nil {
		log.Println("decode transaction error", txHex, utils.HexToBytes(txHex), err)
		return "decode transaction error", err
	}

	if len(addresses) == 1 {
		priv, err = ks.GetPrivkey(addresses[0], auth)
		if err != nil {
			return "no privatekey", err
		}

		b := priv.D.Bits()
		defer utils.ZeroMemory(b)
	}

	log.Println(rawTx)
	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		signedTx, err = types.SignTx(rawTx, types.NewEIP155Signer(chainID), priv)
	} else {
		signedTx, err = types.SignTx(rawTx, types.HomesteadSigner{}, priv)
	}
	if err != nil {
		return "", err
	}
	log.Printf("tx%+v", signedTx)
	txBytes, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return "", err
	}
	return utils.BytesToHex(txBytes), err
}
