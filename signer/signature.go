package signer

import (
	"crypto/ecdsa"

	"github.com/maiiz/coinlib/crypto"
	"github.com/maiiz/coinlib/crypto/secp256k1"
	"github.com/maiiz/coinlib/keystore"
	"github.com/maiiz/coinlib/utils"
)

// SignWithPassphrase signs digest and returns signature.
func SignWithPassphrase(addresses []utils.Address,
	hash string,
	auth string,
	ks *keystore.KeyStore) (string, error) {

	var (
		priv *ecdsa.PrivateKey
		err  error
		sig  crypto.Signature
	)
	if len(addresses) == 1 {
		priv, err = ks.GetPrivkey(addresses[0], auth)
		if err != nil {
			return "no privatekey", err
		}

		b := priv.D.Bits()
		defer utils.ZeroMemory(b)
	}

	sig, err = (*secp256k1.PrivateKey)(priv).Sign(utils.HexToBytes(hash))
	if err != nil {
		return "", err
	}

	return utils.BytesToHex(sig.Bytes()), err
}
