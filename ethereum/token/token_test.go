package token

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	address  = common.HexToAddress("0x46705dfff24256421a05d056c29e81bdc09723b8")
	value    = new(big.Int).Mul(big.NewInt(1058), big.NewInt(1e18))
	expInput = "0xa9059cbb00000000000000000000000046705dfff24256421a05d056c29e81bdc09723b80000000000000000000000000000000000000000000000395ab31279cb480000"
)

func TestPackParams(t *testing.T) {
	data, err := PackParams("transfer", address, value)
	if err != nil {
		t.Errorf("PackParams error %v", err)
	}
	if fmt.Sprintf("0x%x", data) != expInput {
		t.Errorf("expect input %s, not 0x%x", expInput, data)
	}
}

func TestUnpackTransferInput(t *testing.T) {
	a, v, err := UnpackTransferInput(common.Hex2Bytes(expInput[10:]))
	if a != address || value.Cmp(v) != 0 || err != nil {
		t.Errorf("UnpackTransferInput error, expect %s - %v, get %s - %v", address, value, a, v)
	}
}
