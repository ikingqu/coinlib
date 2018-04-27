package rsa

import (
	"testing"

	"github.com/maiiz/coinlib/utils"
)

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(2048)
	if err != nil {
		t.Errorf("generatekey error %v", err)
	}
	utils.WriteToFile(ExportKey(priv), "./test_rsa")
	pubBytes, err := ExportPubkey(&priv.PublicKey)
	if err != nil {
		t.Errorf("export publickey error %v", err)
	}
	utils.WriteToFile(pubBytes, "./test_rsa.pub")
}
