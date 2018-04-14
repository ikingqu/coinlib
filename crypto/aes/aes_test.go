package aes

import (
	"bytes"
	"encoding/base64"
	"testing"
)

var (
	salt, iv  = GenEncryptInfo()
	password  = "woyouyizhixiaomaolv"
	plainText = "conlibcoinlibcoinlibconlibcoinlibcoinlibconlibcoinlibcoinlib"
)

func TestCBCEncrypt(t *testing.T) {
	derivedKey := GetDerivedKey(password, salt)
	cipherText, err := CBCEncrypt([]byte(plainText), derivedKey, iv)
	if err != nil {
		t.Errorf("CBCEncrypt error %s", err)
	}

	decryptText, err := CBCDecrypt(cipherText, derivedKey, iv)
	if !bytes.Equal(decryptText, []byte(plainText)) {
		t.Errorf("CBCDecrypt error %s", err)
	}
}

func TestCBCEncryptWithBase64(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString("rD3VAbDQTfZdLMuc9J1yP/t9hdshHKyZWvBjX3TUAJI=")
	iv, _ := base64.StdEncoding.DecodeString("vj2/VcvgZyFjdE9jROHQKQ==")
	input := "1BYAzjvRvYnj394XpeoJUn8dxdMBpxeUUC"
	cipherText := "z8EoBY_408rDmdtXf594mCipMnzFrolmLIc_4AMh1okrt4HTFQ-w5n_P67MpTkVP"
	enc, err := CBCEncrypt([]byte(input), key, iv)
	if err != nil {
		t.Errorf("CBCEncrypt error %s", err)
	}
	if base64.URLEncoding.EncodeToString(enc) != cipherText {
		t.Errorf("enc result error %x %x %x", enc, key, iv)
	}
}
