package keystore

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"log"
	"os"

	"github.com/maiiz/coinlib/crypto"
	"github.com/maiiz/coinlib/crypto/secp256k1"
	"github.com/maiiz/coinlib/params"
	"github.com/maiiz/coinlib/utils"
)

const (
	encryptKeySize          = 32
	walletFile              = "wallet.dat"
	changeAddressNum uint32 = 20
)

var (
	walletMagic = utils.HexToBytes("0901419396d7679bf46d7c0c28a7a8eb2d793bea3c9bea222e7eedc77dc7e174")

	ErrNoWalletFile    = errors.New("no wallet file")
	ErrKeyNotFind      = errors.New("key not find")
	ErrWrongPasspharse = errors.New("mac not match")
	ErrFileNotEmpty    = errors.New("wallet file not empty")
)

type (

	// EncryptKey represents a encrypt key.
	EncryptKey [encryptKeySize]byte
)

// KeyStore represents the key storage manager.
type KeyStore struct {
	file          *os.File
	keys          map[utils.Address][]byte
	salt, iv, mac []byte
}

// New returns a new keystore instance.
func New() *KeyStore {
	return &KeyStore{
		keys: make(map[utils.Address][]byte),
		salt: make([]byte, 32),
		iv:   make([]byte, 16),
		mac:  make([]byte, 32),
	}
}

// Open opens the wallet file and load wallet data.
func (ks *KeyStore) open() (err error) {
	f, err := utils.OpenFile(walletFile)
	if err != nil {
		panic(err)
	}
	ks.file = f
	return err
}

func (ks *KeyStore) write(b []byte) (n int, err error) { return ks.file.Write(b) }
func (ks *KeyStore) close() error                      { return ks.file.Close() }
func (ks *KeyStore) read(b []byte) (n int, err error)  { return ks.file.Read(b) }

// GenerateKeys generate many pair of private/public key, and write it to file.
func (ks *KeyStore) GenerateKeys(num uint32, auth string) error {
	ks.open()
	if ks.file != nil {
		fileInfo, err := ks.file.Stat()
		if err != nil {
			return err
		} else if fileInfo.Size() > 0 {
			return ErrFileNotEmpty
		}
		// Write Address
		addrFile, _ := utils.OpenFile("addrs.txt")
		defer addrFile.Close()

		// Write Change Address
		changeFile, _ := utils.OpenFile("changes.txt")
		defer changeFile.Close()

		// Write EncryptInfo
		ks.salt, ks.iv = crypto.GenEncryptInfo()
		derivedKey := crypto.GetDerivedKey(auth, ks.salt)
		ks.mac = crypto.Keccak256(derivedKey[16:32])

		ks.write(walletMagic)
		ks.write(ks.salt)
		ks.write(ks.iv)
		ks.write(ks.mac)

		// write length
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, num+changeAddressNum)
		ks.write(buf)

		// Write Address->Key
		for i := uint32(0); i < num+changeAddressNum; i++ {
			priv, pub := generateKey()
			addr := params.Params.AddressHashFunc(pub)
			encryptKey, err := crypto.Encrypt(derivedKey[:16], priv, ks.iv)
			if err != nil {
				panic(err)
			}

			ks.write(addr)
			if i < changeAddressNum {
				changeFile.WriteString(params.Params.ToAddress(addr))
				changeFile.WriteString("\n")
			} else {
				addrFile.WriteString(params.Params.ToAddress(addr))
				addrFile.WriteString("\n")
			}
			// addrFile.WriteString(fmt.Sprintf("0x%x%x\n", addr, priv))

			ks.write(encryptKey)
			ks.keys[utils.BytesToAddress(addr)] = encryptKey

		}
		ks.close()
		return nil
	}
	return ErrNoWalletFile
}

// Load loads wallet data.
func (ks *KeyStore) Load() error {
	if utils.FileExist(walletFile) {
		if err := ks.open(); err != nil {
			return err
		}

		// Read DecryptInfo
		var (
			magic = make([]byte, 32)
			buf   = make([]byte, 4)
		)
		log.Println("magic")
		log.Println(ks.read(magic))
		ks.read(ks.salt)
		ks.read(ks.iv)
		ks.read(ks.mac)

		ks.read(buf)
		num := binary.LittleEndian.Uint32(buf)
		log.Println(magic, ks.salt, ks.iv, ks.mac, buf)
		log.Printf("load keys %d addrs, %d change addrs", num, changeAddressNum)
		for i := uint32(0); i < num+changeAddressNum; i++ {
			var (
				addr       = make([]byte, 20)
				encryptKey = make([]byte, 32)
			)
			ks.read(addr)
			ks.read(encryptKey)

			ks.keys[utils.BytesToAddress(addr)] = encryptKey
		}
		return nil
	}
	return ErrNoWalletFile
}

// GetPrivkey gets privatekey by address.
func (ks KeyStore) GetPrivkey(addr utils.Address, auth string) (*ecdsa.PrivateKey, error) {
	// ks.mu.Lock()
	// defer ks.mu.UnLock()
	encryptKey, ok := ks.keys[addr]
	if !ok {
		return nil, ErrKeyNotFind
	}

	derivedKey := crypto.GetDerivedKey(auth, ks.salt)
	privBytes, err := crypto.Decrypt(derivedKey[:16], encryptKey, ks.iv, ks.mac)
	if err != nil {
		return nil, err
	}

	return (*ecdsa.PrivateKey)(secp256k1.ToECDSA(privBytes)), err
}

// AppendKeys appends keys to wallet file.
// TODO.
func (ks *KeyStore) AppendKeys(num int, auth string) error {
	return nil
}

func generateKey() (priv, pub []byte) {
	privKey, err := secp256k1.GenerateKey()
	if err != nil {
		panic(err)
	}

	return privKey.SecretBytes(), privKey.Public().Bytes()
}
