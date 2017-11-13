package script

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MaxScriptElementSize defines Maximum number of bytes pushable to the stack.
	MaxScriptElementSize = 520

	// MaxOpsPerScript defines Maximum number of non-push operations per script.
	MaxOpsPerScript = 201

	// MaxPubkeysPerMultisig defines Maximum number of public keys per multisig.
	MaxPubkeysPerMultisig = 20

	// MaxScriptSize defines Maximum script length in bytes.
	MaxScriptSize = 10000

	// MaxStackSize defines Maximum number of values on script interpreter stack.
	MaxStackSize = 1000

	// LocktimeThreshold defines Threshold for nLockTime: below this value it is interpreted as block number
	// otherwise as UNIX timestamp.
	LocktimeThreshold = 500000000 // Tue Nov  5 00:53:20 1985 UTC

	// MaxOpCode defines Maximum value that an opcode can be.
	MaxOpCode = OP_NOP10
)

// Script represents the Serialized script, used inside transaction inputs and outputs.
type Script []byte

// SigOp represents the oprations of every step in script.
type SigOp struct {
	code int
	data []byte
	i    int
}

// Bytes returns the bytes of the script.
func (s Script) Bytes() []byte {
	return s[:]
}

func (s Script) Marshal(w io.Writer) []byte {
	return nil
}

// AddBytes appends bytes to scripts.
func (s Script) AddBytes(data []byte) {
	s = append(s, data...)
}

// AddOpCode adds byte to script.
func (s Script) AddOpCode(opCode int) {
	if opCode < 0 || opCode > 0xff {
		panic(fmt.Errorf("Script AddOpCode error: invalid opcode %d", opCode))
	}
	s = append(s, byte(opCode))
}

// AddInt64 adds int64 to script.
func (s Script) AddInt64(n int64) {
	if n == -1 || (n >= 1 && n <= 16) {
		s = append(s, byte(n+(OP_1-1)))
	} else if n == 0 {
		s = append(s, byte(OP_0))
	} else {
		s.AddBytes(BigNumber(n).Bytes())
	}
}

// PushData Encodes a PUSHDATA op, returning bytes.
func (s *Script) PushData(data []byte) {
	bb := new(bytes.Buffer)
	if len(data) < OP_PUSHDATA1 {
		bb.Write([]byte{byte(len(data))})
	} else if len(data) <= 0xff {
		bb.Write([]byte{OP_PUSHDATA1})
		bb.Write([]byte{byte(len(data))})
	} else if len(data) <= 0xffff {
		bb.Write([]byte{OP_PUSHDATA2})
		binary.Write(bb, binary.LittleEndian, uint16(len(data)))
	} else {
		bb.Write([]byte{OP_PUSHDATA4})
		binary.Write(bb, binary.LittleEndian, uint32(len(data)))
	}
	bb.Write(data)
	s.AddBytes(bb.Bytes())
}

// GetOp returns the sigOps in the script.
func (s Script) GetOp(i int) (opCodeRet int, data []byte, idx int, ok bool) {
	var (
		dataSize   int
		scriptSize = len(s)
	)

	opCodeRet = OP_INVALIDOPCODE
	ok = true

	if i >= scriptSize || scriptSize-i < 1 {
		return opCodeRet, nil, i, false
	}

	opCode := int(s[i])
	i++

	if opCode <= OP_PUSHDATA4 {
		if opCode < OP_PUSHDATA1 {
			dataSize = int(opCode)
		} else if opCode == OP_PUSHDATA1 {
			if scriptSize-i < 1 {
				ok = false
			} else {
				dataSize = int(s[i])
				i++
			}
		} else if opCode == OP_PUSHDATA2 {
			if scriptSize-i < 2 {
				ok = false
			} else {
				dataSize = int(s[i]) + (int(s[i+1]) << 8)
				i += 2
			}
		} else if opCode == OP_PUSHDATA4 {
			if scriptSize-i < 4 {
				ok = false
			} else {
				dataSize = int(s[i]) + int(s[i+1])<<8 + int(s[i+2])<<16 + int(s[i+3])<<24
				i += 4
			}
		}
	}

	if dataSize > 0 {
		data = s[i:dataSize]
	}

	return opCode, data, i, ok
}

// GetSigOpCount defines Accurately count sigOps, including sigOps in pay-to-script-hash transactions.
func (s Script) GetSigOpCount(fAccurate bool) int {
	var (
		n          int
		opCode     = OP_INVALIDOPCODE
		lastOpCode = OP_INVALIDOPCODE
		ok         bool
	)

	for i := 0; i < s.Size(); i++ {
		if opCode, _, i, ok = s.GetOp(i); !ok {
			break
		}
		if opCode == OP_CHECKSIG || opCode == OP_CHECKSIGVERIFY {
			n++
		} else if opCode == OP_CHECKMULTISIG || opCode == OP_CHECKMULTISIGVERIFY {
			if fAccurate && (lastOpCode >= OP_1 && lastOpCode <= OP_16) {
				n += DecodeOPN(lastOpCode)
			} else {
				n += MaxPubkeysPerMultisig
			}
		}
		lastOpCode = opCode
	}

	return n
}

// IsP2SH returns if the script is a p2sh scriptPubKey.
func (s Script) IsP2SH() bool {
	// Extra-fast test for pay-to-script-hash CScripts:
	return (len(s) == 23 &&
		s[0] == OP_HASH160 &&
		s[1] == 0x14 &&
		s[22] == OP_EQUAL)
}

// IsP2WSH returns if the script is a scriptpubkey signaling segregated witness.
func (s Script) IsP2WSH() bool {
	// Extra-fast test for pay-to-witness-script-hash CScripts:
	return (len(s) == 34 &&
		s[0] == OP_0 &&
		s[1] == 0x20)
}

// IsWitnessProgram aa
// A witness program is any valid CScript that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes.
func (s Script) IsWitnessProgram(version int, program []byte) bool {
	scriptSize := len(s)
	if scriptSize < 4 || scriptSize > 42 {
		return false
	}
	if s[0] != OP_0 && (s[0] < OP_1 || s[0] > OP_16) {
		return false
	}
	if int(s[1]+2) == scriptSize {
		version = DecodeOPN((int)(s[0]))
		program = s[2:scriptSize]
		return true
	}
	return false
}

// IsPushOnly returns if the script only contains pushdata ops.
// Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
func (s Script) IsPushOnly() bool {
	var (
		opCode int
		ok     bool
	)
	for i := 1; i < len(s); i++ {
		if opCode, _, i, ok = s.GetOp(i); ok {
			return false
		}
		// Note that IsPushOnly() *does* consider OP_RESERVED to be a
		// push-type opcode, however execution of OP_RESERVED fails, so
		// it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
		// the P2SH special validation code being executed.
		if opCode > OP_16 {
			return false
		}
	}
	return true
}

// HasValidOps Checks if the script contains valid OP_CODES.
func (s Script) HasValidOps() bool {
	var (
		opCode int
		data   []byte
		i      int
		ok     bool
	)
	for i = 0; i < len(s); i++ {
		if opCode, data, i, ok = s.GetOp(i); ok || opCode > MaxOpCode || len(data) > MaxScriptElementSize {
			return false
		}
	}
	return true
}

// IsUnspendable Returns whether the script is guaranteed to fail at execution,
// regardless of the initial stack. This allows outputs to be pruned
// instantly when entering the UTXO set.
func (s Script) IsUnspendable() bool {
	return (len(s) > 0 && int(s[0]) == OP_RETURN) || (len(s) > MaxScriptSize)
}

// Size returns the length of the script.
func (s Script) Size() int {
	return len(s)
}

// func (s *Script) Reset() {
//
// }

// P2PKH DUP HASH160 PUSHDATA(20)[679fbd5c5e5146d61b00042a3c68f8682651aa66] EQUALVERIFY CHECKSIG
// P2SH HASH160 PUSHDATA(20)[355fa493f0dc8795f3ba4dfdce346a51c6008375] EQUAL

// ScriptSig:
// PUSHDATA(72)[3045022100da92e9bd2dd926acd062bfc5cc694ed4639fc092d154321a064313b64708e36b022040377fe4d632fd87fac9b2d52c82c184b579eb7179defdd4dd826fd98d9e0a5901]
// PUSHDATA(33)[038836175234670ee4c53943900615248f4a007b002b3c91c84c3edae009b9af3b]

// ScriptSig:
// 0[]
// PUSHDATA(71)[304402202d36d44387d92366d3c5469f26bc413e907564bd646f304f37eefab1371242d902200b0f0ed43a9f66b8e0da96907fdcdd362d5a66ca8fce041d7f20f8024dcaf66b01]
// PUSHDATA(72)[304502210090ca8f60035a0d2d42417714b1b702cb21b77fe7540436c8526736dd5cc40b60022038d6a1552710b90120d8c3a4c669fd6f3b878d1fb87fee453e693dd75d8854ec01]
// PUSHDATA1[5221023df3558b2d0cd5ac358a3f0a6d10b4f8fd74af7fc5c18e6b502d56768c1acf1b2102c977fbf3fb7919d6d0411a001113510f0c9e4b74988e749378e77aa465beda71210240dbbb25ce93a544a47002af049d33f04465a886b967fb6375cd2c88902b69e453ae]

func (s Script) ToP2SHScriptPubkey() Script {
	// Create P2SH scriptPubKey from this redeemScript
	// That is, create the P2SH scriptPubKey that requires this script as a
	// redeemScript to spend.
	// checksize - Check if the redeemScript is larger than the 520-byte max
	// pushdata limit; raise ValueError if limit exceeded.
	// Since a >520-byte PUSHDATA makes EvalScript() fail, it's not actually
	// possible to redeem P2SH outputs with redeem scripts >520 bytes.

	// if checksize and len(self) > MAX_SCRIPT_ELEMENT_SIZE:
	// 	raise ValueError("redeemScript exceeds max allowed size; P2SH output would be unspendable")
	// return Script([OP_HASH160, crypto.Hash160(self), OP_EQUAL])
	return nil
}
