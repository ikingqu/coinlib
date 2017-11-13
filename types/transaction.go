package types

import (
	"encoding/binary"
	"io"

	"github.com/maiiz/coinlib/encoding/varint"

	"github.com/maiiz/coinlib/crypto"
	"github.com/maiiz/coinlib/script"
)

const (
	// SequenceFinal defines Setting sequnce to this value for every input in a transaction
	// disables lock-time.
	SequenceFinal = 0xffffffff

	// SequenceLocktimeDisableFlag defines Below flags apply in the context of BIP 68
	// If this flag set, Tx.sequence is NOT interpreted as a
	// relative lock-time.
	SequenceLocktimeDisableFlag = (1 << 31)

	// SequnceLocktimeTypeFlag defines If txIn::sequence encodes a relative lock-time and this flag
	// is set, the relative lock-time has units of 512 seconds,
	// otherwise it specifies blocks with a granularity of 1. */
	SequnceLocktimeTypeFlag = (1 << 22)

	// SequenceLocktimeMask defines If CTxIn::nSequence encodes a relative lock-time, this mask is
	// applied to extract that lock-time from the sequence field.
	SequenceLocktimeMask = 0x0000ffff

	// SequenceLocktimeGranularity defines a lock-time granularity flag.
	// In order to use the same number of bits to encode roughly the
	/* same wall-clock duration, and because blocks are naturally
	 * limited to occur every 600s on average, the minimum granularity
	 * for time-based relative lock-time is fixed at 512 seconds.
	 * Converting from TxIn::Sequence to seconds is performed by
	 * multiplying by 512 = 2^9, or equivalently shifting up by
	 * 9 bits. */
	SequenceLocktimeGranularity = 9
)

var (
	// MarkerFlag defines the marker and flag in witness.
	MarkerFlag = []byte{0x00, 0x01}
)

// Transaction represents a transaction in blockchain.
type Transaction struct {
	Version  int32
	Vin      []*TxIn
	Vout     []*TxOut
	LockTime uint32
	Witness  [][]byte
}

// TxIn represets An input of a transaction
// Contains the location of the previous transaction's output that it claims,
// and a signature that matches the output's public key.
type TxIn struct {
	Prevout   *OutPoint
	ScriptSig script.Script
	Sequence  uint32
}

// TxOut defines a transaction output.
type TxOut struct {
	ScriptPubkey script.Script
	Value        int64
}

// OutPoint represents the combination of a transaction hash and an index n into its vout
type OutPoint struct {
	Hash  crypto.Hash
	Index uint32
}

// NewTxIn retruns a new transaction input.
func NewTxIn(h crypto.Hash, i uint32, scriptSig script.Script) *TxIn {
	return &TxIn{Prevout: NewOutPoint(h, i), ScriptSig: scriptSig, Sequence: SequenceFinal}
}

// NewOutPoint returns a new transaction outpoint.
func NewOutPoint(h crypto.Hash, i uint32) *OutPoint {
	return &OutPoint{Hash: h, Index: i}
}

// NewTxOut returns a new transaction output.
func NewTxOut(scriptPubkey script.Script, v int64) *TxOut {
	return &TxOut{ScriptPubkey: scriptPubkey, Value: v}
}

func (ti TxIn) marshal(w io.Writer) {
	ti.Prevout.marshal(w)
	ti.ScriptSig.Marshal(w)
	binary.Write(w, binary.LittleEndian, ti.Sequence)
}

func (op OutPoint) marshal(w io.Writer) {
	w.Write(op.Hash.Bytes())
	binary.Write(w, binary.LittleEndian, op.Index)
}

func (to TxOut) marshal(w io.Writer) {
	binary.Write(w, binary.LittleEndian, to.Value)
	to.ScriptPubkey.Marshal(w)
}

// AddTxIn adds a transaction input to the transaction.
func (tx *Transaction) AddTxIn(ti *TxIn) {
	tx.Vin = append(tx.Vin, ti)
}

// AddTxOut adds a transaction output to the transaction.
func (tx *Transaction) AddTxOut(to *TxOut) {
	tx.Vout = append(tx.Vout, to)
}

// Marshal encodes transaction to writer.
func (tx *Transaction) Marshal(w io.Writer) {
	binary.Write(w, binary.LittleEndian, tx.Version)

	// marker & flag
	if tx.HasWitness() {
		w.Write(MarkerFlag)
	}

	varint.WriteVarInt(w, uint64(len(tx.Vin)))
	for _, ti := range tx.Vin {
		ti.marshal(w)
	}

	varint.WriteVarInt(w, uint64(len(tx.Vout)))
	for _, to := range tx.Vout {
		to.marshal(w)
	}

	if tx.HasWitness() {
		for _, wit := range tx.Witness {
			varint.WriteVarInt(w, uint64(len(wit)))
			w.Write(wit)
		}
	}

	binary.Write(w, binary.LittleEndian, tx.LockTime)
}

// Unmarshal decodes reader to transaction.
func (tx *Transaction) Unmarshal(r io.Reader) error {
	err := binary.Read(r, binary.LittleEndian, tx.Version)
	if err != nil {
		return err
	}

	_, err = varint.ReadVarInt(r)
	if err != nil {
		return err
	}
	return nil
}

// HasWitness returns the segwit flag of the transaction.
func (tx Transaction) HasWitness() bool {
	return len(tx.Witness) != 0
}
