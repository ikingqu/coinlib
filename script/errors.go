package script

import "errors"

var (
	ErrOK        = errors.New("no error")
	ErrUnknown   = errors.New("unknown error")
	ErrEvalFalse = errors.New("Script evaluated without error but finished with a false/empty top stack element")
	ErrOPReturn  = errors.New("OP_RETURN was encountered")

	/* Max sizes */
	ErrScriptSize  = errors.New("Script is too big")
	ErrorPushSize  = errors.New("Push value size limit exceeded")
	ErrOPCount     = errors.New("Operation limit exceeded")
	ErrStackSize   = errors.New("Stack size limit exceeded")
	ErrSigCount    = errors.New("Signature count negative or greater than pubkey count")
	ErrPubkeyCount = errors.New("Pubkey count negative or limit execeeded")

	/* Failed verify operations */
	ErrVerify              = errors.New("Script failed an OP_VERIFY operation")
	ErrEqualVerify         = errors.New("Script failed an OP_EQUALVERIFY operation")
	ErrCheckMultiSigVerify = errors.New("Script failed an OP_CHECKMULTISIGVERIFY operation")
	ErrCheckSigVerify      = errors.New("Script failed an OP_CHECKSIGVERIFY operatin")
	ErrNumEqualVerify      = errors.New("Script failed an OP_NUMEQUALVERIFY operation")

	/* Logical/Format/Canonical errors */
	ErrBadOPCode                = errors.New("Opcode missing or not understood")
	ErrDisabledOPCode           = errors.New("Attemped to use a disabled opcode")
	ErrInvalidStackOperation    = errors.New("Operation not valid with the current stack size")
	ErrInvalidAltstackOperation = errors.New("Operation not valid with the current altstack size")
	ErrUnbalancedConditional    = errors.New("Invalid OP_IF construction")

	/* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
	ErrNagativeLocktime    = errors.New("Negative locktime")
	ErrUnsatisfiedLocktime = errors.New("Locktime requirement not satisfied")

	/* Malleability */
	ErrSigHashType  = errors.New("Signature hash type missing or not understood")
	ErrSigDER       = errors.New("Non-canonical DER signature")
	ErrMinimalData  = errors.New("Data push larger than necessary")
	ErrSigPushOnly  = errors.New("Only non-push operators allowed in signatures")
	ErrSigHighS     = errors.New("Non-canonical signature: S value is unnessarily high")
	ErrSigNullDummy = errors.New("Dummy CHECKMULTISIG argument must be zero")
	ErrPubkeyType   = errors.New("Public key is neither compressed or uncompressed")
	// ErrCleanStack = error.New("")
	ErrMinimalIf   = errors.New("OP_IF/NOTIF argument must be minimal")
	ErrSigNullFail = errors.New("Signature must be zero for failed CHECK(MULTI)SIG operation")

	/* softfork safeness */
	ErrDiscourageUpgradableNops           = errors.New("NOPx reserved for soft-fork upgrades")
	ErrDiscourageUpgradableWitnessProgram = errors.New("Witness version reserved for soft-fork upgrades")

	/* segregated witness */
	ErrWitnessProgramWrongLength  = errors.New("Witness program has incorrect length")
	ErrWitnessProgramWitnessEmpty = errors.New("Witness program was passed an empty witness")
	ErrWitnessProgramMimatch      = errors.New("Witness program hash mismatch")
	ErrWitnessMalleated           = errors.New("Witness requires empty scriptSig")
	ErrWitnessMalleatedP2SH       = errors.New("Witness requires only-redeemscript scriptSig")
	ErrWitnessUnexpected          = errors.New("Witness provided for non-witness script")
	ErrWitnessPubkeyType          = errors.New("Using non-compressed keys in segwit")

	ErrCount = errors.New("unknown error")
)
