package script

import "fmt"

// Signature hash types/flags.
const (
	SigHashAll          = 1
	SigHashNone         = 2
	SigHashSingle       = 3
	SighashAnyOneCanPay = 0x80
)

// Script verification flags.
const (
	ScriptVerifyNone = 0

	// Evaluate P2SH subscripts (softfork safe, BIP16).
	ScriptVeryP2SH = (1 << 0)

	// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
	// Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
	// (softfork safe, but not used or intended as a consensus rule).
	ScriptVerifyStrictenc = (1 << 1)

	// Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
	ScriptVerifyDERSig = (1 << 2)

	// Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
	// (softfork safe, BIP62 rule 5).
	ScriptVerifyLowS = (1 << 3)

	// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
	ScriptVerifyNullDummy = (1 << 4)

	// Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
	ScriptVerivySigPushOnly = (1 << 5)

	// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
	// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
	// any other push causes the script to fail (BIP62 rule 3).
	// In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
	// (softfork safe)
	ScriptVerifyMinimalData = (1 << 6)

	// Discourage use of NOPs reserved for upgrades (NOP1-10)
	//
	// Provided so that nodes can avoid accepting or mining transactions
	// containing executed NOP's whose meaning may change after a soft-fork,
	// thus rendering the script invalid; with this flag set executing
	// discouraged NOPs fails the script. This verification flag will never be
	// a mandatory flag applied to scripts in a block. NOPs that are not
	// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
	ScriptVerifyDiscourageUpgradableNops = (1 << 7)

	// Require that only a single stack element remains after evaluation. This changes the success criterion from
	// "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
	// "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
	// (softfork safe, BIP62 rule 6)
	// Note: CLEANSTACK should never be used without P2SH or WITNESS.
	ScriptVerifyCleanStack = (1 << 8)

	// Verify CHECKLOCKTIMEVERIFY
	//
	// See BIP65 for details.
	ScriptVerifyCheckLockTimeVerify = (1 << 9)

	// support CHECKSEQUENCEVERIFY opcode
	//
	// See BIP112 for details
	ScriptVerifyCheckSequenceVerify = (1 << 10)

	// Support segregated witness
	//
	ScriptVerifyWitness = (1 << 11)

	// Making v1-v16 witness program non-standard
	//
	ScriptVerifyDiscourageUpgradableWitnessProgram = (1 << 12)

	// Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
	//
	ScriptVerifyMinimalIf = (1 << 13)

	// Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
	//
	ScriptVerifyNullFail = (1 << 14)

	// Public keys in segregated witness scripts must be compressed
	//
	ScriptVerifyWitnessPubkeyType = (1 << 15)
)

// SigVersion
const (
	SigVersionBase      = 0
	SigVersionWitnessV0 = 1
)

func checkExec(data []bool) bool {
	return true
}

// CastToBool xx.
func CastToBool(d []byte) bool {
	for i := 0; i < len(d); i++ {
		if d[i] != 0 {
			// Can be negative zero
			if (i == len(d)-1) && d[i] == 0x80 {
				return false
			}
			return true
		}
	}

	return false
}

// CheckMinimalPush checks minimal push.
func CheckMinimalPush(data []byte, opCode int) bool {
	dataSize := len(data)
	if dataSize == 0 {
		// Could have used OP_0.
		return opCode == OP_0
	} else if dataSize == 1 && data[0] >= 1 && data[0] <= 16 {
		// Could have used OP_1 .. OP_16.
		return opCode == OP_1+int(data[0]-1)
	} else if dataSize == 1 && data[0] == 0x81 {
		// Could have used OP_1NEGATE.
		return opCode == OP_1NEGATE
	} else if dataSize <= 75 {
		// Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
		return opCode == dataSize
	} else if dataSize <= 255 {
		// Could have used OP_PUSHDATA.
		return opCode == OP_PUSHDATA1
	} else if dataSize <= 65535 {
		// Could have used OP_PUSHDATA2.
		return opCode == OP_PUSHDATA2
	}
	return true
}

// EvalScript Evaluate a script
// stack    - Initial stack
// scriptIn - Script
// txTo     - Transaction the script is a part of
// inIdx    - txin index of the scriptSig
// flags    - SCRIPT_VERIFY_* flags to apply
func EvalScript(stack Stack, script Script, sigVersion, flags int) error {
	if script.Size() > MaxScriptSize {
		return ErrScriptSize
	}

	var (
		vfExec  []bool
		opCode  int
		data    []byte
		i       int
		ok      bool
		opCount int
	)
	isRequireMinimal := (flags & ScriptVerifyMinimalData) != 0

	for i = 0; i < script.Size(); i++ {
		if opCode, data, i, ok = script.GetOp(i); !ok {
			return ErrBadOPCode
		}
		isExec := checkExec(vfExec)

		// check Disabled opcodes.
		if opCode == OP_CAT ||
			opCode == OP_SUBSTR ||
			opCode == OP_LEFT ||
			opCode == OP_RIGHT ||
			opCode == OP_INVERT ||
			opCode == OP_AND ||
			opCode == OP_OR ||
			opCode == OP_XOR ||
			opCode == OP_2MUL ||
			opCode == OP_2DIV ||
			opCode == OP_MUL ||
			opCode == OP_DIV ||
			opCode == OP_MOD ||
			opCode == OP_LSHIFT ||
			opCode == OP_RSHIFT {
			return fmt.Errorf("opcode %s is disabled", GetOpName(opCode))
		}

		if opCode > OP_16 && (opCount+1 > MaxOpsPerScript) {
			return fmt.Errorf("script opCode too large, got %d, maximum %d", opCount, MaxOpsPerScript)
		}

		if isExec && 0 <= opCode && opCode <= OP_PUSHDATA4 {
			if isRequireMinimal && !CheckMinimalPush(data, opCode) {
				return fmt.Errorf("script minimal data error")
			}
			stack.Push(data)
		} else if isExec || (OP_IF <= opCode && opCode <= OP_ENDIF) {
			switch opCode {
			//
			// Push value
			//
			case OP_1NEGATE:
			case OP_1:
			case OP_2:
			case OP_3:
			case OP_4:
			case OP_5:
			case OP_6:
			case OP_7:
			case OP_8:
			case OP_9:
			case OP_10:
			case OP_11:
			case OP_12:
			case OP_13:
			case OP_14:
			case OP_15:
			case OP_16:
				{
					// The result of these opcodes should always be the minimal way to push the data
					// they push, so no need for a CheckMinimalPush here.
					bn := BigNumber(int(opCode) - (int)(OP_1-1))
					stack.Push(bn.Bytes())
					break
				}
			//
			// Control
			//
			case OP_NOP:
				break

			case OP_CHECKLOCKTIMEVERIFY:
				{
					if (flags & ScriptVerifyCheckLockTimeVerify) == 0 {
						// not enabled; treat as a NOP2
						if (flags & ScriptVerifyDiscourageUpgradableNops) != 0 {
							return ErrDiscourageUpgradableNops
						}
						break
					}

					if stack.Size() < 1 {
						return ErrInvalidStackOperation
					}
					// Note that elsewhere numeric opcodes are limited to
					// operands in the range -2**31+1 to 2**31-1, however it is
					// legal for opcodes to produce results exceeding that
					// range. This limitation is implemented by CScriptNum's
					// default 4-byte limit.
					//
					// If we kept to that limit we'd have a year 2038 problem,
					// even though the nLockTime field in transactions
					// themselves is uint32 which only becomes meaningless
					// after the year 2106.
					//
					// Thus as a special case we tell CScriptNum to accept up
					// to 5-byte bignums, which are good until 2**39-1, well
					// beyond the 2**32-1 limit of the nLockTime field itself.

					// TODO: BigNumber Support
					// lockTime := BigNumber(stack.Top(-1), isRequireMinimal, 5)
					// // In the rare event that the argument may be < 0 due to
					// // some arithmetic being done first, you can always use
					// // 0 MAX CHECKLOCKTIMEVERIFY.
					// if lockTime < 0 {
					// 	return ErrNegativeLocktime
					// }

					// // Actually compare the specified lock time with the transaction.
					// TODO: add checker
					// if (!checker.CheckLockTime(nLockTime)){
					// 	return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
					// }
					break
				}
			case OP_CHECKSEQUENCEVERIFY:
				{
					// if (flags & ScriptVerifyCheckSequenceVerify) == 0 {
					// 	// not enabled; treat as a NOP3
					// 	if (flags & ScriptVerifyDiscourageUpgradableNops) == 0 {
					// 		return ErrDiscourageUpgradableNops
					// 	}
					// 	break
					// }

					// if stack.Size() < 1 {
					// 	return ErrInvalidStackOperation
					// }

					// // nSequence, like nLockTime, is a 32-bit unsigned integer
					// // field. See the comment in CHECKLOCKTIMEVERIFY regarding
					// // 5-byte numeric operands.
					// sequence := BigNumber(stack.Top(-1), isRequireMinimal, 5)
					// // In the rare event that the argument may be < 0 due to
					// // some arithmetic being done first, you can always use
					// // 0 MAX CHECKSEQUENCEVERIFY.
					// if sequence < 0 {
					// 	return ErrNegativeLocktime
					// }

					// // To provide for future soft-fork extensibility, if the
					// // operand has the disabled lock-time flag set,
					// // CHECKSEQUENCEVERIFY behaves as a NOP.
					// //
					// if (sequence & types.SequenceLocktimeDisableFlag) != 0 {
					// 	break
					// }
					// Compare the specified sequence number with the input.
					// TODO: add checker
					// if !checker.CheckSequence(sequence) {
					// 	return ErrUnsatisfiedLocktime
					// }
					break
				}
			case OP_NOP1:
			case OP_NOP4:
			case OP_NOP5:
			case OP_NOP6:
			case OP_NOP7:
			case OP_NOP8:
			case OP_NOP9:
			case OP_NOP10:
				{
					if (flags & ScriptVerifyDiscourageUpgradableNops) != 0 {
						return ErrDiscourageUpgradableNops
					}
				}
				break

			case OP_IF:
			case OP_NOTIF:
				{
					// // <expression> if [statements] [else [statements]] endif
					isValue := false
					if isExec {
						if stack.Size() < 1 {
							return ErrUnbalancedConditional
						}
						v := stack.Top(-1)
						if (sigVersion == SigVersionWitnessV0) && (flags&ScriptVerifyMinimalIf) != 0 {
							if len(v) > 1 {
								return ErrMinimalIf
							}
							if len(v) == 1 && v[0] != 1 {
								return ErrMinimalIf
							}
						}
						isValue = CastToBool(v)
						if opCode == OP_NOTIF {
							isValue = !isValue
						}
						stack.Pop()
					}
					vfExec = append(vfExec, isValue)
					break
				}
			case OP_ELSE:
				{
					if len(vfExec) == 0 {
						return ErrUnbalancedConditional
					}

					vfExec[len(vfExec)-1] = !vfExec[len(vfExec)-1]
					break
				}
			case OP_ENDIF:
				{
					if len(vfExec) == 0 {
						return ErrUnbalancedConditional
					}
					vfExec = vfExec[:len(vfExec)-1]
					break
				}
			case OP_VERIFY:
				{
					// (true -- ) or
					// (false -- false) and return
					if stack.Size() < 1 {
						return ErrInvalidStackOperation
					}
					isValue := CastToBool(stack.Top(-1))
					if isValue {
						stack.Pop()
					} else {
						return ErrVerify
					}
					break
				}

			case OP_RETURN:
				{
					return ErrOPReturn
				}

			//
			// Stack ops
			//
			case OP_TOALTSTACK:
				{
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// altstack.push_back(stacktop(-1));
					// popstack(stack);

					break
				}

			case OP_FROMALTSTACK:
				{
					// if (altstack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
					// stack.push_back(altstacktop(-1));
					// popstack(altstack);
					break
				}

			case OP_2DROP:
				{
					// (x1 x2 -- )
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// popstack(stack);
					// popstack(stack);
					break
				}

			case OP_2DUP:
				{
					// (x1 x2 -- x1 x2 x1 x2)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch1 = stacktop(-2);
					// valtype vch2 = stacktop(-1);
					// stack.push_back(vch1);
					// stack.push_back(vch2);
					break
				}

			case OP_3DUP:
				{
					// (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
					// if (stack.size() < 3)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch1 = stacktop(-3);
					// valtype vch2 = stacktop(-2);
					// valtype vch3 = stacktop(-1);
					// stack.push_back(vch1);
					// stack.push_back(vch2);
					// stack.push_back(vch3);
					//
					break
				}

			case OP_2OVER:
				{
					// (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
					// if (stack.size() < 4)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch1 = stacktop(-4);
					// valtype vch2 = stacktop(-3);
					// stack.push_back(vch1);
					// stack.push_back(vch2);
					break
				}

			case OP_2ROT:
				{
					// (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
					// if (stack.size() < 6)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch1 = stacktop(-6);
					// valtype vch2 = stacktop(-5);
					// stack.erase(stack.end()-6, stack.end()-4);
					// stack.push_back(vch1);
					// stack.push_back(vch2);
					break
				}

			case OP_2SWAP:
				{
					// (x1 x2 x3 x4 -- x3 x4 x1 x2)
					// if (stack.size() < 4)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// swap(stacktop(-4), stacktop(-2));
					// swap(stacktop(-3), stacktop(-1));
					break
				}

			case OP_IFDUP:
				{
					// (x - 0 | x x)
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch = stacktop(-1);
					// if (CastToBool(vch))
					// 	stack.push_back(vch);
					break
				}

			case OP_DEPTH:
				{
					// -- stacksize
					// CScriptNum bn(stack.size());
					// stack.push_back(bn.getvch())
					break
				}

			case OP_DROP:
				{
					// (x -- )
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// popstack(stack);
					break
				}

			case OP_DUP:
				{
					// (x -- x x)
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch = stacktop(-1);
					// stack.push_back(vch);
					break
				}

			case OP_NIP:
				{
					// (x1 x2 -- x2)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// stack.erase(stack.end() - 2);
					break
				}

			case OP_OVER:
				{
					// (x1 x2 -- x1 x2 x1)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch = stacktop(-2);
					// stack.push_back(vch);
					break
				}

			case OP_PICK:
			case OP_ROLL:
				{
					// (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
					// (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
					// popstack(stack);
					// if (n < 0 || n >= (int)stack.size())
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch = stacktop(-n-1);
					// if (opcode == OP_ROLL)
					//     stack.erase(stack.end()-n-1);
					// stack.push_back(vch);
					break
				}

			case OP_ROT:
				{
					// (x1 x2 x3 -- x2 x3 x1)
					//  x2 x1 x3  after first swap
					//  x2 x3 x1  after second swap
					// if (stack.size() < 3)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// swap(stacktop(-3), stacktop(-2));
					// swap(stacktop(-2), stacktop(-1));
					break
				}

			case OP_SWAP:
				{
					// (x1 x2 -- x2 x1)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// swap(stacktop(-2), stacktop(-1));
					break
				}

			case OP_TUCK:
				{
					// (x1 x2 -- x2 x1 x2)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype vch = stacktop(-1);
					// stack.insert(stack.end()-2, vch);
					break
				}

			case OP_SIZE:
				{
					// (in -- in size)
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// CScriptNum bn(stacktop(-1).size());
					// stack.push_back(bn.getvch());
					break
				}

			//
			// Bitwise logic
			//
			case OP_EQUAL:
			case OP_EQUALVERIFY:
				//case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
				{
					// (x1 x2 - bool)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype& vch1 = stacktop(-2);
					// valtype& vch2 = stacktop(-1);
					// bool fEqual = (vch1 == vch2);
					// // OP_NOTEQUAL is disabled because it would be too easy to say
					// // something like n != 1 and have some wiseguy pass in 1 with extra
					// // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
					// //if (opcode == OP_NOTEQUAL)
					// //    fEqual = !fEqual;
					// popstack(stack);
					// popstack(stack);
					// stack.push_back(fEqual ? vchTrue : vchFalse);
					// if (opcode == OP_EQUALVERIFY)
					// {
					//     if (fEqual)
					//         popstack(stack);
					//     else
					//         return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
					// }
					break
				}

			//
			// Numeric
			//
			case OP_1ADD:
			case OP_1SUB:
			case OP_NEGATE:
			case OP_ABS:
			case OP_NOT:
			case OP_0NOTEQUAL:
				{
					// // (in -- out)
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// CScriptNum bn(stacktop(-1), fRequireMinimal);
					// switch (opcode)
					// {
					// case OP_1ADD:       bn += bnOne; break;
					// case OP_1SUB:       bn -= bnOne; break;
					// case OP_NEGATE:     bn = -bn; break;
					// case OP_ABS:        if (bn < bnZero) bn = -bn; break;
					// case OP_NOT:        bn = (bn == bnZero); break;
					// case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
					// default:            assert(!"invalid opcode"); break;
					// }
					// popstack(stack);
					// stack.push_back(bn.getvch());
					break
				}

			case OP_ADD:
			case OP_SUB:
			case OP_BOOLAND:
			case OP_BOOLOR:
			case OP_NUMEQUAL:
			case OP_NUMEQUALVERIFY:
			case OP_NUMNOTEQUAL:
			case OP_LESSTHAN:
			case OP_GREATERTHAN:
			case OP_LESSTHANOREQUAL:
			case OP_GREATERTHANOREQUAL:
			case OP_MIN:
			case OP_MAX:
				{
					// (x1 x2 -- out)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// CScriptNum bn1(stacktop(-2), fRequireMinimal);
					// CScriptNum bn2(stacktop(-1), fRequireMinimal);
					// CScriptNum bn(0);
					// switch (opcode)
					// {
					// case OP_ADD:
					//     bn = bn1 + bn2;
					//     break;

					// case OP_SUB:
					//     bn = bn1 - bn2;
					//     break;

					// case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
					// case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
					// case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
					// case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
					// case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
					// case OP_LESSTHAN:            bn = (bn1 < bn2); break;
					// case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
					// case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
					// case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
					// case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
					// case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
					// default:                     assert(!"invalid opcode"); break;
					// }
					// popstack(stack);
					// popstack(stack);
					// stack.push_back(bn.getvch());

					// if (opcode == OP_NUMEQUALVERIFY)
					// {
					//     if (CastToBool(stacktop(-1)))
					//         popstack(stack);
					//     else
					//         return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
					// }
					break
				}

			case OP_WITHIN:
				{
					// (x min max -- out)
					// if (stack.size() < 3)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// CScriptNum bn1(stacktop(-3), fRequireMinimal);
					// CScriptNum bn2(stacktop(-2), fRequireMinimal);
					// CScriptNum bn3(stacktop(-1), fRequireMinimal);
					// bool fValue = (bn2 <= bn1 && bn1 < bn3);
					// popstack(stack);
					// popstack(stack);
					// popstack(stack);
					// stack.push_back(fValue ? vchTrue : vchFalse);
					break
				}

			//
			// Crypto
			//
			case OP_RIPEMD160:
			case OP_SHA1:
			case OP_SHA256:
			case OP_HASH160:
			case OP_HASH256:
				{
					// (in -- hash)
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// valtype& vch = stacktop(-1);
					// valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
					// if (opcode == OP_RIPEMD160)
					//     CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
					// else if (opcode == OP_SHA1)
					//     CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
					// else if (opcode == OP_SHA256)
					//     CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
					// else if (opcode == OP_HASH160)
					//     CHash160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
					// else if (opcode == OP_HASH256)
					//     CHash256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
					// popstack(stack);
					// stack.push_back(vchHash);
					break
				}

			case OP_CODESEPARATOR:
				{
					// Hash starts after the code separator
					// pbegincodehash = pc;
					break
				}

			case OP_CHECKSIG:
			case OP_CHECKSIGVERIFY:
				{
					// (sig pubkey -- bool)
					// if (stack.size() < 2)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

					// valtype& vchSig    = stacktop(-2);
					// valtype& vchPubKey = stacktop(-1);

					// // Subset of script starting at the most recent codeseparator
					// CScript scriptCode(pbegincodehash, pend);

					// // Drop the signature in pre-segwit scripts but not segwit scripts
					// if (sigversion == SIGVERSION_BASE) {
					//     scriptCode.FindAndDelete(CScript(vchSig));
					// }

					// if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
					//     //serror is set
					//     return false;
					// }
					// bool fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

					// if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
					//     return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

					// popstack(stack);
					// popstack(stack);
					// stack.push_back(fSuccess ? vchTrue : vchFalse);
					// if (opcode == OP_CHECKSIGVERIFY)
					// {
					//     if (fSuccess)
					//         popstack(stack);
					//     else
					//         return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
					// }
					break
				}

			case OP_CHECKMULTISIG:
			case OP_CHECKMULTISIGVERIFY:
				{
					// ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

					// int i = 1;
					// if ((int)stack.size() < i)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

					// int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
					// if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
					//     return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
					// nOpCount += nKeysCount;
					// if (nOpCount > MAX_OPS_PER_SCRIPT)
					//     return set_error(serror, SCRIPT_ERR_OP_COUNT);
					// int ikey = ++i;
					// // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
					// // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
					// int ikey2 = nKeysCount + 2;
					// i += nKeysCount;
					// if ((int)stack.size() < i)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

					// int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
					// if (nSigsCount < 0 || nSigsCount > nKeysCount)
					//     return set_error(serror, SCRIPT_ERR_SIG_COUNT);
					// int isig = ++i;
					// i += nSigsCount;
					// if ((int)stack.size() < i)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

					// // Subset of script starting at the most recent codeseparator
					// CScript scriptCode(pbegincodehash, pend);

					// // Drop the signature in pre-segwit scripts but not segwit scripts
					// for (int k = 0; k < nSigsCount; k++)
					// {
					//     valtype& vchSig = stacktop(-isig-k);
					//     if (sigversion == SIGVERSION_BASE) {
					//         scriptCode.FindAndDelete(CScript(vchSig));
					//     }
					// }

					// bool fSuccess = true;
					// while (fSuccess && nSigsCount > 0)
					// {
					//     valtype& vchSig    = stacktop(-isig);
					//     valtype& vchPubKey = stacktop(-ikey);

					//     // Note how this makes the exact order of pubkey/signature evaluation
					//     // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
					//     // See the script_(in)valid tests for details.
					//     if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
					//         // serror is set
					//         return false;
					//     }

					//     // Check signature
					//     bool fOk = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

					//     if (fOk) {
					//         isig++;
					//         nSigsCount--;
					//     }
					//     ikey++;
					//     nKeysCount--;

					//     // If there are more signatures left than keys left,
					//     // then too many signatures have failed. Exit early,
					//     // without checking any further signatures.
					//     if (nSigsCount > nKeysCount)
					//         fSuccess = false;
					// }

					// // Clean up stack of actual arguments
					// while (i-- > 1) {
					//     // If the operation failed, we require that all signatures must be empty vector
					//     if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
					//         return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
					//     if (ikey2 > 0)
					//         ikey2--;
					//     popstack(stack);
					// }

					// // A bug causes CHECKMULTISIG to consume one extra argument
					// // whose contents were not checked in any way.
					// //
					// // Unfortunately this is a potential source of mutability,
					// // so optionally verify it is exactly equal to zero prior
					// // to removing it from the stack.
					// if (stack.size() < 1)
					//     return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
					// if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
					//     return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
					// popstack(stack);

					// stack.push_back(fSuccess ? vchTrue : vchFalse);

					// if (opcode == OP_CHECKMULTISIGVERIFY)
					// {
					//     if (fSuccess)
					//         popstack(stack);
					//     else
					//         return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
					// }
					break
				}

			default:
				return fmt.Errorf("")
			}
		}
	}
	return nil
}
