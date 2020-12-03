// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "core_io.h"

#include "key_io.h"
#include "main.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include <univalue.h>
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

using namespace std;

string FormatScript(const CScript& script)
{
    string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_CHECKMULTISIGVERIFY) {
                string str(GetOpName(op));
                if (str.substr(0, 3) == string("OP_")) {
                    ret += str.substr(3, string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            } else {
                ret += strprintf("0x%x", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

const map<unsigned char, string> mapSigHashTypes =
    boost::assign::map_list_of
    (static_cast<unsigned char>(SIGHASH_ALL), string("ALL"))
    (static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), string("ALL|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_NONE), string("NONE"))
    (static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), string("NONE|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_SINGLE), string("SINGLE"))
    (static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), string("SINGLE|ANYONECANPAY"))
    ;

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    string str;
    opcodetype opcode;
    vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, NULL)) {
                        const unsigned char chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType)) {
                            strSigHashDecode = "[" + mapSigHashTypes.find(chSigHashType)->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

string EncodeHexTx(const CTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey,
                        UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    KeyIO keyIO(Params());
    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses) {
        a.push_back(keyIO.EncodeDestination(addr));
    }
    out.pushKV("addresses", a);
}

UniValue TxJoinSplitToJSON(const CTransaction& tx) {
    bool useGroth = tx.fOverwintered && tx.nVersion >= SAPLING_TX_VERSION;
    UniValue vJoinSplit(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vJoinSplit.size(); i++) {
        const JSDescription& jsdescription = tx.vJoinSplit[i];
        UniValue joinsplit(UniValue::VOBJ);

        joinsplit.pushKV("vpub_old", ValueFromAmount(jsdescription.vpub_old));
        joinsplit.pushKV("vpub_oldZat", jsdescription.vpub_old);
        joinsplit.pushKV("vpub_new", ValueFromAmount(jsdescription.vpub_new));
        joinsplit.pushKV("vpub_newZat", jsdescription.vpub_new);

        joinsplit.pushKV("anchor", jsdescription.anchor.GetHex());

        {
            UniValue nullifiers(UniValue::VARR);
            BOOST_FOREACH(const uint256 nf, jsdescription.nullifiers) {
                nullifiers.push_back(nf.GetHex());
            }
            joinsplit.pushKV("nullifiers", nullifiers);
        }

        {
            UniValue commitments(UniValue::VARR);
            BOOST_FOREACH(const uint256 commitment, jsdescription.commitments) {
                commitments.push_back(commitment.GetHex());
            }
            joinsplit.pushKV("commitments", commitments);
        }

        joinsplit.pushKV("onetimePubKey", jsdescription.ephemeralKey.GetHex());
        joinsplit.pushKV("randomSeed", jsdescription.randomSeed.GetHex());

        {
            UniValue macs(UniValue::VARR);
            BOOST_FOREACH(const uint256 mac, jsdescription.macs) {
                macs.push_back(mac.GetHex());
            }
            joinsplit.pushKV("macs", macs);
        }

        CDataStream ssProof(SER_NETWORK, PROTOCOL_VERSION);
        auto ps = SproutProofSerializer<CDataStream>(ssProof, useGroth);
        boost::apply_visitor(ps, jsdescription.proof);
        joinsplit.pushKV("proof", HexStr(ssProof.begin(), ssProof.end()));

        {
            UniValue ciphertexts(UniValue::VARR);
            for (const ZCNoteEncryption::Ciphertext ct : jsdescription.ciphertexts) {
                ciphertexts.push_back(HexStr(ct.begin(), ct.end()));
            }
            joinsplit.pushKV("ciphertexts", ciphertexts);
        }

        vJoinSplit.push_back(joinsplit);
    }
    return vJoinSplit;
}

UniValue TxShieldedSpendsToJSON(const CTransaction& tx) {
    UniValue vdesc(UniValue::VARR);
    for (const SpendDescription& spendDesc : tx.vShieldedSpend) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("cv", spendDesc.cv.GetHex());
        obj.pushKV("anchor", spendDesc.anchor.GetHex());
        obj.pushKV("nullifier", spendDesc.nullifier.GetHex());
        obj.pushKV("rk", spendDesc.rk.GetHex());
        obj.pushKV("proof", HexStr(spendDesc.zkproof.begin(), spendDesc.zkproof.end()));
        obj.pushKV("spendAuthSig", HexStr(spendDesc.spendAuthSig.begin(), spendDesc.spendAuthSig.end()));
        vdesc.push_back(obj);
    }
    return vdesc;
}

UniValue TxShieldedOutputsToJSON(const CTransaction& tx) {
    UniValue vdesc(UniValue::VARR);
    for (const OutputDescription& outputDesc : tx.vShieldedOutput) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("cv", outputDesc.cv.GetHex());
        obj.pushKV("cmu", outputDesc.cmu.GetHex());
        obj.pushKV("ephemeralKey", outputDesc.ephemeralKey.GetHex());
        obj.pushKV("encCiphertext", HexStr(outputDesc.encCiphertext.begin(), outputDesc.encCiphertext.end()));
        obj.pushKV("outCiphertext", HexStr(outputDesc.outCiphertext.begin(), outputDesc.outCiphertext.end()));
        obj.pushKV("proof", HexStr(outputDesc.zkproof.begin(), outputDesc.zkproof.end()));
        vdesc.push_back(obj);
    }
    return vdesc;
}

void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION));
    entry.pushKV("overwintered", tx.fOverwintered);
    if (tx.fOverwintered) {
        entry.pushKV("versiongroupid", HexInt(tx.nVersionGroupId));
    }
    entry.pushKV("locktime", (int64_t)tx.nLockTime);
    if (tx.fOverwintered) {
        entry.pushKV("expiryheight", (int64_t)tx.nExpiryHeight);
    }

    KeyIO keyIO(Params());

    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);

            // Add address and value info if spentindex enabled
            CSpentIndexValue spentInfo;
            CSpentIndexKey spentKey(txin.prevout.hash, txin.prevout.n);
            if (fSpentIndex && GetSpentIndex(spentKey, spentInfo)) {
                in.pushKV("value", ValueFromAmount(spentInfo.satoshis));
                in.pushKV("valueSat", spentInfo.satoshis);

                CTxDestination dest =
                    DestFromAddressHash(spentInfo.addressType, spentInfo.addressHash);
                if (IsValidDestination(dest)) {
                    in.pushKV("address", keyIO.EncodeDestination(dest));
                }
            }
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("valueZat", txout.nValue);
        out.pushKV("valueSat", txout.nValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);

        // Add spent information if spentindex is enabled
        CSpentIndexValue spentInfo;
        CSpentIndexKey spentKey(tx.GetHash(), i);
        if (fSpentIndex && GetSpentIndex(spentKey, spentInfo)) {
            out.pushKV("spentTxId", spentInfo.txid.GetHex());
            out.pushKV("spentIndex", (int)spentInfo.inputIndex);
            out.pushKV("spentHeight", spentInfo.blockHeight);
        }

        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    UniValue vjoinsplit = TxJoinSplitToJSON(tx);
    entry.pushKV("vjoinsplit", vjoinsplit);

    if (tx.fOverwintered && tx.nVersion >= SAPLING_TX_VERSION) {
        entry.pushKV("valueBalance", ValueFromAmount(tx.valueBalance));
        entry.pushKV("valueBalanceZat", tx.valueBalance);
        UniValue vspenddesc = TxShieldedSpendsToJSON(tx);
        entry.pushKV("vShieldedSpend", vspenddesc);
        UniValue voutputdesc = TxShieldedOutputsToJSON(tx);
        entry.pushKV("vShieldedOutput", voutputdesc);
        if (!(vspenddesc.empty() && voutputdesc.empty())) {
            entry.pushKV("bindingSig", HexStr(tx.bindingSig.begin(), tx.bindingSig.end()));
        }
    }

    if (tx.nVersion >= 2 && tx.vJoinSplit.size() > 0) {
        // Copy joinSplitPubKey into a uint256 so that
        // it is byte-flipped in the RPC output.
        uint256 joinSplitPubKey;
        std::copy(
            tx.joinSplitPubKey.bytes,
            tx.joinSplitPubKey.bytes + ED25519_VERIFICATION_KEY_LEN,
            joinSplitPubKey.begin());
        entry.pushKV("joinSplitPubKey", joinSplitPubKey.GetHex());
        entry.pushKV("joinSplitSig",
            HexStr(tx.joinSplitSig.bytes, tx.joinSplitSig.bytes + ED25519_SIGNATURE_LEN));
    }

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
